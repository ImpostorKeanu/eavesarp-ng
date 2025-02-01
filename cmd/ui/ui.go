package main

import (
	"context"
	"database/sql"
	"errors"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	eavesarp_ng "github.com/impostorkeanu/eavesarp-ng"
	"github.com/impostorkeanu/eavesarp-ng/cmd/ui/misc"
	"github.com/impostorkeanu/eavesarp-ng/cmd/ui/panes"
	"github.com/impostorkeanu/eavesarp-ng/cmd/ui/panes/stopwatch"
	"github.com/impostorkeanu/eavesarp-ng/cmd/ui/panes/timer"
	zone "github.com/lrstanley/bubblezone"
	"strconv"
	"strings"
	"time"
)

var (
	deselectedPaneBorderColor = lipgloss.Color("240")
	selectedPaneBorderColor   = lipgloss.Color("248")
	paneStyle                 = lipgloss.NewStyle().
		Border(lipgloss.NormalBorder(), true, true, true, true).
		BorderForeground(deselectedPaneBorderColor)
	centerStyle  = lipgloss.NewStyle().AlignHorizontal(lipgloss.Center)
	spinnerStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("205")).
		Width(35).
		AlignHorizontal(lipgloss.Center).AlignVertical(lipgloss.Center)
	convosTableStyle table.Styles
)

const (
	CfgPoisonButtonId = "poisonBtn"
	doneKey           = "done"
	chKey             = "ch"
	cancelKey         = "cancel"
)

func init() {
	convosTableStyle = table.DefaultStyles()
	convosTableStyle.Header = convosTableStyle.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(true).
		PaddingLeft(1)
	convosTableStyle.Cell.PaddingLeft(1)
	convosTableStyle.Selected = convosTableStyle.Selected.
		//Foreground(lipgloss.Color("229")).
		//Background(lipgloss.Color("57")).
		//UnsetForeground().
		Foreground(lipgloss.Color("255")).
		Bold(true)
}

type (
	model struct {
		db *sql.DB

		maxPaneHeight, uiWidth int
		rightWidth             int
		curConvoHeight         int
		bottomRightHeight      int
		// focusedId tracks the pane ID that is currently in
		// focus within the UI.
		focusedId misc.PaneHeadingId
		// events tracks records emitted by Eavesarp and the UI.
		// Each record is presented to the user via the logPane.
		events []string
		// eWriter is a channel used to write records to events.
		eWriter *misc.EventWriter
		// activeAttacks tracks attacks that are currently active.
		activeAttacks *misc.ActiveAttacks
		// convosTable is the key conversations table that maps
		// sender IPs to target IPs, allowing us to determine which
		// hosts are intercommunicating.
		convosTable table.Model
		// convosSpinner spins while no ARP traffic has been collected
		// to present.
		convosSpinner spinner.Model
		// convosRowSenders maps a row offset to its corresponding
		// sender IP value, allowing us to filter out repetitive
		// IPs from the convosTable table.
		convosRowSenders map[int]string
		convoPoisonPane  panes.PoisonPane
		// curConvoRow contains details related to the currently selected
		// conversation row.
		curConvoRow panes.CurConvoRowDetails
		// curConvoPane presents information related to the currently
		// selected conversation, such as MAC addresses and DNS names.
		curConvoPane panes.CurConvoPane

		// logPane presents lines from events.
		logPane panes.LogsPane
		logsCh  chan string

		// mainSniff determines if the sniffing process should
		// be started. As it allows the UI to run without root,
		// it's sometimes useful to disable this while debugging.
		mainSniff bool
	}

	eavesarpError error
)

func newConvoRow(r table.Row) (_ panes.CurConvoRowDetails, err error) {
	var ind, arpCount int
	if ind, err = strconv.Atoi(r[0]); err != nil {
		return
	} else if arpCount, err = strconv.Atoi(r[5]); err != nil {
		return
	}
	return panes.CurConvoRowDetails{ind, r[1] != "", r[3], r[4], arpCount}, err
}

func (m model) Init() tea.Cmd {
	cmds := []tea.Cmd{
		m.logPane.Init(),
		func() tea.Msg {
			return m.convosSpinner.Tick()
		},
		func() tea.Msg {
			return getConvosTableContent(&m)
		},
		func() tea.Msg {
			m.doCurrConvoRow()
			return m.curConvoPane.GetContent(m.db, m.curConvoRow)
		},
	}

	if m.mainSniff {
		cmds = append(cmds, func() tea.Msg {
			if err := eavesarp_ng.MainSniff(m.db, ifaceName, m.eWriter); err != nil {
				return eavesarpError(err)
			}
			return nil
		})
	}

	return tea.Sequence(cmds...)
}

func packetCountMessageHandler(msg panes.PacketCountMessage) tea.Cmd {
	return func() tea.Msg {
		ch := msg.Ctx.Value(chKey).(chan int)
		select {
		case <-msg.Ctx.Done():
			msg.Ctx = context.WithValue(msg.Ctx, doneKey, true)
			close(msg.Ctx.Value(chKey).(chan int))
			msg.Ctx.Value(cancelKey).(context.CancelFunc)()
			if err := msg.Ctx.Err(); errors.Is(err, context.Canceled) {
				msg.Ew.WriteStringf("poisoning canceled: %s", msg.Id)
			} else if errors.Is(err, context.DeadlineExceeded) {
				msg.Ew.WriteStringf("poisoning timed out: %s", msg.Id)
			} else {
				msg.Ew.WriteStringf("unhandled exception while capturing packets: %s", err.Error())
			}
		case count := <-ch:
			return panes.PacketCountMessage{
				Id:    msg.Id,
				Count: count,
				Ctx:   msg.Ctx,
				Ew:    msg.Ew,
			}
		}
		return nil
	}
}

func (m model) Update(msg tea.Msg) (_ tea.Model, cmd tea.Cmd) {

	switch msg := msg.(type) {

	case panes.PacketCountMessage:

		if msg.Ctx.Value(doneKey) != nil {
			return m, cmd
		}

		poisonPane := poisonPaneLm.Get(msg.Id)
		if poisonPane == nil {
			return m, cmd
		}

		*poisonPane, cmd = poisonPane.Update(msg)
		cmd = tea.Batch(packetCountMessageHandler(msg), cmd)

	case panes.LogEvent:

		m.logPane, cmd = m.logPane.Update(msg)

	case convosTableContent:

		if msg.err != nil {
			_, err := m.eWriter.WriteStringf("failed update conversations content: %v", msg.err.Error())
			if err != nil {
				m.eWriter.WriteString("failed to call WriteStringf while reporting error")
				panic(err)
			}
		} else {
			m.convosRowSenders = msg.rowSenders
			m.doConvoTableContent(msg)
		}

		cmd = func() tea.Msg {
			// Periodically update the ARP table
			// TODO we may want to make the update frequency configurable
			time.Sleep(2 * time.Second)
			return getConvosTableContent(&m)
		}

	case timer.TimeoutMsg:

		// TODO handle when a poisoning attack finishes due to timeout

	case timer.TickMsg:

		if poisonPane := poisonPaneLm.Get(msg.Id); poisonPane == nil {
			// NOP for missing poison pane
		} else if msg.Id != m.curConvoRow.ConvoKey() {
			// Stop ticks for out of focus stopwatches
			cmd = poisonPane.Timer.Stop()
		} else {
			// Update the stopwatch to reflect current tick
			*poisonPane, cmd = poisonPane.Update(msg)
		}
		return m, cmd

	case timer.StartStopMsg:

		if poisonPane := poisonPaneLm.Get(msg.Id); poisonPane != nil {
			*poisonPane, cmd = poisonPane.Update(msg)
		}
		return m, cmd

	case stopwatch.TickMsg:

		if poisonPane := poisonPaneLm.Get(msg.Id); poisonPane == nil {
			// NOP for missing poison pane
		} else if msg.Id != m.curConvoRow.ConvoKey() {
			// Stop ticks for out of focus stopwatches
			cmd = poisonPane.Stopwatch.Stop()
		} else {
			// Update the stopwatch to reflect current tick
			*poisonPane, cmd = poisonPane.Update(msg)
		}
		return m, cmd

	case stopwatch.StartStopMsg:

		if poisonPane := poisonPaneLm.Get(msg.Id); poisonPane != nil {
			*poisonPane, cmd = poisonPane.Update(msg)
		}
		return m, cmd

	case panes.BtnPressMsg:

		switch msg.Event {
		case panes.StartPoisonEvent:

			if err := m.activeAttacks.Add(m.curConvoRow.SenderIp, m.curConvoRow.TargetIp); err != nil {
				panic(err)
			}

			// Emit the proper msg based on timer type
			if poisonPane := poisonPaneLm.Get(m.curConvoRow.ConvoKey()); poisonPane == nil {
				// TODO
				panic("failed to find poison pane for conversation")
			} else if len(poisonPane.CaptureDurationInput().Value()) > 0 {

				// Duration was validated by poison pane
				d, _ := time.ParseDuration(poisonPane.CaptureDurationInput().Value())
				poisonPane.Timer = timer.New(m.curConvoRow.ConvoKey(), d)
				cmd = poisonPane.Timer.Start()

				var ctx context.Context
				ctx, poisonPane.CancelPoisonCtx = context.WithTimeout(context.Background(), d)
				ctx = context.WithValue(ctx, chKey, make(chan int))
				ctx = context.WithValue(ctx, cancelKey, poisonPane.CancelPoisonCtx)

				cmd = tea.Batch(
					poisonPane.Timer.Start(),
					func() tea.Msg {
						return panes.PacketCountMessage{
							Id:    m.curConvoRow.ConvoKey(),
							Count: 0,
							Ctx:   ctx,
							Ew:    m.eWriter,
						}
					},
					func() tea.Msg {
						// TODO start poisoning here
						ch := ctx.Value(chKey).(chan int)
					outer:
						for i := 0; i < 100; i++ {
							select {
							case <-ctx.Done():
								break outer
							default:
								ch <- i
							}
							time.Sleep(time.Second)
						}
						return nil
					})

			} else {

				poisonPane.Stopwatch = stopwatch.NewStopwatch(m.curConvoRow.SenderIp, m.curConvoRow.TargetIp, time.Now(), time.Second)

				var ctx context.Context
				ctx, poisonPane.CancelPoisonCtx = context.WithCancel(context.Background())
				ctx = context.WithValue(ctx, chKey, make(chan int))
				ctx = context.WithValue(ctx, cancelKey, poisonPane.CancelPoisonCtx)

				cmd = tea.Batch(
					poisonPane.Stopwatch.Start(),
					func() tea.Msg {
						return panes.PacketCountMessage{
							Id:    m.curConvoRow.ConvoKey(),
							Count: 0,
							Ctx:   ctx,
							Ew:    m.eWriter,
						}
					},
					func() tea.Msg {
						// TODO start poisoning here
					outer:
						for i := 0; i < 100; i++ {
							select {
							case <-ctx.Done():
								break outer
							default:
								ctx.Value(chKey).(chan int) <- i
								time.Sleep(time.Second)
							}
						}
						return nil
					})

			}
			m.curConvoPane.IsPoisoning = true

		case panes.CancelPoisonEvent:
			m.activeAttacks.Remove(m.curConvoRow.SenderIp, m.curConvoRow.TargetIp)
			if pp := poisonPaneLm.Get(m.curConvoRow.ConvoKey()); pp != nil && pp.CancelPoisonCtx != nil {
				pp.CancelPoisonCtx()
			}
			poisonPaneLm.Delete(m.curConvoRow.ConvoKey())
			m.focusedId = misc.ConvosPaneId
			m.curConvoPane.IsConfiguringPoisoning = false
			m.curConvoPane.IsPoisoning = false
		case panes.CancelConfigEvent:
			poisonPaneLm.Delete(m.curConvoRow.ConvoKey())
			m.focusedId = misc.LogPaneId
			m.curConvoPane.IsConfiguringPoisoning = false
			m.curConvoPane.IsPoisoning = false
		default:
			panic("unknown button press event emitted by poison configuration panel")
		}

		return m, cmd

	case tea.MouseMsg:
		// Handle mouse events, like button presses

		if msg.Action != tea.MouseActionRelease || msg.Button != tea.MouseButtonLeft {
			// We only care about the left mouse button
			break
		}

		// Change focus based on header click
		if m.focusedId != misc.PoisonCfgPaneId {
			if m.focusedId != misc.LogPaneId && zone.Get(misc.LogPaneId.String()).InBounds(msg) {
				m.focusedId = misc.LogPaneId
			} else if m.focusedId != misc.ConvosPaneId && zone.Get(misc.ConvosPaneId.String()).InBounds(msg) {
				m.focusedId = misc.ConvosPaneId
			} else if m.focusedId != misc.CurConvoPaneId && zone.Get(misc.CurConvoPaneId.String()).InBounds(msg) {
				m.focusedId = misc.CurConvoPaneId
			}
		}

		poisonPane := poisonPaneLm.Get(m.curConvoRow.ConvoKey())
		if zone.Get(CfgPoisonButtonId).InBounds(msg) {
			// "Configure Poisoning" button has been clicked
			m.focusedId = misc.PoisonCfgPaneId
			if poisonPane == nil {
				// Create a new poison pane for the conversation
				buff := panes.NewPoison(zone.DefaultManager, m.curConvoRow.SenderIp, m.curConvoRow.TargetIp)
				poisonPane = &buff
				poisonPaneLm.CSet(m.curConvoRow.SenderIp, m.curConvoRow.TargetIp, poisonPane)
				poisonPane.SetWidth(m.rightWidth)
				poisonPane.SetHeight(m.bottomRightHeight)
			}
			m.curConvoPane.IsConfiguringPoisoning = true
		}

		if poisonPane != nil {
			// Update poison pane button clicks
			*poisonPane, cmd = poisonPane.Update(msg)
		}

	case tea.KeyMsg:
		// Handle keystrokes

		cmd = m.handleKeyMsg(msg)
		return m, cmd

	case panes.CurConvoTableData:
		// Receive row and column data for current conversation pane

		m.curConvoPane.SetColumns(msg.Cols)
		m.curConvoPane.SetRows(msg.Rows)
		m.curConvoRow = msg.CurConvoRowDetails

	case spinner.TickMsg:
		// Spin the spinner
		//
		// This type is supplied when the spinner is active,
		// which occurs when no ARP requests have been captured

		if len(m.convosTable.Rows()) == 0 {
			m.convosSpinner, cmd = m.convosSpinner.Update(msg)
		}

	case tea.WindowSizeMsg:
		// Handle window resize events
		//
		// This type is supplied when:
		//
		// - The model is being initialized
		// - The terminal window size has changed
		//
		// Since it's supplied as the model is initialized,
		// this logic will also be accessed during initial
		// rendering.

		m.uiWidth = msg.Width
		m.maxPaneHeight = msg.Height - 4

		m.convosTable.SetHeight(m.maxPaneHeight)

		m.rightWidth = (m.uiWidth / 2) + (m.uiWidth % 2)
		m.curConvoHeight = m.maxPaneHeight - 15

		m.bottomRightHeight = 15

		if m.bottomRightHeight < 0 {
			m.bottomRightHeight = 3
		}

		m.curConvoPane.SetWidth(m.rightWidth)
		m.curConvoPane.SetHeight(m.curConvoHeight)

		m.logPane.SetWidth(m.rightWidth)
		m.logPane.SetHeight(m.bottomRightHeight)

		// TODO reset width and heights for all poison panes

		m.doCurrConvoRow()

	case eavesarpError:

		cmd = tea.Quit

	}

	return m, cmd
}

func (m model) View() string {

	//curPoisonPane := m.getPoisonPane()
	poisonPane := poisonPaneLm.Get(m.curConvoRow.ConvoKey())
	hasActiveAttack := m.activeAttacks.Exists(m.curConvoRow.SenderIp, m.curConvoRow.TargetIp)
	var rightPanes []string

	//====================
	// CONVERSATIONS TABLE
	//====================

	var leftPane string
	convosTblHeading := zone.Mark(misc.ConvosPaneId.String(), centerStyle.Render("Conversations"))

	convosTblStyle := paneStyle.Height(m.maxPaneHeight)
	if m.focusedId == misc.ConvosPaneId {
		convosTblStyle = convosTblStyle.BorderForeground(selectedPaneBorderColor)
	}

	if len(m.convosTable.Rows()) == 0 {
		leftPane = lipgloss.JoinVertical(lipgloss.Center,
			convosTblHeading,
			convosTblStyle.Render(m.convosSpinner.View()+" Capturing ARP traffic"))
	} else {
		leftPane = lipgloss.JoinVertical(lipgloss.Center,
			convosTblHeading,
			convosTblStyle.Render(lipgloss.JoinHorizontal(lipgloss.Center, m.convosTable.View())))
	}

	//==========================
	// CURRENT CONVERSATION PANE
	//==========================

	currConvoStyle := paneStyle.Width(m.rightWidth - 2).MaxWidth(m.rightWidth)
	if m.focusedId == misc.CurConvoPaneId {
		currConvoStyle = currConvoStyle.BorderForeground(selectedPaneBorderColor)
	}

	m.curConvoPane.IsPoisoning = hasActiveAttack
	m.curConvoPane.IsSnac = m.curConvoRow.IsSnac
	m.curConvoPane.Style = currConvoStyle
	rightPanes = append(rightPanes,
		zone.Mark(misc.CurConvoPaneId.String(),
			centerStyle.Width(m.rightWidth).Render("Selected Conversation")),
		m.curConvoPane.View())

	//==========================
	// PREPARE BOTTOM RIGHT PANE
	//==========================

	if m.curConvoRow.IsSnac && poisonPane != nil {

		//=============================
		// POISONING CONFIGURATION PANE
		//=============================

		if m.focusedId == misc.PoisonCfgPaneId {
			poisonPane.Style = paneStyle.BorderForeground(selectedPaneBorderColor)
		} else {
			poisonPane.Style = paneStyle.BorderForeground(deselectedPaneBorderColor)
		}
		rightPanes = append(rightPanes, poisonPane.View())

	} else {

		//==========
		// LOGS PANE
		//==========

		if m.focusedId == misc.LogPaneId {
			m.logPane.SetStyle(paneStyle.BorderForeground(selectedPaneBorderColor))
		} else {
			m.logPane.SetStyle(paneStyle)
		}
		rightPanes = append(rightPanes, m.logPane.View())

	}

	rightPane := lipgloss.JoinVertical(lipgloss.Top, rightPanes...)
	return zone.Scan(lipgloss.JoinHorizontal(lipgloss.Left, leftPane, rightPane))
}

func (m *model) doCurrConvoRow() {

	if len(m.convosTable.Rows()) == 0 {
		return
	}

	// Copy the currently selected row and insert the current sender IP,
	// which is needed to query the content for the currently selected
	// row
	selectedRow := make(table.Row, len(m.convosTable.SelectedRow()))
	copy(selectedRow, m.convosTable.SelectedRow())

	// Retrieve sender IP from row senders
	if strings.HasSuffix(selectedRow[3], "↖") {
		selectedRow[3] = m.convosRowSenders[m.convosTable.Cursor()]
	}

	var err error
	if m.curConvoRow, err = newConvoRow(selectedRow); err != nil {
		m.eWriter.WriteStringf("failed to generate table for selected convo row: %v", err.Error())
		return
	}

	m.curConvoPane.IsPoisoning = m.activeAttacks.Exists(m.curConvoRow.SenderIp, m.curConvoRow.TargetIp)
	m.curConvoPane.IsSnac = m.curConvoRow.IsSnac
	m.curConvoPane.IsConfiguringPoisoning = !m.curConvoPane.IsPoisoning && poisonPaneLm.Get(m.curConvoRow.ConvoKey()) != nil

}

func (m *model) doConvoTableContent(c convosTableContent) {
	if len(c.rows) > 0 {
		m.convosTable.SetColumns(c.cols)
		m.convosTable.SetRows(c.rows)
		m.doCurrConvoRow()
	}
}

func (m *model) handleKeyMsg(msg tea.KeyMsg) (cmd tea.Cmd) {

	switch msg.String() {
	case "q", "ctrl+c":
		// TODO check for ongoing attacks and prompt for confirmation
		// TODO kill background routines
		return tea.Quit
	}

	handleBottomPane := func() {
		if poisonPaneLm.Get(m.curConvoRow.ConvoKey()) != nil {
			m.focusedId = misc.PoisonCfgPaneId
		} else {
			m.focusedId = misc.LogPaneId
		}
	}

	switch m.focusedId {
	case misc.ConvosPaneId:

		// Command sequence to run if a new conversation is being selected
		// from the main table
		cmd = tea.Sequence(func() tea.Msg {
			m.doCurrConvoRow()
			return m.curConvoPane.GetContent(m.db, m.curConvoRow)
		}, func() tea.Msg {
			if pp := poisonPaneLm.Get(m.curConvoRow.ConvoKey()); pp != nil && pp.Running() {
				// Restart stopwatch/timer if an attack is ongoing
				if pp.CaptureDurationInput().Value() == "" {
					return pp.Stopwatch.Start()()
				} else {
					return pp.Timer.Start()()
				}
			}
			return nil
		})

		switch msg.String() {
		case "up", "k":
			if m.convosTable.Cursor() == 0 {
				m.convosTable.GotoBottom()
			} else {
				m.convosTable, _ = m.convosTable.Update(msg)
			}
			m.curConvoPane.GotoTop()
		case "down", "j":
			if m.convosTable.Cursor() == len(m.convosTable.Rows())-1 {
				m.convosTable.GotoTop()
			} else {
				m.convosTable, _ = m.convosTable.Update(msg)
			}
			m.curConvoPane.GotoTop()
		case "ctrl+shift+up", "ctrl+shift+right":
			m.focusedId = misc.CurConvoPaneId
			m.curConvoPane.FocusTable()
			cmd = nil
		case "ctrl+shift+down":
			handleBottomPane()
			cmd = nil
		default:
			m.convosTable, _ = m.convosTable.Update(msg)
		}

		return cmd

	case misc.CurConvoPaneId:

		switch msg.String() {
		case "ctrl+shift+left":
			m.focusedId = misc.ConvosPaneId
			m.convosTable.Focus()
		case "ctrl+shift+down", "ctrl+shift+up":
			handleBottomPane()
		default:
			m.curConvoPane, cmd = m.curConvoPane.Update(msg)
		}

	case misc.LogPaneId:

		switch msg.String() {
		case "ctrl+shift+left":
			m.focusedId = misc.ConvosPaneId
			m.convosTable.Focus()
		case "ctrl+shift+down", "ctrl+shift+up":
			m.focusedId = misc.CurConvoPaneId
		default:
			m.logPane, cmd = m.logPane.Update(msg)
		}

	case misc.PoisonCfgPaneId:

		poisonPane := poisonPaneLm.Get(m.curConvoRow.ConvoKey())

		switch msg.String() {
		case "ctrl+shift+left":
			if poisonPane == nil || m.curConvoPane.IsPoisoning {
				m.focusedId = misc.ConvosPaneId
			}
			m.convosTable.Focus()
		case "ctrl+shift+down", "ctrl+shift+up":
			if poisonPane == nil || m.curConvoPane.IsPoisoning {
				m.focusedId = misc.CurConvoPaneId
			}
		default:
			// Pass all other keystrokes to the poisoning configuration pane
			if m.focusedId == misc.PoisonCfgPaneId {
				*poisonPane, cmd = poisonPane.Update(msg)
			}
		}

	}

	return
}
