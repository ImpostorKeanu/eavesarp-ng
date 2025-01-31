package main

import (
	"database/sql"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	eavesarp_ng "github.com/impostorkeanu/eavesarp-ng"
	"github.com/impostorkeanu/eavesarp-ng/cmd/ui/panes"
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
	maxLogCount  = 1000
	maxLogLength = 2000

	cfgPoisonButtonId = "poisonBtn"
	poisonCfgPaneId   = "poisonCfgPane"
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
		focusedId paneHeadingId
		// events tracks records emitted by Eavesarp and the UI.
		// Each record is presented to the user via the logsPane.
		events []string
		// eWriter is a channel used to write records to events.
		eWriter eventWriter
		// activeAttacks tracks attacks that are currently active.
		activeAttacks *ActiveAttacks
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
		// convosPoisonPanes maps ongoing poison configurations
		// back to specific conversations, allowing us to run
		// concurrent poisoning attacks.
		//convosPoisonPanes PoisoningPanes

		convoPoisonPane panes.PoisonPane
		// curConvoRow contains details related to the currently selected
		// conversation row.
		curConvoRow panes.CurConvoRowDetails
		// curConvoPane presents information related to the currently
		// selected conversation, such as MAC addresses and DNS names.
		curConvoPane panes.CurConvoPane

		// logsPane presents lines from events.
		logsPane panes.LogsPane
		logsCh   chan string

		// mainSniff determines if the sniffing process should
		// be started. As it allows the UI to run without root,
		// it's sometimes useful to disable this while debugging.
		mainSniff bool
	}

	logEvent      string
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
		m.logsPane.Init(),
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

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {

	var cmd tea.Cmd

	switch msg := msg.(type) {

	case panes.LogEvent:

		m.logsPane, cmd = m.logsPane.Update(msg)

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
			//m.doCurrConvoRow()
		}

		cmd = func() tea.Msg {
			// Periodically update the ARP table
			// TODO we may want to make the update frequency configurable
			time.Sleep(2 * time.Second)
			//return getConvosTableContent(m.db, 100, 0)
			return getConvosTableContent(&m)
		}

	case panes.TickMsg:

		if poisonPane := poisonPaneLm.Get(msg.Id); poisonPane == nil {
			// NOP for missing poison pane
		} else if msg.Id != m.curConvoRow.ConvoKey() {
			// Stop ticks for out of focus stop watches
			cmd = poisonPane.Stopwatch.Stop()
		} else {
			// Update the stopwatch to reflect current tick
			*poisonPane, cmd = poisonPane.Update(msg)
		}
		return m, cmd

	case panes.StartStopMsg:

		if poisonPane := poisonPaneLm.Get(msg.Id); poisonPane != nil {
			*poisonPane, cmd = poisonPane.Update(msg)
		}
		return m, cmd

	case panes.BtnPressMsg:

		poisonPane := poisonPaneLm.Get(m.curConvoRow.ConvoKey())

		switch msg.Event {
		case panes.StartPoisonEvent:
			// TODO start to be offloaded to the poisoning panel itself
			if err := m.activeAttacks.Add(m.curConvoRow.SenderIp, m.curConvoRow.TargetIp); err != nil {
				// TODO
				panic(err)
			}
			m.curConvoPane.IsPoisoning = true
			// Emit the proper msg based on timer type
			if poisonPane == nil {
				// TODO
				panic("failed to find poison pane for conversation")
			} else if len(poisonPane.CaptureDurationInput().Value()) > 0 {
				// TODO new timer
			} else {
				poisonPane.Stopwatch = panes.NewStopwatch(m.curConvoRow.SenderIp, m.curConvoRow.TargetIp, time.Now(), time.Second)
				cmd = poisonPane.Stopwatch.Start()
				// TODO start poisoning
				//    Be sure to include cmd in a Tea.Sequence
			}
		case panes.CancelPoisonEvent:
			m.activeAttacks.Remove(m.curConvoRow.SenderIp, m.curConvoRow.TargetIp)
			//poisonPanes.Remove(m.curConvoRow.SenderIp, m.curConvoRow.TargetIp)
			poisonPaneLm.CDelete(m.curConvoRow.SenderIp, m.curConvoRow.TargetIp)
			m.focusedId = convosTableId
			m.curConvoPane.IsConfiguringPoisoning = false
			m.curConvoPane.IsPoisoning = false
			//m.convoPoisonPane = nil
		case panes.CancelConfigEvent:
			//poisonPanes.Remove(m.curConvoRow.SenderIp, m.curConvoRow.TargetIp)
			poisonPaneLm.CDelete(m.curConvoRow.SenderIp, m.curConvoRow.TargetIp)
			m.focusedId = logPaneId
			m.curConvoPane.IsConfiguringPoisoning = false
			m.curConvoPane.IsPoisoning = false
			//m.convoPoisonPane = nil
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
		if m.focusedId != poisonCfgPaneId {
			if m.focusedId != logPaneId && zone.Get(logPaneId.String()).InBounds(msg) {
				m.focusedId = logPaneId
			} else if m.focusedId != convosTableId && zone.Get(convosTableId.String()).InBounds(msg) {
				m.focusedId = convosTableId
			} else if m.focusedId != attacksViewPortHeadingId && zone.Get(attacksViewPortHeadingId.String()).InBounds(msg) {
				m.focusedId = attacksViewPortHeadingId
			} else if m.focusedId != curConvoId && zone.Get(curConvoId.String()).InBounds(msg) {
				m.focusedId = curConvoId
			}
		}

		poisonPane := poisonPaneLm.Get(m.curConvoRow.ConvoKey())
		if zone.Get(cfgPoisonButtonId).InBounds(msg) {
			// "Configure Poisoning" button has been clicked
			m.focusedId = poisonCfgPaneId
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

		switch msg.String() {
		case "q", "ctrl+c":
			// TODO kill background routines
			return m, tea.Quit
		}

		handleBottomPanel := func() {
			if poisonPaneLm.Get(m.curConvoRow.ConvoKey()) != nil {
				m.focusedId = poisonCfgPaneId
			} else {
				m.focusedId = logPaneId
			}
		}

		switch m.focusedId {
		case convosTableId:

			cmd = tea.Sequence(func() tea.Msg {
				m.doCurrConvoRow()
				return m.curConvoPane.GetContent(m.db, m.curConvoRow)
			}, func() tea.Msg {
				if pp := poisonPaneLm.Get(m.curConvoRow.ConvoKey()); pp != nil && pp.Running() {
					// TODO the ticker selection logic should probably be moved
					//   to the PoisonPane itself
					if pp.CaptureDurationInput().Value() == "" {
						// Restart the stopwatch ticker
						return pp.Stopwatch.Start()()
					} else {
						// TODO restart timer ticker
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
			case "down", "j":
				if m.convosTable.Cursor() == len(m.convosTable.Rows())-1 {
					m.convosTable.GotoTop()
				} else {
					m.convosTable, _ = m.convosTable.Update(msg)
				}
			case "ctrl+shift+up", "ctrl+shift+right":
				m.focusedId = curConvoId
				m.curConvoPane.FocusTable()
				cmd = nil
			case "ctrl+shift+down":
				handleBottomPanel()
				cmd = nil
			default:
				m.convosTable, _ = m.convosTable.Update(msg)
			}

			return m, cmd

		case curConvoId:

			switch msg.String() {
			case "ctrl+shift+left":
				m.focusedId = convosTableId
				m.convosTable.Focus()
			case "ctrl+shift+down", "ctrl+shift+up":
				handleBottomPanel()
			default:
				buff, _ := m.curConvoPane.Update(msg)
				m.curConvoPane = buff.(panes.CurConvoPane)
			}

		case logPaneId:

			switch msg.String() {
			case "ctrl+shift+left":
				m.focusedId = convosTableId
				m.convosTable.Focus()
			case "ctrl+shift+down", "ctrl+shift+up":
				m.focusedId = curConvoId
				// TODO focus the cur convo table
			default:
				// Pass all other keystrokes to the logs pane
				m.logsPane, cmd = m.logsPane.Update(msg)
			}

		case poisonCfgPaneId:

			poisonPane := poisonPaneLm.Get(m.curConvoRow.ConvoKey())

			switch msg.String() {
			case "ctrl+shift+left":
				if poisonPane == nil || m.curConvoPane.IsPoisoning {
					m.focusedId = convosTableId
				}
				m.convosTable.Focus()
			case "ctrl+shift+down", "ctrl+shift+up":
				if poisonPane == nil || m.curConvoPane.IsPoisoning {
					m.focusedId = curConvoId
				}
			default:
				// Pass all other keystrokes to the poisoning configuration pane
				if m.focusedId == poisonCfgPaneId {
					*poisonPane, cmd = poisonPane.Update(msg)
				}
			}

		}

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

		m.logsPane.SetWidth(m.rightWidth)
		m.logsPane.SetHeight(m.bottomRightHeight)

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
	convosTblHeading := zone.Mark(convosTableId.String(), centerStyle.Render("Conversations"))

	convosTblStyle := paneStyle.Height(m.maxPaneHeight)
	if m.focusedId == convosTableId {
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
	if m.focusedId == curConvoId {
		currConvoStyle = currConvoStyle.BorderForeground(selectedPaneBorderColor)
	}

	m.curConvoPane.IsPoisoning = hasActiveAttack
	m.curConvoPane.IsSnac = m.curConvoRow.IsSnac
	m.curConvoPane.Style = currConvoStyle
	rightPanes = append(rightPanes,
		zone.Mark(curConvoId.String(),
			centerStyle.Width(m.rightWidth).Render("Selected Conversation")),
		m.curConvoPane.View())

	//==========================
	// PREPARE BOTTOM RIGHT PANE
	//==========================

	if m.curConvoRow.IsSnac && poisonPane != nil {

		//=============================
		// POISONING CONFIGURATION PANE
		//=============================

		if m.focusedId == poisonCfgPaneId {
			poisonPane.Style = paneStyle.BorderForeground(selectedPaneBorderColor)
		} else {
			poisonPane.Style = paneStyle.BorderForeground(deselectedPaneBorderColor)
		}
		rightPanes = append(rightPanes, poisonPane.View())

	} else {

		//==========
		// LOGS PANE
		//==========

		if m.focusedId == logPaneId {
			m.logsPane.SetStyle(paneStyle.BorderForeground(selectedPaneBorderColor))
		} else {
			m.logsPane.SetStyle(paneStyle)
		}
		rightPanes = append(rightPanes, m.logsPane.View())

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
