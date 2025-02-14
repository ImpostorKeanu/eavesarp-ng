package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/enescakir/emoji"
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

// ui styling variables
var (
	sniffCtx                  = context.TODO()
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
	convosTableStyle   table.Styles
	activeAttacks      misc.ActiveAttacks           // Track conversation keys for ongoing attacks
	snacChar           = string(emoji.YellowCircle) // Character displayed in the table when a conversation is a SNAC
	senderPoisonedChar = string(emoji.GreenCircle)  // Character displayed when a sender is poisoned
)

const (
	// headers for the conversation table that are used as keys
	// to map back to their proper index in a row.
	// (see convosTblColInds).
	//
	// NOTE: these _do not_ indicate ordering.
	convosTblIndHeader      = "#"
	convosTblSenderHeader   = "Sender"
	convosTblTargetHeader   = "Target"
	convosTblARPCountHeader = "ARP #"
	convosTblSNACHeader     = "SNAC"
	convosTblPoisonedHeader = "Poisoned"

	sniffCtxCancelKey eavesarp_ng.CtxKey = "sniffCtxCancel" // key used to access the cancel function for the ctx
	CfgPoisonButtonId                    = "poisonBtn"
)

var (
	// convosTblCols establishes column headers and ordering.
	//
	// It's copied later when generating content for rows.
	convosTblCols = []table.Column{
		{convosTblIndHeader, 0},
		{convosTblSenderHeader, 0},
		{convosTblTargetHeader, 0},
		{convosTblARPCountHeader, 0},
		{convosTblSNACHeader, 0},
		{convosTblPoisonedHeader, 0},
	}
	// indexes for each column of the conversations table
	convosTblIndInd      int
	convosTblSenderInd   int
	convosTblTargetInd   int
	convosTblARPCountInd int
	convosTblSNACInd     int
	convosTblPoisonedInd int
)

// SQL queries for the conversations table
const (
	// TODO we may need to add a limit & offset to this
	//    unknown how large these rows are going to become
	convosTableQuery = `
SELECT sender.id AS sender_ip_id,
       sender.value AS sender_ip_value,
       target.id AS target_ip_id,
       target.value AS target_ip_value,
       count AS arp_count,
       (target.arp_resolved AND target.mac_id IS NULL) AS snac
FROM arp_count
INNER JOIN ip AS sender ON arp_count.sender_ip_id = sender.id
INNER JOIN ip AS target ON arp_count.target_ip_id = target.id
ORDER BY
	snac DESC,
    sender.value,
    arp_count.count DESC`
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

	// Assign index offsets to conversations table headers
	// so we can pull values from the row reliably.
	for i, r := range convosTblCols {
		switch r.Title {
		case convosTblIndHeader:
			convosTblIndInd = i
		case convosTblSenderHeader:
			convosTblSenderInd = i
		case convosTblTargetHeader:
			convosTblTargetInd = i
		case convosTblARPCountHeader:
			convosTblARPCountInd = i
		case convosTblSNACHeader:
			convosTblSNACInd = i
		case convosTblPoisonedHeader:
			convosTblPoisonedInd = i
		}
	}
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
		//convosRowSenders map[int]string
		convoPoisonPane panes.PoisonPane
		// curConvoRow contains details related to the currently selected
		// conversation row.
		//curConvoRow *panes.CurConvoRowDetails
		// convoPane presents information related to the currently
		// selected conversation, such as MAC addresses and DNS names.
		convoPane          panes.CurConvoPane
		senderPoisonedChar string
		snacChar           string

		// logPane presents lines from events.
		logPane panes.LogsPane
		logsCh  chan string

		// mainSniff determines if the sniffing process should
		// be started. As it allows the UI to run without root,
		// it's sometimes useful to disable this while debugging.
		mainSniff bool

		lastSender, lastTarget string
	}

	eavesarpError error

	convosTableContent struct {
		cols []table.Column
		rows []table.Row
		err  error
	}
)

func newConvoRow(r table.Row) (_ panes.CurConvoRowDetails, err error) {
	var ind, arpCount int
	if ind, err = strconv.Atoi(r[convosTblIndInd]); err != nil {
		return
	} else if arpCount, err = strconv.Atoi(r[convosTblARPCountInd]); err != nil {
		return
	}
	return panes.CurConvoRowDetails{ind,
		r[convosTblSNACInd] != "",
		r[convosTblSenderInd],
		r[convosTblTargetInd], arpCount}, err
}

// convoKey returns the conversation key for the currently selected row
// in the conversations table.
func (m *model) convoKey() (k string) {
	if len(m.convosTable.SelectedRow()) > 0 {
		r := m.convosTable.SelectedRow()
		return eavesarp_ng.FmtConvoKey(r[convosTblSenderInd], r[convosTblTargetInd])
	}
	return
}

// getSenderTargetIps retrieves the sender and target IPs associated with
// currently selected conversations table row.
func (m model) getSenderTargetIps() (string, string) {
	return m.getRowSenderIp(), m.getRowTargetIp()
}

func (m model) Init() tea.Cmd {

	cmds := []tea.Cmd{
		m.logPane.Init(),
		func() tea.Msg {
			return m.convosSpinner.Tick()
		},
	}

	var cancel context.CancelFunc
	sniffCtx, cancel = context.WithCancel(sniffCtx)
	sniffCtx = context.WithValue(sniffCtx, sniffCtxCancelKey, cancel)

	if m.mainSniff {
		cmds = append(cmds, func() tea.Msg {
			m.eWriter.WriteStringf("starting arp sniffer routine")
			// TODO update to support address specification for interface
			if err := eavesarp_ng.Sniff(sniffCtx, m.db, ifaceName, "", m.eWriter); err != nil {
				return eavesarpError(err)
			}
			return nil
		})
	}

	return tea.Batch(cmds...)
}

func (m model) Update(msg tea.Msg) (_ tea.Model, cmd tea.Cmd) {

	// initialize last sender and target ip values
	//
	// this allows ensures that the currently selected
	// row remains selected when new conversations are
	// discovered, which will change the index of the row
	// should the new conversation have a lesser index
	if m.lastSender == "" && m.lastTarget == "" {
		m.lastSender = m.getRowSenderIp()
		m.lastTarget = m.getRowTargetIp()
	}

	switch msg := msg.(type) {

	case convosTableContent:

		if msg.err != nil {
			_, err := m.eWriter.WriteStringf("failed update conversations content: %v", msg.err.Error())
			if err != nil {
				m.eWriter.WriteString("failed to call WriteStringf while reporting error")
				panic(err)
			}
		} else if len(msg.rows) > 0 {
			m.convosTable.SetColumns(msg.cols)
			m.convosTable.SetRows(msg.rows)
		}
		m.setConvosCursor(m.lastSender, m.lastTarget)

		// periodically update the conversations table
		cmd = func() tea.Msg {
			// may want to make the update frequency configurable
			time.Sleep(2 * time.Second)
			return getConvosTableContent(&m)
		}

	case *panes.CurConvoRowDetails:

		// accept updates only for the currently selected row
		if !m.hasConvoRows() || msg == nil || msg.ConvoKey() != m.convoKey() {
			break
		}
		m.convoPane, cmd = m.convoPane.Update(*msg)
		// periodically update the conversation to reflect new
		// information like ports and dns records
		cmd = tea.Batch(cmd, func() tea.Msg {
			time.Sleep(2 * time.Second)
			return m.doCurrConvoRow()
		})

	case panes.PoisoningStatusMsg:

		poisonPane := poisonPaneLm.Get(msg.Id)
		if poisonPane == nil {
			return m, cmd
		}
		*poisonPane, cmd = poisonPane.Update(msg)
		if msg.Done() {
			activeAttacks.Remove(msg.Id)
			poisonPaneLm.Delete(msg.Id)
			m.convoPane.IsPoisoning = false
			m.convoPane.IsConfiguringPoisoning = false
		}

	case panes.LogEvent:

		m.logPane, cmd = m.logPane.Update(msg)

	case timer.TimeoutMsg:

		// TODO handle when a poisoning attack finishes due to timeout

	case timer.TickMsg:

		if poisonPane := poisonPaneLm.Get(msg.Id); poisonPane == nil {
			// NOP for missing poison pane
		} else if msg.Id != m.convoKey() {
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
		} else if msg.Id != m.convoKey() {
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

		if !m.hasConvoRows() {
			return m, nil
		}
		cmd = m.handleBtnPressMsg(msg)
		return m, cmd

	case tea.MouseMsg:

		if !m.hasConvoRows() {
			return m, nil
		}
		cmd = m.handleMouseMsg(msg)
		return m, cmd

	case tea.KeyMsg:

		cmd = m.handleKeyMsg(msg)
		return m, cmd

	//case panes.CurConvoTableData:
	//	// Receive row and column data for current conversation pane
	//
	//	m.convoPane.SetColumns(msg.Cols)
	//	m.convoPane.SetRows(msg.Rows)
	//	m.curConvoRow = msg.CurConvoRowDetails
	//	if msg.Err != nil {
	//		m.eWriter.WriteString(msg.Err.Error())
	//	}

	case spinner.TickMsg:
		// Spin the spinner
		//
		// This type is supplied when the spinner is active,
		// which occurs when no ARP requests have been captured

		if len(m.convosTable.Rows()) == 0 {
			m.convosSpinner, cmd = m.convosSpinner.Update(msg)
			cmd = tea.Batch(cmd,
				func() tea.Msg {
					return getConvosTableContent(&m)
				})
		} else {
			cmd = tea.Sequence(
				//m.logPane.Init(),
				func() tea.Msg {
					return getConvosTableContent(&m)
				},
				func() tea.Msg {
					return m.doCurrConvoRow()
				})
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

		m.convoPane.SetWidth(m.rightWidth)
		m.convoPane.SetHeight(m.curConvoHeight)

		m.logPane.SetWidth(m.rightWidth)
		m.logPane.SetHeight(m.bottomRightHeight)

		// TODO reset width and heights for all poison panes

		m.doCurrConvoRow()

	case eavesarpError:

		// TODO
		m.eWriter.WriteStringf("unhanled exception: %v", msg)
		m.eWriter.WriteString("quitting")
		sniffCtx.Value(sniffCtxCancelKey).(context.CancelFunc)()
		cmd = tea.Quit

	}

	return m, cmd
}

func (m model) View() string {

	if !m.hasConvoRows() || m.convoKey() == "" {
		return m.convosSpinner.View() + " Capturing ARP traffic" + "\n\n" + m.logPane.View()
	}

	poisonPane := poisonPaneLm.Get(m.convoKey())
	//hasActiveAttack := activeAttacks.Exists(m.convoKey())
	var rightPanes []string

	//=========================
	// FILTER DUPLICATE SENDERS
	//=========================

	// Preserve original table rows by copying the table
	convosTbl := m.convosTable
	// Make a new slice of rows
	rows := make([]table.Row, len(m.convosTable.Rows()))

	// Iterate over each row and copy the values
	// Note: we can't copy the set of rows directly because
	//       it's a multidimensional slice, meaning references
	//       to the second dimension would be copied instead
	//       of the underlying values to be modified.
	var lastSender string
	for i, r := range m.convosTable.Rows() {
		row := make(table.Row, len(r))
		copy(row, r)
		rows[i] = row
		if r[convosTblSenderInd] == lastSender {
			rows[i][convosTblSenderInd] = strings.Repeat(" ", len(lastSender)-1) + "↖"
		} else {
			lastSender = r[convosTblSenderInd]
		}
	}
	convosTbl.SetRows(rows)

	//====================
	// CONVERSATIONS TABLE
	//====================

	var leftPane string
	convosTblHeading := zone.Mark(misc.ConvosPaneId.String(), centerStyle.Render("Conversations"))

	convosTblStyle := paneStyle.Height(m.maxPaneHeight)
	if m.focusedId == misc.ConvosPaneId {
		convosTblStyle = convosTblStyle.BorderForeground(selectedPaneBorderColor)
	}

	leftPane = lipgloss.JoinVertical(lipgloss.Center,
		convosTblHeading,
		convosTblStyle.Render(lipgloss.JoinHorizontal(lipgloss.Center, convosTbl.View())))

	//==========================
	// CURRENT CONVERSATION PANE
	//==========================

	currConvoStyle := paneStyle.Width(m.rightWidth - 2).MaxWidth(m.rightWidth)
	if m.focusedId == misc.CurConvoPaneId {
		currConvoStyle = currConvoStyle.BorderForeground(selectedPaneBorderColor)
	}

	m.convoPane.Style = currConvoStyle
	rightPanes = append(rightPanes,
		zone.Mark(misc.CurConvoPaneId.String(),
			centerStyle.Width(m.rightWidth).Render("Selected Conversation")),
		m.convoPane.View())

	//==========================
	// PREPARE BOTTOM RIGHT PANE
	//==========================

	if m.convoPane.IsSnac && poisonPane != nil {

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

// doCurrConvoRow reads the currently selected row in the conversations
// table and extracts critical values for subsequent updates.
func (m *model) doCurrConvoRow() (d *panes.CurConvoRowDetails) {
	if len(m.convosTable.Rows()) == 0 {
		return
	} else if ccrd, err := newConvoRow(m.convosTable.SelectedRow()); err != nil {
		panic(fmt.Errorf("failed to generate conversation row: %v", err.Error()))
	} else {
		d = &ccrd
	}
	return
}

func (m *model) handleBtnPressMsg(msg panes.BtnPressMsg) (cmd tea.Cmd) {

	switch msg.Event {
	case panes.StartPoisonBtnEvent:

		// Emit the proper message based on timer type
		var poisonPane *panes.PoisonPane
		if poisonPane = poisonPaneLm.Get(m.convoKey()); poisonPane == nil {
			panic("failed to find poison pane for conversation (database corrupted?)")

		}
		*poisonPane, cmd = poisonPane.Update(msg)
		if err := activeAttacks.Add(m.convoKey()); err != nil {
			panic(fmt.Errorf("failed to track new poisoning attack: %v", err.Error()))
		}
		m.convoPane.IsPoisoning = true

	case panes.CancelPoisonBtnEvent:

		if pp := poisonPaneLm.Get(m.convoKey()); pp != nil {
			*pp, cmd = pp.Update(msg)
			poisonPaneLm.Delete(m.convoKey())
		}
		activeAttacks.Remove(m.convoKey())
		m.focusedId = misc.ConvosPaneId
		m.convoPane.IsConfiguringPoisoning = false
		m.convoPane.IsPoisoning = false

	case panes.CancelConfigBtnEvent:

		if pp := poisonPaneLm.Get(m.convoKey()); pp != nil {
			*pp, cmd = pp.Update(msg)
			poisonPaneLm.Delete(m.convoKey())
		}
		m.focusedId = misc.LogPaneId
		m.convoPane.IsConfiguringPoisoning = false
		m.convoPane.IsPoisoning = false

	default:

		panic("unknown button press event emitted by poison configuration panel")

	}

	return cmd
}

func (m *model) handleMouseMsg(msg tea.MouseMsg) (cmd tea.Cmd) {
	// Handle mouse events, like button presses

	if msg.Action != tea.MouseActionRelease || msg.Button != tea.MouseButtonLeft {
		// We only care about the left mouse button
		return
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

	poisonPane := poisonPaneLm.Get(m.convoKey())
	if zone.Get(CfgPoisonButtonId).InBounds(msg) {
		// "Configure Poisoning" button has been clicked
		m.focusedId = misc.PoisonCfgPaneId
		if poisonPane == nil {
			s, t := m.getSenderTargetIps()
			// Create a new poison pane for the conversation
			buff := panes.NewPoison(m.db, ifaceName, s, t, zone.DefaultManager, m.eWriter)
			buff.SetWidth(m.rightWidth)
			buff.SetHeight(m.bottomRightHeight)
			poisonPane = &buff
			poisonPaneLm.CSet(s, t, poisonPane)
		}
		m.convoPane.IsConfiguringPoisoning = true
	}

	if poisonPane != nil {
		// Update poison pane button clicks
		*poisonPane, cmd = poisonPane.Update(msg)
	}

	return
}

// hasConvoRows determines if the conversations table currently
// contains any rows to display.
func (m *model) hasConvoRows() bool {
	return len(m.convosTable.Rows()) > 0
}

func (m *model) handleKeyMsg(msg tea.KeyMsg) (cmd tea.Cmd) {

	if msg.String() == "q" || msg.String() == "ctrl+c" {
		// TODO check for ongoing attacks and prompt for confirmation
		sniffCtx.Value(sniffCtxCancelKey).(context.CancelFunc)()
		m.eWriter.WriteString("quitting")
		return tea.Quit
	} else if !m.hasConvoRows() {
		return
	}

	handleBottomPane := func() {
		if poisonPaneLm.Get(m.convoKey()) != nil {
			m.focusedId = misc.PoisonCfgPaneId
		} else {
			m.focusedId = misc.LogPaneId
		}
	}

	switch m.focusedId {
	case misc.ConvosPaneId:

		origCursor := m.convosTable.Cursor()

		switch msg.String() {
		case "up", "k":
			if m.convosTable.Cursor() == 0 {
				m.convosTable.GotoBottom()
			} else {
				m.convosTable, _ = m.convosTable.Update(msg)
			}
			m.convoPane.GotoTop()
			m.lastSender = m.getRowSenderIp()
			m.lastTarget = m.getRowTargetIp()
		case "down", "j":
			if m.convosTable.Cursor() == len(m.convosTable.Rows())-1 {
				m.convosTable.GotoTop()
			} else {
				m.convosTable, _ = m.convosTable.Update(msg)
			}
			m.convoPane.GotoTop()
			m.lastSender = m.getRowSenderIp()
			m.lastTarget = m.getRowTargetIp()
		case "ctrl+shift+up", "ctrl+shift+right":
			m.focusedId = misc.CurConvoPaneId
			m.convoPane.FocusTable()
		case "ctrl+shift+down":
			handleBottomPane()
		default:
			m.convosTable, _ = m.convosTable.Update(msg)
		}

		if origCursor != m.convosTable.Cursor() {
			// Command sequence to run if a new conversation is being selected
			// from the main table
			cmd = tea.Sequence(func() tea.Msg {
				msg := m.doCurrConvoRow()
				//m.curConvoRow = msg
				return msg
			}, func() tea.Msg {
				if pp := poisonPaneLm.Get(m.convoKey()); pp != nil && pp.Running() {
					// Restart stopwatch/timer if an attack is ongoing
					if pp.CaptureDurationInput().Value() == "" {
						return pp.Stopwatch.Start()()
					} else {
						return pp.Timer.Start()()
					}
				}
				return nil
			})
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
			m.convoPane, cmd = m.convoPane.Update(msg)
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

		poisonPane := poisonPaneLm.Get(m.convoKey())

		switch msg.String() {
		case "ctrl+shift+left":
			if poisonPane == nil || m.convoPane.IsPoisoning {
				m.focusedId = misc.ConvosPaneId
			}
			m.convosTable.Focus()
		case "ctrl+shift+down", "ctrl+shift+up":
			if poisonPane == nil || m.convoPane.IsPoisoning {
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

// getRowSenderIp gets the string IP address for the sender column
// of the currently selected row of the conversations table.
func (m *model) getRowSenderIp() (s string) {
	if m.convosTable.SelectedRow() != nil {
		s = m.convosTable.SelectedRow()[convosTblSenderInd]
	}
	return
}

// getRowTargetIp gets the string IP address for the target column
// of the currently selected row of the conversations table.
func (m *model) getRowTargetIp() (t string) {
	if m.convosTable.SelectedRow() != nil {
		t = m.convosTable.SelectedRow()[convosTblTargetInd]
	}
	return
}

// setConvoCursor sets the convos table cursor to the row matching
// the sender and the target.
func (m *model) setConvosCursor(sender, target string) (e error) {
	if m.convosTable.SelectedRow() == nil || (m.getRowSenderIp() == sender && m.getRowTargetIp() == target) {
		return
	}
	for i, r := range m.convosTable.Rows() {
		if r[convosTblSenderInd] == sender && r[convosTblTargetInd] == target {
			m.convosTable.SetCursor(i)
			return
		}
	}
	return errors.New("not found")
}

func getConvosTableContent(m *model) (content convosTableContent) {

	rows, err := m.db.Query(convosTableQuery)
	if err != nil {
		content.err = fmt.Errorf("failed to query conversations content: %w", err)
		return
	}

	// Variables to track information about row content
	// - these are used to format convosTable columns later
	var senderIpWidth, targetIpWidth int
	arpCountWidth := len(convosTblARPCountHeader)

	defer rows.Close()

	for rowInd := 1; rows.Next(); rowInd++ {

		//====================
		// HANDLE DATABASE ROW
		//====================

		// Variables to hold data retrieved from the db
		var sender, target eavesarp_ng.Ip
		var arpCount int
		var hasSnac bool

		// Get data from the sql row
		err = rows.Scan(&sender.Id, &sender.Value,
			&target.Id, &target.Value,
			&arpCount, &hasSnac)
		if err != nil {
			content.err = fmt.Errorf("failed to scan conversations row: %w", err)
			return
		}

		var sC string
		if hasSnac {
			sC = m.snacChar
		}

		var senderPoisoned string
		if is := activeAttacks.Exists(eavesarp_ng.FmtConvoKey(sender.Value, target.Value)); is {
			senderPoisoned = m.senderPoisonedChar
		}

		arpCountValue := fmt.Sprintf("%d", arpCount)

		//=====================
		// ADJUST WIDTH OFFSETS
		//=====================

		eavesarp_ng.GreaterLength(sender.Value, &senderIpWidth)
		eavesarp_ng.GreaterLength(target.Value, &targetIpWidth)
		eavesarp_ng.GreaterLength(arpCountValue, &arpCountWidth)

		//======================================
		// CONSTRUCT AND CAPTURE THE CURRENT ROW
		//======================================

		tRow := make(table.Row, len(convosTblCols))
		content.rows = append(content.rows, tRow)
		tRow[convosTblIndInd] = fmt.Sprintf("%d", rowInd)
		tRow[convosTblSNACInd] = sC
		tRow[convosTblPoisonedInd] = senderPoisoned
		tRow[convosTblSenderInd] = sender.Value
		tRow[convosTblTargetInd] = target.Value
		tRow[convosTblARPCountInd] = arpCountValue
	}

	//======================
	// PREPARE TABLE COLUMNS
	//======================

	// copy convosTblCols and set the width for each column
	for _, col := range convosTblCols {
		switch col.Title {
		case convosTblIndHeader:
			col.Width = len(fmt.Sprintf("%d", len(content.rows)))
		case convosTblSNACHeader, convosTblPoisonedHeader:
			col.Width = len(col.Title)
		case convosTblSenderHeader:
			col.Width = senderIpWidth
		case convosTblTargetHeader:
			col.Width = targetIpWidth
		case convosTblARPCountHeader:
			col.Width = arpCountWidth
		default:
			panic("unexpected convos table header")
		}
		content.cols = append(content.cols, col)
	}

	return
}
