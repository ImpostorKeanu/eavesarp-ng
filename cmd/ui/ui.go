package main

import (
	"database/sql"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	eavesarp_ng "github.com/impostorkeanu/eavesarp-ng"
	pp "github.com/impostorkeanu/eavesarp-ng/cmd/ui/poison_panel"
	zone "github.com/lrstanley/bubblezone"
	"math"
	"slices"
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
	convosStyle table.Styles
	eventsC     = make(chan string)
)

const (
	maxLogCount  = 1000
	maxLogLength = 2000

	poisonButtonId       = "poisonBtn"
	poisonCfgPaneId      = "poisonCfgPane"
	poisonCancelButtonId = "poisonCancelBtn"
	poisonStartButtonId  = "poisonStartBtn"
)

func init() {
	convosStyle = table.DefaultStyles()
	convosStyle.Header = convosStyle.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(true).
		PaddingLeft(1)
	convosStyle.Cell.PaddingLeft(1)
	convosStyle.Selected = convosStyle.Selected.
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("57")).
		Bold(false)
}

type (
	model struct {
		db *sql.DB

		uiHeight, uiWidth       int
		rightHeight, rightWidth int
		focusedId               paneId

		events  []string
		eWriter eventWriter

		convosTable   table.Model
		convosSpinner spinner.Model
		// convosRowSenders maps a row offset to its corresponding
		// sender IP value, allowing us to filter out repetitive
		// IPs from the convosTable table.
		convosRowSenders   map[int]string
		convosPoisonPanels *PoisoningPanels
		poisonPanelIds     map[string]*pp.PoisonPanel

		curConvoRow       convoRow
		curConvoTable     table.Model
		curConvoTableData *curConvoTableData

		logsViewPort         viewport.Model
		poisoningCfgViewPort viewport.Model
		activeAttacks        *ActiveAttacks

		poisonCfgShow bool

		// mainSniff determines if the sniffing process should
		// be started. As it allows the UI to run without root,
		// it's sometimes useful to disable this while debugging.
		mainSniff bool
	}

	poisoningViewPort struct {
		viewport.Model
	}

	convoRow struct {
		index    int
		isSnac   bool
		senderIp string
		targetIp string
		arpCount int
	}

	logEvent      string
	eavesarpError error
)

func newArpTableRow(r table.Row) (_ convoRow, err error) {
	var ind, arpCount int
	if ind, err = strconv.Atoi(r[0]); err != nil {
		return
	} else if arpCount, err = strconv.Atoi(r[5]); err != nil {
		return
	}
	return convoRow{ind, r[1] != "", r[3], r[4], arpCount}, err
}

func (m model) Init() tea.Cmd {
	cmds := []tea.Cmd{emitEvent,
		func() tea.Msg {
			return m.convosSpinner.Tick()
		},
		func() tea.Msg {
			return getConvosTableContent(&m)
			//return getConvosTableContent(m.db, 100, 0)
		}}

	if m.mainSniff {
		cmds = append(cmds, func() tea.Msg {
			if err := eavesarp_ng.MainSniff(m.db, ifaceName, m.eWriter); err != nil {
				return eavesarpError(err)
			}
			return nil
		})
	}

	return tea.Batch(cmds...)
}

func emitEvent() tea.Msg {
	return logEvent(<-eventsC)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case spinner.TickMsg:

		if len(m.convosTable.Rows()) == 0 {
			var cmd tea.Cmd
			m.convosSpinner, cmd = m.convosSpinner.Update(msg)
			return m, cmd
		}

	case tea.WindowSizeMsg:
		// This type is supplied when:
		//
		// - The model is being initialized
		// - The terminal window size has changed
		//
		// Since it's supplied as the model is initialized,
		// this logic will also be accessed during initial
		// rendering.

		m.doResize(msg)

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

		return m, func() tea.Msg {
			// Periodically update the ARP table
			// TODO we may want to make the update frequency configurable
			time.Sleep(2 * time.Second)
			//return getConvosTableContent(m.db, 100, 0)
			return getConvosTableContent(&m)
		}

	case logEvent:

		s := string(msg)

		// Trim length of the log event
		if len(s) > maxLogLength {
			s = s[:maxLogLength-1]
		}

		// Trim 10% of logs when the maximum has been met to
		// make room for new events
		if len(m.events) >= maxLogCount {
			l := len(m.events)
			m.events = slices.Delete(m.events, l-(l/10), l-1)
		}

		// Capture the event and write to the viewport
		m.events = append(m.events, s)
		m.logsViewPort.SetContent(strings.Join(m.events, "\n"))

		// Return the model and start a new process to catch the
		// next event, which is handled by the event loop managed
		// by charmbracelet.
		return m, emitEvent

	case tea.MouseMsg:

		if msg.Action != tea.MouseActionRelease || msg.Button != tea.MouseButtonLeft {
			return m, nil
		}

		//===========================================
		// CHANGE FOCUSED PANES BASED ON HEADER CLICK
		//===========================================

		if m.focusedId != logsViewPortId && zone.Get(logsViewPortId.String()).InBounds(msg) {
			m.focusedId = logsViewPortId
		} else if m.focusedId != convosTableId && zone.Get(convosTableId.String()).InBounds(msg) {
			m.focusedId = convosTableId
		} else if m.focusedId != attacksViewPortId && zone.Get(attacksViewPortId.String()).InBounds(msg) {
			m.focusedId = attacksViewPortId
		} else if m.focusedId != curConvoTableId && zone.Get(curConvoTableId.String()).InBounds(msg) {
			m.focusedId = curConvoTableId
		}

		if zone.Get(poisonButtonId).InBounds(msg) {

			m.focusedId = poisonCfgPaneId
			//m.convosPoisonPanels.GetOrCreate(m.curConvoRow.senderIp, m.curConvoRow.targetIp)
			p := m.convosPoisonPanels.GetOrCreate(m.curConvoRow.senderIp, m.curConvoRow.targetIp)
			p.Style = paneStyle.BorderForeground(selectedPaneBorderColor)
			return m, nil

		}
		//if zone.Get(poisonButtonId).InBounds(msg) {
		//
		//	m.focusedId = poisonCfgPaneId
		//	m.convosPoisonPanels.GetOrCreate(m.curConvoRow.senderIp, m.curConvoRow.targetIp)
		//	//p := m.convosPoisonPanels.GetOrCreate(m.curConvoRow.senderIp, m.curConvoRow.targetIp)
		//	//p.Style = paneStyle
		//	return m, nil
		//
		//} else if zone.Get(poisonStartButtonId).InBounds(msg) {
		//
		//	// TODO start to be offloaded to the poisoning panel itself
		//	if err := m.activeAttacks.Add(m.curConvoRow.senderIp, m.curConvoRow.targetIp); err != nil {
		//		// TODO
		//		panic(err)
		//	}
		//	m.focusedId = curConvoTableId
		//	return m, nil
		//
		//} else if zone.Get(poisonCancelButtonId).InBounds(msg) {
		//
		//	// TODO poisoning cancellation to be offloaded to poisoning panel itself
		//	m.activeAttacks.Remove(m.curConvoRow.senderIp, m.curConvoRow.targetIp)
		//	m.focusedId = curConvoTableId
		//	return m, nil
		//
		//}

		if m.convosPoisonPanels.Exists(m.curConvoRow.senderIp, m.curConvoRow.targetIp) {
			cmd, err := m.convosPoisonPanels.Update(m.curConvoRow.senderIp, m.curConvoRow.targetIp, msg)
			if err != nil {
				// TODO
				panic("failed to update poison panel")
			}
			return m, cmd
		}

	case eavesarpError:

		return m, tea.Quit

	case pp.BtnPressMsg:

		switch msg.Event {
		case pp.StartPoisonEvent:
			// TODO start to be offloaded to the poisoning panel itself
			if err := m.activeAttacks.Add(m.curConvoRow.senderIp, m.curConvoRow.targetIp); err != nil {
				// TODO
				panic(err)
			}
		case pp.CancelPoisonEvent:
			m.activeAttacks.Remove(m.curConvoRow.senderIp, m.curConvoRow.targetIp)
			m.convosPoisonPanels.Remove(m.curConvoRow.senderIp, m.curConvoRow.targetIp)
			m.focusedId = convosTableId
		case pp.CancelConfigEvent:
			m.convosPoisonPanels.Remove(m.curConvoRow.senderIp, m.curConvoRow.targetIp)
			m.focusedId = logsViewPortId
		default:
			panic("unknown button press event emitted by poison configuration panel")
		}

		// TODO handle poison panel button press event
		return m, nil

	case tea.KeyMsg:

		//====================
		// STANDARD KEYSTROKES
		//====================

		switch msg.String() {
		case "q", "ctrl+c":
			// TODO kill background routines
			return m, tea.Quit
		}

		hasPoisonPanel := m.convosPoisonPanels.Exists(m.curConvoRow.senderIp, m.curConvoRow.targetIp)
		handleBottomPanel := func() {
			if hasPoisonPanel {
				m.focusedId = poisonCfgPaneId
			} else {
				m.focusedId = logsViewPortId
			}
		}

		switch m.focusedId {

		case convosTableId:

			//========================
			// CONVOS TABLE KEYSTROKES
			//========================

			switch msg.String() {
			case "up", "k":
				if m.convosTable.Cursor() == 0 {
					m.convosTable.GotoBottom()
				} else {
					m.convosTable.MoveUp(1)
				}
				m.doCurrConvoRow()
			case "down", "j":
				if m.convosTable.Cursor() == len(m.convosTable.Rows())-1 {
					m.convosTable.GotoTop()
				} else {
					m.convosTable.MoveDown(1)
				}
				m.doCurrConvoRow()
			case "ctrl+shift+up", "ctrl+shift+right":
				m.focusedId = curConvoTableId
			case "ctrl+shift+down":
				handleBottomPanel()
			case "q", "ctrl+c":
				return m, tea.Quit
			}
			return m, nil

		case curConvoTableId:

			//===============================
			// CURRENT CONVO TABLE KEYSTROKES
			//===============================

			switch msg.String() {
			case "ctrl+shift+left":
				m.focusedId = convosTableId
			case "ctrl+shift+down":
				handleBottomPanel()
			case "ctrl+shift+up":
				handleBottomPanel()
			}

		case logsViewPortId, poisonCfgPaneId:

			switch msg.String() {
			case "down":
				m.logsViewPort.LineDown(1)
			case "up":
				m.logsViewPort.LineUp(1)
			case "ctrl+shift+left":
				m.focusedId = convosTableId
			case "ctrl+shift+down", "ctrl+shift+up":
				m.focusedId = curConvoTableId
			default:
				// Pass all other keystrokes to the poisoning configuration panel
				if m.focusedId == poisonCfgPaneId {
					cmd, err := m.convosPoisonPanels.Update(m.curConvoRow.senderIp, m.curConvoRow.targetIp, msg)
					if err != nil {
						// TODO
						panic("failed to update poison panel")
					}
					return m, cmd
				}
			}
		}
	}

	return m, nil
}

func (m model) View() string {

	//===========================
	// CURRENT ARP TABLE ROW PANE
	//===========================

	m.curConvoTable.SetWidth(m.rightWidth)
	m.curConvoTable.SetHeight(m.rightHeight * 2)

	//================
	// REMAINING PANES
	//================

	rightPaneStyle := paneStyle
	rightPaneStyle = rightPaneStyle.Width(m.rightWidth).Height(m.rightHeight)

	// Logging pane will be shorter than the other two right-hand panes
	w, h := lipgloss.Size(rightPaneStyle.Render())

	logsHeight := m.uiHeight - (h * 2) + 1
	logsPaneStyle := rightPaneStyle
	logsPaneStyle = logsPaneStyle.Height(logsHeight)

	m.logsViewPort.Height = m.uiHeight - (h * 2) + 1
	m.logsViewPort.Width = w

	if m.logsViewPort.YOffset == 0 && m.logsViewPort.Height > 0 {
		// Scroll to the bottom of the logs viewport
		m.logsViewPort.GotoBottom()
	}

	centerRightHeadingStyle := centerStyle
	centerRightHeadingStyle = centerRightHeadingStyle.Width(m.rightWidth)

	convosTblStyle := paneStyle
	selectedArpTableStyle := paneStyle
	attacksPanelStyle := paneStyle
	logViewPortStyle := paneStyle

	//==================================
	// BRIGHTEN BORDER FOR SELECTED PANE
	//==================================

	switch m.focusedId {
	case convosTableId:
		convosTblStyle = convosTblStyle.BorderForeground(selectedPaneBorderColor)
	case curConvoTableId:
		selectedArpTableStyle = selectedArpTableStyle.BorderForeground(selectedPaneBorderColor)
	case attacksViewPortId:
		attacksPanelStyle = attacksPanelStyle.BorderForeground(selectedPaneBorderColor)
	case logsViewPortId, poisonCfgPaneId:
		logViewPortStyle = logViewPortStyle.BorderForeground(selectedPaneBorderColor)
	}

	m.logsViewPort.Style = logViewPortStyle
	attacksPanelStyle = attacksPanelStyle.Width(m.rightWidth).Height(m.rightHeight)

	//==============================
	// BUILD THE CONVERSATIONS TABLE
	//==============================

	var leftPane string
	arpTblHeading := zone.Mark(convosTableId.String(), centerStyle.Render("Conversations"))

	if len(m.convosTable.Rows()) == 0 {
		s := convosTblStyle
		s = s.Height(m.uiHeight)
		leftPane = lipgloss.JoinVertical(lipgloss.Center,
			arpTblHeading,
			s.Render(m.convosSpinner.View()+" Capturing ARP traffic"))
	} else {
		leftPane = lipgloss.JoinVertical(lipgloss.Center,
			arpTblHeading,
			convosTblStyle.Render(lipgloss.JoinHorizontal(lipgloss.Center, m.convosTable.View())))
	}

	hasPoisonPanel := m.convosPoisonPanels.Exists(m.curConvoRow.senderIp, m.curConvoRow.targetIp)
	hasActiveAttack := m.activeAttacks.Exists(m.curConvoRow.senderIp, m.curConvoRow.targetIp)

	//=====================================
	// BUILD THE CURRENT CONVERSATION TABLE
	//=====================================

	var rightPanels []string
	if m.curConvoTableData != nil {

		rightPanels = append(rightPanels,
			zone.Mark(curConvoTableId.String(), centerRightHeadingStyle.Render("Selected Conversation")),
			selectedArpTableStyle.Render(m.curConvoTable.View()))

		if m.curConvoRow.isSnac && m.focusedId != poisonCfgPaneId && !hasPoisonPanel && !hasActiveAttack {
			var button string
			// TODO clean this up
			s := lipgloss.NewStyle().
				Width(m.rightWidth).
				MarginLeft(1).MarginBottom(1).
				PaddingRight(1).
				AlignHorizontal(lipgloss.Center).
				Background(lipgloss.Color("240"))
			button = zone.Mark(poisonButtonId, s.Render("Configure Poisoning"))
			rightPanels = append(rightPanels, button)
		}
	}

	if m.curConvoRow.isSnac && (m.focusedId == poisonCfgPaneId || hasPoisonPanel) {

		//==============================
		// POISONING CONFIGURATION PANEL
		//==============================

		p := m.convosPoisonPanels.Get(m.curConvoRow.senderIp, m.curConvoRow.targetIp)
		if p == nil {
			// TODO
			panic("missing poison panel for conversation")
		}
		p.Width = m.rightWidth
		p.Height = m.logsViewPort.Height

		if m.focusedId == poisonCfgPaneId {
			p.Style = p.Style.BorderForeground(selectedPaneBorderColor)
		} else {
			p.Style = p.Style.BorderForeground(deselectedPaneBorderColor)
		}

		rightPanels = append(rightPanels, lipgloss.JoinVertical(lipgloss.Center,
			centerRightHeadingStyle.Render("Poisoning"), p.View()))

	} else {

		//===========
		// LOGS PANEL
		//===========

		rightPanels = append(rightPanels,
			zone.Mark(logsViewPortId.String(),
				centerRightHeadingStyle.Render("Logs")),
			m.logsViewPort.View())

	}

	rightPane := lipgloss.JoinVertical(lipgloss.Left, rightPanels...)
	//zone.Mark(attacksViewPortId.String(), centerRightHeadingStyle.Render("Attacks")),
	//attacksPanelStyle.Render("stuff and things"),

	return zone.Scan(lipgloss.JoinHorizontal(lipgloss.Left, leftPane, rightPane))
}

func (m *model) doResize(msg tea.WindowSizeMsg) {
	m.uiHeight = int(math.Round(float64(msg.Height) * .90))
	m.uiWidth = int(math.Round(float64(msg.Width) * .99))
	m.convosTable.SetHeight(m.uiHeight)
	m.rightWidth = m.uiWidth / 2
	m.rightHeight = m.uiHeight / 3
	m.doCurrConvoRow()
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
	if strings.HasSuffix(selectedRow[3], "↖") {
		selectedRow[3] = m.convosRowSenders[m.convosTable.Cursor()]
	}

	var err error
	if m.curConvoRow, err = newArpTableRow(selectedRow); err != nil {
		m.eWriter.WriteStringf("failed to generate table for selected arp row: %v", err.Error())
		return
	}

	// Get content for the selected ARP table
	buff := getSelectedArpTableContent(m)
	if buff.err != nil {
		_, err = m.eWriter.WriteStringf("failed to get selected conversations content: %v", err.Error())
		if err != nil {
			m.eWriter.WriteString("failed to write error to log pane")
			panic(err)
		}
	} else {
		m.curConvoTableData = &buff
		m.curConvoTable.SetColumns(buff.cols)
		m.curConvoTable.SetRows(buff.rows)
	}
}

func (m *model) doConvoTableContent(c convosTableContent) {
	if len(c.rows) > 0 {
		m.convosTable.SetColumns(c.cols)
		m.convosTable.SetRows(c.rows)
		m.doCurrConvoRow()
	}
}
