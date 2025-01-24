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
	"math"
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

	poisonButtonId  = "poisonBtn"
	poisonCfgPaneId = "poisonCfgPane"
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
		focusedId               paneHeadingId

		events  []string
		eWriter eventWriter

		convosTable   table.Model
		convosSpinner spinner.Model
		// convosRowSenders maps a row offset to its corresponding
		// sender IP value, allowing us to filter out repetitive
		// IPs from the convosTable table.
		convosRowSenders  map[int]string
		convosPoisonPanes PoisoningPanels

		curConvoRow       convoRow
		curConvoTable     table.Model
		curConvoTableData *curConvoTableData

		activeAttacks *ActiveAttacks

		poisonCfgShow bool

		logsPane panes.LogsPane
		logsCh   chan string

		// mainSniff determines if the sniffing process should
		// be started. As it allows the UI to run without root,
		// it's sometimes useful to disable this while debugging.
		mainSniff bool
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
	cmds := []tea.Cmd{
		m.logsPane.Init(),
		func() tea.Msg {
			return m.convosSpinner.Tick()
		},
		func() tea.Msg {
			return getConvosTableContent(&m)
			//return getConvosTableContent(m.db, 100, 0)
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

	return tea.Batch(cmds...)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case panes.LogEvent:

		lP, c := m.logsPane.Update(msg)
		m.logsPane = lP.(panes.LogsPane)
		return m, c

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

	case panes.BtnPressMsg:

		switch msg.Event {
		case panes.StartPoisonEvent:
			// TODO start to be offloaded to the poisoning panel itself
			if err := m.activeAttacks.Add(m.curConvoRow.senderIp, m.curConvoRow.targetIp); err != nil {
				// TODO
				panic(err)
			}
		case panes.CancelPoisonEvent:
			m.activeAttacks.Remove(m.curConvoRow.senderIp, m.curConvoRow.targetIp)
			m.convosPoisonPanes.Remove(m.curConvoRow.senderIp, m.curConvoRow.targetIp)
			m.focusedId = convosTableHeadingId
		case panes.CancelConfigEvent:
			m.convosPoisonPanes.Remove(m.curConvoRow.senderIp, m.curConvoRow.targetIp)
			m.focusedId = logsViewPortHeadingId
		default:
			panic("unknown button press event emitted by poison configuration panel")
		}

		// TODO handle poison panel button press event
		return m, nil

	case tea.MouseMsg:
		// Handle mouse events, like button presses

		if msg.Action != tea.MouseActionRelease || msg.Button != tea.MouseButtonLeft {
			// We only care about the left mouse button
			return m, nil
		}

		//===========================================
		// CHANGE FOCUSED PANES BASED ON HEADER CLICK
		//===========================================

		if m.focusedId != logsViewPortHeadingId && zone.Get(logsViewPortHeadingId.String()).InBounds(msg) {
			m.focusedId = logsViewPortHeadingId
		} else if m.focusedId != convosTableHeadingId && zone.Get(convosTableHeadingId.String()).InBounds(msg) {
			m.focusedId = convosTableHeadingId
		} else if m.focusedId != attacksViewPortHeadingId && zone.Get(attacksViewPortHeadingId.String()).InBounds(msg) {
			m.focusedId = attacksViewPortHeadingId
		} else if m.focusedId != curConvoTableHeadingId && zone.Get(curConvoTableHeadingId.String()).InBounds(msg) {
			m.focusedId = curConvoTableHeadingId
		}

		if zone.Get(poisonButtonId).InBounds(msg) {
			m.focusedId = poisonCfgPaneId
			p := m.convosPoisonPanes.GetOrCreate(m.curConvoRow.senderIp, m.curConvoRow.targetIp)
			p.Style = paneStyle.BorderForeground(selectedPaneBorderColor)
			return m, nil
		}

		if m.convosPoisonPanes.Exists(m.curConvoRow.senderIp, m.curConvoRow.targetIp) {
			cmd, err := m.convosPoisonPanes.Update(m.curConvoRow.senderIp, m.curConvoRow.targetIp, msg)
			if err != nil {
				// TODO
				panic("failed to update poison panel")
			}
			return m, cmd
		}

	case tea.KeyMsg:
		// Handle keystrokes

		switch msg.String() {
		case "q", "ctrl+c":
			// TODO kill background routines
			return m, tea.Quit
		}

		hasPoisonPanel := m.convosPoisonPanes.Exists(m.curConvoRow.senderIp, m.curConvoRow.targetIp)
		handleBottomPanel := func() {
			if hasPoisonPanel {
				m.focusedId = poisonCfgPaneId
			} else {
				m.focusedId = logsViewPortHeadingId
			}
		}

		switch m.focusedId {
		case convosTableHeadingId:

			switch msg.String() {
			case "up", "k":
				if m.convosTable.Cursor() == 0 {
					m.convosTable.GotoBottom()
				} else {
					m.convosTable, _ = m.convosTable.Update(msg)
				}
				m.doCurrConvoRow()
			case "down", "j":
				if m.convosTable.Cursor() == len(m.convosTable.Rows())-1 {
					m.convosTable.GotoTop()
				} else {
					m.convosTable, _ = m.convosTable.Update(msg)
				}
				m.doCurrConvoRow()
			case "ctrl+shift+up", "ctrl+shift+right":
				m.focusedId = curConvoTableHeadingId
			case "ctrl+shift+down":
				handleBottomPanel()
			default:
				m.convosTable, _ = m.convosTable.Update(msg)
				m.doCurrConvoRow()
			}
			return m, nil

		case curConvoTableHeadingId:

			switch msg.String() {
			case "ctrl+shift+left":
				m.focusedId = convosTableHeadingId
				m.convosTable.Focus()
			case "ctrl+shift+down", "ctrl+shift+up":
				handleBottomPanel()
			}

		case logsViewPortHeadingId:

			switch msg.String() {
			case "ctrl+shift+left":
				m.focusedId = convosTableHeadingId
				m.convosTable.Focus()
			case "ctrl+shift+down", "ctrl+shift+up":
				m.focusedId = curConvoTableHeadingId
			default:
				// Pass all other keystrokes to the logs pane
				lP, c := m.logsPane.Update(msg)
				m.logsPane = lP.(panes.LogsPane)
				return m, c
			}

		case poisonCfgPaneId:

			switch msg.String() {
			case "ctrl+shift+left":
				m.focusedId = convosTableHeadingId
				m.convosTable.Focus()
			case "ctrl+shift+down", "ctrl+shift+up":
				m.focusedId = curConvoTableHeadingId
			default:
				// Pass all other keystrokes to the poisoning configuration pane
				if m.focusedId == poisonCfgPaneId {
					cmd, err := m.convosPoisonPanes.Update(m.curConvoRow.senderIp, m.curConvoRow.targetIp, msg)
					if err != nil {
						// TODO
						panic("failed to update poison panel")
					}
					return m, cmd
				}
			}

		}

	case spinner.TickMsg:
		// Spin the spinner
		//
		// This type is supplied when the spinner is active,
		// which occurs when no ARP requests have been captured

		if len(m.convosTable.Rows()) == 0 {
			var cmd tea.Cmd
			m.convosSpinner, cmd = m.convosSpinner.Update(msg)
			return m, cmd
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

		m.doResize(msg)

	case eavesarpError:

		return m, tea.Quit

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

	logsHeight := m.uiHeight - (h * 2) + 2
	logsPaneStyle := rightPaneStyle
	logsPaneStyle = logsPaneStyle.Height(logsHeight)

	centerRightHeadingStyle := centerStyle
	centerRightHeadingStyle = centerRightHeadingStyle.Width(m.rightWidth)

	convosTblStyle := paneStyle
	selectedArpTableStyle := paneStyle
	attacksPanelStyle := paneStyle
	logViewPortStyle := paneStyle

	hasPoisonPanel := m.convosPoisonPanes.Exists(m.curConvoRow.senderIp, m.curConvoRow.targetIp)
	hasActiveAttack := m.activeAttacks.Exists(m.curConvoRow.senderIp, m.curConvoRow.targetIp)
	var hasConfigurePoisoningBtn bool

	//==================================
	// BRIGHTEN BORDER FOR SELECTED PANE
	//==================================

	switch m.focusedId {
	case convosTableHeadingId:
		convosTblStyle = convosTblStyle.BorderForeground(selectedPaneBorderColor)
	case curConvoTableHeadingId:
		selectedArpTableStyle = selectedArpTableStyle.BorderForeground(selectedPaneBorderColor)
	case attacksViewPortHeadingId:
		attacksPanelStyle = attacksPanelStyle.BorderForeground(selectedPaneBorderColor)
	case logsViewPortHeadingId, poisonCfgPaneId:
		logViewPortStyle = logViewPortStyle.BorderForeground(selectedPaneBorderColor)
	}

	m.logsPane.Style = logViewPortStyle
	attacksPanelStyle = attacksPanelStyle.Width(m.rightWidth).Height(m.rightHeight)

	//====================
	// CONVERSATIONS TABLE
	//====================

	var leftPane string
	arpTblHeading := zone.Mark(convosTableHeadingId.String(), centerStyle.Render("Conversations"))

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

	var rightPanels []string
	if m.curConvoTableData != nil {

		//===========================
		// CURRENT CONVERSATION TABLE
		//===========================

		rightPanels = append(rightPanels,
			zone.Mark(curConvoTableHeadingId.String(), centerRightHeadingStyle.Render("Selected Conversation")),
			selectedArpTableStyle.Render(m.curConvoTable.View()))

		if m.curConvoRow.isSnac && m.focusedId != poisonCfgPaneId && !hasPoisonPanel && !hasActiveAttack {
			// TODO clean this up
			s := lipgloss.NewStyle().
				Width(m.rightWidth).
				MarginLeft(1).
				PaddingRight(1).
				AlignHorizontal(lipgloss.Center).
				Background(lipgloss.Color("240"))
			button := zone.Mark(poisonButtonId, s.Render("Configure Poisoning"))
			rightPanels = append(rightPanels, button)
			hasConfigurePoisoningBtn = true
		}
	}

	if m.curConvoRow.isSnac && (m.focusedId == poisonCfgPaneId || hasPoisonPanel) {

		//==============================
		// POISONING CONFIGURATION PANEL
		//==============================

		p := m.convosPoisonPanes.Get(m.curConvoRow.senderIp, m.curConvoRow.targetIp)
		if p == nil {
			// TODO
			panic("missing poison panel for conversation")
		}
		p.Width = m.rightWidth
		p.Height = logsHeight

		if m.focusedId == poisonCfgPaneId {
			p.Style = p.Style.BorderForeground(selectedPaneBorderColor)
		} else {
			p.Style = p.Style.BorderForeground(deselectedPaneBorderColor)
		}

		rightPanels = append(rightPanels, lipgloss.JoinVertical(lipgloss.Center,
			zone.Mark(poisonPaneHeadingId.String(), centerRightHeadingStyle.Render("Poisoning")), p.View()))

	} else {

		//===========
		// LOGS PANEL
		//===========

		if !hasConfigurePoisoningBtn {
			logsHeight += 2
		}

		m.logsPane.Width(w)
		m.logsPane.Height(logsHeight)

		rightPanels = append(rightPanels,
			zone.Mark(logsViewPortHeadingId.String(),
				centerRightHeadingStyle.Render("Logs")),
			m.logsPane.View())

	}

	rightPane := lipgloss.JoinVertical(lipgloss.Left, rightPanels...)
	//zone.Mark(attacksViewPortHeadingId.String(), centerRightHeadingStyle.Render("Attacks")),
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
