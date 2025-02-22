package panes

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/enescakir/emoji"
	eavesarp_ng "github.com/impostorkeanu/eavesarp-ng"
	"github.com/impostorkeanu/eavesarp-ng/cmd/misc"
	"github.com/impostorkeanu/eavesarp-ng/cmd/panes/stopwatch"
	"github.com/impostorkeanu/eavesarp-ng/cmd/panes/timer"
	zone "github.com/lrstanley/bubblezone"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

var (
	btnStyle = lipgloss.NewStyle().
		Align(lipgloss.Center).
		Background(misc.BtnColor).
		Foreground(misc.BtnTextColor).
		PaddingLeft(1).
		PaddingRight(1)
	focusedStyle           = lipgloss.NewStyle()
	blurredStyle           = lipgloss.NewStyle().Foreground(misc.BlurredColor)
	underlineStyle         = lipgloss.NewStyle().Underline(true)
	validationFailureStyle = lipgloss.NewStyle().Foreground(misc.FailedValidationColor)
	validationSuccessStyle = lipgloss.NewStyle().Foreground(misc.SuccessValidationColor)
	captureDurationHeading = underlineStyle.Render("Capture Duration")
	packetLimitHeading     = underlineStyle.Render("Packet Limit")
	outputFileHeading      = underlineStyle.Render("Output File")
	validators             = []validator{validateDuration, validatePacketLimit, validateOutputFile}
)

const (
	captureDurationInputIndex = iota
	packetLimitInputIndex
	outputFileInputIndex
)

const (
	startBtnMark         = "startBtn"
	cancelBtnMark        = "cancelBtn"
	CancelConfigBtnEvent = "CancelConfigBtnEvent"
	CancelPoisonBtnEvent = "CancelPoisonBtnEvent"
	StartPoisonBtnEvent  = "StartPoisonBtnEvent"
)

const (
	doneKey          = eavesarp_ng.CtxKey("poisonPaneDone")
	statusPktCountCh = eavesarp_ng.CtxKey("poisonPaneStatusPktCountCh")
	cancelKey        = eavesarp_ng.CtxKey("poisonPaneCancelKey")
)

type (
	// poisoningStatusCtxKey are keys used to set and retrieve values
	// on the context of PoisoningStatusMsg.
	poisoningStatusCtxKey string
	// PoisonPane is the poisoning configuration form presented
	// after the user has elected to begin poisoning a SNAC conversation.
	//
	// NewPoison should always be used to initialize this type to ensure
	// creation of unique identifiers.
	//
	// Use Id to obtain the randomly created identifier.
	PoisonPane struct {
		Style     lipgloss.Style  // Style for the panel element
		Stopwatch stopwatch.Model // For tracking elapsed time
		Timer     timer.Model     // For tracking how long until completion (capture duration)
		// Track height and width such that setters must be used.
		//
		// These values override those set in styles during render.
		height, width      int
		paneHeadingZoneId  string            // To make the pane's "Poisoning" heading clickable
		id                 string            // random id created by NewPoison
		inputs             []textinput.Model // text input fields
		errors             []string          // error messages for inputs
		inputFocusIndex    int               // track which input has focus
		running            bool              // determines if the poisoning attack is running
		startBtnMark       string            // unique zone mark for this panel's start button
		cancelBtnMark      string            // unique zone mark for this panel's cancel button
		zoneM              *zone.Manager     // created by NewPoison
		senderIp, targetIp string
		packetCount        int
		cancelPoisonCtx    context.CancelFunc
		eWriter            *misc.EventWriter
		ifaceName          string // name of the network interface to monitor while poisoning
		db                 *sql.DB
		arpSoofCh          chan eavesarp_ng.AttackSnacCfg
	}

	// BtnPressMsg indicates a button has been pressed in a PoisonPane.
	BtnPressMsg struct {
		Event    string // Event that was emitted
		FormData FormData
	}

	FormData struct {
		CaptureDuration, PacketLimit, OutputFile string
	}

	validator func(string) error

	PoisoningStatusMsg struct {
		Id          string
		PacketCount int
		ctx         context.Context
		ew          *misc.EventWriter
	}
)

func (p PoisoningStatusMsg) Done() bool {
	return p.ctx.Value(doneKey) != nil
}

func (p PoisonPane) ConvoKey() string {
	return eavesarp_ng.FmtConvoKey(p.senderIp, p.targetIp)
}

func NewPoison(db *sql.DB, ifaceName, senderIp, targetIp string, z *zone.Manager, arpSpoofCh chan eavesarp_ng.AttackSnacCfg, eW *misc.EventWriter) PoisonPane {
	id := z.NewPrefix()
	return PoisonPane{
		zoneM:         z,
		inputs:        newTextInputs(),
		id:            id,
		startBtnMark:  fmt.Sprintf("%s-%s", id, startBtnMark),
		cancelBtnMark: fmt.Sprintf("%s-%s", id, cancelBtnMark),
		senderIp:      senderIp,
		targetIp:      targetIp,
		eWriter:       eW,
		ifaceName:     ifaceName,
		db:            db,
		arpSoofCh:     arpSpoofCh,
	}
}

func validatePacketLimit(v string) (err error) {
	if v == "" {
		return
	} else if i, e := strconv.Atoi(v); e != nil {
		err = errors.New("invalid packet limit")
	} else if i < 1 {
		err = errors.New("packet limit must be > 0")
	}
	return
}

func validateDuration(v string) (err error) {
	if v == "" {
		return
	} else if _, e := time.ParseDuration(v); e != nil {
		err = errors.New("poorly formatted duration")
	}
	return
}

func validateOutputFile(v string) (err error) {
	if v == "" {
		return
	}

	// does the file already exist?
	if fI, e := os.Stat(v); os.IsNotExist(e) {
		// if not, is does the directory exist
		d, _ := path.Split(v)
		if fI, e = os.Stat(d); d != "" && os.IsNotExist(e) {
			err = errors.New("parent directory doesn't exist")
		}
	} else if !fI.IsDir() {
		err = errors.New("file already exists")
	}
	return
}

func (p PoisonPane) Running() bool {
	return p.running
}

// Id returns the ID value that was randomly generated by NewPoison.
func (p PoisonPane) Id() string {
	return p.id
}

func (p PoisonPane) SenderIp() string {
	return p.senderIp
}

func (p PoisonPane) TargetIp() string {
	return p.targetIp
}

func newTextInputs() []textinput.Model {
	cDur := textinput.New()
	cDur.PromptStyle = focusedStyle
	cDur.TextStyle = focusedStyle
	cDur.Placeholder = "Blank to capture forever or 10m, 1h, etc."
	cDur.Focus()

	pLim := textinput.New()
	pLim.Placeholder = "Integer or blank for no limit"
	pLim.PromptStyle = blurredStyle
	pLim.TextStyle = blurredStyle

	oF := textinput.New()
	oF.Placeholder = "Absolute path or blank to not save"
	oF.PromptStyle = blurredStyle
	oF.TextStyle = blurredStyle

	return []textinput.Model{cDur, pLim, oF}
}

func (p PoisonPane) PacketLimitInput() textinput.Model {
	return p.inputs[packetLimitInputIndex]
}

func (p PoisonPane) CaptureDurationInput() textinput.Model {
	return p.inputs[captureDurationInputIndex]
}

func (p PoisonPane) OutputFileInput() textinput.Model {
	return p.inputs[outputFileInputIndex]
}

func (p PoisonPane) Init() tea.Cmd {
	p.inputs[0].Focus()
	return nil
}

func (p PoisonPane) FormData() FormData {
	return FormData{
		CaptureDuration: p.CaptureDurationInput().Value(),
		PacketLimit:     p.PacketLimitInput().Value(),
		OutputFile:      p.OutputFileInput().Value(),
	}
}

func (p PoisonPane) Update(msg tea.Msg) (_ PoisonPane, cmd tea.Cmd) {
	switch msg := msg.(type) {
	case PoisoningStatusMsg:

		if msg.ctx.Value(doneKey) != nil {
			return p, cmd
		}

		p.packetCount = msg.PacketCount
		return p, handlePoisoningStatusMsg(msg)

	case timer.TimeoutMsg:

		// TODO handle timer.TimedoutMsg

	case timer.TickMsg, timer.StartStopMsg:

		p.Timer, cmd = p.Timer.Update(msg)
		return p, cmd

	case stopwatch.TickMsg, stopwatch.StartStopMsg:

		p.Stopwatch, cmd = p.Stopwatch.Update(msg)
		return p, cmd

	case tea.MouseMsg:

		if msg.Action == tea.MouseActionRelease && msg.Button == tea.MouseButtonLeft {

			if p.zoneM.Get(p.cancelBtnMark).InBounds(msg) {

				// May need to cancel configuration before starting an attack
				if p.running {
					// Cancel a running attack
					p.running = false
					p.inputs[p.inputFocusIndex].Focus()
					p.inputs[p.inputFocusIndex].TextStyle = focusedStyle
					p.inputs[p.inputFocusIndex].PromptStyle = focusedStyle
					return p, func() tea.Msg {
						// Notify that poisoning should be canceled
						return BtnPressMsg{
							Event:    CancelPoisonBtnEvent,
							FormData: p.FormData(),
						}
					}
				}

				p.inputFocusIndex = 0
				p.inputs = newTextInputs()
				p.inputs[captureDurationInputIndex].Focus()
				return p, func() tea.Msg {
					// Notify that configuration should stop
					return BtnPressMsg{
						Event:    CancelConfigBtnEvent,
						FormData: p.FormData(),
					}
				}

			} else if p.zoneM.Get(p.startBtnMark).InBounds(msg) {
				// Start button clicked
				p.running = true
				p.inputs[p.inputFocusIndex].Blur()
				p.inputs[p.inputFocusIndex].TextStyle = blurredStyle
				p.inputs[p.inputFocusIndex].PromptStyle = blurredStyle
				return p, func() tea.Msg {
					// Notify that poisoning should start
					return BtnPressMsg{
						Event:    StartPoisonBtnEvent,
						FormData: p.FormData(),
					}
				}
			}
		}

	case tea.KeyMsg:

		switch msg.String() {
		case "tab", "shift+tab":

			if p.running {
				// Preserve inputs while runs
				break
			}

			if msg.String() == "tab" {
				// Move forward
				p.inputFocusIndex++
			} else {
				// Move backward
				p.inputFocusIndex--
			}

			if p.inputFocusIndex == len(p.inputs) {
				// Return to first input
				p.inputFocusIndex = 0
			} else if p.inputFocusIndex < 0 {
				// Jump to last input
				p.inputFocusIndex = len(p.inputs) - 1
			}

			cmds := make([]tea.Cmd, len(p.inputs)+1)
			for i := 0; i <= len(p.inputs)-1; i++ {
				if i == p.inputFocusIndex {
					// Set focused state
					cmds[i] = p.inputs[i].Focus()
					p.inputs[i].PromptStyle = focusedStyle
					p.inputs[i].TextStyle = focusedStyle
					continue
				}
				// Remove focused state
				p.inputs[i].Blur()
				p.inputs[i].PromptStyle = blurredStyle
				p.inputs[i].TextStyle = blurredStyle
			}

			return p, tea.Batch(cmds...)

		}

	case BtnPressMsg:

		switch msg.Event {
		case StartPoisonBtnEvent:

			cmd = p.startPoisoning(msg)

		case CancelPoisonBtnEvent:

			if p.cancelPoisonCtx != nil {
				p.cancelPoisonCtx()
			}

		case CancelConfigBtnEvent:

			// NOP

		default:

			// TODO
			panic("unknown button press event emitted by poison configuration panel")

		}

		return p, cmd

	}

	return p, p.updateInputs(msg)
}

// startPoisoning starts a poisoning attack for a given conversation.
func (p *PoisonPane) startPoisoning(msg BtnPressMsg) tea.Cmd {

	//=======================================
	// CREATE NEW ATTACK FOR THE CONVERSATION
	//=======================================

	var sIp, tIp eavesarp_ng.Ip
	var err error

	sIp, err = eavesarp_ng.GetOrCreateIp(p.db, p.senderIp, nil, "", false, false)
	if err != nil {
		p.eWriter.WriteStringf("failed to retrieve sender ip from database: %s", err.Error())
		return nil
	}
	tIp, err = eavesarp_ng.GetOrCreateIp(p.db, p.targetIp, nil, "", false, false)
	if err != nil {
		p.eWriter.WriteStringf("failed to retrieve target ip from database: %s", err.Error())
		return nil
	}

	var attack eavesarp_ng.Attack
	attack, err = eavesarp_ng.GetOrCreateAttack(p.db, nil, sIp.Id, tIp.Id)
	if err != nil {
		p.eWriter.WriteStringf("failed to create new attack in database: %s", err.Error())
		return nil
	}

	//=============================
	// PREPARE ADDITIONAL VARIABLES
	//=============================

	// maximum number of packets to capture
	// NOTE: value is validated prior to this event
	packetLimit, _ := strconv.Atoi(p.PacketLimitInput().Value())

	// get an ip values for sniff function later
	var senderIp, targetIp net.IP
	if senderIp = net.ParseIP(p.senderIp); senderIp == nil {
		p.eWriter.WriteString("failed to parse sender ip for poisoning initialization")
		p.eWriter.WriteStringf("sender ip value: %s", p.senderIp)
		return nil
	} else if targetIp = net.ParseIP(p.targetIp); targetIp == nil {
		p.eWriter.WriteString("failed to parse target ip for poisoning initialization")
		p.eWriter.WriteStringf("target ip value: %s", p.senderIp)
		return nil
	}

	var (
		ctx                                context.Context    // context to enable cross-routine attack timeout/cancellation
		cancel                             context.CancelFunc // cancel function that will be used to stop the attack
		startClockCmd                      tea.Cmd            // start command for the ui timer/stopwatch
		outputFileHandler, pktLimitHandler eavesarp_ng.ArpSpoofHandler
		statusCntCh                        = make(chan int, 100) // channel used to send the packet count to the ui
	)

	//====================================================
	// PREPARE UI TIMER/STOPWATCH AND CONTEXT CANCELLATION
	//====================================================

	// update ctx with cancellation and/or timeout
	if len(p.CaptureDurationInput().Value()) > 0 {
		// Apply a timeout on the attack
		// Note: duration value was validated by poison pane
		d, _ := time.ParseDuration(p.CaptureDurationInput().Value())
		p.Timer = timer.New(p.ConvoKey(), d)
		ctx, cancel = context.WithTimeout(context.Background(), d)
		startClockCmd = p.Timer.Start()
	} else {
		// Attack will run until cancelled
		p.Stopwatch = stopwatch.NewStopwatch(p.ConvoKey(), time.Now(), time.Second)
		ctx, cancel = context.WithCancel(context.Background())
		startClockCmd = p.Stopwatch.Start()
	}

	// close all channels upon context timeout/cancellation
	var hasClosed atomic.Bool
	p.cancelPoisonCtx = func() {
		cancel()
		if !hasClosed.Load() {
			hasClosed.Store(true)
			close(statusCntCh)
		}
	}

	ctx = context.WithValue(ctx, statusPktCountCh, statusCntCh) // total packet count written here to emit status msg
	ctx = context.WithValue(ctx, cancelKey, p.cancelPoisonCtx)  // bind the cancel function to make it accessible to routines

	//========================
	// DEFINE CAPTURE HANDLERS
	//========================
	// handlers are functions that receive each packet for handling

	pktCntCh, pktCntHandler := eavesarp_ng.PacketCounterHandler(ctx, 0)
	pktCntReceiverCmd := func() tea.Msg {
		for {
			select {
			case <-ctx.Done():
				return nil
			case c := <-pktCntCh:
				statusCntCh <- c
			}
		}
	}

	attackPortHandler := eavesarp_ng.AttackPortHandler(ctx, p.db, attack.Id, func(err error) {
		p.eWriter.WriteStringf("failed to update attack port: %s", err.Error())
		p.cancelPoisonCtx()
	})

	if packetLimit > 0 {
		pktLimitHandler = eavesarp_ng.PacketLimitHandler(ctx, packetLimit, func() {
			p.eWriter.WriteString("packet limit met")
			p.cancelPoisonCtx()
		})
	}

	// handle writing to output file
	if p.OutputFileInput().Value() != "" {
		var f *os.File
		if f, err = os.Create(p.OutputFileInput().Value()); err != nil {
			p.eWriter.WriteStringf("failed to create output file: %s", err.Error())
			return nil
		}
		outputFileHandler, err = eavesarp_ng.OutputFileHandler(ctx, f, func(err error) {
			p.eWriter.WriteStringf("error while writine to packet capture file: %s", err.Error())
			p.cancelPoisonCtx()
		})
	}

	// block and capture packets until ctx is canceled
	poisonerCmd := func() tea.Msg {
		p.eWriter.WriteStringf("starting poisoning attack: %s -> %s", sIp.Value, tIp.Value)
		// TODO update for ip address specification on interface
		p.arpSoofCh <- eavesarp_ng.AttackSnacCfg{
			Ctx:      ctx,
			SenderIp: senderIp,
			TargetIp: targetIp,
			Handlers: []eavesarp_ng.ArpSpoofHandler{pktCntHandler, attackPortHandler, outputFileHandler, pktLimitHandler},
		}
		p.eWriter.WriteStringf("ending poisoning attack: %s -> %s", sIp.Value, tIp.Value)
		return nil
	}

	// sends a poisoning status message to start monitoring
	// for packet count updates
	poisoningStatusCmd := func() tea.Msg {
		return PoisoningStatusMsg{
			Id:          p.ConvoKey(),
			PacketCount: 0,
			ctx:         ctx,
			ew:          p.eWriter,
		}
	}

	return tea.Batch(startClockCmd, poisoningStatusCmd, poisonerCmd, pktCntReceiverCmd)
}

func (p *PoisonPane) updateInputs(msg tea.Msg) tea.Cmd {
	cmds := make([]tea.Cmd, len(p.inputs))

	// Only text inputs with Focus() set will respond, so it's safe to simply
	// update all of them here without any further logic.
	for i := range p.inputs {
		p.inputs[i], cmds[i] = p.inputs[i].Update(msg)
	}

	return tea.Batch(cmds...)
}

func (p *PoisonPane) SetHeight(h int) {
	p.height = h - 2
}

func (p *PoisonPane) SetWidth(w int) {
	p.width = w - 2
}

func (p PoisonPane) View() string {
	var hasErrors bool
	var builder strings.Builder

	for i := range p.inputs {

		var err error
		if !p.running { // no reason to validate if we're poisoning
			err = validators[i](p.inputs[i].Value())
		}
		switch i {
		case captureDurationInputIndex:
			builder.WriteString(captureDurationHeading)
		case packetLimitInputIndex:
			builder.WriteString(packetLimitHeading)
		case outputFileInputIndex:
			builder.WriteString(outputFileHeading)
		default:
			// TODO
			panic("heading offset exceeded")
		}

		builder.WriteString(" ")
		if err != nil {
			builder.WriteString(validationFailureStyle.Render(err.Error()))
			if !hasErrors {
				hasErrors = true
			}
		} else if p.running {
			builder.WriteString(emoji.Locked.String())
		} else {
			builder.WriteString(validationSuccessStyle.Render("✔"))
		}
		builder.WriteString("\n" + p.inputs[i].View())
		if i < len(p.inputs)-1 {
			builder.WriteString("\n\n")
		}
	}

	var pO int
	if p.running {
		pO++
	}
	for btnPad := p.height - lipgloss.Height(builder.String()); btnPad > (1 + pO); btnPad-- {
		builder.WriteString("\n")
	}

	centerStyle := lipgloss.NewStyle().AlignHorizontal(lipgloss.Center).Width(p.width)
	heading := "Poisoning"
	if p.running {

		btn := p.zoneM.Mark(p.cancelBtnMark, btnStyle.Render("Stop"))

		//=================
		// STATS HEADER ROW
		//=================

		maxW := p.width
		halfW := maxW / 2

		tHeader := "Time Elapsed"
		pHeader := "Packet Count"

		if p.CaptureDurationInput().Value() != "" {
			tHeader = "Time Remaining"
		}

		builder.WriteString(underlineStyle.Width(halfW + (maxW % 2)).AlignHorizontal(lipgloss.Left).Render(tHeader))
		builder.WriteString(underlineStyle.Width(halfW).AlignHorizontal(lipgloss.Right).Render(pHeader))
		builder.WriteString("\n")

		//==========
		// STATS ROW
		//==========

		var tVal string
		if p.CaptureDurationInput().Value() != "" {
			tVal = p.Timer.View()
		} else {
			tVal = p.Stopwatch.View()
		}
		pVal := fmt.Sprintf("%d", p.packetCount)

		halfW = (maxW / 2) - (lipgloss.Width(btn) / 2)
		builder.WriteString(lipgloss.NewStyle().AlignHorizontal(lipgloss.Left).Width(halfW + (maxW % 2)).Render(tVal))
		builder.WriteString(btn)
		builder.WriteString(lipgloss.NewStyle().AlignHorizontal(lipgloss.Right).Width(halfW).Render(pVal))

	} else if hasErrors {

		heading = "Configuration Error"
		// Show cancel button along with capture stats
		s := lipgloss.NewStyle().Width(p.width)
		builder.WriteString(
			s.AlignHorizontal(lipgloss.Center).Render(p.zoneM.Mark(p.cancelBtnMark, btnStyle.Render("Cancel"))))

	} else {

		// Show start and cancel button
		heading = "Configure Poisoning"
		builder.WriteString(centerStyle.Render(lipgloss.JoinHorizontal(lipgloss.Center,
			p.zoneM.Mark(p.startBtnMark, btnStyle.MarginRight(1).Render("Start")),
			p.zoneM.Mark(p.cancelBtnMark, btnStyle.Render("Cancel")))))

	}

	return p.Style.Width(p.width).Height(p.height).Render(
		centerStyle.Render(p.zoneM.Mark(p.paneHeadingZoneId, heading)), builder.String())
}

func handlePoisoningStatusMsg(msg PoisoningStatusMsg) tea.Cmd {
	return func() tea.Msg {
		statusCh := msg.ctx.Value(statusPktCountCh).(chan int)
		cancel := msg.ctx.Value(cancelKey).(context.CancelFunc)
		select {
		case <-msg.ctx.Done():
			msg.ctx = context.WithValue(msg.ctx, doneKey, true)
			cancel()
			if err := msg.ctx.Err(); errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				msg.ew.WriteStringf("done poisoning: %s", msg.Id)
			} else {
				msg.ew.WriteStringf("unhandled exception while poisoning: %s", err.Error())
			}
			// message indicating end of poisoning
			return PoisoningStatusMsg{Id: msg.Id, PacketCount: 0, ew: msg.ew, ctx: msg.ctx}
		case count := <-statusCh:
			// message indicating the current count of captured packets
			return PoisoningStatusMsg{Id: msg.Id, PacketCount: count, ctx: msg.ctx, ew: msg.ew,
			}
		}
	}
}
