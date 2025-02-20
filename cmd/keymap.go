package main

import (
	"github.com/charmbracelet/bubbles/key"
)

type keyMap struct {
	CtrlShiftUp    key.Binding
	CtrlShiftDown  key.Binding
	CtrlShiftLeft  key.Binding
	CtrlShiftRight key.Binding
	Up             key.Binding
	Down           key.Binding
	Help           key.Binding
	Quit           key.Binding
}

var keys = keyMap{
	CtrlShiftUp: key.NewBinding(
		key.WithKeys("ctrl+shift+up"),
		key.WithHelp("ctrl+shift+up", "move up pane")),
	CtrlShiftDown: key.NewBinding(
		key.WithKeys("ctrl+shift+down"),
		key.WithHelp("ctrl+shift+down", "move down pane")),
	CtrlShiftLeft: key.NewBinding(key.WithKeys("ctrl+shift+left"),
		key.WithHelp("ctrl+shift+left", "move left pane")),
	CtrlShiftRight: key.NewBinding(
		key.WithKeys("ctrl+shift+right"),
		key.WithHelp("ctrl+shift+right", "move right pane")),
	Up: key.NewBinding(
		key.WithKeys("up", "k"),
		key.WithHelp("↑/k", "move up row")),
	Down: key.NewBinding(
		key.WithKeys("down", "j"),
		key.WithHelp("↓/j", "move down row")),
	Help: key.NewBinding(
		key.WithKeys("?"),
		key.WithHelp("?", "toggle help")),
	Quit: key.NewBinding(
		key.WithKeys("q", "esc", "ctrl+c"),
		key.WithHelp("q/esc", "quit")),
}

func (k keyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Help, k.Quit}
}

func (k keyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.CtrlShiftUp, k.CtrlShiftDown, k.CtrlShiftLeft, k.CtrlShiftRight},
		{k.Up, k.Down, k.Help, k.Quit},
	}
}
