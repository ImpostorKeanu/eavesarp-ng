package main

// paneId represents a bubble zone mark ID used to
// identify a UI pane.
type paneId string

const (
	arpTableId        paneId = "arpTable"
	curArpTableId     paneId = "selectedArpTable"
	logViewPortId     paneId = "logViewPort"
	attacksViewPortId paneId = "attacksViewPort"
)

func (p paneId) String() string {
	return string(p)
}

// Int returns an index indicating where in the ui
// that the pane resides.
func (p paneId) Int() int {
	switch p {
	case arpTableId:
		return 0
	case curArpTableId:
		return 1
	case attacksViewPortId:
		return 2
	case logViewPortId:
		return 3
	default:
		panic("invalid paneId")
	}
}

// nextPane accepts an integer value representing the currently
// selected ui pane and returns the ID of the next one. Direction,
// "forward" or "backward", indicates if the next pane will be
// selected in a clockwise or counter-clockwise motion respectively.
func (p paneId) nextPane(direction string) (next paneId) {

	i := p.Int()

	switch direction {
	case "f", "for", "forward", ">":
		i++
	case "b", "back", "backward", "<":
		i--
	default:
		panic("invalid direction supplied")
	}

	if i > 3 {
		i = 0
	} else if i < 0 {
		i = 3
	}

	switch i {
	case 0:
		next = arpTableId
	case 1:
		next = curArpTableId
	case 2:
		next = attacksViewPortId
	case 3:
		next = logViewPortId
	}

	return
}
