package main

// paneHeadingId represents a bubble zone mark ID used to
// identify a UI pane.
type paneHeadingId string

const (
	convosTableId            paneHeadingId = "convosTable"
	curConvoId               paneHeadingId = "selectedArpTable"
	logPaneId                paneHeadingId = "logsViewPort"
	attacksViewPortHeadingId paneHeadingId = "attacksViewPort"
	poisonPaneHeadingId      paneHeadingId = "poisonPane"
)

func (p paneHeadingId) String() string {
	return string(p)
}

// Int returns an index indicating where in the ui
// that the pane resides.
func (p paneHeadingId) Int() int {
	switch p {
	case convosTableId:
		return 0
	case curConvoId:
		return 1
	case attacksViewPortHeadingId:
		return 2
	case logPaneId:
		return 3
	default:
		panic("invalid paneHeadingId")
	}
}

// nextPane accepts an integer value representing the currently
// selected ui pane and returns the ID of the next one. Direction,
// "forward" or "backward", indicates if the next pane will be
// selected in a clockwise or counter-clockwise motion respectively.
func (p paneHeadingId) nextPane(direction string) (next paneHeadingId) {

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
		next = convosTableId
	case 1:
		next = curConvoId
	case 2:
		next = attacksViewPortHeadingId
	case 3:
		next = logPaneId
	}

	return
}
