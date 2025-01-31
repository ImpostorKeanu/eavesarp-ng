package panes

import (
	"database/sql"
	"fmt"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	eavesarp_ng "github.com/impostorkeanu/eavesarp-ng"
	zone "github.com/lrstanley/bubblezone"
	"slices"
	"strings"
)

const (
	convoTableSelectionQuery = `
SELECT ip.value AS ip,
       ip.disc_meth AS ip_disc_meth,
       ip.ptr_resolved AS ip_ptr_resolved,
       COALESCE(mac.value, '') AS mac,
       COALESCE(mac.disc_meth, '') AS mac_disc_meth,
       COALESCE(dns_record.kind, '') AS dns_record_kind,
       COALESCE(dns_name.value, '') AS dns_name
FROM ip
LEFT JOIN mac ON mac.Id = ip.mac_id
LEFT JOIN dns_record ON dns_record.ip_id = ip.Id
LEFT JOIN dns_name ON dns_name.Id = dns_record.dns_name_id
WHERE ip.value IN (?,?);
`
	snacAitmQuery = `
SELECT snac_ip.value AS snac_ip, upstream_ip.value AS upstream_ip, dns_name.value AS forward_dns_name
FROM aitm_opt
INNER JOIN ip AS snac_ip ON snac_ip.Id = aitm_opt.snac_target_ip_id
INNER JOIN ip AS upstream_ip ON upstream_ip.Id = aitm_opt.upstream_ip_id
LEFT JOIN dns_record ON dns_record.ip_id = aitm_opt.upstream_ip_id AND dns_record.kind = 'a'
LEFT JOIN dns_name ON dns_name.Id = dns_record.dns_name_id
WHERE aitm_opt.snac_target_ip_id = ?;
`
)

var (
	curConvoTableStyle table.Styles
	protoWeights       = map[string]int{"tcp": 1, "udp": 2, "sctp": 3}
)

func init() {
	//curConvoTableStyle = table.DefaultStyles()
	curConvoTableStyle.Header = curConvoTableStyle.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(true).
		Padding(0, 0, 0, 2).
		Margin(0, 0, 0, 0)
	//PaddingLeft(1).
	//curConvoTableStyle.Cell.PaddingLeft(1)
	curConvoTableStyle.Cell = curConvoTableStyle.Cell.
		Padding(0, 0, 0, 2).
		Margin(0, 0, 0, 0)
	curConvoTableStyle.Selected = curConvoTableStyle.Selected.
		Foreground(lipgloss.Color("255")).
		Bold(true).
		Padding(0, 0, 0, 0).
		Margin(0, 0, 0, 0)
}

type (
	CurConvoPane struct {
		Style                  lipgloss.Style
		db                     *sql.DB
		zone                   *zone.Manager
		curConvoRow            CurConvoRowDetails
		tbl                    table.Model
		poisonCfgBtnId         string
		IsSnac                 bool
		IsPoisoning            bool
		IsConfiguringPoisoning bool
	}

	CurConvoRowDetails struct {
		Index    int
		IsSnac   bool
		SenderIp string
		TargetIp string
		ArpCount int
	}

	CurConvoTableData struct {
		Cols               []table.Column
		Rows               []table.Row
		CurConvoRowDetails CurConvoRowDetails
		Err                error
	}
)

func (c CurConvoRowDetails) ConvoKey() string {
	return eavesarp_ng.FmtConvoKey(c.SenderIp, c.TargetIp)
}

func (c CurConvoRowDetails) IsZero() bool {
	return c.SenderIp == "" && c.TargetIp == "" && c.ArpCount == 0
}

func NewCurConvoPane(db *sql.DB, zone *zone.Manager, poisonCfgBtnId string) CurConvoPane {
	return CurConvoPane{
		db:             db,
		zone:           zone,
		poisonCfgBtnId: poisonCfgBtnId,
		tbl:            table.New(table.WithKeyMap(table.DefaultKeyMap()), table.WithStyles(curConvoTableStyle)),
	}
}

func (c CurConvoPane) Init() tea.Cmd {
	return nil
}

func (c CurConvoPane) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			if c.tbl.Cursor() == 0 {
				c.tbl.GotoBottom()
			} else {
				c.tbl, _ = c.tbl.Update(msg)
			}
			cmd = func() tea.Msg {
				return c.GetContent(c.db, c.curConvoRow)
			}
		case "down", "j":
			if c.tbl.Cursor() == len(c.tbl.Rows())-1 {
				c.tbl.GotoTop()
			} else {
				c.tbl, _ = c.tbl.Update(msg)
			}
			cmd = func() tea.Msg {
				return c.GetContent(c.db, c.curConvoRow)
			}
		}
	}
	return c, cmd
}

func (c *CurConvoPane) SetWidth(w int) {
	c.tbl.SetWidth(w)
}

func (c *CurConvoPane) SetHeight(h int) {
	c.tbl.SetHeight(h)
}

func (c CurConvoPane) View() string {

	if len(c.tbl.Columns()) > 0 {

		c.tbl.SetWidth(c.Style.GetWidth())
		widthPaddingOffset :=
		  (curConvoTableStyle.Header.GetPaddingRight() + curConvoTableStyle.Header.GetPaddingLeft()) *
			len(c.tbl.Columns())

		// Calculate the widest width for first column
		for _, r := range c.tbl.Rows() {
			if len(r[0]) > c.tbl.Columns()[0].Width {
				c.tbl.Columns()[0].Width = len(r[0])
			} else if r[0] == "" {
				break
			}
		}

		// Calculate width for remaining columns
		c.tbl.Columns()[1].Width = (c.tbl.Width()-c.tbl.Columns()[0].Width)/2 - widthPaddingOffset
		c.tbl.Columns()[2].Width = c.tbl.Width() - c.tbl.Columns()[0].Width - c.tbl.Columns()[1].Width - widthPaddingOffset
	}

	var content string
	if c.IsSnac && !c.IsPoisoning && !c.IsConfiguringPoisoning {

		//====================================
		// RENDER WITH POISONING CONFIG BUTTON
		//====================================

		c.tbl.SetHeight(c.tbl.Height() + 1)
		s := lipgloss.NewStyle().
			Width(c.Style.GetWidth() / 4).
			AlignHorizontal(lipgloss.Center).
			Background(lipgloss.Color("240"))
		btn := zone.Mark(c.poisonCfgBtnId, s.Render("Configure Poisoning"))
		content = lipgloss.JoinVertical(lipgloss.Center, c.tbl.View(), btn)

	} else {

		content = c.tbl.View()

	}

	return c.Style.Render(content)
}

func (c *CurConvoPane) FocusTable() {
	c.tbl.Focus()
}

func (c *CurConvoPane) SetColumns(columns []table.Column) {
	c.tbl.SetColumns(columns)
}

func (c *CurConvoPane) SetRows(rows []table.Row) {
	c.tbl.SetRows(rows)
}

func (c CurConvoPane) GetContent(db *sql.DB, curConvoRow CurConvoRowDetails) tea.Msg {

	content := CurConvoTableData{
		CurConvoRowDetails: curConvoRow,
	}
	rows, err := db.Query(convoTableSelectionQuery, curConvoRow.SenderIp, curConvoRow.TargetIp)
	if err != nil {
		content.Err = fmt.Errorf("failed to get selected arp row content: %w", err)
		return content
	}

	//=====================================
	// RETRIEVE SENDER AND TARGET IP FIELDS
	//=====================================

	var sender, target *eavesarp_ng.Ip

	for rows.Next() {

		var ip, ipDiscMeth, mac, macDiscMeth, dnsRecordKind, dnsName string
		var ptrResolved bool
		if err = rows.Scan(&ip, &ipDiscMeth, &ptrResolved, &mac, &macDiscMeth, &dnsRecordKind, &dnsName); err != nil {
			content.Err = fmt.Errorf("failed to read row: %w", err)
			return content
		}

		if ip == "" {
			continue
		}

		var ipObj *eavesarp_ng.Ip
		if ip == curConvoRow.SenderIp {

			if sender == nil {

				//======================
				// INITIALIZE THE SENDER
				//======================

				ipObj = &eavesarp_ng.Ip{
					Value: ip,
					Mac: &eavesarp_ng.Mac{
						Value:      mac,
						DiscMethod: eavesarp_ng.DiscMethod(macDiscMeth),
					},
					PtrResolved: ptrResolved,
					DiscMethod:  eavesarp_ng.DiscMethod(ipDiscMeth),
				}
				sender = ipObj

			} else {
				ipObj = sender
			}

		} else if ip == curConvoRow.TargetIp {

			if target == nil {

				//======================
				// INITIALIZE THE TARGET
				//======================

				var m *eavesarp_ng.Mac
				if mac != "" {
					m = &eavesarp_ng.Mac{
						Value:      mac,
						DiscMethod: eavesarp_ng.DiscMethod(macDiscMeth),
					}
				}
				ipObj = &eavesarp_ng.Ip{
					Value:       ip,
					Mac:         m,
					DiscMethod:  eavesarp_ng.DiscMethod(ipDiscMeth),
					PtrResolved: ptrResolved,
				}
				target = ipObj

			} else {
				ipObj = target
			}

		} else {
			continue
		}

		if dnsRecordKind != "" {
			dnsFields := eavesarp_ng.DnsRecordFields{
				Ip:   *ipObj,
				Name: eavesarp_ng.DnsName{Id: 0, IsNew: false, Value: dnsName},
			}
			switch dnsRecordKind {
			case "a":
				target.ARecords = append(target.ARecords, eavesarp_ng.ARecord{DnsRecordFields: dnsFields})
			case "ptr":
				target.PtrRecords = append(target.PtrRecords, eavesarp_ng.PtrRecord{DnsRecordFields: dnsFields})
			default:
				content.Err = fmt.Errorf("unsupported dns record kind: %s", dnsRecordKind)
				return content
			}
		}
	}

	if err = rows.Close(); err != nil {
		content.Err = fmt.Errorf("failed to close Rows after querying for selected arp row content: %w", err)
		return content
	}

	// TODO this should probably be handled more gracefully but it's technically
	//   a fatal error that the user can't influence
	if sender == nil {
		panic("no sender for selected arp row found")
	} else if target == nil {
		panic("no target for selected row found")
	}

	//===================
	// PREPARE TABLE ROWS
	//===================

	tMac := "---"
	if target.Mac != nil {
		tMac = target.Mac.Value
	}
	content.Rows = append(content.Rows,
		table.Row{"IP", sender.Value, target.Value},
		table.Row{"MAC", sender.Mac.Value, tMac})

	// Cells for DNS values
	dnsRows := make([][]string, 2)

	// sender DNS values
	for _, r := range sender.PtrRecords {
		dnsRows[0] = append(dnsRows[0], fmt.Sprintf("%s (%s)", r.Name.Value, "ptr"))
	}
	for _, r := range sender.ARecords {
		dnsRows[0] = append(dnsRows[0], fmt.Sprintf("%s (%s)", r.Name.Value, "a"))
	}

	// target DNS values
	for _, r := range target.PtrRecords {
		dnsRows[1] = append(dnsRows[1], fmt.Sprintf("%s (%s)", r.Name.Value, "ptr"))
	}
	for _, r := range target.ARecords {
		dnsRows[1] = append(dnsRows[1], fmt.Sprintf("%s (%s)", r.Name.Value, "a"))
	}

	longestDnsRow := len(dnsRows[0])
	if len(dnsRows[1]) > longestDnsRow {
		longestDnsRow = len(dnsRows[1])
	}

	for i := 0; i < longestDnsRow; i++ {
		var sender, target, head string
		if i == 0 {
			head = "DNS"
		}
		if len(dnsRows[0]) > 0 && i < len(dnsRows[0]) {
			sender = dnsRows[0][i]
		}
		if len(dnsRows[1]) > 0 && i < len(dnsRows[1]) {
			target = dnsRows[1][i]
		}
		content.Rows = append(content.Rows, table.Row{head, sender, target})
	}

	//===================================
	// RETRIEVE TARGET AITM OPPORTUNITIES
	//===================================

	rows, err = db.Query(snacAitmQuery, sender.Value)
	if err != nil {
		content.Err = fmt.Errorf("failed to query aitm row content for selected arp: %w", err)
		return content
	}

	head := "AITM"
	for rows.Next() {
		var snacIp, upstreamIp, forwardDnsName string
		if err = rows.Scan(&snacIp, &upstreamIp, &forwardDnsName); err != nil {
			content.Err = fmt.Errorf("failed to read aitm row: %w", err)
			return content
		}
		content.Rows = append(content.Rows, table.Row{head, "", fmt.Sprintf("%s (%s)", upstreamIp, forwardDnsName)})
		if head != "" {
			head = ""
		}
	}

	if err = rows.Close(); err != nil {
		content.Err = fmt.Errorf("failed to close Rows after querying aitmValues for selected arp row: %w", err)
		return content
	}

	//=============
	// HANDLE PORTS
	//=============

	//TODO query for ports

	var dbPorts []eavesarp_ng.Port
	for n := 0; n < 100; n++ {
		dbPorts = append(dbPorts, eavesarp_ng.Port{Number: n, Protocol: "sctp"})
		dbPorts = append(dbPorts, eavesarp_ng.Port{Number: n, Protocol: "udp"})
		dbPorts = append(dbPorts, eavesarp_ng.Port{Number: n, Protocol: "tcp"})
	}

	// Example formatting:
	//
	// Ports    tcp/80     udp/86    sctp/443
	//          tcp/443    udp/86    sctp/7
	//          tcp/3389

	portsByProto := make(map[string][]string) // track port strings by protocol
	var longestPortSlice int                  // longest slice of ports
	var maxPortWidth int                      // widest port string in format tcp/443
	var protocols []string                    // observed protocols

	// unpack the ports into a map where the key is the port's protocol
	// while tracking the widest port string width and the longest slice
	for _, port := range dbPorts {
		// get formatted port string, e.g., tcp/80
		s := port.String()
		if len(s) > maxPortWidth {
			// update max port width with this length
			maxPortWidth = len(s)
		}
		if !slices.Contains(protocols, port.Protocol) {
			// capture new protocol
			protocols = append(protocols, port.Protocol)
		}
		portsByProto[port.Protocol] = append(portsByProto[port.Protocol], s)
		if len(portsByProto[port.Protocol]) > longestPortSlice {
			longestPortSlice = len(portsByProto[port.Protocol])
		}
	}

	// Sort protocols by weight
	slices.SortFunc(protocols, func(a, b string) int {
		return protoWeights[a] - protoWeights[b]
	})

	curRow := table.Row{"Ports Seen"}
	for i := 0; i < longestPortSlice; i++ {
		// current port line
		var line string
		protoInd := 1

		for _, proto := range protocols {
			var v string
			if i >= len(portsByProto[proto]) {
				continue
			}
			// retrieve the port value
			v = portsByProto[proto][i]
			if maxPortWidth-len(v) > 0 {
				// pad the value to the right
				v += strings.Repeat(" ", maxPortWidth-len(v))
			}
			if protoInd < len(protocols) {
				// add space between each value
				v += "  "
			}
			line += v
			protoInd++
		}

		// update the current row with the line and final column
		curRow = append(curRow, line, "")

		// capture the row
		buff := make(table.Row, 3)
		copy(buff, curRow)
		content.Rows = append(content.Rows, buff)

		// initialize a new row
		curRow = table.Row{""}
	}

	content.Cols = append(content.Cols,
		table.Column{Title: ""},
		table.Column{Title: "Sender"},
		table.Column{Title: "Target"})

	return content
}
