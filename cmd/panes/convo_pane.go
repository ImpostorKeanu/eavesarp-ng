package panes

import (
	"database/sql"
	"fmt"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/impostorkeanu/eavesarp-ng/cmd/misc"
	"github.com/impostorkeanu/eavesarp-ng/db"
	sniffMisc "github.com/impostorkeanu/eavesarp-ng/sniff"
	zone "github.com/lrstanley/bubblezone"
	"slices"
	"strings"
)

const (
	convoTableSelectionQuery = `
SELECT
  ip.value AS ip,
  ip.id AS ip_id,
  ip.disc_meth AS ip_disc_meth,
  ip.arp_resolved AS ip_arp_resolved,
  ip.ptr_resolved AS ip_ptr_resolved,
  COALESCE(mac.value, '') AS mac,
  COALESCE(mac.disc_meth, '') AS mac_disc_meth,
  COALESCE(dns_record.kind, '') AS dns_record_kind,
  COALESCE(dns_name.value, '') AS dns_name
FROM ip
LEFT JOIN mac
  ON mac.Id = ip.mac_id
LEFT JOIN dns_record
  ON dns_record.ip_id = ip.Id
LEFT JOIN dns_name
  ON dns_name.Id = dns_record.dns_name_id
WHERE ip.value IN (?,?);
`
	attackPortsQuery = `
SELECT DISTINCT port.proto AS protocol,
  port.number AS number FROM attack
INNER JOIN attack_port
  ON attack_port.attack_id = attack.id
INNER JOIN port
  ON port.id = attack_port.port_id
WHERE attack.sender_ip_id = ?
  AND attack.target_ip_id = ?
ORDER BY port.number;
`
	snacAitmQuery = `
SELECT
  snac_ip.value AS snac_ip,
  downstream_ip.value AS downstream_ip,
  dns_name.value AS forward_dns_name
FROM aitm_opt
INNER JOIN ip AS snac_ip
  ON snac_ip.Id = aitm_opt.snac_target_ip_id
INNER JOIN ip AS downstream_ip
  ON downstream_ip.Id = aitm_opt.downstream_ip_id
LEFT JOIN dns_record ON
  dns_record.ip_id = aitm_opt.downstream_ip_id
  AND dns_record.kind = 'a'
LEFT JOIN dns_name
  ON dns_name.Id = dns_record.dns_name_id
WHERE aitm_opt.snac_target_ip_id = ?;
`
)

var (
	curConvoTableStyle table.Styles
	protoWeights       = map[string]int{"tcp": 1, "udp": 2, "sctp": 3}
)

func init() {
	curConvoTableStyle.Header = curConvoTableStyle.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(misc.DeselectedPaneBorderColor).
		BorderBottom(true).
		Bold(true).
		Padding(0, 0, 0, 2).
		Margin(0, 0, 0, 0)
	curConvoTableStyle.Cell = curConvoTableStyle.Cell.
		Padding(0, 0, 0, 2).
		Margin(0, 0, 0, 0)
	curConvoTableStyle.Selected = curConvoTableStyle.Selected.
		Foreground(misc.SelectedRowForegroundColor).
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
		activeAttacks          *misc.ActiveAttacks
		poisonPaneLm           *sniffMisc.ConvoLockMap[PoisonPane]
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
	return sniffMisc.FmtConvoKey(c.SenderIp, c.TargetIp)
}

func (c CurConvoRowDetails) IsZero() bool {
	return c.SenderIp == "" && c.TargetIp == "" && c.ArpCount == 0
}

func NewCurConvoPane(db *sql.DB, zone *zone.Manager, activeAttacks *misc.ActiveAttacks, poisonPaneLm *sniffMisc.ConvoLockMap[PoisonPane], poisonCfgBtnId string) CurConvoPane {
	return CurConvoPane{
		db:             db,
		zone:           zone,
		poisonCfgBtnId: poisonCfgBtnId,
		poisonPaneLm:   poisonPaneLm,
		activeAttacks:  activeAttacks,
		tbl:            table.New(table.WithKeyMap(table.DefaultKeyMap()), table.WithStyles(curConvoTableStyle)),
	}
}

func (c CurConvoPane) Init() tea.Cmd {
	return nil
}

func (c *CurConvoPane) GotoTop() {
	c.tbl.GotoTop()
}

func (c CurConvoPane) Update(msg tea.Msg) (_ CurConvoPane, cmd tea.Cmd) {
	switch msg := msg.(type) {
	case CurConvoRowDetails:
		if err := c.getContent(msg); err != nil {
			// TODO handle this error
		}
		c.IsPoisoning = c.activeAttacks.Exists(msg.ConvoKey())
		c.IsConfiguringPoisoning = !c.IsPoisoning && c.poisonPaneLm.Get(msg.ConvoKey()) != nil
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			if c.tbl.Cursor() == 0 {
				c.tbl.GotoBottom()
			} else {
				c.tbl, cmd = c.tbl.Update(msg)
			}
		case "down", "j":
			if c.tbl.Cursor() == len(c.tbl.Rows())-1 {
				c.tbl.GotoTop()
			} else {
				c.tbl, cmd = c.tbl.Update(msg)
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
			}
		}

		// Calculate width for remaining columns
		c.tbl.Columns()[1].Width = (c.tbl.Width()-c.tbl.Columns()[0].Width)/2 - widthPaddingOffset
		c.tbl.Columns()[2].Width = c.tbl.Width() - c.tbl.Columns()[0].Width - c.tbl.Columns()[1].Width - widthPaddingOffset
	}

	c.tbl.SetHeight(c.tbl.Height() + 1)
	var btn string
	var content string
	if c.IsSnac && !c.IsPoisoning && !c.IsConfiguringPoisoning {

		//====================================
		// RENDER WITH POISONING CONFIG BUTTON
		//====================================

		btnTxt := "Configure Poisoning"
		s := lipgloss.NewStyle().
			Width(len(btnTxt) + 2).
			AlignHorizontal(lipgloss.Center).
			Background(misc.BtnColor).
			Foreground(misc.BtnTextColor)
		btn = zone.Mark(c.poisonCfgBtnId, s.Render(btnTxt))

	}

	content = lipgloss.JoinVertical(lipgloss.Center, c.tbl.View(), btn)

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

func (c *CurConvoPane) getContent(curConvoRow CurConvoRowDetails) (err error) {

	var (
		tblCols = []table.Column{{Title: ""}, {Title: "Sender"}, {Title: "Target"}}
		tblRows []table.Row
		rows    *sql.Rows
	)

	rows, err = c.db.Query(convoTableSelectionQuery, curConvoRow.SenderIp, curConvoRow.TargetIp)
	if err != nil {
		err = fmt.Errorf("failed to get selected arp row content: %w", err)
		return
	}

	//=====================================
	// RETRIEVE SENDER AND TARGET IP FIELDS
	//=====================================

	var sender, target *db.Ip

	for rows.Next() {

		var (
			ip, ipDiscMeth, mac, macDiscMeth, dnsRecordKind, dnsName string
			ipId                                                     int
			arpResolved, ptrResolved                                 bool
		)

		if err = rows.Scan(&ip, &ipId, &ipDiscMeth, &arpResolved, &ptrResolved, &mac, &macDiscMeth, &dnsRecordKind, &dnsName); err != nil {
			err = fmt.Errorf("failed to read row: %w", err)
			return
		}

		if ip == "" {
			continue
		}

		var ipObj *db.Ip
		if ip == curConvoRow.SenderIp {

			if sender == nil {

				//======================
				// INITIALIZE THE SENDER
				//======================

				ipObj = &db.Ip{
					Id:    ipId,
					Value: ip,
					Mac: &db.Mac{
						Value:      mac,
						DiscMethod: db.DiscMethod(macDiscMeth),
					},
					PtrResolved: ptrResolved,
					DiscMethod:  db.DiscMethod(ipDiscMeth),
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

				var m *db.Mac
				if mac != "" {
					m = &db.Mac{
						Value:      mac,
						DiscMethod: db.DiscMethod(macDiscMeth),
					}
				}
				ipObj = &db.Ip{
					Id:          ipId,
					Value:       ip,
					Mac:         m,
					DiscMethod:  db.DiscMethod(ipDiscMeth),
					ArpResolved: arpResolved,
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
			dnsFields := db.DnsRecordFields{
				Ip:   *ipObj,
				Name: db.DnsName{Id: 0, IsNew: false, Value: dnsName},
			}
			switch dnsRecordKind {
			case "a":
				ipObj.ARecords = append(ipObj.ARecords, db.ARecord{DnsRecordFields: dnsFields})
			case "ptr":
				ipObj.PtrRecords = append(ipObj.PtrRecords, db.PtrRecord{DnsRecordFields: dnsFields})
			default:
				err = fmt.Errorf("unsupported dns record kind: %s", dnsRecordKind)
				return
			}
		}
	}

	if err = rows.Close(); err != nil {
		err = fmt.Errorf("failed to close Rows after querying for selected arp row content: %w", err)
		return
	}

	// TODO this should probably be handled more gracefully but it's technically
	//   a fatal error that the user can't influence
	if sender == nil {
		panic("no sender for selected arp row found")
	} else if target == nil {
		panic("no target for selected row found")
	}

	// Manage the MAC address for the target
	tMac := "---"
	if target.Mac != nil {
		tMac = target.Mac.Value
	}

	tblRows = append(tblRows,
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

	// Add DNS records to content
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
		tblRows = append(tblRows, table.Row{head, sender, target})
	}

	//===================================
	// RETRIEVE TARGET AITM OPPORTUNITIES
	//===================================

	rows, err = c.db.Query(snacAitmQuery, sender.Value)
	if err != nil {
		err = fmt.Errorf("failed to query aitm row content for selected arp: %w", err)
		return
	}

	head := "AITM Opts"
	for rows.Next() {
		var snacIp, downstreamIP, forwardDnsName string
		if err = rows.Scan(&snacIp, &downstreamIP, &forwardDnsName); err != nil {
			err = fmt.Errorf("failed to read aitm row: %w", err)
			return
		}
		tblRows = append(tblRows, table.Row{head, "", fmt.Sprintf("%s (%s)", downstreamIP, forwardDnsName)})
		if head != "" {
			head = ""
		}
	}

	if err = rows.Close(); err != nil {
		err = fmt.Errorf("failed to close Rows after querying aitmValues for selected arp row: %w", err)
		return
	}

	//====================
	// QUERY PORTS FROM DB
	//====================

	rows, err = c.db.Query(attackPortsQuery, sender.Id, target.Id)
	if err != nil {
		err = fmt.Errorf("failed to query ports from database: %w", err)
		return
	}

	var dbPorts []db.Port
	for rows.Next() {
		var number int
		var proto string
		if err = rows.Scan(&proto, &number); err != nil {
			err = fmt.Errorf("failed to read database row: %w", err)
			return
		}
		dbPorts = append(dbPorts, db.Port{Number: number, Protocol: proto})
	}

	if err = rows.Close(); err != nil {
		err = fmt.Errorf("failed to close Rows after querying ports from database: %w", err)
		return
	}

	//====================
	// FORMAT PORT RECORDS
	//====================

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
			if i < len(portsByProto[proto]) {
				// retrieve the port value
				v = portsByProto[proto][i]
			}
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
		tblRows = append(tblRows, buff)

		// initialize a new row
		curRow = table.Row{""}
	}

	c.tbl.SetColumns(tblCols)
	c.tbl.SetRows(tblRows)
	c.IsSnac = target.ArpResolved && target.Mac == nil
	return
}
