package main

import (
	"database/sql"
	"fmt"
	"github.com/charmbracelet/bubbles/table"
	"github.com/enescakir/emoji"
	eavesarp_ng "github.com/impostorkeanu/eavesarp-ng"
	"strings"
)

const (
	// TODO we may need to add a limit & offset to this
	//    unknown how large these queries are going to become
	arpTableQuery = `
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

	arpTableCountQuery = "SELECT COUNT(*) FROM (" + arpTableQuery + ")"

	arpTableSelectionQuery = `
SELECT ip.value AS ip,
       ip.disc_meth AS ip_disc_meth,
       ip.ptr_resolved AS ip_ptr_resolved,
       COALESCE(mac.value, '') AS mac,
       COALESCE(mac.disc_meth, '') AS mac_disc_meth,
       COALESCE(dns_record.kind, '') AS dns_record_kind,
       COALESCE(dns_name.value, '') AS dns_name
FROM ip
LEFT JOIN mac ON mac.id = ip.mac_id
LEFT JOIN dns_record ON dns_record.ip_id = ip.id
LEFT JOIN dns_name ON dns_name.id = dns_record.dns_name_id
WHERE ip.value IN (?,?);
`

	snacAitmQuery = `
SELECT snac_ip.value AS snac_ip, upstream_ip.value AS upstream_ip, dns_name.value AS forward_dns_name
FROM aitm_opt
INNER JOIN ip AS snac_ip ON snac_ip.id = aitm_opt.snac_target_ip_id
INNER JOIN ip AS upstream_ip ON upstream_ip.id = aitm_opt.upstream_ip_id
LEFT JOIN dns_record ON dns_record.ip_id = aitm_opt.upstream_ip_id AND dns_record.kind = 'a'
LEFT JOIN dns_name ON dns_name.id = dns_record.dns_name_id
WHERE aitm_opt.snac_target_ip_id = ?;
`
)

type (
	arpTableContent struct {
		cols       []table.Column
		rows       []table.Row
		rowSenders map[int]string
		err        error
	}

	curConvoTableData struct {
		cols []table.Column
		rows []table.Row
		err  error
	}
)

func getArpTableCount(m *model) (count int, err error) {
	if row := m.db.QueryRow(arpTableCountQuery); row.Err() != nil {
		err = row.Scan(&count)
	} else {
		err = row.Err()
	}
	return
}

func getSelectedArpTableContent(m *model) (content curConvoTableData) {

	rows, err := m.db.Query(arpTableSelectionQuery, m.curConvoRow.senderIp, m.curConvoRow.targetIp)
	if err != nil {
		content.err = fmt.Errorf("failed to get selected arp row content: %w", err)
		return
	}

	//=====================================
	// RETRIEVE SENDER AND TARGET IP FIELDS
	//=====================================

	var sender, target *eavesarp_ng.Ip

	for rows.Next() {

		var ip, ipDiscMeth, mac, macDiscMeth, dnsRecordKind, dnsName string
		var ptrResolved bool
		if err = rows.Scan(&ip, &ipDiscMeth, &ptrResolved, &mac, &macDiscMeth, &dnsRecordKind, &dnsName); err != nil {
			content.err = fmt.Errorf("failed to read row: %w", err)
			return
		}

		if ip == "" {
			continue
		}

		var ipObj *eavesarp_ng.Ip
		if ip == m.curConvoRow.senderIp {

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

		} else if ip == m.curConvoRow.targetIp {

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
				content.err = fmt.Errorf("unsupported dns record kind: %s", dnsRecordKind)
				return
			}
		}
	}

	if err = rows.Close(); err != nil {
		content.err = fmt.Errorf("failed to close rows after querying for selected arp row content: %w", err)
		return
	}

	// TODO this should probably be handled more gracefully but it's technically
	//   a fatal error that the user can't influence
	if sender == nil {
		panic("no sender for selected arp row found")
	} else if target == nil {
		panic("no target for selected row found")
	}

	//===================================
	// RETRIEVE TARGET AITM OPPORTUNITIES
	//===================================

	var aitmValue string
	rows, err = m.db.Query(snacAitmQuery, sender.Value)
	if err != nil {
		content.err = fmt.Errorf("failed to query aitm row content for selected arp: %w", err)
		return
	}

	for rows.Next() {
		var snacIp, upstreamIp, forwardDnsName string
		if err = rows.Scan(&snacIp, &upstreamIp, &forwardDnsName); err != nil {
			content.err = fmt.Errorf("failed to read aitm row: %w", err)
			return
		}
		aitmValue += fmt.Sprintf("%s (%s)\n", upstreamIp, forwardDnsName)
	}
	aitmValue = strings.TrimSpace(aitmValue)

	if err = rows.Close(); err != nil {
		content.err = fmt.Errorf("failed to close rows after querying aitmValue for selected arp row: %w", err)
		return
	}

	//===================
	// PREPARE TABLE ROWS
	//===================

	// Cells for DNS values
	var senderDnsCell, targetDnsCell string

	// sender DNS values
	for _, r := range sender.PtrRecords {
		senderDnsCell += fmt.Sprintf("%s (%s)", r.Name.Value, "ptr")
	}
	for _, r := range sender.ARecords {
		senderDnsCell += fmt.Sprintf("%s (%s)", r.Name.Value, "a")
	}

	// target DNS values
	for _, r := range target.PtrRecords {
		targetDnsCell += fmt.Sprintf("%s (%s)", r.Name.Value, "ptr")
	}
	for _, r := range target.ARecords {
		targetDnsCell += fmt.Sprintf("%s (%s)", r.Name.Value, "a")
	}

	emptyOrDefault(&senderDnsCell, "---")
	emptyOrDefault(&targetDnsCell, "---")
	emptyOrDefault(&aitmValue, "---")

	content.rows = append(content.rows,
		table.Row{"IP", sender.Value, target.Value},
		table.Row{"MAC", sender.Mac.Value, "---"},
		table.Row{"DNS", senderDnsCell, targetDnsCell},
		table.Row{"AITM", "---", aitmValue},
		table.Row{"Ports", "---", "---"})

	if target.Mac != nil {
		content.rows[len(content.rows)-3][2] = target.Mac.Value
	}

	// TODO Why is this math for the sender and target columns so wonky?
	//  Just can't seem to get the table to align correctly! wtf!?
	w := (m.rightWidth - (5 + 6)) / 2
	content.cols = append(content.cols,
		table.Column{Title: "", Width: 5},
		table.Column{Title: "Sender", Width: w},
		table.Column{Title: "Target", Width: w})

	return
}

func getArpTableContent(db *sql.DB) (content arpTableContent) {

	rows, err := db.Query(arpTableQuery)
	if err != nil {
		content.err = fmt.Errorf("failed to query conversations content: %w", err)
		return
	}

	// Variables to track information about row content
	// - these are used to format convosTable columns later
	var senderIpWidth, targetIpWidth int
	var snacsSeen bool
	arpCountHeader := "ARP #"
	arpCountWidth := len(arpCountHeader)

	defer rows.Close()

	for rowInd := 1; rows.Next(); rowInd++ {

		//====================
		// HANDLE DATABASE ROW
		//====================

		// Variables to hold data retrieved from the db
		var sender, target eavesarp_ng.Ip
		var arpCount int
		var hasSnac bool
		//var senderChanged bool

		// Get data from the sql row
		err = rows.Scan(&sender.Id, &sender.Value,
			&target.Id, &target.Value,
			&arpCount, &hasSnac)
		if err != nil {
			content.err = fmt.Errorf("failed to scan conversations row: %w", err)
			return
		}

		// Determine if the SNAC column should be displayed
		if hasSnac && !snacsSeen {
			snacsSeen = true
		}

		arpCountValue := fmt.Sprintf("%d", arpCount)

		//=====================
		// ADJUST WIDTH OFFSETS
		//=====================

		greaterLength(sender.Value, &senderIpWidth)
		greaterLength(target.Value, &targetIpWidth)
		greaterLength(arpCountValue, &arpCountWidth)

		//======================================
		// CONSTRUCT AND CAPTURE THE CURRENT ROW
		//======================================

		tRow := table.Row{fmt.Sprintf("%d", rowInd)}

		// Include the snacs column if they've been seen regardless
		// if the row represents a snac
		//if snacsSeen {
		//	if hasSnac {
		//		tRow = append(tRow, string(emoji.DirectHit))
		//	} else {
		//		tRow = append(tRow, "")
		//	}
		//}

		if hasSnac {
			tRow = append(tRow, string(emoji.DirectHit))
		} else {
			tRow = append(tRow, "")
		}

		tRow = append(tRow, sender.Value)
		content.rows = append(content.rows, append(tRow, target.Value, arpCountValue))
	}

	content.rowSenders = make(map[int]string)
	var lastSender string
	for i, r := range content.rows {
		content.rowSenders[i] = content.rows[i][2]
		if r[2] == lastSender {
			content.rows[i][2] = strings.Repeat(" ", len(lastSender)-1) + "↖"
		} else {
			lastSender = r[2]
		}
	}

	//======================
	// PREPARE TABLE COLUMNS
	//======================

	// Include the snacs column if snacs were seen
	content.cols = append(content.cols,
		table.Column{"#", len(fmt.Sprintf("%d", len(content.rows)))},
		table.Column{"SNAC", 4},
		table.Column{"Sender", senderIpWidth},
		table.Column{"Target", targetIpWidth},
		table.Column{arpCountHeader, arpCountWidth})

	return

}

// greaterLength will split a string on newlines and set i
// to the longest length line so long as it is greater than
// the supplied value.
func greaterLength(s string, i *int) {
	for _, x := range strings.Split(s, "\n") {
		if len(x) > *i {
			*i = len(x)
		}
	}
}

// emptyOrDefault sets the value of s to d if it's currently
// empty.
func emptyOrDefault(s *string, d string) {
	if *s == "" {
		*s = d
	}
}
