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
    arp_count.count DESC
LIMIT ? OFFSET ?`

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
		cols []table.Column
		rows []table.Row
		err  error
	}

	selectedArpTableContent struct {
		cols []table.Column
		rows []table.Row
		err  error
	}
)

func getSelectedArpTableContent(db *sql.DB, m *model) (content selectedArpTableContent) {

	rows, err := db.Query(arpTableSelectionQuery, m.curArpRow.senderIp, m.curArpRow.targetIp)
	if err != nil {
		// TODO
		panic(err)
	}

	//=====================================
	// RETRIEVE SENDER AND TARGET IP FIELDS
	//=====================================

	var sender, target *eavesarp_ng.Ip

	for rows.Next() {

		var ip, ipDiscMeth, mac, macDiscMeth, dnsRecordKind, dnsName string
		var ptrResolved bool
		if err = rows.Scan(&ip, &ipDiscMeth, &ptrResolved, &mac, &macDiscMeth, &dnsRecordKind, &dnsName); err != nil {
			// TODO
			panic(err)
		}

		if ip == "" {
			continue
		}

		var ipObj *eavesarp_ng.Ip
		if ip == m.curArpRow.senderIp {

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

		} else if ip == m.curArpRow.targetIp {

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
			}
		}
	}

	// TODO
	rows.Close()

	// TODO
	if sender == nil {
		panic("no sender for row found")
	} else if target == nil {
		panic("no target for row found")
	}

	//===================================
	// RETRIEVE TARGET AITM OPPORTUNITIES
	//===================================

	var aitmValue string
	rows, err = db.Query(snacAitmQuery, sender.Value)
	for rows.Next() {
		var snacIp, upstreamIp, forwardDnsName string
		if err = rows.Scan(&snacIp, &upstreamIp, &forwardDnsName); err != nil {
			// TODO
			panic("failed to scan row")
		}
		aitmValue += fmt.Sprintf("%s (%s)\n", upstreamIp, forwardDnsName)
	}
	aitmValue = strings.TrimSpace(aitmValue)

	// TODO
	rows.Close()

	//===================
	// PREPARE TABLE ROWS
	//===================

	// Cells for DNS values
	var senderDnsCell, targetDnsCell string

	// sender DNS values
	for _, r := range sender.PtrRecords {
		senderDnsCell += fmt.Sprintf("%s (%s)", r.Name, "ptr")
	}
	for _, r := range sender.ARecords {
		senderDnsCell += fmt.Sprintf("%s (%s)", r.Name, "a")
	}

	// target DNS values
	for _, r := range target.PtrRecords {
		targetDnsCell += fmt.Sprintf("%s (%s)", r.Name, "ptr")
	}
	for _, r := range target.ARecords {
		targetDnsCell += fmt.Sprintf("%s (%s)", r.Name, "a")
	}

	emptyOrDefault(&senderDnsCell, "---")
	emptyOrDefault(&targetDnsCell, "---")
	emptyOrDefault(&aitmValue, "---")

	content.rows = append(content.rows,
		table.Row{"IP", sender.Value, target.Value},
		table.Row{"MAC", sender.Mac.Value, "---"},
		table.Row{"DNS", senderDnsCell, targetDnsCell},
		table.Row{"AITM", "---", aitmValue})

	if target.Mac != nil {
		content.rows[len(content.rows)-1][2] = target.Mac.Value
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

func getArpTableContent(db *sql.DB, limit, offset int) (content arpTableContent) {

	rows, err := db.Query(arpTableQuery, limit, offset)
	if err != nil {
		content.err = err
		return
	}

	// Variables to track information about row content
	// - these are used to format arpTable columns later
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
			content.err = err
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
		if snacsSeen {
			if hasSnac {
				tRow = append(tRow, string(emoji.DirectHit))
			} else {
				tRow = append(tRow, "")
			}
		}

		tRow = append(tRow, sender.Value)
		content.rows = append(content.rows, append(tRow, target.Value, arpCountValue))
	}

	//======================
	// PREPARE TABLE COLUMNS
	//======================

	// Include the snacs column if snacs were seen
	content.cols = append(content.cols, table.Column{"#", 1})
	if snacsSeen {
		content.cols = append(content.cols, table.Column{"", 2})
	}

	// Add remaining arpTable columns
	content.cols = append(content.cols,
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
