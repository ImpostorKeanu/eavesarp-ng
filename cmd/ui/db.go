package main

import (
	"fmt"
	"github.com/charmbracelet/bubbles/table"
	eavesarp_ng "github.com/impostorkeanu/eavesarp-ng"
)

const (
	// TODO we may need to add a limit & offset to this
	//    unknown how large these queries are going to become
	convosTableQuery = `
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

	convoTableSelectionQuery = `
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
	convosTableContent struct {
		cols []table.Column
		rows []table.Row
		err  error
	}
)

func getConvosTableContent(m *model) (content convosTableContent) {

	rows, err := m.db.Query(convosTableQuery)
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

		var senderPoisoned string
		if is := activeAttacks.Exists(eavesarp_ng.FmtConvoKey(sender.Value, target.Value)); is {
			senderPoisoned = m.senderPoisonedChar
		}

		// Determine if the SNAC column should be displayed
		if hasSnac && !snacsSeen {
			snacsSeen = true
		}

		arpCountValue := fmt.Sprintf("%d", arpCount)

		//=====================
		// ADJUST WIDTH OFFSETS
		//=====================

		eavesarp_ng.GreaterLength(sender.Value, &senderIpWidth)
		eavesarp_ng.GreaterLength(target.Value, &targetIpWidth)
		eavesarp_ng.GreaterLength(arpCountValue, &arpCountWidth)

		//======================================
		// CONSTRUCT AND CAPTURE THE CURRENT ROW
		//======================================

		tRow := table.Row{fmt.Sprintf("%d", rowInd)}

		if hasSnac {
			tRow = append(tRow, m.snacChar, senderPoisoned)
		} else {
			tRow = append(tRow, "", senderPoisoned)
		}

		tRow = append(tRow, sender.Value)
		content.rows = append(content.rows, append(tRow, target.Value, arpCountValue))
	}

	//======================
	// PREPARE TABLE COLUMNS
	//======================

	// Include the snacs column if snacs were seen
	content.cols = append(content.cols,
		table.Column{"#", len(fmt.Sprintf("%d", len(content.rows)))},
		table.Column{"SNAC", 4},
		table.Column{"Poisoned", 8},
		table.Column{"Sender", senderIpWidth},
		table.Column{"Target", targetIpWidth},
		table.Column{arpCountHeader, arpCountWidth})

	return

}
