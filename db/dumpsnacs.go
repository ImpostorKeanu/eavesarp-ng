package db

import (
	"database/sql"
	"fmt"
)

var (
	// SNACDumpCSVHeader is the header row for CSV files containing
	// SNACDumpRecord values.
	SNACDumpCSVHeader = []string{"sender_ip", "target_ip", "arp_count", "attack_count", "port_count"}
	// SNACDumpQuery is the query used to get all SNAC records
	// from a database.
	SNACDumpQuery = `
SELECT
  sip.value AS sipVal,
  tip.value AS tipVal,
  ac.count AS arpCount,
  COUNT(DISTINCT at.id) AS attackCount,
  COUNT(ap.attack_id) AS attackPortCount
FROM
  ip AS tip
LEFT JOIN arp_count AS ac
  ON ac.target_ip_id=tip.id
LEFT JOIN ip AS sip
  ON sip.id=ac.sender_ip_id
LEFT JOIN attack AS at
  ON at.sender_ip_id=sip.id AND at.target_ip_id=tip.id
LEFT JOIN attack_port AS ap
  ON ap.attack_id=at.id
WHERE
  sip.value IS NOT NULL
  AND tip.arp_resolved=TRUE
  AND tip.mac_id IS NULL
GROUP BY sip.value, tip.value
ORDER BY ac.count DESC;
`
)

// SNACDumpRecord contains basic information related to a SNAC.
type SNACDumpRecord struct {
	SenderIP    string `json:"sender_ip"`    // sender ip of the snac
	TargetIP    string `json:"target_ip"`    // target ip of the snac
	ArpCount    int    `json:"arp_count"`    // count of arp requests observed
	AttackCount int    `json:"attack_count"` // number of aitm attacks performed
	PortCount   int    `json:"port_count"`   // count of ports seen across the attacks
}

func (r SNACDumpRecord) CSVRow() []string {
	return []string{r.SenderIP, r.TargetIP,
		fmt.Sprintf("%d", r.ArpCount),
		fmt.Sprintf("%d", r.AttackCount),
		fmt.Sprintf("%d", r.PortCount)}
}

// DumpSNACs queries db and extracts all SNAC records.
//
// See SNACDumpQuery for the SQL.
func DumpSNACs(db *sql.DB) ([]SNACDumpRecord, error) {
	var snacs []SNACDumpRecord
	rows, err := db.Query(SNACDumpQuery)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var snac SNACDumpRecord
		if err = rows.Scan(&snac.SenderIP, &snac.TargetIP, &snac.ArpCount,
			&snac.AttackCount, &snac.PortCount); err != nil {
			return nil, err
		}
		snacs = append(snacs, snac)
	}
	return snacs, err
}
