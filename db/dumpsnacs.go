package db

import (
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

var (
	// snacDumpCSVHeader is the header row for CSV files containing
	// SNACDumpRecord values.
	snacDumpCSVHeader = []string{"sender_ip", "target_ip", "arp_count", "attack_count", "port_count"}
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

// CSVRow returns the record as a CSV row.
func (r SNACDumpRecord) CSVRow() []string {
	return []string{r.SenderIP, r.TargetIP,
		fmt.Sprintf("%d", r.ArpCount),
		fmt.Sprintf("%d", r.AttackCount),
		fmt.Sprintf("%d", r.PortCount)}
}

// SNACDumpCSVHeaderS returns the header row for values returned by
// SNACDumpRecord.CSVRow.
func SNACDumpCSVHeaderS() string {
	return strings.Join(snacDumpCSVHeader, ",")
}

// SNACDumpCSVHeader is the same as SNACDumpCSVHeaderS, but returns
// a slice value.
func SNACDumpCSVHeader() []string {
	cp := make([]string, len(snacDumpCSVHeader))
	copy(cp, snacDumpCSVHeader)
	return cp
}

// DumpSNACs queries all SNACs from db and writest them to dst
// in the specified format.
func DumpSNACs(db *sql.DB, dst io.Writer, format string) (int, error) {
	snacs, err := QuerySNACs(db)
	if err != nil {
		return 0, fmt.Errorf("error while querying the database: %w", err)
	}
	snacLen := len(snacs)
	if snacLen == 0 {
		return 0, nil
	}
	return snacLen, WriteSNACs(snacs, dst, format)
}

// QuerySNACs queries db and extracts all SNAC records.
//
// See SNACDumpQuery for the SQL.
func QuerySNACs(db *sql.DB) ([]SNACDumpRecord, error) {
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

// WriteSNACs writes the snacs to dst in the format specified
// by f.
func WriteSNACs(snacs []SNACDumpRecord, dst io.Writer, f string) error {
	switch strings.ToLower(f) {
	case "csv":
		return WriteCSVSnacs(snacs, dst)
	case "jsonl":
		return WriteJSONLSnacs(snacs, dst)
	case "json":
		return WriteJSONSnacs(snacs, dst)
	default:
		return fmt.Errorf("unsupported output format (%s); supported formats: csv, json, jsonl", f)
	}
}

// WriteCSVSnacs writes snacs to dst in CSV format.
func WriteCSVSnacs(snacs []SNACDumpRecord, dst io.Writer) (err error) {
	w := csv.NewWriter(dst)
	if err = w.Write(SNACDumpCSVHeader()); err != nil {
		return
	}
	for _, snac := range snacs {
		if err = w.Write(snac.CSVRow()); err != nil {
			return
		}
	}
	w.Flush()
	return
}

// WriteJSONSnacs writes snacs to dst in JSON format.
func WriteJSONSnacs(snacs []SNACDumpRecord, dst io.Writer) error {
	output, err := json.Marshal(snacs)
	if err != nil {
		return err
	}
	_, err = dst.Write(output)
	return err
}

// WriteJSONLSnacs writes snacs to dst in JSONL format.
func WriteJSONLSnacs(snacs []SNACDumpRecord, dst io.Writer) error {
	for _, snac := range snacs {
		output, err := json.Marshal(snac)
		if err != nil {
			return err
		} else if _, err = fmt.Fprint(dst, string(output)+"\n"); err != nil {
			return err
		}
	}
	return nil
}
