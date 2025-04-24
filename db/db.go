package db

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

var (
	//go:embed schema.sql
	SchemaSQL string
)

// ARP and DNS resolution methods.
const (
	// PassiveArpMeth indicates that an Ip _or_ Mac was discovered passively
	// by monitoring ARP requests. This occurs when a host broadcasts
	// an ARP request containing their MAC address.
	PassiveArpMeth = DiscMethod("passive_arp")
	// ActiveArpMeth indicates that a Mac was discovered by actively
	// generating an ARP request. This occurs when the application
	// broadcasts an ARP request for a Target.
	ActiveArpMeth = DiscMethod("active_arp")
	// ForwardDnsMeth indicates that an Ip was discovered by performing
	// forward name resolution.
	ForwardDnsMeth = DiscMethod("forward_dns")
)

type (
	// DiscMethod indicates how a given Ip was discovered.
	DiscMethod string

	// Mac represents a MAC address.
	Mac struct {
		Id    int
		Value string
		IsNew bool
		// DiscMethod indicates how the Mac was discovered. One of:
		//
		// - PassiveArpMeth (passive_arp)
		// - ActiveArpMeth (active_arp)
		DiscMethod DiscMethod
		Ip         *Ip
	}

	// Ip represents an IPv4 address.
	Ip struct {
		Id    int
		Value string
		IsNew bool
		MacId *int
		// DiscMethod indicates how the Ip was discovered. One of:
		//
		// - PassiveArpMeth (passive_arp)
		// - ActiveArpMeth (active_arp)
		// - ForwardDnsMeth (forward_dns)
		DiscMethod DiscMethod
		// ArpResolved indicates if active ARP resolution has occurred
		// for the Ip.
		//
		// If true _and_ MacId is nil, then there's a high likelihood
		// that hosts attempting to contact this Ip are configured with
		// a SNAC.
		ArpResolved bool
		// PtrResolved indicates if reverse name resolution has been
		// performed for the Ip.
		PtrResolved bool
		Mac         *Mac
		ARecords    []ARecord
		PtrRecords  []PtrRecord
	}

	// ArpCount is the number of times that a sender has been
	// observed to request the MAC address of an IPv4 address.
	ArpCount struct {
		SenderIpId int
		TargetIpId int
		Count      int
	}

	// DnsRecordFields is common values for all DNS record types.
	DnsRecordFields struct {
		Id    int
		IsNew bool
		Ip    Ip
		Name  DnsName
	}

	// DnsName is the string friendly name value of a DNS type.
	DnsName struct {
		Id    int
		IsNew bool
		Value string
	}

	// PtrRecord associates an Ip with a DnsName that was discovered
	// via reverse name resolution.
	PtrRecord struct {
		DnsRecordFields
	}

	// ARecord associates a DnsName with an Ip that was discovered
	// via forward name resolution.
	ARecord struct {
		DnsRecordFields
	}

	// AitmOpt indicates a potential AITM opportunity discovered through
	// DNS resolution, which occurs when a PTR record reveals an A record
	// that resolves to a distinct IP address. This indicates that the host
	// that was once assigned the SNACTargetIP has a new IP address, and
	// the expected service may be available for AITM by NAT techniques.
	AitmOpt struct {
		IsNew                      bool
		SNACTargetIPID             int // Original IP
		DownstreamIPID             int // IP that we should NAT traffic to
		SNACTargetIP, DownstreamIP *Ip
	}

	// Port records indicate ports and protocols observed during poisoning
	// attacks.
	Port struct {
		Id       int
		IsNew    bool
		Number   int
		Protocol string
	}

	// Attack records track ARP poisoning attacks in a conversation.
	Attack struct {
		Id         int
		IsNew      bool
		SenderIpId int
		TargetIpId int
		SenderIp   *Ip
		TargetIp   *Ip
		Ports      []Port
	}

	// AttackPort records track which Port records an Attack has seen.
	AttackPort struct {
		AttackId, PortId int
		IsNew            bool
	}

	// GoCArgs defines arguments for "get or create" functions that manage
	// database records using GetOrCreate.
	GoCArgs struct {
		// GetStmt is the SQL query used to attempt retrieval of the record
		// before creating it. It should return a single row.
		GetStmt string
		// CreateStmt is the SQL query used to create the row if it wasn't
		// retrieved using GetStmt.
		CreateStmt string
		// Params define query parameters available to a SQL queries. These
		// values are referenced by GetParams and CreateParams by supplying
		// keys that are subsequently used to access values.
		Params map[string]any
		// GetParams is a slice of keys mapping back to values in Params,
		// indicating which parameters will be rendered into GetStmt.
		GetParams []string
		// CreateParams is the same as GetParams, but for CreateStmt.
		CreateParams []string
		// Outputs are pointers leading to variables or attributes that will
		// receive outputs from the returned row.
		Outputs []any
	}
)

func (p Port) String() string {
	return fmt.Sprintf("%d/%s", p.Number, p.Protocol)
}

func GetSnacs(db *sql.DB) (ips []Ip, err error) {
	rows, err := db.Query(`SELECT * FROM ip WHERE arp_resolved=TRUE AND ip.mac_id IS NULL`)
	if rows == nil {
		return
	}
	for rows.Next() {
		var ip Ip
		if err = rows.Scan(&ip.Id, &ip.Value, &ip.MacId, &ip.DiscMethod, &ip.ArpResolved, &ip.PtrResolved); err != nil {
			// TODO
			break
		}
		ips = append(ips, ip)
	}
	return
}

func GetOrCreateAitmOpt(db *sql.DB, snacTargetIpId, downstreamIPID int) (opt AitmOpt, err error) {
	opt.IsNew, err = GetOrCreate(db, GoCArgs{
		GetStmt:      "SELECT * FROM aitm_opt WHERE snac_target_ip_id = ? AND downstream_ip_id = ?",
		CreateStmt:   "INSERT INTO aitm_opt (snac_target_ip_id, downstream_ip_id) VALUES (?, ?) RETURNING *",
		Params:       map[string]any{"snac_target_ip_id": snacTargetIpId, "downstream_ip_id": downstreamIPID},
		GetParams:    []string{"snac_target_ip_id", "downstream_ip_id"},
		CreateParams: []string{"snac_target_ip_id", "downstream_ip_id"},
		Outputs:      []any{&opt.SNACTargetIPID, &opt.SNACTargetIPID},
	})
	return
}

func GetOrCreateAttack(db *sql.DB, id *int, senderIpId int, targetIpId int) (attack Attack, err error) {
	// This works because 0 is never used as a row id
	if id == nil {
		buff := 0
		id = &buff
	}
	attack.IsNew, err = GetOrCreate(db, GoCArgs{
		GetStmt:      "SELECT * FROM attack WHERE id=?",
		CreateStmt:   "INSERT INTO attack (sender_ip_id, target_ip_id) VALUES (?, ?) RETURNING *",
		Params:       map[string]any{"id": *id, "sender_ip_id": senderIpId, "target_ip_id": targetIpId},
		GetParams:    []string{"id"},
		CreateParams: []string{"sender_ip_id", "target_ip_id"},
		Outputs:      []any{&attack.Id, &attack.SenderIpId, &attack.TargetIpId},
	})
	return
}

func GetOrCreatePort(db *sql.DB, id *int, number int, proto string) (port Port, err error) {
	if id == nil {
		buff := 0
		id = &buff
	}
	port.IsNew, err = GetOrCreate(db, GoCArgs{
		GetStmt:      "SELECT * FROM port WHERE id=? OR (number=? AND proto=?)",
		CreateStmt:   "INSERT INTO port (number, proto) VALUES (?, ?) RETURNING *",
		Params:       map[string]any{"id": *id, "number": number, "proto": proto},
		GetParams:    []string{"id", "number", "proto"},
		CreateParams: []string{"number", "proto"},
		Outputs:      []any{&port.Id, &port.Number, &port.Protocol},
	})
	return
}

func GetOrCreateAttackPort(db *sql.DB, attackId, portId int) (aP AttackPort, err error) {
	aP.IsNew, err = GetOrCreate(db, GoCArgs{
		GetStmt:      "SELECT attack_id, port_id FROM attack_port WHERE attack_id=? AND port_id=?",
		CreateStmt:   "INSERT INTO attack_port (attack_id, port_id) VALUES (?, ?) RETURNING *",
		Params:       map[string]any{"attack_id": attackId, "port_id": portId},
		GetParams:    []string{"attack_id", "port_id"},
		CreateParams: []string{"attack_id", "port_id"},
		Outputs:      []any{&aP.AttackId, &aP.PortId},
	})
	return
}

func GetOrCreateMac(db *sql.DB, v string, arpDiscMethod DiscMethod) (mac Mac, err error) {
	mac.IsNew, err = GetOrCreate(db, GoCArgs{"SELECT * FROM mac WHERE value=?",
		"INSERT INTO mac (value,disc_meth) VALUES (?,?) RETURNING *",
		map[string]any{"value": v, "disc_meth": arpDiscMethod},
		[]string{"value"},
		[]string{"value", "disc_meth"},
		[]any{&mac.Id, &mac.Value, &mac.DiscMethod}})
	return
}

func GetOrCreateIp(db *sql.DB, v string, macId *int, ipDiscMethod DiscMethod, arpRes, ptrRes bool) (ip Ip, err error) {
	ip.IsNew, err = GetOrCreate(db, GoCArgs{"SELECT * FROM ip WHERE value=?",
		`INSERT INTO ip (value, mac_id, disc_meth, arp_resolved, ptr_resolved)
VALUES (?, ?, ?, ?, ?) RETURNING *`,
		map[string]any{"value": v, "mac_id": macId, "disc_meth": ipDiscMethod, "arp_resolved": arpRes, "ptr_resolved": ptrRes},
		[]string{"value"},
		[]string{"value", "mac_id", "disc_meth", "arp_resolved", "ptr_resolved"},
		[]any{&ip.Id, &ip.Value, &ip.MacId, &ip.DiscMethod, &ip.ArpResolved, &ip.PtrResolved}})
	return
}

func GetOrCreateDnsName(db *sql.DB, name string) (dns DnsName, err error) {
	dns.IsNew, err = GetOrCreate(db, GoCArgs{"SELECT * FROM dns_name WHERE value=?",
		"INSERT INTO dns_name (value) VALUES (?) RETURNING *",
		map[string]any{"value": name}, []string{"value"},
		[]string{"value"},
		[]any{&dns.Id, &dns.Value}})
	return
}

func buildDnsQueries(kind string) (getStmt, insStmt string) {
	getStmt = strings.Replace(`
SELECT ip_id, dns_name_id
FROM dns_record
INNER JOIN ip ON ip.id=dns_record.ip_id
INNER JOIN dns_name ON dns_record.dns_name_id=dns_name.id
WHERE ip.id=? AND dns_name.id=? AND dns_record.Kind="RECORD_KIND"
LIMIT 1`, "RECORD_KIND", kind, -1)
	insStmt = strings.Replace(`
INSERT INTO dns_record (ip_id, dns_name_id, Kind)
VALUES (?,?,"RECORD_KIND") RETURNING ip_id, dns_name_id`, "RECORD_KIND", kind, -1)
	return
}

func GetOrCreateDnsPtrRecord(db *sql.DB, ip Ip, name DnsName) (ptrRec PtrRecord, err error) {
	get, ins := buildDnsQueries("ptr")
	ptrRec.IsNew, err = GetOrCreate(db, GoCArgs{get, ins,
		map[string]any{"ip_id": ip.Id, "dns_name_id": name.Id},
		[]string{"ip_id", "dns_name_id"},
		[]string{"ip_id", "dns_name_id"},
		[]any{&ip.Id, &name.Id}})
	ptrRec.Ip = ip
	ptrRec.Name = name

	err = SetPtrResolved(db, ip)
	return
}

func SetPtrResolved(db *sql.DB, ip Ip) (err error) {
	_, err = db.Exec(`UPDATE OR IGNORE ip SET ptr_resolved=1 WHERE id=?`, ip.Id)
	return
}

func GetOrCreateDnsARecord(db *sql.DB, ip Ip, name DnsName) (aRec ARecord, err error) {
	get, ins := buildDnsQueries("a")
	aRec.IsNew, err = GetOrCreate(db, GoCArgs{get, ins,
		map[string]any{"ip_id": ip.Id, "dns_name_id": name.Id},
		[]string{"ip_id", "dns_name_id"},
		[]string{"ip_id", "dns_name_id"},
		[]any{&ip.Id, &name.Id}})
	aRec.Ip = ip
	aRec.Name = name
	return
}

// IncArpCount increments the arp_count value for the row identified by senderIpId and
// targetIpId by 1.
func IncArpCount(db *sql.DB, senderIpId int, targetIpId int) (count int, err error) {
	err = GetRow(db,
		`INSERT INTO arp_count (sender_ip_id, target_ip_id) VALUES (?, ?)
ON CONFLICT DO UPDATE SET count=count+1 RETURNING count`,
		[]any{senderIpId, targetIpId}, &count)
	return
}

// SetArpResolved updates the Ip database record identified by ipId such that the arp_resolved
// field is true.
func SetArpResolved(db *sql.DB, ipId int) (err error) {
	if _, err = db.Exec(`UPDATE ip SET arp_resolved=1 WHERE id=?`, ipId); err != nil {
		return fmt.Errorf("failed to update arp_resolved attribute: %v", err.Error())
	}
	return
}

// GetOrCreate is used to manage a single database record.
func GetOrCreate(db *sql.DB, args GoCArgs) (created bool, err error) {

	var getValues, createValues []any

	// unpack params for the get query
	for _, name := range args.GetParams {
		if v, ok := args.Params[name]; ok {
			getValues = append(getValues, v)
		} else {
			err = fmt.Errorf("missing get param: %s", name)
			return
		}
	}

	// unpack params for the create query
	for _, name := range args.CreateParams {
		if v, ok := args.Params[name]; ok {
			createValues = append(createValues, v)
		} else {
			err = fmt.Errorf("missing create param: %s", name)
			return
		}
	}

	// reqTry the get query first
	if err = GetRow(db, args.GetStmt, getValues, args.Outputs...); errors.Is(err, sql.ErrNoRows) {
		// looks like it needs to be created
		if err = GetRow(db, args.CreateStmt, createValues, args.Outputs...); err != nil {
			return
		}
		created = true
	}
	return

}

func GetRow(db *sql.DB, stmt string, queryArgs []any, scanDest ...any) error {
	// TODO configurable context time
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return db.QueryRowContext(ctx, stmt, queryArgs...).Scan(scanDest...)
}

// Open the database specified by dsn with read-write access.
func Open(dsn string) (db *sql.DB, created bool, err error) {
	if dsn, err = parseDSN(dsn, false); err != nil {
		return
	}
	return open(dsn)
}

// open opens a database with dsn.
func open(dsn string) (db *sql.DB, created bool, err error) {
	if _, err := os.Stat(strings.Split(dsn, "?")[0]); errors.Is(err, os.ErrNotExist) {
		created = true
	}
	db, err = sql.Open("sqlite", dsn)
	if err != nil {
		return
	}
	db.SetMaxOpenConns(1)
	return
}

// OpenRO opens the database specified by dsn with read-only
// access.
func OpenRO(dsn string) (db *sql.DB, created bool, err error) {
	if dsn, err = parseDSN(dsn, true); err != nil {
		return
	}
	return open(dsn)
}

// parseDSN parses and sets missing connection string values,
// which are supplied via URL-style query string.
//
// - If the query string is omitted, relevant values will be set.
// - Relevant query values already set in the DSN are preserved.
//
// Relevant connection string keys:
//
// - `_foreign_keys`, `_fk` should be `true`.
// - `_journal_mode`, `_journal` should be `WAL`
// - `mode`, which is set to `ro` when readOnly is true AND no
//    value is already set.
//
// See go [go-sqlite readme] for more information.
//
// [go-sqlite readme]: https://github.com/mattn/go-sqlite3?tab=readme-ov-file#connection-string
func parseDSN(dsn string, readOnly bool) (string, error) {

	qSplit := strings.Split(dsn, "?")
	var q url.Values
	var err error
	if len(qSplit) == 1 {
		q = make(url.Values)
	} else {
		q, err = url.ParseQuery(qSplit[1])
		if err != nil {
			return "", fmt.Errorf("failed to parse dsn query string: %s", dsn)
		}
	}

	if !q.Has("_foreign_keys") && !q.Has("_fk") {
		q.Set("_fk", "true")
	}

	if !q.Has("_journal_mode") && !q.Has("_journal") {
		q.Set("_journal", "WAL")
	}

	if readOnly && !q.Has("mode") {
		q.Set("mode", "ro")
	}
	return fmt.Sprintf("%s?%s", dsn, q.Encode()), nil
}
