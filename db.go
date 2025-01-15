package eavesarp_ng

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	//go:embed sql/schema.sql
	SchemaSql string
)

const (
	// PassiveArpMeth indicates that an Ip _or_ Mac was discovered passively
	// by monitoring ARP requests. This occurs when a host broadcasts
	// an ARP request containing their MAC address.
	PassiveArpMeth = DiscMethod("passive_arp")
	// ActiveArpMeth indicates that a Mac was discovered by actively
	// generating an ARP request. This occurs when the application
	// broadcasts an ARP request for a target.
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

	AitmOpt struct {
		SnacTargetIpId           int
		UpstreamIpId             int
		SnacTargetIp, UpstreamIp *Ip
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

func (i Ip) IsSnac() bool {
	return i.ArpResolved && i.MacId != nil
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

func GetOrCreateMac(db *sql.DB, v string, arpDiscMethod DiscMethod) (mac Mac, err error) {
	var created bool
	created, err = GetOrCreate(db, GoCArgs{"SELECT * FROM mac WHERE value=?",
		"INSERT INTO mac (value,disc_meth) VALUES (?,?) RETURNING *",
		map[string]any{"value": v, "disc_meth": arpDiscMethod},
		[]string{"value"},
		[]string{"value", "disc_meth"},
		[]any{&mac.Id, &mac.Value, &mac.DiscMethod}})
	mac.IsNew = created
	return
}

func GetOrCreateIp(db *sql.DB, v string, macId *int, ipDiscMethod DiscMethod, arpRes, ptrRes bool) (ip Ip, err error) {
	var created bool
	created, err = GetOrCreate(db, GoCArgs{"SELECT * FROM ip WHERE value=?",
		`INSERT INTO ip (value, mac_id, disc_meth, arp_resolved, ptr_resolved)
VALUES (?, ?, ?, ?, ?) RETURNING *`,
		map[string]any{"value": v, "mac_id": macId, "disc_meth": ipDiscMethod, "arp_resolved": arpRes, "ptr_resolved": ptrRes},
		[]string{"value"},
		[]string{"value", "mac_id", "disc_meth", "arp_resolved", "ptr_resolved"},
		[]any{&ip.Id, &ip.Value, &ip.MacId, &ip.DiscMethod, &ip.ArpResolved, &ip.PtrResolved}})
	ip.IsNew = created
	return
}

func GetOrCreateDnsName(db *sql.DB, name string) (dns DnsName, err error) {
	var created bool
	created, err = GetOrCreate(db, GoCArgs{"SELECT * FROM dns_name WHERE value=?",
		"INSERT INTO dns_name (value) VALUES (?) RETURNING *",
		map[string]any{"value": name}, []string{"value"},
		[]string{"value"},
		[]any{&dns.Id, &dns.Value}})
	dns.IsNew = created
	return
}

func buildDnsQueries(kind string) (getStmt, insStmt string) {
	getStmt = strings.Replace(`
SELECT ip_id, dns_name_id
FROM dns_record
INNER JOIN ip ON ip.id=dns_record.ip_id
INNER JOIN dns_name ON dns_record.dns_name_id=dns_name.id
WHERE ip.id=? AND dns_name.id=? AND kind=RECORD_KIND
LIMIT 1`, "RECORD_KIND", kind, -1)
	insStmt = strings.Replace(`
INSERT INTO dns_record (ip_id, dns_name_id, RECORD_KIND)
VALUES (?,?,?) RETURNING id`, "RECORD_KIND", kind, -1)
	return
}

func GetOrCreateDnsPtrRecord(db *sql.DB, ip Ip, name DnsName) (ptrRec PtrRecord, err error) {
	get, ins := buildDnsQueries("ptr")
	var created bool
	created, err = GetOrCreate(db, GoCArgs{get, ins,
		map[string]any{"ip_id": ip.Id, "dns_name_id": name.Id},
		[]string{"ip_id", "dns_name_id"},
		[]string{"ip_id", "dns_name_id"},
		[]any{&ip.Id, &name.Id}})
	ptrRec.IsNew = created
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
	var created bool
	created, err = GetOrCreate(db, GoCArgs{get, ins,
		map[string]any{"ip_id": ip.Id, "dns_name_id": name.Id},
		[]string{"ip_id", "dns_name_id"},
		[]string{"ip_id", "dns_name_id"},
		[]any{&ip.Id, &name.Id}})
	aRec.IsNew = created
	aRec.Ip = ip
	aRec.Name = name
	return
}

func IncArpCount(db *sql.DB, senderIpId int, targetIpId int) (count int, err error) {
	err = GetRow(db,
		`INSERT INTO arp_count (sender_ip_id, target_ip_id) VALUES (?, ?)
ON CONFLICT DO UPDATE SET count=count+1 RETURNING count`,
		[]any{senderIpId, targetIpId}, &count)
	return
}

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

	// try the get query first
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
	// TODO context time
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return db.QueryRowContext(ctx, stmt, queryArgs...).Scan(scanDest...)
}
