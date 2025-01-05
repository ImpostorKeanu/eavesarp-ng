package eavesarp_ng

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

var (
	//go:embed sql/schema.sql
	SchemaSql string
)

const (
	PassiveArpMeth = DiscMethod("passive_arp")
	ActiveArpMeth  = DiscMethod("active_arp")
	ForwardDnsMeth = DiscMethod("forward_dns")
)

type (
	DiscMethod string

	Mac struct {
		Id         int
		Value      string
		IsNew      bool
		DiscMethod DiscMethod
	}

	Ip struct {
		Id          int
		Value       string
		IsNew       bool
		MacId       *int
		DiscMethod  DiscMethod
		ArpResolved bool
		PtrResolved bool
	}

	ArpCount struct {
		SenderIpId int
		TargetIpId int
		Count      int
	}

	DnsRecordFields struct {
		Id    int
		IsNew bool
		Ip    Ip
		Name  DnsName
	}

	DnsName struct {
		Id    int
		IsNew bool
		Value string
	}

	PtrRecord struct {
		DnsRecordFields
	}

	ARecord struct {
		DnsRecordFields
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
	created, err = GetOrCreate(db,
		"SELECT * FROM mac WHERE value=?",
		"INSERT INTO mac (value,disc_meth) VALUES (?,?) RETURNING *",
		map[string]any{"value": v, "disc_meth": arpDiscMethod},
		[]string{"value"},
		[]string{"value", "disc_meth"},
		&mac.Id, &mac.Value, &mac.DiscMethod)
	mac.IsNew = created
	return
}

func GetOrCreateIp(db *sql.DB, v string, macId *int, ipDiscMethod DiscMethod, arpRes, ptrRes bool) (ip Ip, err error) {
	var created bool
	created, err = GetOrCreate(db,
		"SELECT * FROM ip WHERE value=?",
		`INSERT INTO ip (value, mac_id, disc_meth, arp_resolved, ptr_resolved)
VALUES (?, ?, ?, ?, ?) RETURNING *`,
		map[string]any{"value": v, "mac_id": macId, "disc_meth": ipDiscMethod, "arp_resolved": arpRes, "ptr_resolved": ptrRes},
		[]string{"value"},
		[]string{"value", "mac_id", "disc_meth", "arp_resolved", "ptr_resolved"},
		&ip.Id, &ip.Value, &ip.MacId, &ip.DiscMethod, &ip.ArpResolved, &ip.PtrResolved)
	ip.IsNew = created
	return
}

//func GetOrCreatePtr(db *sql.Conn, ipId int, fqdn string) (ptr PtrRecord, err error) {
//	return ptr, GetOrCreate(db, gocPtrSql,
//		[]any{ipId, fqdn},
//		[]any{&ptr.Id, &ptr.IpId, &ptr.Name})
//}

func GetOrCreateDnsName(db *sql.DB, name string) (dns DnsName, err error) {
	var created bool
	created, err = GetOrCreate(db,
		"SELECT * FROM dns_name WHERE value=?",
		"INSERT INTO dns_name (value) VALUES (?) RETURNING *",
		map[string]any{"value": name}, []string{"value"},
		[]string{"value"}, &dns.Id, &dns.Value)
	dns.IsNew = created
	return
}

func buildDnsQueries(tblName string) (getStmt, insStmt string) {
	getStmt = strings.Replace(`
SELECT TBLNAME.id
FROM TBLNAME
INNER JOIN ip ON ip.id=TBLNAME.ip_id
INNER JOIN dns_name ON TBLNAME.dns_name_id=dns_name.id
WHERE ip.id=? AND dns_name.id=?
LIMIT 1`, "TBLNAME", tblName, -1)
	insStmt = strings.Replace(`
INSERT INTO TBLNAME (ip_id, dns_name_id)
VALUES (?,?) RETURNING id`, "TBLNAME", tblName, -1)
	return
}

func GetOrCreateDnsPtrRecord(db *sql.DB, ip Ip, name DnsName) (ptrRec PtrRecord, err error) {
	get, ins := buildDnsQueries("ptr_record")
	var created bool
	created, err = GetOrCreate(db, get, ins,
		map[string]any{"ip_id": ip.Id, "dns_name_id": name.Id},
		[]string{"ip_id", "dns_name_id"},
		[]string{"ip_id", "dns_name_id"},
		&ptrRec.Id)
	ptrRec.IsNew = created
	ptrRec.Ip = ip
	ptrRec.Name = name

	if _, err := db.Exec(`UPDATE OR IGNORE ip SET ptr_resolved=1 WHERE id=?`, ip.Id); err != nil {
		// TODO failed to update ip record
	}
	return
}

func GetOrCreateDnsARecord(db *sql.DB, ip Ip, name DnsName) (aRec ARecord, err error) {
	get, ins := buildDnsQueries("a_record")
	var created bool
	created, err = GetOrCreate(db, get, ins,
		map[string]any{"ip_id": ip.Id, "dns_name_id": name.Id},
		[]string{"ip_id", "dns_name_id"},
		[]string{"ip_id", "dns_name_id"},
		&aRec.Id)
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
		// TODO
		println("failed to update arp_resolved attribute", err.Error())
		os.Exit(1)
	}
	return
}

func GetOrCreate(db *sql.DB, getStmt, createStmt string, params map[string]any, getParams []string,
  createParams []string, outFields ...any) (created bool, err error) {

	var getValues, createValues []any

	// unpack params for the get query
	for _, name := range getParams {
		if v, ok := params[name]; ok {
			getValues = append(getValues, v)
		} else {
			err = fmt.Errorf("missing get param: %s", name)
			return
		}
	}

	// unpack params for the create query
	for _, name := range createParams {
		if v, ok := params[name]; ok {
			createValues = append(createValues, v)
		} else {
			err = fmt.Errorf("missing create param: %s", name)
			return
		}
	}

	// try the get query first
	if err = GetRow(db, getStmt, getValues, outFields...); errors.Is(err, sql.ErrNoRows) {
		// looks like it needs to be created
		if err = GetRow(db, createStmt, createValues, outFields...); err != nil {
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
