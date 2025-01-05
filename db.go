package eavesarp_ng

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"time"
)

var (
	//go:embed sql/schema.sql
	SchemaSql string
)

const (
	PassiveArpMeth = DiscMethod("passive_arp")
	ActiveArpMeth  = DiscMethod("active_arp")
	ReverseDnsMeth = DiscMethod("reverse_dns")
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

	Ptr struct {
		Id    int
		IsNew bool
		IpId  int
		Fqdn  string
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

func GetOrCreateMac(db *sql.DB, v string, arpDiscMethod DiscMethod) (mac Mac, created bool, err error) {
	created, err = GetOrCreate(db,
		"SELECT * FROM mac WHERE value=?",
		"INSERT INTO mac (value,disc_meth) VALUES (?,?) RETURNING *",
		map[string]any{"value": v, "disc_meth": arpDiscMethod},
		[]string{"value"},
		[]string{"value", "disc_meth"},
		&mac.Id, &mac.Value, &mac.DiscMethod)
	return
}

func GetOrCreateIp(db *sql.DB, v string, macId *int, ipDiscMethod DiscMethod, arpRes, ptrRes bool) (ip Ip, created bool, err error) {
	created, err = GetOrCreate(db,
		"SELECT * FROM ip WHERE value=?",
		`INSERT INTO ip (value, mac_id, disc_meth, arp_resolved, ptr_resolved)
VALUES (?, ?, ?, ?, ?) RETURNING *`,
		map[string]any{"value": v, "mac_id": macId, "disc_meth": ipDiscMethod, "arp_resolved": arpRes, "ptr_resolved": ptrRes},
		[]string{"value"},
		[]string{"value", "mac_id", "disc_meth", "arp_resolved", "ptr_resolved"},
		&ip.Id, &ip.Value, &ip.MacId, &ip.DiscMethod, &ip.ArpResolved, &ip.PtrResolved)
	return
}

//func GetOrCreatePtr(db *sql.Conn, ipId int, fqdn string) (ptr Ptr, err error) {
//	return ptr, GetOrCreate(db, gocPtrSql,
//		[]any{ipId, fqdn},
//		[]any{&ptr.Id, &ptr.IpId, &ptr.Fqdn})
//}

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
