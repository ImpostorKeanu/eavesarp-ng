package eavesarp_ng

import (
	"context"
	"database/sql"
	_ "embed"
	"time"
)

var (
	//go:embed sql/schema.sql
	SchemaSql string
	//go:embed sql/goc_mac.sql
	gocMacSql string
	//go:embed sql/goc_ip.sql
	gocIpSql string
	//go:embed sql/goc_arp_count.sql
	gocArpCountSql string
	//go:embed sql/goc_ptr.sql
	gocPtrSql string
	//go:embed sql/inc_arp_count.sql
	incArpCountSql string
)

const (
	ArpDiscMethodActive  = MacDiscMethod("active")
	ArpDiscMethodPassive = MacDiscMethod("passive")

	IpDiscMethodPassiveArp = IpDiscMethod("passive_arp")
	IpDiscMethodReverseDns = IpDiscMethod("reverse_dns")
	IpDiscMethodForwardDns = IpDiscMethod("forward_dns")
)

type (
	MacDiscMethod string
	IpDiscMethod  string

	Base struct {
		Id    int
		Value string
	}

	Mac struct {
		*Base
		ArpDiscMethod MacDiscMethod
	}

	IpResolvedValues struct {
		Arp, Ptr bool
	}

	Ip struct {
		*Base
		MacID      int
		DiscMethod IpDiscMethod
		Resolved   IpResolvedValues
	}

	ArpCount struct {
		SenderIpId, TargetIpId int
		Count                  int
	}

	Ptr struct {
		Id, IpId int
		Fqdn     string
	}
)

func GetOrCreate(conn *sql.Conn, stmt string, queryArgs []any, scanDest []any) (err error) {
	// TODO timeout should be configurable
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rows, err := conn.QueryContext(ctx, stmt, queryArgs...)

	if err != nil {
		// TODO
		return
	}

	for rows.Next() {
		if err = rows.Scan(scanDest...); err != nil {
			// TODO
			return
		}
	}
	return
}

func GetOrCreateMac(conn *sql.Conn, v string, arpDiscMethod MacDiscMethod) (mac Mac, err error) {
	mac.Base = &Base{}
	return mac, GetOrCreate(conn, gocMacSql, []any{v, string(arpDiscMethod)},
		[]any{&mac.Id, &mac.Value, &mac.ArpDiscMethod})
}

func GetOrCreateIp(conn *sql.Conn, v string, macId *int, ipDiscMethod IpDiscMethod, arpRes, ptrRes bool) (ip Ip, err error) {
	ip.Base = &Base{}
	return ip, GetOrCreate(conn, gocIpSql,
		[]any{v, macId, ipDiscMethod, arpRes, ptrRes},
		[]any{&ip.Id, &ip.Value, &ip.MacID, &ip.DiscMethod, &ip.Resolved.Arp, &ip.Resolved.Ptr})
}

func GetOrCreateArpCount(conn *sql.Conn, senderIpId, targetIpId int) (aC ArpCount, err error) {
	return aC, GetOrCreate(conn, gocArpCountSql,
		[]any{senderIpId, targetIpId},
		[]any{&aC.SenderIpId, &aC.TargetIpId, &aC.Count})
}

func GetOrCreatePtr(conn *sql.Conn, ipId int, fqdn string) (ptr Ptr, err error) {
	return ptr, GetOrCreate(conn, gocPtrSql,
		[]any{ipId, fqdn},
		[]any{&ptr.Id, &ptr.IpId, &ptr.Fqdn})
}

// IncArpCount increments the count field for a sender and target IP.
func IncArpCount(conn *sql.Conn, senderIpId int, targetIpId int) (count int, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rows, err := conn.QueryContext(ctx, incArpCountSql, senderIpId, targetIpId)
	if err != nil {
		// TODO
		return
	}
	for rows.Next() {
		if err = rows.Scan(&count); err != nil {
			// TODO
			return
		}
	}
	return
}
