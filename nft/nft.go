package nft

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/impostorkeanu/eavesarp-ng/misc"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
	"net"
	"strconv"
	"strings"
)

const (
	TablePrefix   = "eavesarp_"   // prefix for all nft tables created by eavesarp
	TableTemplate = "eavesarp_%s" // template used to render the nft table name
	SpoofedIPs    = "spoofed_ips" // name of the set that maintains ip addresses we've spoofed
	AllPorts      = "all_ports"   // name of the set that represents all possible ports for the NAT rule
)

// TableName formats and returns the nft table name.
func TableName(id string) string {
	return fmt.Sprintf(TableTemplate, id)
}

// StaleTables lists potentially stale Eavesarp tables that persist from old runs.
func StaleTables(conn *nftables.Conn, log *zap.Logger) error {
	if tables, err := conn.ListTables(); err != nil {
		return fmt.Errorf("could not list nft tables: %w", err)
	} else {
		for _, t := range tables {
			if strings.HasPrefix(t.Name, TablePrefix) {
				log.Warn("potentially stale pre-existing eavesarp nft table",
					zap.String("table_name", t.Name))
			}
		}
	}
	return nil
}

// CreateTable creates a new nft table that NATs traffic to proxyAddr.
func CreateTable(conn *nftables.Conn, proxyAddr *misc.Addr, tblName string, log *zap.Logger) (eaTbl *nftables.Table, err error) {

	//===================================
	// PREPARE THE PROXY ADDRESS AND PORT
	//===================================

	var proxyPort []byte
	proxyIP := net.ParseIP(proxyAddr.IP).To4()
	if i, err := strconv.ParseUint(proxyAddr.Port, 10, 16); err != nil {
		err = fmt.Errorf("failed to parse proxy server port: %w", err)
		return nil, err
	} else {
		proxyPort = binaryutil.BigEndian.PutUint16(uint16(i))
	}

	//=================
	// CREATE THE TABLE
	//=================

	// get a list of all nftable names
	var nTBLNames []string
	if tables, err := conn.ListTables(); err != nil {
		return eaTbl, fmt.Errorf("could not list nft tables: %w", err)
	} else {
		for _, t := range tables {
			if strings.HasPrefix(t.Name, TablePrefix) {
				log.Warn("potentially stale pre-existing eavesarp nft table",
					zap.String("table_name", t.Name))
			}
			nTBLNames = append(nTBLNames, t.Name)
		}
	}

	// create the table
	eaTbl = &nftables.Table{
		Name:   tblName,
		Use:    0,
		Flags:  0,
		Family: nftables.TableFamilyIPv4,
	}
	conn.CreateTable(eaTbl)
	if err = conn.Flush(); err != nil {
		err = fmt.Errorf("failed to initialize nft: %w", err)
		return
	} else if eaTbl, err = conn.ListTable(eaTbl.Name); err != nil {
		err = fmt.Errorf("failed to load newly created nft: %w", err)
		return
	}

	//======================
	// ADD spoofed_addrs set
	//======================

	// create spoofed set
	addrsSet := &nftables.Set{
		Table:   eaTbl,
		Name:    SpoofedIPs,
		Timeout: 0,
		KeyType: nftables.TypeIPAddr,
	}
	if err = conn.AddSet(addrsSet, nil); err != nil {
		err = fmt.Errorf("failed to add addrs set to nft table: %w", err)
		return
	}
	if err = conn.Flush(); err != nil {
		err = fmt.Errorf("failed to initialize nft: %w", err)
		return
	}

	//==================
	// ADD all_ports SET
	//==================

	// create all_ports set
	portSet := &nftables.Set{
		Table:    eaTbl,
		Name:     AllPorts,
		Interval: true,
		KeyType:  nftables.TypeInetService,
	}
	if err = conn.AddSet(portSet, []nftables.SetElement{{Key: []uint8{0, 0}}}); err != nil {
		err = fmt.Errorf("failed to add port set to nft table: %w", err)
		return
	}
	if err = conn.Flush(); err != nil {
		err = fmt.Errorf("failed to initialize nft: %w", err)
		return
	}

	//===================================
	// ADD AND CONFIGURE prerouting TABLE
	//===================================

	pri := nftables.ChainPriority(-int32(100))
	pol := nftables.ChainPolicyAccept

	// create prerouting chain
	chain := conn.AddChain(&nftables.Chain{
		Name:     "prerouting",
		Table:    eaTbl,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: &pri,
		Type:     nftables.ChainTypeNAT,
		Policy:   &pol,
		Device:   "",
	})

	// create prerouting dnat rule
	conn.AddRule(&nftables.Rule{
		Table:    eaTbl,
		Chain:    chain,
		Position: 0,
		Handle:   0,
		Flags:    0,
		Exprs: []expr.Any{
			&expr.Payload{
				OperationType:  0,
				DestRegister:   1,
				SourceRegister: 0,
				Base:           expr.PayloadBaseNetworkHeader,
				Offset:         16,
				Len:            4,
				CsumType:       expr.CsumTypeNone,
				CsumOffset:     0,
				CsumFlags:      0,
			},
			&expr.Lookup{
				SourceRegister: 1,
				DestRegister:   0,
				IsDestRegSet:   false,
				SetID:          addrsSet.ID,
				SetName:        addrsSet.Name,
				Invert:         false,
			},
			&expr.Payload{
				OperationType:  expr.PayloadLoad,
				DestRegister:   1,
				SourceRegister: 0,
				Base:           expr.PayloadBaseNetworkHeader,
				Offset:         9,
				Len:            1,
				CsumType:       expr.CsumTypeNone,
				CsumOffset:     0,
				CsumFlags:      0,
			},
			&expr.Payload{
				OperationType:  expr.PayloadLoad,
				DestRegister:   1,
				SourceRegister: 0,
				Base:           expr.PayloadBaseTransportHeader,
				Offset:         2,
				Len:            2,
				CsumType:       expr.CsumTypeNone,
				CsumOffset:     0,
				CsumFlags:      0,
			},
			&expr.Lookup{
				SourceRegister: 1,
				DestRegister:   0,
				IsDestRegSet:   false,
				SetID:          portSet.ID,
				SetName:        portSet.Name,
				Invert:         false,
			},
			&expr.Counter{
				Bytes:   0,
				Packets: 0,
			},
			&expr.Immediate{
				Register: 1,
				Data:     proxyIP,
			},
			&expr.Immediate{
				Register: 2,
				Data:     proxyPort,
			},
			&expr.NAT{
				Type:        expr.NATTypeDestNAT,
				Family:      unix.NFPROTO_IPV4,
				RegAddrMin:  1,
				RegAddrMax:  1,
				RegProtoMin: 2,
				RegProtoMax: 2,
				Random:      false,
				FullyRandom: false,
				Persistent:  false,
				Prefix:      false,
				Specified:   true,
			},
		},
		UserData: nil,
	})

	if err = conn.Flush(); err != nil {
		err = fmt.Errorf("failed to initialize nft: %w", err)
		return
	}

	//t, _ := conn.ListTable("eavesarp_bzl4L")
	//c, _ := conn.ListChain(t, "prerouting")
	//oR, _ := conn.GetRules(t, c)
	//nR, _ := conn.GetRules(eaTbl, chain)
	//println(oR, nR)

	return
}

// getSpoofedAddrSetElement retrieves the IP identified by addr from the
// @spoofed_ips nft set.
func getSpoofedAddrSetElement(conn *nftables.Conn, set *nftables.Set, addr net.IP) (*nftables.SetElement, error) {
	if eles, err := conn.GetSetElements(set); err != nil {
		err = fmt.Errorf("failed to load poisoned addr set elements: %w", err)
		return nil, err
	} else {
		for _, e := range eles {
			if bytes.Compare(e.Key, addr) == 0 {
				return &e, nil
			}
		}
	}
	return nil, nil
}

// AddSpoofedIP adds an IP to the @spoofed_ips nft set.
func AddSpoofedIP(conn *nftables.Conn, tbl *nftables.Table, addr net.IP) error {
	if set, err := conn.GetSetByName(tbl, SpoofedIPs); err != nil {
		return err
	} else if set == nil {
		return errors.New("spoofed_ips set is missing")
	} else if e, err := getSpoofedAddrSetElement(conn, set, addr); err != nil {
		return err
	} else if e == nil {
		// add the element to the set
		if err = conn.SetAddElements(set, []nftables.SetElement{{Key: addr.To4()}}); err != nil {
			return err
		} else if err = conn.Flush(); err != nil {
			return err
		}
	}
	return nil
}

// DelSpoofedIP removes an IP from the @spoofed_ips nft set.
func DelSpoofedIP(conn *nftables.Conn, tbl *nftables.Table, addr net.IP) error {
	if set, err := conn.GetSetByName(tbl, SpoofedIPs); err != nil {
		return err
	} else if set == nil {
		return errors.New("spoofed_ips set is missing")
	} else if e, err := getSpoofedAddrSetElement(conn, set, addr); err != nil {
		return err
	} else if e != nil {
		err = conn.SetDeleteElements(set, []nftables.SetElement{{Key: addr.To4()}})
		if err != nil {
			return fmt.Errorf("failed to delete spoofed_ip set elements: %w", err)
		} else if err = conn.Flush(); err != nil {
			return err
		}
	}
	return nil
}

// DelTable deletes the nft table.
func DelTable(conn *nftables.Conn, tbl *nftables.Table) error {
	conn.DelTable(tbl)
	return conn.Flush()
}
