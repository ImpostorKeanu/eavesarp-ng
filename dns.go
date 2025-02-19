package eavesarp_ng

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/google/gopacket/pcap"
	"net"
	"time"
)

func init() {
	dnsFailCounter = NewFailCounter(DnsMaxFailures)
}

const (
	PtrDnsKind     DnsRecordKind = "ptr"
	ADnsKind       DnsRecordKind = "a"
	DnsMaxFailures               = 10
)

var (
	// dnsSenderC receives DoDnsCfg and runs DNS jobs based
	// on their values.
	// dnsResolver allows us to configure a custom context for name
	// resolution, enabling a custom timeout.
	//
	// Note: Further enhancement may need to be applied here in the
	// future. See the following resource for more information:
	// https://pkg.go.dev/net#hdr-Name_Resolution
	dnsResolver = net.Resolver{}
	// unsupportedDnsError is returned when an unsupported DnsRecordKind
	// is supplied to SendDns via DoDnsCfg.
	unsupportedDnsError = errors.New("unsupported dns record type")
	dnsFailCounter      *FailCounter
)

type (
	// DnsRecordKind is a Kind of DNS record.
	DnsRecordKind string
	// DoDnsCfg has all necessary values to perform a name
	// resolution job.
	//
	// These are passed to SendDns via dnsSenderC.
	DoDnsCfg struct {
		Kind     DnsRecordKind
		Target   string
		FailureF func(error)
		AfterF   func([]string)
		SenderC  chan DoDnsCfg
	}

	// handlePtrNameArgs is a structure used to document args required
	// for handling reverse resolved names.
	handlePtrNameArgs[DT DoDnsCfg, AT ActiveArp] struct {
		ip         *Ip             // ip that was reverse resolved
		name       string          // name obtained through reverse resolution
		srcIfaceIp []byte          // srcIfaceIp address used to send arp requests for new ips
		srcIfaceHw []byte          // srcIfaceHw address used to send arp requests for new ips
		activeArp  *LockMap[AT]    // track active arp requests
		arpSenderC chan SendArpCfg // channel used to send arp requests
		activeDns  *LockMap[DT]    // track active dns resolutions
		dnsSenderC chan DoDnsCfg   // channel used to send dns queries
		handle     *pcap.Handle    // pcap handle used to send arp requests and dns queries
	}
)

// SendDns is a background process that receives DNS resolution
// jobs via dnsSenderC.
func SendDns(dA DoDnsCfg) error {

	if dnsFailCounter.Exceeded() {
		// TODO log this event
		//eWriters.Write("dns FailureF count exceeded; skipping name resolution")
		return nil
	}

	//===================
	// DO NAME RESOLUTION
	//===================

	var err error
	var resolved []string

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	//dnsKind := string(dA.Kind)
	switch dA.Kind {
	case PtrDnsKind:
		resolved, err = dnsResolver.LookupAddr(ctx, dA.Target)
	case ADnsKind:
		resolved, err = dnsResolver.LookupHost(ctx, dA.Target)
	default:
		err = unsupportedDnsError
	}
	cancel()

	if e, ok := err.(*net.DNSError); ok && e.IsNotFound {
		if dA.FailureF != nil {
			dA.FailureF(err)
		}
		//eWriters.Writef("no %v record found for %v", dnsKind, dA.Target)
		//continue
		return nil
	} else if ok {
		//eWriters.Writef("dns FailureF: %v", e.Error())
		dnsFailCounter.Inc() // Increment the maximum fail counter
		return nil
	}

	if err != nil {
		//eWriters.Writef("error while performing name resolution: %v", err.Error())
		return fmt.Errorf("unhandled dns exception: %w", err)
	}

	// Handle the output
	if dA.AfterF != nil {
		dA.AfterF(resolved)
	}
	if dA.FailureF != nil {
		dA.FailureF(err)
	}

	return nil
}

// handlePtrName processes string DNS name values resolved
// via reverse name resolution. It:
func handlePtrName(db *sql.DB, depth int, cfg handlePtrNameArgs[DoDnsCfg, ActiveArp], eWriters *EventWriters) {

	dnsName, err := GetOrCreateDnsName(db, cfg.name)
	if err != nil {
		eWriters.Writef("failed to create dns name: %v", err.Error())
		return
	}

	if _, err = GetOrCreateDnsPtrRecord(db, *cfg.ip, dnsName); err != nil {
		eWriters.Writef("failed to create dns ptr record: %v", err.Error())
		return
	}

	// Avoid duplicate forward name resolution
	if !dnsName.IsNew || dnsFailCounter.Exceeded() || cfg.activeDns.Get(FmtDnsKey(cfg.name, ADnsKind)) != nil {
		return
	}

	// Do forward lookups for each newly discovered name
	dArgs := DoDnsCfg{
		Kind:    ADnsKind,
		SenderC: cfg.dnsSenderC,
		Target:  cfg.name,
		FailureF: func(err error) {
			cfg.activeDns.Delete(FmtDnsKey(cfg.name, ADnsKind))
		},
		AfterF: func(newIpStrings []string) {
			for _, newIpS := range newIpStrings {

				newIp, err := GetOrCreateIp(db, newIpS, nil, ForwardDnsMeth,
					false, false)

				if newIp.IsNew || newIp.MacId == nil {
					// arp resolve newly discovered ip addresses
					//go doArpRequest(db, &newIp, cfg.srcIfaceIp, cfg.srcIfaceHw, net.ParseIP(newIp.Value).To4(),
					//	nil, cfg.handle, cfg.arpSenderC, cfg.activeArp, eWriters)
					go doArpRequest(db, doArpRequestArgs[ActiveArp]{
						tarIpRecord: &newIp,
						senIp:       cfg.srcIfaceIp,
						senHw:       cfg.srcIfaceHw,
						tarIp:       net.ParseIP(newIp.Value).To4(),
						tarHw:       nil,
						senderC:     cfg.arpSenderC,
						activeArps:  cfg.activeArp,
						handle:      cfg.handle,
					}, eWriters)
				}

				if err != nil {
					eWriters.Writef("failed to create new ip: %v", err.Error())
					return
				} else if _, err = GetOrCreateDnsARecord(db, newIp, dnsName); err != nil {
					eWriters.Writef("failed to create dns a record: %v", err.Error())
					return
				}

				// speculate if the host that had the original ip has since
				// moved to the newly discovered one
				if newIpS != cfg.ip.Value {
					if _, err = GetOrCreateAitmOpt(db, cfg.ip.Id, newIp.Id); err != nil {
						eWriters.Writef("failed to create aitm_opt record: ", err.Error())
						return
					}
				}

				// determine if we should reverse resolve the new ip
				if depth <= 0 ||
				  newIp.PtrResolved ||
				  cfg.activeDns.Get(FmtDnsKey(newIp.Value, PtrDnsKind)) == nil {
					return
				}

				dArgs := DoDnsCfg{
					SenderC: cfg.dnsSenderC,
					Kind:    PtrDnsKind,
					Target:  newIp.Value,
					FailureF: func(e error) {
						if err := SetPtrResolved(db, *cfg.ip); err != nil {
							eWriters.Writef("failed to set ptr to resolved: %v", err.Error())
						}
						cfg.activeDns.Delete(FmtDnsKey(newIp.Value, PtrDnsKind))
					},
					AfterF: func(names []string) {
						if err := SetPtrResolved(db, *cfg.ip); err != nil {
							eWriters.Writef("failed to set ptr to resolved: %v", err.Error())
							cfg.activeDns.Delete(FmtDnsKey(newIp.Value, PtrDnsKind))
							return
						}
						// call recursively for each friendly name
						for _, name := range names {
							depth -= 1
							cfg.name = name
							handlePtrName(db, depth, cfg, eWriters)
						}
						cfg.activeDns.Delete(FmtDnsKey(newIp.Value, PtrDnsKind))
					},
				}

				cfg.activeDns.Set(FmtDnsKey(newIp.Value, PtrDnsKind), &dArgs)
				cfg.dnsSenderC <- dArgs

			}

			cfg.activeDns.Delete(FmtDnsKey(cfg.name, ADnsKind))
		},
	}

	cfg.activeDns.Set(FmtDnsKey(cfg.name, ADnsKind), &dArgs)
	cfg.dnsSenderC <- dArgs
}
