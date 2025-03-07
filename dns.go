package eavesarp_ng

import (
	"context"
	"errors"
	"fmt"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"go.uber.org/zap"
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
		ip         *Ip          // ip that was reverse resolved
		name       string       // name obtained through reverse resolution
		srcIfaceIp []byte       // srcIfaceIp address used to send arp requests for new ips
		srcIfaceHw []byte       // srcIfaceHw address used to send arp requests for new ips
		handle     *pcap.Handle // pcap handle used to send arp requests and dns queries
	}
)

// SendDns is a background process that receives DNS resolution
// jobs via dnsSenderC.
func SendDns(cfg Cfg, dA DoDnsCfg) error {

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
		cfg.log.Debug("no dns record found", zap.String("target", dA.Target), zap.String("kind", string(dA.Kind)), zap.Error(err))
		return nil
	} else if ok {
		cfg.log.Error("error while resolving dns", zap.String("target", dA.Target), zap.String("kind", string(dA.Kind)), zap.Error(err))
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
func handlePtrName(cfg Cfg, depth int, args handlePtrNameArgs[DoDnsCfg, ActiveArp]) {

	dnsName, err := GetOrCreateDnsName(cfg.db, args.name)
	if err != nil {
		cfg.log.Error("failed to create dns name", zap.Error(err))
		return
	}

	if _, err = GetOrCreateDnsPtrRecord(cfg.db, *args.ip, dnsName); err != nil {
		cfg.log.Error("failed to create dns ptr record", zap.Error(err))
		return
	}

	// Avoid duplicate forward name resolution
	if !dnsName.IsNew || dnsFailCounter.Exceeded() || cfg.activeDns.Get(FmtDnsKey(args.name, ADnsKind)) != nil {
		return
	}

	cfg.log.Info("doing forward dns resolution", zap.String("name", args.name))

	// Do forward lookups for each newly discovered name
	dArgs := DoDnsCfg{
		Kind:    ADnsKind,
		SenderC: cfg.dnsSenderC,
		Target:  args.name,
		FailureF: func(err error) {
			cfg.activeDns.Delete(FmtDnsKey(args.name, ADnsKind))
		},
		AfterF: func(newIpStrings []string) {
			for _, newIpS := range newIpStrings {

				cfg.log.Info("forward name resolution found ip",
					zap.String("name", args.name), zap.String("ip", newIpS))

				if i := net.ParseIP(newIpS); i == nil || i.To4() == nil {
					continue
				} else {
					newIpS = i.To4().String()
				}
				newIp, err := GetOrCreateIp(cfg.db, newIpS, nil, ForwardDnsMeth,
					false, false)

				if newIp.IsNew || newIp.MacId == nil {
					cfg.log.Info("arp resolving ip discovered via dns", zap.String("ip", newIp.Value))

					// arp resolve newly discovered ip addresses
					//go doArpRequest(db, &newIp, cfg.srcIfaceIp, cfg.srcIfaceHw, net.ParseIP(newIp.Value).To4(),
					//	nil, cfg.handle, cfg.arpSenderC, cfg.activeArp, eWriters)
					go func() {
						cfg.arpSenderC <- SendArpCfg{
							Handle:     args.handle,
							Operation:  layers.ARPRequest,
							SenderIp:   args.srcIfaceIp,
							SenderHw:   args.srcIfaceHw,
							TargetIp:   net.ParseIP(newIp.Value).To4(),
							ReqTarget:  &newIp,
							ReqRetries: maxArpRetries,
						}
					}()
				}

				if err != nil {
					cfg.log.Error("failed to create new ip", zap.Error(err))
					return
				} else if _, err = GetOrCreateDnsARecord(cfg.db, newIp, dnsName); err != nil {
					cfg.log.Error("failed to create dns a record", zap.Error(err))
					return
				}

				// speculate if the host that had the original ip has since
				// moved to the newly discovered one
				if newIpS != args.ip.Value {
					cfg.log.Info("found new potential aitm opportunity",
						zap.String("name", args.name),
						zap.String("targetIp", args.ip.Value),
						zap.String("newIp", newIpS),
						zap.String("reason",
							"recursive name resolution revealed a pointer to an a record "+
							  "that resolves to a new ip address, suggesting dhcp may have issued "+
							  "the target a new ip address"))
					if _, err = GetOrCreateAitmOpt(cfg.db, args.ip.Id, newIp.Id); err != nil {
						cfg.log.Error("failed to create aitm_opt record", zap.Error(err))
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
						if err := SetPtrResolved(cfg.db, *args.ip); err != nil {
							cfg.log.Error("failed to set ptr to resolved: %v", zap.Error(err))
						}
						cfg.activeDns.Delete(FmtDnsKey(newIp.Value, PtrDnsKind))
					},
					AfterF: func(names []string) {
						if err := SetPtrResolved(cfg.db, *args.ip); err != nil {
							cfg.log.Error("failed to set ptr to resolved", zap.Error(err))
							cfg.activeDns.Delete(FmtDnsKey(newIp.Value, PtrDnsKind))
							return
						}
						// call recursively for each friendly name
						cfg.log.Info("recursively resolving newly discovered names", zap.Strings("names", names))
						for _, name := range names {
							depth -= 1
							args.name = name
							handlePtrName(cfg, depth, args)
						}
						cfg.activeDns.Delete(FmtDnsKey(newIp.Value, PtrDnsKind))
					},
				}

				cfg.activeDns.Set(FmtDnsKey(newIp.Value, PtrDnsKind), &dArgs)
				cfg.dnsSenderC <- dArgs

			}

			cfg.activeDns.Delete(FmtDnsKey(args.name, ADnsKind))
		},
	}

	cfg.activeDns.Set(FmtDnsKey(args.name, ADnsKind), &dArgs)
	cfg.dnsSenderC <- dArgs
}
