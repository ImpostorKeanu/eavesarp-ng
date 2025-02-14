package eavesarp_ng

import (
	"context"
	"database/sql"
	"errors"
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
	activeDns = NewLockMap(make(map[string]*DnsSenderArgs))
	// stopDnsSenderC is used to stop the DnsSender process.
	stopDnsSenderC = make(chan bool)
	// dnsSenderC receives DnsSenderArgs and runs DNS jobs based
	// on their values.
	dnsSenderC = make(chan DnsSenderArgs, 100)
	// dnsResolver allows us to configure a custom context for name
	// resolution, enabling a custom timeout.
	//
	// Note: Further enhancement may need to be applied here in the
	// future. See the following resource for more information:
	// https://pkg.go.dev/net#hdr-Name_Resolution
	dnsResolver = net.Resolver{}
	// unsupportedDnsError is returned when an unsupported DnsRecordKind
	// is supplied to DnsSender via DnsSenderArgs.
	unsupportedDnsError = errors.New("unsupported dns record type")
	dnsFailCounter      *FailCounter
	dnsSleeper          = NewSleeper(1, 4, 30)
)

type (
	// DnsRecordKind is a kind of DNS record.
	DnsRecordKind string
	// DnsSenderArgs has all necessary values to perform a name
	// resolution job.
	//
	// These are passed to DnsSender via dnsSenderC.
	DnsSenderArgs struct {
		kind    DnsRecordKind
		target  string
		failure func(error)
		after   func([]string)
	}
)

// DnsSender is a background process that receives DNS resolution
// jobs via dnsSenderC.
func DnsSender(eWriters *EventWriters) {
	eWriters.Write("starting dns sender routine")
	for {
		dnsSleeper.Sleep()
		select {
		case <-stopDnsSenderC:
			eWriters.Write("stopping dns sender routine")
			break
		case dA := <-dnsSenderC:

			if dnsFailCounter.Exceeded() {
				eWriters.Write("dns failure count exceeded; skipping name resolution")
				continue
			}

			//===================
			// DO NAME RESOLUTION
			//===================

			var err error
			var resolved []string

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			dnsKind := string(dA.kind)
			switch dA.kind {
			case PtrDnsKind:
				resolved, err = dnsResolver.LookupAddr(ctx, dA.target)
			case ADnsKind:
				resolved, err = dnsResolver.LookupHost(ctx, dA.target)
			default:
				err = unsupportedDnsError
			}
			cancel()

			if e, ok := err.(*net.DNSError); ok && e.IsNotFound {
				if dA.failure != nil {
					dA.failure(err)
				}
				eWriters.Writef("no %v record found for %v", dnsKind, dA.target)
				continue
			} else if ok {
				eWriters.Writef("dns failure: %v", e.Error())
				dnsFailCounter.Inc() // Increment the maximum fail counter
			}

			if err != nil {
				eWriters.Writef("error while performing name resolution: %v", err.Error())
				continue
			}

			// Handle the output
			if dA.after != nil {
				dA.after(resolved)
			}

			if dA.failure != nil {
				dA.failure(err)
			}
		}
	}
}

// handlePtrName processes string DNS name values resolved
// via reverse name resolution. It:
//
// - Creates a DnsName for the string in the db
// - Associates the Ip with the DnsName by creating a PtrRecord
// - If the DnsName is new, a forward lookup on the newly discovered DnsName
//   is performed.
// - To a maximum depth of 10, each newly discovered Ip will be subjected
//   to reverse name resolution.
func handlePtrName(db *sql.DB, eWriters *EventWriters, ip *Ip, name string, depth *int) {

	if depth == nil {
		buff := 10
		depth = &buff
	} else if *depth > 10 {
		// TODO log this as an event
		*depth = 10
	}

	dnsName, err := GetOrCreateDnsName(db, name)
	if err != nil {
		eWriters.Writef("failed to create dns name: %v", err.Error())
		return
	}

	if _, err = GetOrCreateDnsPtrRecord(db, *ip, dnsName); err != nil {
		eWriters.Writef("failed to create dns ptr record: %v", err.Error())
		return
	}

	// Avoid duplicate forward name resolution
	if !dnsName.IsNew || dnsFailCounter.Exceeded() || activeDns.Get(FmtDnsKey(name, ADnsKind)) != nil {
		return
	}

	// Do forward lookups for each newly discovered name
	dArgs := DnsSenderArgs{
		kind:   ADnsKind,
		target: name,
		failure: func(err error) {
			activeDns.Delete(FmtDnsKey(name, ADnsKind))
		},
		after: func(newIpStrings []string) {
			for _, newIpS := range newIpStrings {

				newIp, err := GetOrCreateIp(db, newIpS, nil, ForwardDnsMeth,
					false, false)

				if err != nil {
					eWriters.Writef("failed to create new ip: %v", err.Error())
					return
				} else if _, err = GetOrCreateDnsARecord(db, newIp, dnsName); err != nil {
					eWriters.Writef("failed to create dns a record: %v", err.Error())
					return
				}

				// speculate if the host that had the original ip has since
				// moved to the newly discovered one
				if newIpS != ip.Value {
					// TODO this should probably be a GOC function
					if _, err = db.Exec(`INSERT OR IGNORE INTO aitm_opt (snac_target_ip_id, upstream_ip_id) VALUES (?,?)`,
						ip.Id, newIp.Id); err != nil {
						eWriters.Writef("failed to create aitm_opt record: ", err.Error())
						return
					}
				}

				// determine if we should reverse resolve the new ip
				if *depth <= 0 ||
				  newIp.PtrResolved ||
				  activeDns.Get(FmtDnsKey(newIp.Value, PtrDnsKind)) == nil {
					return
				}

				dArgs := DnsSenderArgs{
					kind:   PtrDnsKind,
					target: newIp.Value,
					failure: func(e error) {
						if err := SetPtrResolved(db, *ip); err != nil {
							eWriters.Writef("failed to set ptr to resolved: %v", err.Error())
						}
						activeDns.Delete(FmtDnsKey(newIp.Value, PtrDnsKind))
					},
					after: func(names []string) {
						if err := SetPtrResolved(db, *ip); err != nil {
							eWriters.Writef("failed to set ptr to resolved: %v", err.Error())
							activeDns.Delete(FmtDnsKey(newIp.Value, PtrDnsKind))
							return
						}
						// call recursively for each friendly name
						for _, name := range names {
							d := *depth - 1
							handlePtrName(db, eWriters, &newIp, name, &d)
						}
						activeDns.Delete(FmtDnsKey(newIp.Value, PtrDnsKind))
					},
				}

				activeDns.Set(FmtDnsKey(newIp.Value, PtrDnsKind), &dArgs)
				dnsSenderC <- dArgs

			}

			activeDns.Delete(FmtDnsKey(name, ADnsKind))
		},
	}

	activeDns.Set(FmtDnsKey(name, ADnsKind), &dArgs)
	dnsSenderC <- dArgs
}
