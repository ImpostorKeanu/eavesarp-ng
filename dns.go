package eavesarp_ng

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"os"
	"time"
)

func init() {
	dnsFailCounter = NewFailCounter(DnsMaxFailures)
}

const (
	PtrDnsKind     DnsKind = "ptr"
	ADnsKind       DnsKind = "a"
	DnsMaxFailures         = 10
)

var (
	// stopDnsSenderC is used to stop the DnsSender process.
	stopDnsSenderC = make(chan bool)
	// dnsSenderC receives DnsSenderArgs and runs DNS jobs based
	// on their values.
	dnsSenderC = make(chan DnsSenderArgs)
	// dnsResolver allows us to configure a custom context for name
	// resolution, enabling a custom timeout.
	//
	// Note: Further enhancement may need to be applied here in the
	// future. See the following resource for more information:
	// https://pkg.go.dev/net#hdr-Name_Resolution
	dnsResolver = net.Resolver{}
	// unsupportedDnsError is returned when an unsupported DnsKind
	// is supplied to DnsSender via DnsSenderArgs.
	unsupportedDnsError = errors.New("unsupported dns record type")
	dnsFailCounter      *FailCounter
	dnsSleeper          = NewSleeper(1, 4, 30)
)

type (
	// DnsKind is a kind of DNS record.
	DnsKind string
	// DnsSenderArgs has all necessary values to perform a name
	// resolution job.
	//
	// These are passed to DnsSender via dnsSenderC.
	DnsSenderArgs struct {
		kind    DnsKind
		target  string
		failure func(error)
		after   func([]string)
	}
)

// DnsSender is a background process that receives DNS resolution
// jobs via dnsSenderC.
func DnsSender() {
	println("starting dns sender process")
	for {
		dnsSleeper.Sleep()
		select {
		case <-stopDnsSenderC:
			println("stopping dns sender process")
			break
		case dA := <-dnsSenderC:

			if dnsFailCounter.Exceeded() {
				// TODO log dns fail count exceeded event
				println("dns failure count exceeded; skipping name resolution")
				continue
			}

			//===================
			// DO NAME RESOLUTION
			//===================

			var err error
			var resolved []string

			ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
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
				dA.failure(err)
				// TODO log not found
				println("dns record not found:", dA.target)
				continue
			} else if ok {
				// TODO log DNS failure
				print("dns failure:", e.Error())
				// Increment the maximum fail counter
				dnsFailCounter.Inc()
			}

			// TODO handle name resolution error
			if err != nil {
				println("error while performing name resolution", err.Error())
				os.Exit(1)
				continue
			}

			// Handle the output
			dA.after(resolved)
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
func handlePtrName(db *sql.DB, ip *Ip, name string, depth *int) {

	if depth == nil {
		buff := 10
		depth = &buff
	} else if *depth > 10 {
		// TODO log this as an event
		*depth = 10
	}

	dnsName, err := GetOrCreateDnsName(db, name)
	if err != nil {
		// TODO
		println("failed to create dns name", err.Error())
		os.Exit(1)
	}

	if _, err = GetOrCreateDnsPtrRecord(db, *ip, dnsName); err != nil {
		// TODO
		println("failed to create dns ptr record", err.Error())
		os.Exit(1)
	}

	// Avoid duplicate forward name resolution
	if !dnsName.IsNew || dnsFailCounter.Exceeded() {
		return
	}

	// Do forward lookups for each newly discovered name
	dnsSenderC <- DnsSenderArgs{
		kind:   ADnsKind,
		target: name,
		after: func(newIpStrings []string) {
			for _, newIpS := range newIpStrings {

				newIp, err := GetOrCreateIp(db, newIpS, nil, ForwardDnsMeth,
					false, false)

				if err != nil {
					// TODO
					println("failed to create new ip", err.Error())
					os.Exit(1)
				}

				if _, err = GetOrCreateDnsARecord(db, newIp, dnsName); err != nil {
					// TODO
					println("failed to create dns a record", err.Error())
					os.Exit(1)
				}

				if _, err := db.Exec(`INSERT OR IGNORE INTO aitm_opt (snac_target_ip_id, upstream_ip_id) VALUES (?,?)`,
					ip.Id, newIp.Id); err != nil {
					// TODO
					println("failed to create aitm_opt record", err.Error())
					os.Exit(1)
				}

				if *depth > 0 && !newIp.PtrResolved {

					dnsSenderC <- DnsSenderArgs{
						kind:   PtrDnsKind,
						target: newIp.Value,
						failure: func(e error) {
							if err := SetPtrResolved(db, *ip); err != nil {
								// TODO
								println("failed to set ptr to resolved: ", err.Error())
								os.Exit(1)
							}
						},
						after: func(names []string) {
							for _, name := range names {
								d := *depth - 1
								handlePtrName(db, &newIp, name, &d)
							}
						},
					}

				}
			}
		},
	}
}
