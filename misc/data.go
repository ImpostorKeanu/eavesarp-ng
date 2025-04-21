package misc

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	// VictimDataSender indicates that the AttackData was sent
	// by the victim side of a conversation.
	VictimDataSender DataSender = "victim"
	// DownstreamDataSender indicates that the AttackData was sent
	// by the victim side of a conversation.
	DownstreamDataSender DataSender = "downstream"
)

type (
	// DataSender indicates the address that sent AttackData.
	DataSender string

	// AttackData is extracted from poisoned traffic for logging.
	AttackData struct {
		// Time when the Raw was logged.
		Time time.Time `json:"time"`
		// Sender of the Raw indicates which side of the conversation
		// sent the Raw.
		//
		// See VictimDataSender and DownstreamDataSender.
		Sender DataSender `json:"sender"`
		// VictimAddr is the address of the victim in the poisoning
		// attack.
		VictimAddr VictimAddr `json:"victim_address"`
		// SpoofedAddr is the address set to our MAC address by poisoning
		// the victim's ARP cache.
		SpoofedAddr Addr `json:"spoofed_address"`
		// ProxyAddr is the address of the proxy used to forward
		// traffic to DownstreamAddr during the conversation.
		ProxyAddr Addr `json:"proxy_address"`
		// DownstreamAddr is the address that receives Raw
		// from the VictimAddr via ProxyAddr.
		DownstreamAddr *Addr `json:"downstream_address"`
		// Transport protocol used to send the Raw.
		Transport Transport `json:"transport"`
		// Data is the base64 encoded value of Raw.
		Data string `json:"data"`
		Raw  []byte `json:"-"`
	}

	// VictimAddr is the same as Addr, but has both the source
	// and destination port values.
	//
	// This is critical when logging data that does not have
	// a downstream that would normally reveal the destination
	// port.
	VictimAddr struct {
		IP        string    `json:"ip,omitempty"`
		SrcPort   string    `json:"src_port,omitempty"`
		DstPort   string    `json:"dst_port,omitempty"`
		Transport Transport `json:"transport,omitempty"`
	}
)

func (v VictimAddr) SrcString() string {
	return net.JoinHostPort(v.IP, v.SrcPort)
}

func (v VictimAddr) DstString() string {
	return net.JoinHostPort(v.IP, v.DstPort)
}

// Log JSON marshals the AttackData to log.
//
// If Time is nil, the current time is set to the log record
// before writing it.
//
// If AttackData is empty (""), Raw is base64 encoded and set to
// AttackData before writing.
func (d *AttackData) Log(w io.Writer) (err error) {
	if w == nil {
		err = errors.New("nil log")
		return
	}
	if d.Time.IsZero() {
		d.Time = time.Now()
	}
	if d.Data == "" {
		d.Data = base64.StdEncoding.EncodeToString(d.Raw)
	}
	var b []byte
	if b, err = json.Marshal(d); err != nil {
		err = fmt.Errorf("failed to json marshal data: %w", err)
	}
	b = append(b, '\n')
	if _, err = w.Write(b); err != nil {
		err = fmt.Errorf("failed to write data to log: %w", err)
	}
	return
}

// NewVictimAddr initializes a VictimAddr type and obtains the
// DstPort value from spoofed, which is a mapping of:
//
// map[VICTIM_IP:VICTIM_SRC_PORT]=SPOOFED_IP:DST_PORT
func NewVictimAddr(vIP, vSrcPort string, spoofed *sync.Map, t Transport) (victimA VictimAddr, spoofedA *Addr, err error) {
	victimA = VictimAddr{IP: vIP, SrcPort: vSrcPort, Transport: t}
	if v, ok := spoofed.Load(victimA.SrcString()); !ok {
		err = errors.New("failed to recover dst port from spoofed addresses")
	} else if sA, ok := v.(Addr); !ok {
		err = errors.New("unsupported type returned from spoofmap")
	} else {
		spoofedA = &sA
		victimA.DstPort = sA.Port
	}
	return victimA, spoofedA, nil
}
