package misc

import (
	"errors"
	"net"
)

// Connection filtering requires protocol numbers.
// Source: https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
const (
	TCPProtoNumber uint8 = 0x06
	UDPProtoNumber uint8 = 0x11
)

const (
	TCPConntrackTransport ConntrackTransport = "tcp"
	UDPConntrackTransport ConntrackTransport = "udp"
)

type (
	Addr struct {
		IP   string `json:"ip,omitempty"`
		Port string `json:"port,omitempty"`
	}

	// ConntrackTransport indicates the transport protocol of the
	// connection. See TCPConntrackTransport and UDPConntrackTransport.
	ConntrackTransport string

	// ConntrackInfo contains information related to a poisoned connection
	// that's being proxied through Eavesarp.
	ConntrackInfo struct {
		Addr      `json:",omitempty"`
		Transport ConntrackTransport `json:"transport,omitempty"`
	}
)

func ConntrackTransportFromProtoNum(i uint8) (t ConntrackTransport) {
	// determine the protocol of the connection
	// note: only tcp and udp are currently supported
	switch i {
	case TCPProtoNumber:
		t = TCPConntrackTransport
	case UDPProtoNumber:
		t = UDPConntrackTransport
	}
	return
}

func (c ConntrackInfo) String() string {
	return net.JoinHostPort(c.Addr.IP, c.Addr.Port)
}

func (c ConntrackInfo) Network() string {
	switch c.Transport {
	case UDPConntrackTransport:
		return "udp4"
	default:
		return "tcp4"
	}
}

func NewConntrackInfo(addr any, transport any) (c ConntrackInfo, err error) {
	var t ConntrackTransport
	switch v := transport.(type) {
	case ConntrackTransport:
		t = v
	case string:
		t = ConntrackTransport(v)
	default:
		err = errors.New("invalid transport type")
		return
	}

	switch t {
	case TCPConntrackTransport, UDPConntrackTransport:
	default:
		err = errors.New("invalid transport value")
		return
	}

	switch addr := addr.(type) {
	case net.Addr:
		c.IP, c.Port, err = net.SplitHostPort(addr.String())
	case Addr:
		c.Addr = addr
	case string:
		c.IP, c.Port, err = net.SplitHostPort(addr)
	}
	return
}
