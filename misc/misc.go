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
	TCPAddrTransport AddrTransport = "tcp"
	UDPAddrTransport AddrTransport = "udp"
)

type (
	// Addr contains information related to a poisoned connection
	// that's being proxied through Eavesarp.
	Addr struct {
		IP        string        `json:"ip,omitempty"`
		Port      string        `json:"port,omitempty"`
		Transport AddrTransport `json:"transport,omitempty"`
	}

	// AddrTransport indicates the transport protocol of the
	// connection. See TCPAddrTransport and UDPAddrTransport.
	AddrTransport string
)

func ConntrackTransportFromProtoNum(i uint8) (t AddrTransport) {
	// determine the protocol of the connection
	// note: only tcp and udp are currently supported
	switch i {
	case TCPProtoNumber:
		t = TCPAddrTransport
	case UDPProtoNumber:
		t = UDPAddrTransport
	}
	return
}

func (a Addr) String() string {
	return net.JoinHostPort(a.IP, a.Port)
}

func (a Addr) Network() string {
	switch a.Transport {
	case UDPAddrTransport:
		return "udp4"
	default:
		return "tcp4"
	}
}

func NewAddr(addr any, transport any) (a Addr, err error) {
	var t AddrTransport
	switch v := transport.(type) {
	case AddrTransport:
		t = v
	case string:
		t = AddrTransport(v)
	default:
		err = errors.New("invalid transport type")
		return
	}

	switch t {
	case TCPAddrTransport, UDPAddrTransport:
	default:
		err = errors.New("invalid transport value")
		return
	}

	switch addr := addr.(type) {
	case net.Addr:
		a.IP, a.Port, err = net.SplitHostPort(addr.String())
	case Addr:
		a.IP, a.Port = addr.IP, addr.Port
	case string:
		a.IP, a.Port, err = net.SplitHostPort(addr)
	}
	return
}
