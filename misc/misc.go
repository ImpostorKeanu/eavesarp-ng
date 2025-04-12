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
	TCPTransport Transport = "tcp"
	UDPTransport Transport = "udp"
)

type (
	// Addr contains information related to a poisoned connection
	// that's being proxied through Eavesarp.
	Addr struct {
		IP        string    `json:"ip,omitempty"`
		Port      string    `json:"port,omitempty"`
		Transport Transport `json:"transport,omitempty"`
	}

	// Transport indicates the transport protocol of the
	// connection. See TCPTransport and UDPTransport.
	Transport string
)

func ConntrackTransportFromProtoNum(i uint8) (t Transport) {
	// determine the protocol of the connection
	// note: only tcp and udp are currently supported
	switch i {
	case TCPProtoNumber:
		t = TCPTransport
	case UDPProtoNumber:
		t = UDPTransport
	}
	return
}

func (a Addr) String() string {
	return net.JoinHostPort(a.IP, a.Port)
}

func (a Addr) Network() string {
	switch a.Transport {
	case UDPTransport:
		return "udp4"
	default:
		return "tcp4"
	}
}

func NewAddr(addr any, transport any) (a Addr, err error) {
	var t Transport
	switch v := transport.(type) {
	case Transport:
		t = v
	case string:
		t = Transport(v)
	default:
		err = errors.New("invalid transport type")
		return
	}

	switch t {
	case TCPTransport, UDPTransport:
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
