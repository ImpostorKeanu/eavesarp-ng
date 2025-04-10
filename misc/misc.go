package misc

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
