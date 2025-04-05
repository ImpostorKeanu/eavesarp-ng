package misc

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
		Addr
		Transport ConntrackTransport `json:"transport,omitempty"`
	}
)
