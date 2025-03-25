# Problem

Client applications that use TCP as a transport protocol will not send data until
after connection establishment. This means that only the initial SYN request will
be received unless a listener is running to catch the connection.

# Proposed Solution

The destination port of an incoming TCP connection is revealed through packet
sniffing, so we start a TCP listener for a TLS aware TCP proxy on that port,
allowing for connections to be established and sent to a downstream.

## Details

- Listeners send connections through a TLS aware TCP proxy to a downstream service
  - The TCP proxy can dynamically retrieve proxy/downstream addresses and TLS configurations,
    enabling dynamic certificate generation and downstream selection
- Each attack should be able to be configured with a single downstream where
  the proxy will send traffic to
- **Three listener types**:
  - *Static Listeners*: listeners that are running any time a spoofing attack is running
  - *Reactive Listeners*: listeners that are started in response to a detected port
- **Default Service**
    - Always run a TCP listener on localhost that responds with an empty TCP segment after data
      is received from a proxy listener
  - Connections are proxied here when *no downstream is configured for a connection*
- **Default Downstream**
  - Allow configuration of a default downstream host that should receive proxied connections
    when an attack does not have a downstream configured

**Question:** Once started, how long should a reactive listener persist?

- As long as the application is running?
- As long as any spoofing attack is running?
- As long as there is at least one spoofing attack that has seen the listener port?

## Limitations

- Listeners started by other applications will occupy ports, preventing us from
  starting the TCP proxy
- Initial client connection for reactive listeners will fail
  - Client retries _may_ succeed if the TCP proxy is initialized quickly enough

# Implementation

# FAQs

## Why Not NAT?

NAT rules can be used to alter the packet such that it's sent to a listener, but
this approach becomes platform dependent due to inconsistent NAT support across
operating systems.
