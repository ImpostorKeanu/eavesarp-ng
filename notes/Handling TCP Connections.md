# Problem

Client applications that use TCP as a transport will not send data until after
connection establishment, thus only the initial SYN request will be received
unless a listener is running.

Even when a TCP listener is available to accept the connection request, SSL/TLS
becomes a new challenge.

# Solution

## Netfilter CONNTRACK and Destination NAT (DNAT)

- Registers filtered function
  - Runs upon new connection from victim for target
  - Function updates map with VIC_IP:VIC_PORT=TAR_IP:TAR_PORT
- On connection end (detected by net.Conn); removes map VIC_IP:VIC_PORT

## Standalone TCP Server

standalone tls-aware tcp server handles all connections for attacks
without a downstream configured

## TCP Reverse Proxy

single tls-aware tcp proxy server handles all connections for attacks
with a downstream