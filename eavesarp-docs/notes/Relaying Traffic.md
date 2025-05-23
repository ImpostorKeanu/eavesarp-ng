---
tags:
- concept
---

Upon establishing [[notes/Adversary in the Middle|AITM positioning]], an attacker node must send traffic received from the victim node down to the impersonated node. There are a number of techniques for this, but the two most common are NAT and transparent proxying -- the latter used by Eavesarp-NG.

# Relay via NAT

[Network Address Translation (NAT)][wikipedia-nat] rewrites packets as they flow through the attacker node's kernel such that they're addressed to the impersonated node. This is a simple technique, but SSL/TLS connections generally thwart data capture and manipulation.

# Relay via Transparent Proxy

[Transparent Proxying][imperva-proxy] answers TCP connections from victim nodes, intercepts application data, and establishes a new connection with the impersonated node. It's possible for transparent proxies to detect and terminate SSL/TLS connections by fingerprinting their respective handshakes, allowing the attacker to log and manipulate application data as it flows through the proxy. It should be noted that NAT happens with this technique, but only to divert traffic to the proxy processes.

[wikipedia-nat]: https://en.wikipedia.org/wiki/Network_address_translation
[imperva-proxy]: https://www.imperva.com/learn/ddos/transparent-proxy/
[kernel-tproxy]: https://docs.kernel.org/networking/tproxy.html