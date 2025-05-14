---
tags:
- concept
---

Eavesarp uses [Netfilter][netfilter] tables to DNAT poisoned traffic to the [[notes/Proxying Traffic|TCP and UDP proxy]] initialized during startup. Inspecting Netfilter tables after starting Eavesarp will reveal a table like the one depicted below.

```bash
nft list ruleset ip
```

![[notes/artifacts/nftrule-example.png]]

For TCP and UDP traffic originating from addresses listed in the `spoofed_ips` set, the `prerouting` chain rewrites the destination address and port such that it's sent to the proper proxy. The `spoofed_ips` set is updated by Eavesarp any time that a poisoning attack starts or ends, i.e., the sender's address is added or removed, respectively.

[netfilter]: https://www.netfilter.org/

```mermaid
flowchart
subgraph sg-sender[SNAC Sender]
	tcp-client(TCP Client)
	arp-cache["ARP Cache Poisoned for 192.168.86.99"]
end

tcp-client ==>|"192.168.86.99:445"| nic

subgraph sg-attacker[Attacker Host]

	poisoned-addr["Spoofed Address:</br>192.168.86.99"]

	nic[/NIC\] ==> kernel(Kernel) -->|Map connection| libpcap(libpcap)
	kernel ===> netfilter(Netfilter DNAT)

	subgraph sg-attack[Attack]
		packet-capture[/"Packet Capture"\]
		downstream(Downstream Address)
	end
	
	connection-map(Connection Map)
	downstream-map(Downstream Map)

	subgraph sg-tcp-proxy["TCP Proxy"]

		proxy-addr["Listen Address:</br>192.168.86.174:5432"]
	
		subgraph sg-lookup[Lookup Conn. Info]
			lookup-downstream(Lookup Downstream) -->
			lookup-orig-port(Lookup Original Port)
		end

	
		accept(Accept) <-->|"Got Downstream</br>192.168.86.4:455"| lookup-downstream
		accept ==> connect(Connect to Downstream</br>on Original Port)
	end

	downstream -->|"Insert</br>192.168.86.4"| downstream-map
	lookup-downstream <-->|"Got</br>192.168.86.4"| downstream-map
	lookup-orig-port <-->|"Got</br>tcp/445"| connection-map
	libpcap --> packet-capture -->|Map original port| connection-map

	netfilter ===>|"DNAT to: 192.168.86.174:4532"| accept
end

subgraph sg-downstream[Downstream]
	downstream-tcp("TCP Server</br>0.0.0.0:445")
	downstream-port["IP Address</br>192.168.86.4"]
end

connect ==>|"Destination:</br>192.168.86.4:445"| downstream-tcp
```