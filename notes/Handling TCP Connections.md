# Problem

Client applications that use TCP as a transport will not send data until after
connection establishment, thus only the initial SYN request will be received
unless a listener is running.

Even when a TCP listener is available to accept the connection request, SSL/TLS
becomes a new challenge.

# Solution: Netfilter Prerouting Hook and Destination NAT (DNAT)

A Netfilter prerouting hook function is used to detect new poisoned connections
and capture the original connection details before a destination NAT (DNAT) rule
is applied to redirect the connection to a TLS-aware TCP proxy. The TCP proxy
references the in-memory connection details set by the hook function and connects
to either the default TCP server or a downstream set by the poisoning attack.

The flow looks roughly like:

```mermaid
flowchart

A(Attacker) -->|Poison ARP Cache| V(Victim)
DS(Downstream)

subgraph sg-AKern[Attacker Kernel]
    subgraph NFT[nftables]
        HookFunc(Hook Function) -->
        DNAT(DNAT)
    end
    eth0(eth0)
end

subgraph sg-AEa[Attacker Eavesarp Process]

    CTL(Ctrl Routine)
    subgraph PR[Proxy Routine]
        portLookup(Lookup Orig. Port) -->
        dsLookup(Lookup Downstream) -->
        dsConnect(Connect to Downstream</br>On Orig. Port)
    end

    DSM(Downstream Map)

    CTL -.->|Manages Netfilter| NFT

    CT(Connection Table)
end

HookFunc -.->|Updates| CT

A -.-> sg-AKern
A -..-> sg-AEa

V -->|Poisoned conn| eth0

eth0 --> NFT
DNAT ---> PR
CTL -.->|Manages</br>Downstreams| DSM

portLookup <-..->|Look up DST port</br>from conntrack| CT
dsLookup <-..->|Look up downstream</br>by src IP| DSM
dsConnect <--> DS
```

## Default TCP Server

standalone tls-aware tcp server handles all connections for attacks
without a downstream configured

## TCP Reverse Proxy

single tls-aware tcp proxy server handles all connections for attacks
with a downstream