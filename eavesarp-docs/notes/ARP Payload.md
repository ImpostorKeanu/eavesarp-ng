---
tags:
- term
---

In ARP, Ethernet frames encapsulate the ARP payload containing the IP and MAC addresses of the [[notes/ARP Sender|sender]] and [[notes/ARP Target|target]]. A host's operating system (OS) consumes ARP payloads to maintain an [[notes/ARP Cache|ARP cache]] so that it may dial hosts when it needs to send network traffic.

Per [RFC826](https://datatracker.ietf.org/doc/html/rfc826), an Ethernet frame encapsulating an ARP payload is structured as:

```
Packet format:
--------------

To communicate mappings from <protocol, address> pairs to 48.bit
Ethernet addresses, a packet format that embodies the Address
Resolution protocol is needed.  The format of the packet follows.

    Ethernet transmission layer (not necessarily accessible to
         the user):
        48.bit: Ethernet address of destination
        48.bit: Ethernet address of sender
        16.bit: Protocol type = ether_type$ADDRESS_RESOLUTION
    Ethernet packet data:
        16.bit: (ar$hrd) Hardware address space (e.g., Ethernet,
                         Packet Radio Net.)
        16.bit: (ar$pro) Protocol address space.  For Ethernet
                         hardware, this is from the set of type
                         fields ether_typ$<protocol>.
         8.bit: (ar$hln) byte length of each hardware address
         8.bit: (ar$pln) byte length of each protocol address
        16.bit: (ar$op)  opcode (ares_op$REQUEST | ares_op$REPLY)
        nbytes: (ar$sha) Hardware address of sender of this
                         packet, n from the ar$hln field.
        mbytes: (ar$spa) Protocol address of sender of this
                         packet, m from the ar$pln field.
        nbytes: (ar$tha) Hardware address of target of this
                         packet (if known).
        mbytes: (ar$tpa) Protocol address of target.
```

Example Ethernet frame encapsulating an [[notes/ARP Request|ARP Request]] payload:

![[notes/artifacts/ex-ethernet-frame-arp-req.png]]

Example Ethernet frame encapsulating an [[notes/ARP Reply|ARP Reply]] payload:

![[notes/artifacts/ex-ethernet-frame-arp-rep.png]]