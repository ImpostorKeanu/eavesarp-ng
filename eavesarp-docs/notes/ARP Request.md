---
tags:
- term
---

An **ARP request** is emitted by a host when it needs to obtain the hardware (MAC) address associated with a protocol (IPv4) address. The request:

- Is sent to all hosts in the broadcast domain by setting all bits of the ethernet frame's destination address to 1 (`FF:FF:FF:FF:FF:FF`)
- Has the sender's IP and MAC addresses
- Has the target's IP address, but all bits of the MAC address are set to zero (`00:00:00:00:00:00`)

Targets respond to ARP requests with [[notes/ARP Reply|ARP replies]].