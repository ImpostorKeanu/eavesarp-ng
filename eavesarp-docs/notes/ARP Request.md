---
tags:
- term
---

An **ARP request** is sent by a [[notes/ARP Sender|sender]] when it needs to obtain the MAC address associated with an IP address. [[notes/ARP Target|Targets]] respond to ARP requests with [[notes/ARP Reply|ARP replies]]. Detection of a ARP requests indicates a [[notes/Conversation|conversation]].

Normally, the request:

- Is sent to all hosts on the network segment by setting all bits of the ethernet frame's destination address (`FF:FF:FF:FF:FF:FF`)
- Has the sender's IP and MAC addresses
- Has the target's IP address, but all bits of the MAC address are set to zero (`00:00:00:00:00:00`)

Additional thoughts on ARP requests:

- The ARP RFC prescribes no method of authenticating replies, allowing [[notes/ARP Cache Poisoning|ARP cache poisoning]].
- When a sender dials a host on a different network segment, the gateway performs ARP on its behalf.