---
tags:
- term
---

An **ARP reply** is emitted in response to an [[notes/ARP Request|ARP request]]. It replies to the request sender with its MAC address. The reply:

- Has the request sender's IP and MAC addresses set as the target values
- Has its IP and MAC address set as the sender values
- As the request contained the sender's ARP and IP address, the reply is addressed to the request sender directly (unicast)