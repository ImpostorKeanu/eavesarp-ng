---
tags:
- tldr
---

- [[notes/Address Resolution Protocol|Address Resolution Protocol (ARP)]] is a data link layer ([OSI][osi-model-source] L2) protocol.
- ARP enables network communication by resolving IPs (L3) to MACs (L2).
- ARP [[notes/ARP Request|requests]] are _generally_ addressed to all hosts on a network segment (broadcast).
- ARP [[notes/ARP Reply|replies]] are _generally_[^gratuitous-note] addressed to specific hosts on a network segment (unicast).
- ARP requests indicate the start of a [[notes/Conversation|conversation]][^conversation-note].
- ARP is implemented by a host's operating system (OS).
- A host's OS maintains a cache of IP to MAC mappings.
	- Cached non-stale record MACs are used instead of a broadcasting a request.
	- Only replies update the cache.
	- After a lifetime expires, cache records are marked stale.
	- Stale records are resolved by the OS as needed.
- ARP doesn't authenticate replies, allowing for [[notes/ARP Cache Poisoning|cache poisoning]].
- ARP messages aren't routed (unless there's a network oddity).
- When a target is on a distinct network segment, the final hop gateway handles ARP resolution.

[osi-model-source]: https://www.cloudflare.com/learning/ddos/glossary/open-systems-interconnection-model-osi/
[^gratuitous-note]: See Gratuitous ARP.
[^conversation-note]: "conversation" is term a word used by this documentation, not part of the ARP RFC.