---
tags:
- term
---

A broadcast [[notes/ARP Request|ARP request]] indicates that a [[notes/ARP Sender|sender]] and [[notes/ARP Target|target]] are engaged in conversation. This is just a word indicating that one IP (the sender) ARP resolved another (the target). It gives us a "handle" to easily reference the association.

In practice, the operating system (OS) updates the ARP cache only upon receiving an [[notes/ARP Reply|ARP reply]], so the target is _likely_ to initiate its own conversation with the sender.

>[!EXAMPLE]
>
>Given the IPs `x.1` and `x.2`, two distinct conversations are possible:
>
>|Sender||Target|
>|---|---|---|
>|`x.1`|-->|`x.2`|
>|`x.2`|-->|`x.1`|

>[!IMPORTANT]
>
>Conversations indicate that the sender IP has attempted to ARP resolve the target IP.
>
>Conversations ***do not*** indicate the flow of network traffic.

# See Also

- [[notes/Stale Conversation|Stale Conversation]]
- [[notes/Poisoned Conversation|Poisoned Conversation]]