---
tags:
- term
---

>[!TIP]
>A SNAC that targets an IP address on a distinct network is called a [[notes/Forwarded SNAC|forwarded SNAC]].

A **stale network address configuration (SNAC)** occurs when a process running on the [[notes/ARP Sender|sender]] of an [[notes/Conversation|ARP conversation]] is configured to dial a [[notes/ARP Target|target address]] that fails ARP resolution.  Since an [[notes/ARP Reply|reply]] is never received and [[notes/ARP Cache|cached]] by the sender's operating system, it sends a [[notes/ARP Request|request]] each time its processes attempt communication, which signals to neighboring hosts that it's trying to contact the offline target.

In many cases, the SNAC is applied to a client application that uses a hardcoded credential to authenticate to an unreachable service. A targeted [[notes/ARP Cache Poisoning|ARP cache poisoning attack]] on the sender can [[notes/Poisoned Conversation|poison the conversation]] and capture the credential.

In terms of network DOS, a SNAC is probably the lowest risk [[notes/Adversary in the Middle|AITM]] opportunity. The sender is already experiencing a DOS because the target is non-responsive. Should we choose to [[notes/Relaying Traffic|relay]] traffic to downstream hosts, however, risk increases at the application layer because we have no reliable method of understanding the actions that the sender's processes will perform. It's possible, even likely, that downstream applications or data will be altered.

The following diagram illustrates SNAC behavior where both attacker and sender are on the same network segment:

![[notes/artifacts/eavesarp-blog-snac-example.png]]