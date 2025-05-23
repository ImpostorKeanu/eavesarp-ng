---
tags:
- term
---

>[!WARNING]
>Exploiting a FSNAC is somewhat higher risk, especially when many hosts are attempting to access the offline target in parallel. Because all traffic intended for the SNAC target will be sent to the [[notes/Attacker|attacker]], it may become overwhelmed and experience DOS conditions.

A [[notes/Stale Network Address Configuration|SNAC]] that is resolved by a gateway on a distinct network segment is called a **forwarded SNAC (FSNAC)**. FSNACs can be exploited just like SNACs, except the destination network gateway [[notes/Gateway Poisoning|gateway is poisoned]][^dest-reminder]  to establish AITM positioning on the FSNAC host.

FSNACs are interesting because the host with the SNAC never sends an ARP request for the [[notes/ARP Target|target]]. Since [[notes/Address Resolution Protocol|ARP]] isn't routed, the final hop gateway ARP resolves the target on the destination network. This has two interesting implications that make detection and attribution of FSNACs challenging:

1. Attribution requires the FSNAC's source IP, which can be recovered only from  network layer packets.[^arp-reminder]
2. FSNAC detection and exploitation **must occur on the destination network segment**.

The following diagram roughly illustrates an FSNAC:

![[notes/artifacts/fsnac-diagram.png]]

[^dest-reminder]: FSNACs can be exploited only from the destination network.
[^arp-reminder]: The sender of the ARP request to resolve the target *is the gateway*, so the sender's IP is available only at layer 3.