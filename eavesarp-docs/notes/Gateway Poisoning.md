---
tags:
- term
---

>[!DANGER]
>Unless targeting an [[notes/Forwarded SNAC|FSNAC]], this is a high risk technique. Should DOS occur, the host side of the conversation will lose network connectivity, which means that all clients on the source network segment will no longer be able to access its services.

In the context of ARP, **gateway poisoning**[^stationx] occurs when an attacker [[notes/ARP Cache Poisoning|poisons the ARP cache]] of a network gateway to spoof the IP of a host. Simultaneously, the host's cache is poisoned such that it believes the attacker is the gateway. If poisoning is successful for both victims -- gateway and host -- the attacker becomes an intermediary hop and relays network traffic accordingly.

>[!IMPORTANT]
>Gateway poisoning captures only the network traffic that crosses the network boundary established by the victim gateway and is addressed to the victim host.

[^stationx]: This resource does a good job of illustrating gateway/host poisoning. https://www.stationx.net/how-to-perform-an-arp-poisoning-attack/