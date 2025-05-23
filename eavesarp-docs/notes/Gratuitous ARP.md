---
tags:
- term
---

>[!QUOTE]
>**Gratuitous ARP** ([RFC 5227](https://tools.ietf.org/html/rfc5227)) could mean both gratuitous ARP _request_ or gratuitous ARP _reply_. Gratuitous in this case means a request/reply that is not normally needed according to the ARP specification ([RFC 826](https://tools.ietf.org/html/rfc826)) but could be used in some cases. A gratuitous ARP request is an [AddressResolutionProtocol](https://wiki.wireshark.org/AddressResolutionProtocol) request packet where the source and destination IP are both set to the IP of the machine issuing the packet and the destination MAC is the broadcast address `ff:ff:ff:ff:ff:ff`. Ordinarily, no reply packet will occur. A gratuitous ARP reply is a reply to which no request has been made.
>
>Source: [Wireshark.org](https://wiki.wireshark.org/Gratuitous_ARP)