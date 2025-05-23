---
tags:
- term
---

>[!TIP]
>See [[notes/ARP TLDR|this file]] for a TL;DR.

>[!QUOTE]
> The **Address Resolution Protocol** (**ARP**) is a [communication protocol](https://en.wikipedia.org/wiki/Communication_protocol "Communication protocol") for discovering the [link layer](https://en.wikipedia.org/wiki/Link_layer "Link layer") address, such as a [MAC address](https://en.wikipedia.org/wiki/MAC_address "MAC address"), associated with a [internet layer](https://en.wikipedia.org/wiki/Internet_layer "Internet layer") address, typically an [IPv4 address](https://en.wikipedia.org/wiki/IPv4_address).
>
> *Source:* [Wikipedia: Address Resolution Protocol](https://en.wikipedia.org/wiki/Address_Resolution_Protocol)

[ARP][arp-rfc] is the link layer protocol ([OSI Model][osi-model-source]) responsible for resolving IP addresses to MAC addresses within IPv4 network segments. It's a request-response protocol implemented in the background by a host's operating system (OS) as processes make system calls to interact with applications over the network.

Encapsulated in Ethernet frames, [[notes/ARP Payload|ARP payloads]] contain IP and MAC values related to a  [[notes/ARP Sender|sender]] and a [[notes/ARP Target|target]]. The sender is always the host that sent a given frame and the target is the intended recipient. An ARP request indicates the beginning of a [[notes/Conversation|conversation]] between an ARP sender and a target.

[[notes/ARP Request|ARP requests]] are broadcast by an OS when a process makes a system call that tries to dial a target. The target assigned that address sends a [[notes/ARP Reply|reply]] with its MAC directly to the sender (unicast). If the target is offline or if the address is unassigned, the sender will receive no reply. The ARP RFC prescribes no method of authenticating replies, allowing [[notes/ARP Cache Poisoning|ARP cache poisoning]].

|ARP Operation|Transmission Type|Intent|
|---|---|---|
|Request|broadcast|Who has this IP?|
|Reply|unicast|Me! Here's my MAC.|

The following images illustrate successful resolution under ideal conditions.

![[eavesarp-blog-example-arp-request.png]]

![[eavesarp-blog-example-arp-reply.png]]

ARP replies are temporarily [[notes/ARP Cache|cached]] by the OS to minimize broadcast traffic. Each OS implements ARP differently and enforces varying lifetimes, but they all mark expired cache records "stale" once the lifetime has expired. ARP requests are sent for stale records as needed. Many OS update their cache when replies are received even without having first sent a request (see [[notes/Gratuitous ARP|Gratuitous ARP]]).[^arp-games-source]

By OS, here's a table outlining the maximum lifetime of a cached ARP record:[^configurable-note]

|OS|~Lifetime|Source|
|---|---|---|
|Windows|45 sec.|[microsoft.com][microsoft-arp-stale-source]|
|Mac|20 min.|[manpage.me][mac-arp-stale-source]|
|Linux|1 min.|[man7.org][linux-arp-stale-source]|

The following flowchart roughly illustrates a simplified example of ARP resolution on Linux where `curl` is trying to send an HTTP request.

![[eavesarp-blog-arp-resolution-flowchart.png]]

[arp-rfc]: https://datatracker.ietf.org/doc/html/rfc826
[osi-model-source]: https://www.cloudflare.com/learning/ddos/glossary/open-systems-interconnection-model-osi/
[microsoft-arp-stale-source]: https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/address-resolution-protocol-arp-caching-behavior
[mac-arp-stale-source]: https://manpage.me/index.cgi?q=arp&sektion=4&apropos=0&manpath=FreeBSD+12-CURRENT+and+Ports
[linux-arp-stale-source]: https://man7.org/linux/man-pages/man7/arp.7.html
[^arp-games-source]: https://insecure.org/sploits/arp.games.html
[^configurable-note]: Lifetimes are configurable and may vary between OS and host.