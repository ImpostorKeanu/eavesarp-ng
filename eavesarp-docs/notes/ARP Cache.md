---
tags:
- term
---

To minimize broadcast traffic, operating systems (OS) maintain a mapping of IPs to MACs in what's known as an ARP cache. Each OS manages its ARP cache in accordance with its ARP implementation and configuration, but there are four (4) consistent behaviors generally apply:

1. The OS will update it's cache upon receiving [[notes/ARP Reply|reply]] that corresponds to a [[notes/ARP Request|request]] it sent.
2. Cache records expire after a period of time has passed (known as the **lifetime**).
3. Once a record expires, the OS marks it **stale**, and sends ARP requests for it when needed.
4. **Static entries** (manually configured) do not expire and are not updated dynamically

The table below outlines the typical ARP cache lifetimes by operating system:

|OS|~Lifetime|Source|
|---|---|---|
|Windows|45 sec.|[microsoft.com][microsoft-arp-stale-source]|
|Mac|20 min.|[manpage.me][mac-arp-stale-source]|
|Linux|1 min.|[man7.org][linux-arp-stale-source]|

Depending on the OS and its configuration, the [[notes/Gratuitous ARP|gratuitous ARP]] replies *may* update the cache.

[microsoft-arp-stale-source]: https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/address-resolution-protocol-arp-caching-behavior
[mac-arp-stale-source]: https://manpage.me/index.cgi?q=arp&sektion=4&apropos=0&manpath=FreeBSD+12-CURRENT+and+Ports
[linux-arp-stale-source]: https://man7.org/linux/man-pages/man7/arp.7.html