Welcome to the Eavesarp-NG (Eavesarp) documentation.

Penetration testers have been using [Responder][responder-github] to poison conversations for years, just at the application layer. The ultimate purpose of this project is bring similar capabilities to the data link layer by providing a reliable application to target individual [[notes/Conversation|conversations]] with [[notes/ARP Cache Poisoning|ARP cache poisoning]] attacks. 

However, there are currently [[notes/Current Limitations of Eavesarp|some limitations]].

# Features

- Terminal UI
- ARP conversation discovery
- Active SNAC verification
- Cache poisoning for SNAC conversations
- Per-attack PCAPs
- Logging of application data to disk in JSONL format
- Automated DNAT-driven TCP/UDP proxies
- TLS splitting
- Dynamic TLS certificate generation

# Quick Start

1. [[notes/Installation|install Eavesarp]]
2. Start it:

```bash
eavesarp-ng start -v debug -i eth0
```

See [[notes/General Usage|General Usage]] for more information.

# Slow Start

I recommend checking out these notes before getting started. They provide a foundation for understanding what Eavesarp's doing and how to use it.

- [[notes/ARP TLDR|ARP TLDR]] (and/or verbose [[notes/Address Resolution Protocol|Address Resolution Protocol]])
- [[notes/Conversation|Conversation]]
- [[notes/Stale Network Address Configuration|Stale Network Address Configuration]]
- [[notes/Forwarded SNAC|Forwarded SNAC]]

Then check out:

- [[notes/General Usage|General Usage]]
- [[notes/SNAC Lab|SNAC Lab]]

# Labs

- [[notes/SNAC Lab|SNAC Lab]]

[responder-github]: https://github.com/lgandx/Responder