Eavesarp-NG is a Go-based tool to detect and exploit Stale Network Address
Configurations (SNACs) via network traffic analysis and ARP poisoning
techniques, designed for security researchers and network administrators.

# Current Features

- Charm TUI
- ARP conversation discovery
- Active SNAC verification
- ARP Cache poisoning for SNAC conversations
- Per-attack PCAPs
- Logging of application data to disk in JSONL format
- Automated DNAT-driven TCP/UDP proxies
- TLS splitting
- Dynamic TLS certificate generation

# Dependencies

Eavesarp uses `nft` and `conntrack` to proxy traffic from poisoned senders.

```bash
apt update && apt install -y nft conntrack
```

# Usage

```bash
./eavesarp start -v debug -i eth0
```

![demo](eavesarp-docs/demo.png)

# Automated Builds

See the [releases](https://github.com/ImpostorKeanu/eavesarp-ng/releases) page
for automated builds.

# Intended Use

Use `eavesarp-ng` only on networks you own or have written permission to analyze.
Unauthorized use may violate laws like the CFAA (US) or local equivalents.

# Disclaimer

`eavesarp-ng` is a security research tool intended for authorized testing and
network analysis by professionals. The author is not responsible for any misuse,
damage, or legal consequences arising from its use. Use responsibly and only
on networks you own or have explicit permission to test.

# Legal Notice

For security research and authorized testing only. The author is not liable for
misuse or damages. Use only with permission on networks you control.