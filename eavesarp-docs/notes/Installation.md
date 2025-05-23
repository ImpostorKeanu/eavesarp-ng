---
tags:
- procedure
---

>[!NOTE] Operating System Support Note
>Eavesarp works only on Linux. Future redesigns may support Windows and Mac.

# Procedure

This procedure will install dependencies and install Eavesarp such that it's in your `$PATH`.

## Step 1. Install Dependencies

Eavesarp requires Netfilter Tables and Conntrack.

This command should install the necessary packages for Debian-based systems:

```bash
sudo apt update && sudo apt install -y nft conntrack
```

## Step 2. Get Eavesarp-NG

Visit the [releases page][releases-url] and copy the URL to the binary file under the desired release, then run these commands:

```bash
# Set the URL here
EAVESARP_URL=""
wget -O /bin/eavesarp-ng "$EAVESARP_URL" && chmod 0777 /bin/eavesarp-ng
```

# See Also

- [[notes/General Usage|General Usage]]

[releases-url]: https://github.com/ImpostorKeanu/eavesarp-ng/releases