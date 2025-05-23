---
tags:
- lab
---

This lab deploys a Docker network with three containers to simulate an exploitable [[notes/Stale Network Address Configuration|SNAC]] that sends `https`, `syslog`, and `smb2` traffic. After completing this lab, you'll have a fundamental understanding of using Eavesarp-NG to poison the ARP cache of SNAC senders and extract actionable data from output files.

# Prerequisites

**Dependencies**

The host supporting the lab must have Docker and Compose installed

**Privileges**

The `NET_ADMIN` capability is required in order to capture network traffic in the attacker container, so the user must have administrative capabilities.

# Docker Compose Environment

There are a total of 3 containers connected to a `172.28.0.0/24` network:

- `server2 (x.2)` - Server running samba
    - We'll [[notes/Relaying Traffic|relay]] traffic to this host.
- `cron (x.3)` - A server that periodically to ARP resolve `x.1`
    - Sends traffic for `smb2`, `syslog`, and `https`.
    - `x.1` will not resolve because it's not bound to any container.
    - This means that `cron` has three SNACs, one for each service.
- `attacker (x.86)` - You work here
    - Runs an SSH server on port `22` (**not exposed to network**)
    - Docker's ptty doesn't play well with Eavesarp's [Charm][charm-source] terminal UI, so we SSH to the container.

>[!NOTE]
>The SSH server running in the `attacker` container **is not** exposed to the network.
>
>Docker does networking magic to make it accessible from the Docker host without having to expose services.

Here's a diagram of the lab network:

![[notes/artifacts/eavesarp-blog-snac-example.png]]

## Flags

Look for the following flags while working through the lab:

- `https` - `9c6b060cdbf3afd146143a3afe8bd5e7`
- `syslog` - `c73facd983aea504fb5bb46c574aefa1`
- `smb2` - NTLMv2 password hash extracted via PCredz is the flag

## Building and Running the Compose Stack

The Compose file can be found [here][compose-source]. It hasn't been tested on Windows or Mac, but replicating the example on Linux should be as simple as:

>[!WARNING]
>The attacker container requires the `NET_ADMIN` capability.

```bash
E_COMPOSE_FILE="https://github.com/ImpostorKeanu/eavesarp-ng/blob/680978e348f2dbdda4ce7abe6dd7dc57e2b466d0/eavesarp-docs/notes/artifacts/compose-snac-lab.yml"
mkdir -p eavesarp-lab && cd eavesarp-lab && \
  wget -O compose.yml "$E_COMPOSE_FILE" && \
  docker compose build && \
  docker compose create && \
  docker compose start
```

## Cleaning Up

Enter the lab directory and run these commands to clean up.

```
docker compose stop
docker compose rm -v
```

# Procedure

>[!TIP]
>To get help while using Eavesarp's UI, strike the `?` key.

## Step 1: Prepare for Attack

SSH to the `attacker` container and run Eavesarp to begin monitoring ARP traffic in the container network.

SSH command:

```bash
ssh root@172.28.0.86
```

Eavesarp command:

```bash
eavesarp-ng start -v debug -i eth0
```

Two conversations will appear in the left pane after approximately one minute. Use the up and down keys to select the `x.2` sender row, revealing DNS names obtained through reverse resolution. The `x.2` host appears to be a server and `x.3` looks to be running something via [cron][cron-source].

![[eavesarp-blog-lab-conversations.png]]


## Step 2: Poison the Sender's ARP Cache

Select the `x.1` sender row. The sigma character in that row indicates that the sender has a SNAC for the target. Eavesarp confirmed this by performing ARP resolution in the background. Note the rapidly increasing integer value in the *ARP #* column, another strong indicator of the sender having one or more SNACs for the target.

![[notes/artifacts/lab-example-snac.png]]

Clicking the *Configure Poisoning* button reveals a form that can be used to configure a poisoning attack for the SNAC sender of the conversation. In this case, the form is configured to save a packet capture file for the attack to `test.pcap` and a downstream (proxy destination; see [[notes/Relaying Traffic|Relaying Traffic]]) for `x.2`. Eavesarp will begin poisoning the ARP cache of the SNAC sender after clicking the *Start* button.

![[notes/artifacts/lab-configuring-poisoning.png]]

The below diagram illustrates what's happening during the poisoning attack.

![[notes/artifacts/eavesarp-blog-graph-poisoning-example.png]]

Eavesarp inspects traffic from `x.3` as it's relayed to `x.2`, allowing it to display observed ports and protocols. This informs us of the potential application layer protocols we may find while analyzing output files. Inspecting `test.pcap` will reveal a number interesting application layer protocols, such as:

- `443/tcp` for `tls`
- `139/tcp` and `445/tcp` for `smb2`
- `514/UDP` for `syslog`

![[notes/artifacts/lab-ongoing-poisoning.png]]

## Step 3: Output Analysis

Strike the `q` key to quit Eavesarp and use `tshark` to dump which protocols appear in the packet capture.

```bash
tshark -r test.pcap 2>/dev/null | awk '{print $6}' | sort -u
```

![[notes/artifacts/lab-protocols-dump.png]]

We can use `jq` to query text-based data from the log file (`eavesarp-data.jsonl`). See the [jq manual][jq-manual] to refine queries to best suit future needs.

```bash
jq 'select(recurse | scalars | tostring | (test("514") or test("443"))) | .data | @base64d' eavesarp-data.jsonl -r | less
```

![[notes/artifacts/lab-capturing-flags.png]]

And finally, [PCredz][pcredz-source] can be used to dump NTLMv2 credentials from the PCAP file since we observed SMB2 traffic via tshark earlier.

```bash
Pcredz -f test.pcap -v
```

![[notes/artifacts/lab-pcredz-dump.png]]

And that's all there is to it. Nice and easy, right?

Don't forget to [[#Cleaning Up|clean up]]!

[cron-source]: https://man7.org/linux/man-pages/man8/cron.8.html
[charm-source]: https://charm.sh/libs/
[jq-manual]: https://jqlang.org/manual/
[pcredz-source]: https://github.com/lgandx/PCredz
[compose-source]: https://github.com/ImpostorKeanu/eavesarp-ng/blob/680978e348f2dbdda4ce7abe6dd7dc57e2b466d0/eavesarp-docs/notes/artifacts/compose-snac-lab.yml