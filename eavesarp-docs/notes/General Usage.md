---
tags:
- concept
---

>[!WARNING]
>Examples here are currently prone to rot.
>
>If something's off, please submit a PR with updated content or an issue to notify me.

# Getting Help

Pass the `--help` flag to Eavesarp to learn about subcommands and their flags. *Not all subcommands are documented here.*

# Starting Eavesarp

This command will start Eavesarp and have it listen on the `eth0` network interface.

```bash
eavesarp-ng start -v debug -i eth0
```

# TLS Splitting

TLS splitting is automatically enabled and managed by Eavesarp.

This capability allows us to intercept TLS tunnels and extract clear text application data relayed between the [[notes/Conversation|conversation]] [[notes/ARP Sender|sender]] and the [[notes/ARP Target|target]]. Intercepted data is written to the [[#Data JSONL File]].

## How it Works

>[!NOTE]
>Proxies are started on a random port during initialization. They are not currently user configurable.

A UDP proxy and a TCP proxy is started as Eavesarp is initialized. Traffic associated with poisoning attacks is DNAT'd[^netfilter-table-note] to the proxies, which then [[notes/Relaying Traffic|relay]] the traffic to a downstream (when configured).

# Output Files

Eavesarp produces a number of output files. See the `--help` menu to learn about specifying names for files.

## SQLite database file

This is where Eavesarp stores general data in a SQLite database file. 

## Log JSONL File

Events are logged to disk in JSONL format.

```json
{
  "level": "info",
  "time": "2025-05-23T13:16:16.626Z",
  "message": "tcp proxy server listener started",
  "address": "172.28.0.86:42081"
}
```

## Data JSONL File

Transport layer data extracted during poisoning attacks is written to disk in JSONL format. This can be useful when looking for quick wins when text-based application layer protocols are in use.

This rough command can assist with parsing the file:

```bash
jq 'select(recurse | scalars | tostring | .data | @base64d' eavesarp-data.jsonl -r | less
```

![[notes/artifacts/lab-capturing-flags.png]]

Here is an example record:

```json
{
  "time": "2025-05-23T13:56:18.639896944Z",
  "sender": "victim",
  "victim_address": {
    "ip": "172.28.0.3",
    "src_port": "60816",
    "dst_port": "445",
    "transport": "tcp"
  },
  "spoofed_address": {
    "ip": "172.28.0.1",
    "port": "445",
    "transport": "tcp"
  },
  "proxy_address": {
    "ip": "172.28.0.86",
    "port": "42081",
    "transport": "tcp"
  },
  "downstream_address": null,
  "transport": "tcp",
  "data": "AAAA5P5TTUJAAAAAAAAAAAAAHwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAkAAUAAQAAAH8AAAD16imHWj2ZR52K+7ORpKiocAAAAAQAAAACAhACAAMCAxEDAAABACYAAAAAAAEAIAABACPfMmylhmQDrPeE6rexBA+B73BTmkDkdTMFzsqbBZdZAAACAAoAAAAAAAQAAgABAAQAAwAAAAAAAAAIAAgAAAAAAAMAAgABAAAABQAUAAAAAAAxADcAMgAuADIAOAAuADAALgAxAA=="
}
```

## Poisoning Attack PCAP Files

You have the option of specifying a PCAP output file for any poisoning attack. Just set an output path and it'll be waiting for exfiltration.

# Understanding the UI

Eavesarp provides a friendly user interface (UI) built on the amazing [Charm ecosystem][charm-source].

## Getting Help

After starting Eavesarp, strike the `?` key to get a help screen outlining how to move around.

The following example is static and **may be out of date**.

![[notes/artifacts/usage-help.png]]

## The Conversations Pane

[[notes/Conversation|Conversations]] detected via network sniffing are formatted as a table in this pane. It's mostly self-explanatory, but the **SNAC** and **Poisoned** columns are of interest:

- **SNAC (Σ)** indicates that the sender has one or more [[notes/Stale Network Address Configuration|SNACs]] for the target.
- **Poisoned (Ψ)** indicates that there's an ongoing poisoning attack for the conversation. (See [[notes/Poisoned Conversation|Poisoned Conversation]])

Selecting a row with a [[notes/Greek Alphabet Legend#Sigma|sigma]] symbol will allow you to configure poisoning for the selected conversation. (See [[#The Conversations Pane]] for more information on poisoning attack configuration.)

![[notes/artifacts/usage-conversations-pane.png]]

## The Selected Conversation Pane

Information regarding the currently selected conversation is reflected in this pane. A button to configure poisoning is displayed here when the conversation has a [[notes/Stale Network Address Configuration|SNAC]].

![[notes/artifacts/usage-selected-convo-pane.png]]

Eavesarp always shows general information about the conversation (IP, MAC, etc.), but it will also include additional details as they're discovered (see [[#Configure a Poisoning Attack]]):

- DNS records (`A`/`PTR`)
- For the sender, ports seen in transport layer traffic as it's captured during poisoning attacks

### Configure a Poisoning Attack

>[!WARNING]
>Eavesarp currently supports poisoning for [[notes/Stale Network Address Configuration|SNACs]] only.

>[!TIP]
>Eavesarp supports multiple poisoning attacks running in parallel.

If the conversation has a [[notes/Greek Alphabet Legend#Sigma|sigma character]], this pane will display a clickable button that can be used to configure and launch a poisoning attack against the sender (see [[notes/Poisoned Conversation|Poisoned Conversation]]). Click it and [[#The Events Pane]] will be replaced with a configurable form. After populating the form, just click the *Start* button to begin poisoning.

![[notes/artifacts/usage-start-poisoning-attack.png]]

Once started, the [[#The Selected Conversation Pane]] will begin reflecting updated information.

>[!TIP]
>The attack likely failed if ARP requests are still being detected for the conversation and no packets are being captured.

![[notes/artifacts/usage-ongoing-attack.png]]

## The Events Pane

>[!TIP]
>The [[#Log JSONL File]] contains more information than the events pane.

Events that occur while using Eavesarp are printed in this pane. If you find yourself wanting to review events as a poisoning attack is ongoing for a conversation, just select a different conversation.

![[notes/artifacts/usage-events-pane.png]]

[charm-source]: https://charm.sh/
[^netfilter-table-note]: The netfilter table used to DNAT traffic to the proxies is automatically managed by Eavesarp.