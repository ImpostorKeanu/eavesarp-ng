# Conversation and SNAC Discovery

Eavesarp discovers [[notes/Conversation|conversations]] by passively watching for [[notes/ARP Request|ARP requests]]. The sender's protocol (IP) address and hardware (MAC) address, and the target's IP address, are extracted from the ARP request and associated in the database. Once stored in the database, conversations are displayed in the conversations pane of the UI.

Because [[notes/ARP Reply|ARP replies]] are unicast, Eavesarp determines if a conversation is stale by initiating ARP resolution for any target IP address without a known MAC address. A background routine broadcasts up to three ARP requests for a given target and monitors for a reply. If no reply is received, the conversation is considered to be [[notes/Stale Conversation|stale]]. 

>[!NOTE] Periodic ARP Resolution Enhancement
>**Eavesarp is currently point-in-time**, i.e, it attempts ARP resolution only upon initial discovery of target IPs for which the MAC is unknown.
>
>Future versions will periodically repeat ARP resolution for all IP addresses to maintain an up-to-date inventory of SNACs.

# See Also

- [[notes/Poisoning Stale Conversations|Poisoning Stale Conversations]]