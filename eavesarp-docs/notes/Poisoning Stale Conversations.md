A "Poison Conversation" button appears for [[notes/Stale Conversation|stale conversations]]. Clicking that button reveals an *optional* form used to configure the attack. The input fields are:

- **Capture Duration** determines how long the sender's ARP cache should be poisoned. Leave blank to poison indefinitely.
- **Packet Limit** indicates that cache poisoning should end after the specified number of packets are captured.
- **Output PCAP File** sets a file path where all captured packets will be written.
- **Downstream IPv4 Address** tells Eavesarp to relay traffic to a downstream IPv4 address.

Clicking "Start" will cause Eavesarp to begin poisoning the sender's ARP cache with replies that associate the stale target IP address with the attacking MAC address. The attack continues until canceled or until either the capture duration expires or the packet limit is met.