Let's say we're on a network with two conversing hosts: `cron` and `server1`, and the former is observed to periodically broadcast ARP requests for the latter. Based on the hostname and supporting reconnaissance, we may presume that `cron` is authenticating to `server1` to access its services. 

 Recall the following diagrams from earlier sections:

![[eavesarp-blog-example-arp-request.png]]

![[eavesarp-blog-example-arp-reply.png]]

Let's modify the scenario. Assume `server1` crashed due to a bad update and a failover server is available (`server2`). If the applications run by `cron` don't adapt to the outage, the host's OS will continue to periodically send ARP requests for `server1`.

![[notes/artifacts/eavesarp-blog-snac-example.png]]

 In this scenario, `cron` has one or more SNACs for `server1`. We can generally assume that the target is offline unless we're on a network where static ARP is managed by administrators, and `cron` is experiencing a DOS. Poisoning the ARP cache  of `cron` to become `server1` (convo positioning) is a low risk action.

![[eavesarp-blog-graph-poisoning-example.png]]

 Depending on the intercepted traffic, `attacker` may receive credentials or other useful data if it begins proxying TCP traffic from `cron` to `server2`. An updated diagram look like:

![[eavesarp-blog-proxy-example.png]]