Eavesarp-NG is still in alpha as of 2025/06 and has a number of limitations:

1. The TCP proxy can split only TLS, due to the removal of SSL support from Go's [crypto module][golang-crypto-module].
2. The [module][gosplit-source] that defines the [proxy interface type][gosplit-interface-source] is also in alpha and probably needs a partial redesign. TCP retransmissions will be seen  in PCAPs due to inefficient/opinionated connection handling logic.
    - [sslsplit][sslsplit-source] is superior to this project in every way.
3. There is currently no filtering for targets in the UI, so busy networks where arp/port scanners are run from neighboring hosts will inevitably clutter the conversations pane.
4. ARP cache poisoning attacks are supported only for SNACs.

[golang-crypto-module]: https://github.com/golang/go/issues/32716
[gosplit-source]: https://github.com/impostorkeanu/gosplit
[gosplit-interface-source]: https://github.com/ImpostorKeanu/gosplit/blob/master/cfg.go
[sslsplit-source]: https://github.com/droe/sslsplit