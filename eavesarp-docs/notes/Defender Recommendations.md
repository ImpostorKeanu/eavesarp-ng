- **Dynamic ARP Inspection (DAI)** - If supported by network hardware, enable [DAI][network-lessons-dai] to detect and thwart ARP poisoning attacks. This is likely the quickest win for many organizations.
-  **Change control & application dependency mapping** - Maintain an application dependency map associates hosts with servers. Reference this resource in change control procedures that decommsion hosts and services to prevent SNACs.
- **TLS encrypt traffic and verify certificates** - Use TLS where possible. Deploy and maintain public key infrastructure (PKI) and configure clients to enforce certificate verification. 
- **Zero Trust Architecture** - This involves ["authenticating all connections and encrypting all traffic"][nist-800-207-source] for internal networks. This also may be impractical for many organizations.
- **Static ARP** - It's an option but is likely impractical for large networks.

[network-lessons-dai]: https://networklessons.com/switching/dai-dynamic-arp-inspection
[nist-800-207-source]: https://nvlpubs.nist.gov/nistpubs/specialpublications/NIST.SP.800-207.pdf