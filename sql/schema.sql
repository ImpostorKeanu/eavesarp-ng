PRAGMA foreign_keys = 1;
PRAGMA journal_mode = WAL;

/*
 resolved mac addresses

 - can be associated with multiple ip addresses
 */
CREATE TABLE IF NOT EXISTS mac(
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    -- string value of the mac address
    value TEXT NOT NULL UNIQUE CHECK (length(value) == 17),

    /*
     how the mac was _initially_ discovered

     - mac addresses are always discovered via arp

     valid values:

     - passive - indicates that the mac address was recovered
                 from the sender mac field of a broadcasted arp
                 request
     - active  - indicates that the mac address had to be
                 manually resolved, i.e., associated ip records
                 were targets in an arp request
     */
    disc_meth TEXT NOT NULL CHECK(
        disc_meth == 'passive_arp' OR
        disc_meth == 'active_arp'));


-- observed ipv4 addresses
CREATE TABLE IF NOT EXISTS ip(
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    /*
    string value of the ip address

    - performance penalty for string matching
    - accepted for schema simplicity and user quality
      of life
    */
    value TEXT NOT NULL UNIQUE CHECK (length(value) >= 7 AND length(value) <= 15),

    /*
    associated mac address

    - unknown until arp resolution
    - may have multiple ip addresses (aliasing)
    */
    mac_id INTEGER REFERENCES mac(id),

    /*
    determines how the ip was discovered

    valid values:

    - passive_arp
    - reverse_dns
    - forward_dns

    notes:

    - decided against a default of 'passive_arp' to avoid magic
      induced confusion
    - the _sender's_ mac address is sent along with arp requests
    - forward_dns occurs when a new fqdn is revealed after reverse
      resolving an ip, e.g.,
         - reverse dns for ip-a returns a fqdn
         - forward resolution of the fqdn returns ip-b
         - the disc_meth of ip-b is forward_dns
      - useful information because we may be able to mitm
        the new forward_dns host to extract data
    */
    disc_meth TEXT NOT NULL CHECK (
        disc_meth == 'passive_arp' OR
        disc_meth == 'forward_dns'),

    -- determines if arp resolution has happened
    arp_resolved BOOLEAN NOT NULL DEFAULT FALSE,

    -- determines if reverse dns resolution has happened
    ptr_resolved BOOLEAN NOT NULL DEFAULT FALSE);

/*
track potential aitm opportunities

these arise when a snac target ip (ip set to the misconfigured application client)
has a ptr record that resolves to a distinct host that may be offering
the same services desired by the client.
 */
CREATE TABLE IF NOT EXISTS aitm_opt(
    snac_target_ip_id INTEGER NOT NULL REFERENCES ip(id) ON DELETE CASCADE,
    upstream_ip_id INTEGER NOT NULL REFERENCES ip(id) ON DELETE CASCADE,
    CONSTRAINT aitm_opt_comp_keys PRIMARY KEY (snac_target_ip_id, upstream_ip_id));

-- number of times senders resolve targets
CREATE TABLE IF NOT EXISTS arp_count(
    sender_ip_id INTEGER NOT NULL REFERENCES ip(id) ON DELETE CASCADE,
    target_ip_id INTEGER NOT NULL REFERENCES ip(id) ON DELETE CASCADE,
    count INTEGER NOT NULL DEFAULT 1 CHECK (count >= 1),
    CONSTRAINT arp_cnt_comp_keys PRIMARY KEY (sender_ip_id, target_ip_id));

CREATE TABLE IF NOT EXISTS dns_record(
    ip_id INTEGER REFERENCES ip(id) ON DELETE CASCADE,
    dns_name_id INTEGER REFERENCES dns_name(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (
        kind == 'ptr' OR
        kind == 'a'),
    CONSTRAINT dns_record_comp_keys PRIMARY KEY (ip_id, dns_name_id, kind));

/*
 ptr records obtained through reverse name resolution

 - an ip can have multiple ptrs
 */
-- CREATE TABLE IF NOT EXISTS ptr_record(
--     ip_id INTEGER REFERENCES ip(id) ON DELETE CASCADE,
--     dns_name_id INTEGER REFERENCES dns_name(id) ON DELETE CASCADE,
--     CONSTRAINT ptr_comp_keys PRIMARY KEY (ip_id, dns_name_id));

/*
 ptr -> new fqdn -> potentially new ip

 New IP is a potential AITM opportunity.
 */
-- CREATE TABLE IF NOT EXISTS a_record(
--     ip_id INTEGER REFERENCES ip(id) ON DELETE CASCADE,
--     dns_name_id INTEGER REFERENCES dns_name(id) ON DELETE CASCADE,
--     CONSTRAINT a_comp_keys PRIMARY KEY (ip_id, dns_name_id));

CREATE TABLE IF NOT EXISTS dns_name(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    value TEXT NOT NULL UNIQUE);

CREATE TABLE IF NOT EXISTS attack(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_ip_id INTEGER NOT NULL REFERENCES ip ON DELETE CASCADE,
    target_ip_id INTEGER NOT NULL REFERENCES ip ON DELETE CASCADE);

CREATE TABLE IF NOT EXISTS port(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    number INTEGER NOT NULL CHECK(number >= 0 AND number <= 65535),
    proto TEXT NOT NULL CHECK (
        proto == 'tcp' OR
        proto == 'udp' OR
        proto == 'sctp'),
    CONSTRAINT port_comp_key UNIQUE (number, proto));

CREATE TABLE IF NOT EXISTS attack_port(
    attack_id INTEGER NOT NULL REFERENCES attack(id) ON DELETE CASCADE,
    port_id INTEGER NOT NULL REFERENCES port(id),
    CONSTRAINT attack_port_comp_key PRIMARY KEY (attack_id, port_id));

-- prevent orphaned mac addresses
CREATE TRIGGER IF NOT EXISTS no_orphaned_macs
    BEFORE DELETE ON ip
    FOR EACH ROW
    WHEN (SELECT COUNT(*) FROM ip WHERE mac_id == OLD.mac_id) = 1
BEGIN
    DELETE FROM mac WHERE id == OLD.mac_id;
END;