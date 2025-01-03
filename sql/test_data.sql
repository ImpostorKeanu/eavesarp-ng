PRAGMA foreign_keys = 1;
INSERT INTO mac (arp_disc_meth, value)
VALUES
    ('passive', '00:00:00:00:00:00'),
    ('passive', '00:00:00:00:00:01'),
    ('active', '00:00:00:00:00:02')
ON CONFLICT DO NOTHING;

INSERT INTO ip (value, mac_id, disc_meth, arp_resolved, ptr_resolved)
VALUES
    ('192.168.0.0',1,'passive_arp', 0, 0),
    ('192.168.0.1',2,'passive_arp', 0, 0),
    ('192.168.0.2',3,'passive_arp', 1, 0),
    ('192.168.0.3',3,'passive_arp', 1, 0)
ON CONFLICT DO NOTHING;

INSERT INTO arp_count
VALUES
    (1, 2, 1),
    (2, 3, 5),
    (3, 1, 20)
ON CONFLICT DO NOTHING;

INSERT INTO ptr (ip_id, fqdn)
VALUES
    (1, 'test1.com'),
    (2, 'test2.com')
ON CONFLICT DO NOTHING;