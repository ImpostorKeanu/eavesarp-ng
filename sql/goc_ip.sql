INSERT OR IGNORE INTO ip (value, mac_id, disc_meth, arp_resolved, ptr_resolved)
VALUES (?, ?, ?, ?, ?);
SELECT * FROM ip WHERE value=?;