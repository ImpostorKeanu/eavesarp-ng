INSERT OR IGNORE INTO arp_count (sender_ip_id, target_ip_id)
VALUES (?, ?);
SELECT * FROM arp_count WHERE sender_ip_id=? AND target_ip_id=?;
