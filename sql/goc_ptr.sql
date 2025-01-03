INSERT OR IGNORE INTO ptr (ip_id, fqdn) VALUES (?, ?);
SELECT * FROM ptr WHERE ip_id=? AND fqdn=?;