UPDATE arp_count
SET count=count+1
WHERE sender_ip_id=? AND target_ip_id=?
RETURNING count;
