/*
sip - sender ip
tip - target ip
*/
SELECT sip.value,tip.value FROM ip AS tip
                                    LEFT JOIN arp_count AS AC ON AC.target_ip_id=tip.id
                                    LEFT JOIN ip AS sip ON sip.id=AC.sender_ip_id
WHERE tip.arp_resolved=TRUE AND tip.mac_id IS NULL
ORDER BY sip.id;