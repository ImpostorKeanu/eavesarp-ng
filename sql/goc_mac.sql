INSERT OR IGNORE INTO mac (value, arp_disc_meth)
VALUES (?, ?);
SELECT * FROM mac WHERE value=?;