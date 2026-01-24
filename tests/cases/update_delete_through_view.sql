.output /dev/null

CREATE TABLE __sec_inventory (
    id           INTEGER PRIMARY KEY,
    row_label_id INTEGER,
    item         TEXT,
    quantity     INTEGER
);
INSERT INTO __sec_inventory VALUES
    (1, 1, 'Apples', 10),
    (2, 1, 'Oranges', 5);

.load ./target/debug/libsqlsec
SELECT sec_define_label('true'); -- everyone
SELECT sec_register_table('inventory', '__sec_inventory', 'row_label_id', NULL, NULL);

.output /dev/null
SELECT sec_clear_context();
SELECT sec_set_attr('role', 'admin');
SELECT sec_refresh_views();
.output stdout

.print ------------------------------------------------------------
.print [Admin update/delete test]
.print Original contents:
SELECT * FROM inventory;

.print Performing UPDATE (increase Apples -> 20)
UPDATE inventory SET quantity = 20 WHERE item = 'Apples';
SELECT * FROM inventory;

.print Performing DELETE (remove Oranges)
DELETE FROM inventory WHERE item = 'Oranges';
SELECT * FROM inventory;

.print Verify base table contents:
SELECT * FROM __sec_inventory;