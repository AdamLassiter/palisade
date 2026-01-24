.output /dev/null
CREATE TABLE __sec_customers (
    id           INTEGER PRIMARY KEY,
    row_label_id INTEGER,
    name         TEXT,
    email        TEXT,
    ssn          TEXT
);

.load ./target/debug/libsqlsec

SELECT sec_define_label('true'); -- public
SELECT sec_register_table('customers', '__sec_customers', 'row_label_id', NULL, NULL);

.output /dev/null
SELECT sec_clear_context();
SELECT sec_set_attr('role', 'admin');
SELECT sec_refresh_views();
.output stdout

.print ------------------------------------------------------------
.print [Admin insert test]
.output stdout
INSERT INTO customers (id, name, email, ssn) VALUES (1, 'Example', 'ex@a.com', '999');
SELECT COUNT(*) AS total FROM __sec_customers;