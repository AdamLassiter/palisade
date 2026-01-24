.output /dev/null

CREATE TABLE __sec_customers (
    id            INTEGER PRIMARY KEY,
    row_label_id  INTEGER NOT NULL,
    name          TEXT,
    email         TEXT,
    ssn           TEXT
);

INSERT INTO __sec_customers VALUES
    (1, 1, 'Alice',   'alice@ex.com',   '111'),
    (2, 2, 'Bob',     'bob@ex.com',     '222'),
  (3, 3, 'Charlie', 'charlie@ex.com', '333');

.load ./target/debug/libsqlsec

SELECT sec_define_label('true');
SELECT sec_define_label('role=admin');
SELECT sec_define_label('(role=admin|role=auditor)');

SELECT sec_register_table('customers', '__sec_customers', 'row_label_id', NULL, NULL);

UPDATE sec_columns SET label_id = sec_define_label('role=admin')
  WHERE logical_table = 'customers' AND column_name = 'ssn';
UPDATE sec_columns SET label_id = sec_define_label('(role=admin|role=auditor)')
  WHERE logical_table = 'customers' AND column_name = 'email';

.output /dev/null
SELECT sec_clear_context();
SELECT sec_set_attr('role', 'user');
SELECT sec_refresh_views();
.output stdout

.print ------------------------------------------------------------
.print [Regular user]
SELECT * FROM customers;

.output /dev/null
SELECT sec_clear_context();
SELECT sec_set_attr('role', 'auditor');
SELECT sec_refresh_views();
.output stdout

.print ------------------------------------------------------------
.print [Auditor]
SELECT * FROM customers;

.output /dev/null
SELECT sec_clear_context();
SELECT sec_set_attr('role', 'admin');
SELECT sec_refresh_views();
.output stdout

.print ------------------------------------------------------------
.print [Admin]
SELECT * FROM customers;