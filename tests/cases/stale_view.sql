.output /dev/null

CREATE TABLE __sec_employees (
    id           INTEGER PRIMARY KEY,
    row_label_id INTEGER NOT NULL,
    name         TEXT,
    salary       INTEGER,
    department   TEXT
);

INSERT INTO __sec_employees VALUES
    (1, 1, 'Alice', 50000, 'Sales'),
    (2, 2, 'Bob',   90000, 'Finance'),
    (3, 1, 'Charlie', 60000, 'Engineering');

.load ./target/debug/libsqlsec

SELECT sec_define_label('true');
SELECT sec_define_label('role=manager');
SELECT sec_define_label('role=finance');

SELECT sec_register_table('employees', '__sec_employees', 'row_label_id', NULL, NULL);
SELECT sec_refresh_views();

UPDATE sec_columns SET label_id = sec_define_label('role=manager') WHERE column_name = 'salary';
UPDATE sec_columns SET label_id = sec_define_label('role=finance') WHERE column_name = 'department';

.output /dev/null
SELECT sec_clear_context();
SELECT sec_set_attr('role', 'user');
.output stdout

.print ------------------------------------------------------------
.print [Regular user]
SELECT * FROM employees;
