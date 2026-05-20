.output /dev/null
CREATE TABLE __sec_employees (
    id INTEGER PRIMARY KEY,
    row_label_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    ssn TEXT NOT NULL DEFAULT '123-45-6789'
);

.load ./target/debug/libsqlsec

SELECT sec_define_label('true');
SELECT sec_define_label('role=admin');
SELECT sec_register_table('employees', '__sec_employees', 'row_label_id', NULL, NULL);
UPDATE sec_columns
SET read_label_id = sec_define_label('role=admin')
WHERE logical_table = 'employees' AND column_name = 'ssn';

SELECT sec_clear_context();
SELECT sec_set_attr('role', 'user');
SELECT sec_refresh_views();
.output stdout

.print ------------------------------------------------------------
.print [Audit does not leak hidden values]
INSERT INTO employees (id, name) VALUES (1, 'Alice');
UPDATE employees SET name = 'Alice Public' WHERE id = 1;

SELECT operation, changed_columns_json, instr(COALESCE(row_pk_json, '') || COALESCE(changed_columns_json, '') || context_json || COALESCE(error, ''), '123-45-6789') AS leaked
FROM sec_audit_log
ORDER BY id;
