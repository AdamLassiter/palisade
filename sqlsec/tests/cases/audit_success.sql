.output /dev/null
CREATE TABLE __sec_docs (
    id INTEGER PRIMARY KEY,
    row_label_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    secret TEXT NOT NULL
);

.load ./target/debug/libsqlsec

SELECT sec_define_label('true');
SELECT sec_register_table('docs', '__sec_docs', 'row_label_id', NULL, NULL);

SELECT sec_clear_context();
SELECT sec_set_attr('role', 'admin');
SELECT sec_set_attr('tenant', 'north');
SELECT sec_refresh_views();
.output stdout

.print ------------------------------------------------------------
.print [Audit successful writes]
INSERT INTO docs (id, title, secret) VALUES (1, 'Alpha', 'hidden-alpha');
UPDATE docs SET title = 'Beta' WHERE id = 1;
DELETE FROM docs WHERE id = 1;

SELECT operation, outcome, logical_table, physical_table, row_pk_json, changed_columns_json, context_json, row_label_id
FROM sec_audit_log
ORDER BY id;
