.output /dev/null
CREATE TABLE __sec_docs (
    id INTEGER PRIMARY KEY,
    row_label_id INTEGER NOT NULL,
    title TEXT NOT NULL
);

.load ./target/debug/libsqlsec

SELECT sec_define_label('true');
SELECT sec_register_table('docs', '__sec_docs', 'row_label_id', NULL, NULL);
SELECT sec_clear_context();
SELECT sec_set_attr('role', 'user');
SELECT sec_refresh_views();
.output stdout

.print ------------------------------------------------------------
.print [Manual denied audit event]
SELECT sec_audit_event(
    'docs',
    '__sec_docs',
    'UPDATE',
    'denied',
    '{"id":1}',
    '["title"]',
    1,
    'update denied on column title'
) AS recorded;

SELECT operation, outcome, row_pk_json, changed_columns_json, context_json, error
FROM sec_audit_log
ORDER BY id;
