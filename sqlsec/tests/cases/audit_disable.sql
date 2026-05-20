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
SELECT sec_set_attr('role', 'admin');
SELECT sec_refresh_views();
.output stdout

.print ------------------------------------------------------------
.print [Audit disable/configure]
SELECT sec_audit_disable('docs') AS disabled;
INSERT INTO docs (id, title) VALUES (1, 'no audit');
SELECT COUNT(*) AS after_disabled FROM sec_audit_log;

SELECT sec_audit_enable('docs') AS enabled;
SELECT sec_audit_configure('docs', 'include_context', 0) AS context_off;
SELECT sec_audit_configure('docs', 'audit_update', 0) AS update_off;
INSERT INTO docs (id, title) VALUES (2, 'insert audit');
UPDATE docs SET title = 'update not audited' WHERE id = 2;

SELECT operation, outcome, context_json
FROM sec_audit_log
ORDER BY id;
