.output /dev/null
CREATE TABLE __sec_docs (
    id           INTEGER PRIMARY KEY,
    row_label_id INTEGER,
    title        TEXT
);
INSERT INTO __sec_docs VALUES (1, 1, 'Public'), (2, 2, 'Admin Only');

.load ./target/debug/libsqlsec
SELECT sec_define_label('true');
SELECT sec_define_label('role=admin');
SELECT sec_register_table('docs', '__sec_docs', 'row_label_id', NULL, NULL);

.output /dev/null
SELECT sec_clear_context();
SELECT sec_refresh_views();
.output stdout

.print ------------------------------------------------------------
.print [Guest]
SELECT * FROM docs;

.output /dev/null
SELECT sec_clear_context();
SELECT sec_set_attr('role', 'admin');
SELECT sec_refresh_views();
.output stdout

.print ------------------------------------------------------------
.print [Admin]
SELECT * FROM docs;

.output /dev/null
SELECT sec_clear_context();
SELECT sec_refresh_views();
.output stdout

.print ------------------------------------------------------------
.print [Guest again]
.output stdout
SELECT * FROM docs;