.output /dev/null

-- Base table
CREATE TABLE __sec_docs (
    id           INTEGER PRIMARY KEY,
    row_label_id INTEGER,
    title        TEXT
);

INSERT INTO __sec_docs VALUES
    (1, 1, 'Public'),
    (2, 2, 'Admin Only');

.load ./target/debug/libsqlsec

-- Labels
SELECT sec_define_label('true');          -- id = 1
SELECT sec_define_label('role=admin');    -- id = 2

-- Register table
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
SELECT sec_push_context();
SELECT sec_set_attr('role', 'admin');
SELECT sec_refresh_views();
.output stdout

.print ------------------------------------------------------------
.print [Admin via push]
SELECT * FROM docs;

.output /dev/null
SELECT sec_pop_context();
SELECT sec_refresh_views();
.output stdout

.print ------------------------------------------------------------
.print [After pop]

SELECT * FROM docs;
