.output /dev/null

CREATE TABLE __sec_secrets (
    id           INTEGER PRIMARY KEY,
    row_label_id INTEGER NOT NULL,
    data         TEXT
);

.load ./target/debug/libsqlsec

SELECT sec_define_label('role=admin&team=finance');
SELECT sec_register_table('secrets', '__sec_secrets', 'row_label_id', NULL, NULL);

INSERT INTO __sec_secrets VALUES (1, 1, 'top-secret');

.output /dev/null
SELECT sec_clear_context();
SELECT sec_set_attr('role', 'admin');
SELECT sec_refresh_views();
.output stdout

.print ------------------------------------------------------------
.print [Role=admin only]
SELECT COUNT(*) AS visible_rows FROM secrets;

.output /dev/null
SELECT sec_clear_context();
SELECT sec_set_attr('role', 'admin');
SELECT sec_set_attr('team', 'finance');
SELECT sec_refresh_views();
.output stdout

.print ------------------------------------------------------------
.print [Role=admin + team=finance]
SELECT COUNT(*) AS visible_rows FROM secrets;