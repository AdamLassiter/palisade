.output /dev/null

CREATE TABLE __sec_reports (
    id           INTEGER PRIMARY KEY,
    row_label_id INTEGER NOT NULL,
    data         TEXT
);
INSERT INTO __sec_reports VALUES
    (1, 1, 'Quarterly Results'),
    (2, 1, 'Financial Forecast');

.load ./target/debug/libsqlsec

SELECT sec_define_label('true');
SELECT sec_define_label('role=admin');

SELECT sec_register_table('reports', '__sec_reports', 'row_label_id', 2, NULL);

.output /dev/null
SELECT sec_clear_context();
SELECT sec_set_attr('role', 'user');
SELECT sec_refresh_views();
.output stdout

.print ------------------------------------------------------------
.print [Regular user table access]
.print Checking if logical view exists:
.tables reports

.output /dev/null
SELECT sec_clear_context();
SELECT sec_set_attr('role', 'admin');
SELECT sec_refresh_views();
.output stdout

.print ------------------------------------------------------------
.print [Admin table access]
.print Checking if logical view exists:
.tables reports
SELECT * FROM reports;