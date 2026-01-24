.output /dev/null

CREATE TABLE __sec_data (
    id           INTEGER PRIMARY KEY,
    row_label_id INTEGER NOT NULL,
    public       TEXT,
    secret       TEXT
);
INSERT INTO __sec_data VALUES (1, 1, 'visible', 'hidden');

.load ./target/debug/libsqlsec
SELECT sec_define_label('true');
SELECT sec_define_label('role=admin');
SELECT sec_register_table('data', '__sec_data', 'row_label_id', NULL, NULL);
UPDATE sec_columns SET label_id = sec_define_label('role=admin') WHERE column_name = 'secret';

.output /dev/null
SELECT sec_clear_context();
SELECT sec_set_attr('role', 'user');
SELECT sec_refresh_views();
.output stdout

.print ------------------------------------------------------------
.print [User cannot access secret column]
SELECT * FROM data;