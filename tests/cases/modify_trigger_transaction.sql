.output /dev/null

CREATE TABLE __sec_bad (id INTEGER PRIMARY KEY);

SELECT sec_register_table('bad', '__sec_bad', 'missing_label', NULL, NULL);
SELECT sec_refresh_views();

.output stdout