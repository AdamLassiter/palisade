pub(crate) fn escape_sql_string(s: &str) -> String {
    s.replace('\'', "''")
}
