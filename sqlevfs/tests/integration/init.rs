use sqlevfs::sqlite3_sqlevfs_init;

#[test_log::test]
fn test_sqlite3_evfs_init_with_keyfile_env() {
    unsafe {
        std::env::set_var("EVFS_KEYFILE", "/tmp/test.key");
        std::env::remove_var("EVFS_PASSPHRASE");
        std::env::remove_var("EVFS_KMS_KEY_ID");

        let _result = sqlite3_sqlevfs_init(
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );

        std::env::remove_var("EVFS_KEYFILE");
    }
}

#[test_log::test]
fn test_sqlite3_evfs_init_with_passphrase_env() {
    unsafe {
        std::env::remove_var("EVFS_KEYFILE");
        std::env::set_var("EVFS_PASSPHRASE", "test_password");
        std::env::remove_var("EVFS_KMS_KEY_ID");

        let result = sqlite3_sqlevfs_init(
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );

        assert_eq!(result, 1); // SQLITE_ERROR for null extension API pointer

        std::env::remove_var("EVFS_PASSPHRASE");
    }
}

#[test_log::test]
fn test_sqlite3_evfs_init_no_env() {
    unsafe {
        std::env::remove_var("EVFS_KEYFILE");
        std::env::remove_var("EVFS_PASSPHRASE");
        std::env::remove_var("EVFS_KMS_KEY_ID");

        let result = sqlite3_sqlevfs_init(
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );

        assert_eq!(result, 1); // SQLITE_ERROR
    }
}
