use sqlevfs::crypto::{envelope, keys::Dek, page};

use crate::common::{make_provider, test_db_path};

#[test_log::test]
fn test_crypto_page_round_trip() {
    let dek = Dek::generate();
    let reserve = 48;
    let page_size = 4096;

    let mut buf = vec![0xBEu8; page_size];
    let original = buf.clone();

    page::encrypt_page(&mut buf, 1, &dek, reserve).expect("encrypt page");
    assert_ne!(buf[..page_size - reserve], original[..page_size - reserve]);

    page::decrypt_page(&mut buf, 1, &dek, reserve).expect("decrypt page");
    assert_eq!(buf[..page_size - reserve], original[..page_size - reserve]);
}

#[test_log::test]
fn test_crypto_wrong_key_rejected() {
    let reserve = 48;
    let dek = Dek::generate();
    let wrong = Dek::generate();

    let mut buf = vec![0xCDu8; 4096];
    page::encrypt_page(&mut buf, 1, &dek, reserve).expect("encrypt page");

    let err = page::decrypt_page(&mut buf, 1, &wrong, reserve);
    assert!(err.is_err());
}

#[test_log::test]
fn test_crypto_page_no_is_not_part_of_nonce_tag_binding() {
    let reserve = 48;
    let dek = Dek::generate();

    let mut buf = vec![0xEFu8; 4096];
    page::encrypt_page(&mut buf, 5, &dek, reserve).expect("encrypt page");

    page::decrypt_page(&mut buf, 6, &dek, reserve).expect("decrypt should succeed");
}

#[test_log::test]
fn test_crypto_envelope_round_trip_and_wrong_kek_rejected() {
    let temp = tempfile::TempDir::new().expect("temp dir");
    let keyfile = test_db_path(&temp, "envelope.key");
    std::fs::write(&keyfile, [0x77u8; 32]).expect("write keyfile");
    let provider = make_provider(&keyfile);

    let dek = Dek::generate();
    let wrapped = envelope::wrap_dek(&dek, provider.as_ref()).expect("wrap DEK");
    let unwrapped = envelope::unwrap_dek(&wrapped, provider.as_ref()).expect("unwrap DEK");
    assert_eq!(unwrapped.as_bytes(), dek.as_bytes());

    let wrong_keyfile = test_db_path(&temp, "wrong.key");
    std::fs::write(&wrong_keyfile, [0x88u8; 32]).expect("write wrong keyfile");
    let wrong_provider = make_provider(&wrong_keyfile);

    let err = envelope::unwrap_dek(&wrapped, wrong_provider.as_ref());
    assert!(err.is_err());
}
