use crate::helpers::{TestDir, TestRunner, make_provider};

pub(crate) fn run_evfs_crypto_tests(t: &mut TestRunner) {
    t.section("EVFS Crypto - Page Round-Trip");

    let dek = sqlevfs::crypto::keys::Dek::generate();
    let reserve = 48;
    let page_size = 4096;

    let mut page = vec![0xBEu8; page_size];
    let original = page.clone();

    match sqlevfs::crypto::page::encrypt_page(&mut page, 1, &dek, reserve) {
        Ok(()) => t.ok("encrypt_page succeeded"),
        Err(e) => {
            t.fail("encrypt_page", &e);
            return;
        }
    }

    if page[..page_size - reserve] != original[..page_size - reserve] {
        t.ok("ciphertext differs from plaintext");
    } else {
        t.fail("ciphertext check", &"ciphertext == plaintext");
    }

    match sqlevfs::crypto::page::decrypt_page(&mut page, 1, &dek, reserve) {
        Ok(()) => t.ok("decrypt_page succeeded"),
        Err(e) => {
            t.fail("decrypt_page", &e);
            return;
        }
    }

    if page[..page_size - reserve] == original[..page_size - reserve] {
        t.ok("round-trip payload matches");
    } else {
        t.fail("round-trip", &"payload mismatch after decrypt");
    }

    t.section("EVFS Crypto - Wrong Key Rejection");

    let dek2 = sqlevfs::crypto::keys::Dek::generate();
    let mut page = vec![0xCDu8; page_size];
    sqlevfs::crypto::page::encrypt_page(&mut page, 1, &dek, reserve).unwrap();

    match sqlevfs::crypto::page::decrypt_page(&mut page, 1, &dek2, reserve) {
        Err(_) => t.ok("wrong key correctly rejected"),
        Ok(()) => t.fail("wrong key", &"decryption should have failed"),
    }

    t.section("EVFS Crypto - Wrong Page Number Rejection");

    let mut page = vec![0xEFu8; page_size];
    sqlevfs::crypto::page::encrypt_page(&mut page, 5, &dek, reserve).unwrap();

    match sqlevfs::crypto::page::decrypt_page(&mut page, 6, &dek, reserve) {
        Err(_) => t.ok("wrong page_no correctly rejected"),
        Ok(()) => t.fail("wrong page_no", &"decryption should have failed"),
    }

    t.section("EVFS Crypto - Envelope Encryption");

    let tmp = TestDir::new("evfs-envelope-");
    let kf = tmp.write_keyfile("envelope.key", [0x77; 32]);
    let provider = make_provider(&kf);

    let dek = sqlevfs::crypto::keys::Dek::generate();
    let wrapped = match sqlevfs::crypto::envelope::wrap_dek(&dek, provider.as_ref()) {
        Ok(w) => {
            t.ok("wrap_dek succeeded");
            w
        }
        Err(e) => {
            t.fail("wrap_dek", &e);
            return;
        }
    };

    match sqlevfs::crypto::envelope::unwrap_dek(&wrapped, provider.as_ref()) {
        Ok(unwrapped) => {
            if unwrapped.as_bytes() == dek.as_bytes() {
                t.ok("unwrap_dek round-trip matches");
            } else {
                t.fail("unwrap_dek", &"key bytes differ");
            }
        }
        Err(e) => t.fail("unwrap_dek", &e),
    }

    let kf2 = tmp.write_keyfile("wrong.key", [0x88; 32]);
    let wrong_provider = make_provider(&kf2);
    match sqlevfs::crypto::envelope::unwrap_dek(&wrapped, wrong_provider.as_ref()) {
        Err(_) => t.ok("unwrap with wrong KEK correctly rejected"),
        Ok(_) => t.fail("unwrap wrong KEK", &"should have failed"),
    }
}
