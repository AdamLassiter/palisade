use std::io::Cursor;

use sqlevfs::{backup, crypto::keys::KeyScope, keyring::Keyring};

use crate::helpers::{TestDir, TestRunner, make_provider};

pub(crate) fn run_evfs_backup_tests(t: &mut TestRunner) {
    t.section("EVFS Backup - Setup");

    let tmp = TestDir::new("evfs-backup-");
    let src_key = tmp.write_keyfile("src.key", [0x11; 32]);
    let bkp_key = tmp.write_keyfile("bkp.key", [0x22; 32]);
    let tgt_key = tmp.write_keyfile("tgt.key", [0x33; 32]);
    let db_path = tmp.path("source.db");

    let page_size: u32 = 4096;
    let reserve: usize = 48;
    let page_count: usize = 4;

    let src_provider = make_provider(&src_key);
    let src_keyring = Keyring::new(src_provider.clone());
    let src_dek = match src_keyring.dek_for(&KeyScope::Database) {
        Ok(d) => {
            t.ok("generated source DEK");
            d
        }
        Err(e) => {
            t.fail("generate source DEK", &e);
            return;
        }
    };

    let mut db_bytes = vec![0u8; page_count * page_size as usize];
    for i in 0..page_count {
        let off = i * page_size as usize;
        let pattern = (i as u8).wrapping_add(0x41);
        db_bytes[off..off + page_size as usize - reserve].fill(pattern);
        if let Err(e) = sqlevfs::crypto::page::encrypt_page(
            &mut db_bytes[off..off + page_size as usize],
            i as u32 + 1,
            &src_dek,
            reserve,
        ) {
            t.fail(&format!("encrypt page {}", i + 1), &e);
            return;
        }
    }
    std::fs::write(&db_path, &db_bytes).expect("write source DB");
    t.ok(&format!("created encrypted source DB ({page_count} pages)"));

    t.section("EVFS Backup - Create");

    let bkp_provider = make_provider(&bkp_key);
    let mut backup_buf: Vec<u8> = Vec::new();

    match backup::create_backup(
        &db_path,
        &mut backup_buf,
        &src_keyring,
        bkp_provider.as_ref(),
        page_size,
        reserve,
    ) {
        Ok(()) => t.ok(&format!("backup created ({} bytes)", backup_buf.len())),
        Err(e) => {
            t.fail("create backup", &e);
            return;
        }
    }

    let min_expected = 8 + 4 + page_count * page_size as usize;
    if backup_buf.len() >= min_expected {
        t.ok("backup size plausible");
    } else {
        t.fail(
            "backup size",
            &format!("expected >= {min_expected}, got {}", backup_buf.len()),
        );
    }

    if &backup_buf[..8] == b"EVFSBKUP" {
        t.ok("backup magic correct");
    } else {
        t.fail("backup magic", &"wrong magic bytes");
    }

    t.section("EVFS Backup - Verify");

    match backup::verify_backup(&mut Cursor::new(&backup_buf), bkp_provider.as_ref()) {
        Ok(result) => {
            t.assert_eq("verified page_count", &result.page_count, &(page_count as u32));
            t.assert_eq("pages_ok", &result.pages_ok, &(page_count as u32));
            t.assert_eq("pages_bad", &result.pages_bad, &0u32);
            if result.is_ok() {
                t.ok("backup verification passed");
            } else {
                t.fail("backup verification", &"some pages bad");
            }
        }
        Err(e) => t.fail("verify backup", &e),
    }

    t.section("EVFS Backup - Wrong Key Rejection");

    let wrong_provider = make_provider(&tgt_key);
    match backup::verify_backup(&mut Cursor::new(&backup_buf), wrong_provider.as_ref()) {
        Ok(result) if result.is_ok() => {
            t.fail(
                "wrong-key verify",
                &"should have failed but all pages passed",
            );
        }
        Ok(result) => {
            t.ok(&format!(
                "wrong key correctly fails ({} bad pages)",
                result.pages_bad,
            ));
        }
        Err(_) => {
            t.ok("wrong key correctly rejected at DEK unwrap");
        }
    }

    t.section("EVFS Backup - Restore");

    let tgt_provider = make_provider(&tgt_key);
    let tgt_keyring = Keyring::new(tgt_provider.clone());
    let restored_path = tmp.path("restored.db");

    match backup::restore_backup(
        &mut Cursor::new(&backup_buf),
        &restored_path,
        bkp_provider.as_ref(),
        &tgt_keyring,
    ) {
        Ok(()) => t.ok("backup restored"),
        Err(e) => {
            t.fail("restore backup", &e);
            return;
        }
    }

    let restored_bytes = std::fs::read(&restored_path).expect("read restored DB");
    t.assert_eq(
        "restored DB size",
        &restored_bytes.len(),
        &(page_count * page_size as usize),
    );

    let tgt_dek = tgt_keyring
        .dek_for(&KeyScope::Database)
        .expect("get target DEK");
    let mut all_pages_ok = true;
    for i in 0..page_count {
        let off = i * page_size as usize;
        let mut page = restored_bytes[off..off + page_size as usize].to_vec();
        match sqlevfs::crypto::page::decrypt_page(&mut page, i as u32 + 1, &tgt_dek, reserve) {
            Ok(()) => {
                let expected = (i as u8).wrapping_add(0x41);
                let payload = &page[..page_size as usize - reserve];
                if payload.iter().all(|&b| b == expected) {
                    t.ok(&format!("restored page {} content correct", i + 1));
                } else {
                    t.fail(&format!("restored page {} content", i + 1), &"data mismatch");
                    all_pages_ok = false;
                }
            }
            Err(e) => {
                t.fail(&format!("decrypt restored page {}", i + 1), &e);
                all_pages_ok = false;
            }
        }
    }
    if all_pages_ok {
        t.ok("all restored pages verified");
    }

    t.section("EVFS Backup - KEK Rotation");

    let backup_file = tmp.path("rotatable.evfs-backup");
    std::fs::write(&backup_file, &backup_buf).expect("write backup file");

    let new_kek = tmp.write_keyfile("new-bkp.key", [0x44; 32]);
    let new_provider = make_provider(&new_kek);

    match backup::rotate_backup_kek(&backup_file, bkp_provider.as_ref(), new_provider.as_ref()) {
        Ok(()) => t.ok("KEK rotation succeeded"),
        Err(e) => {
            t.fail("KEK rotation", &e);
            return;
        }
    }

    let rotated_data = std::fs::read(&backup_file).expect("read rotated backup");
    match backup::verify_backup(&mut Cursor::new(&rotated_data), new_provider.as_ref()) {
        Ok(result) if result.is_ok() => {
            t.ok("verify after rotation (new key) passed");
        }
        Ok(result) => {
            t.fail(
                "verify after rotation (new key)",
                &format!("{} bad pages", result.pages_bad),
            );
        }
        Err(e) => t.fail("verify after rotation (new key)", &e),
    }

    match backup::verify_backup(&mut Cursor::new(&rotated_data), bkp_provider.as_ref()) {
        Ok(result) if result.is_ok() => {
            t.fail("verify after rotation (old key)", &"should have failed");
        }
        _ => t.ok("old key correctly rejected after rotation"),
    }

    t.section("EVFS Backup - Restore After Rotation");

    let tgt2_key = tmp.write_keyfile("tgt2.key", [0x55; 32]);
    let tgt2_provider = make_provider(&tgt2_key);
    let tgt2_keyring = Keyring::new(tgt2_provider);
    let restored2_path = tmp.path("restored2.db");

    match backup::restore_backup(
        &mut Cursor::new(&rotated_data),
        &restored2_path,
        new_provider.as_ref(),
        &tgt2_keyring,
    ) {
        Ok(()) => t.ok("restore from rotated backup succeeded"),
        Err(e) => {
            t.fail("restore from rotated backup", &e);
            return;
        }
    }

    let restored2_bytes = std::fs::read(&restored2_path).expect("read restored2 DB");
    let tgt2_dek = tgt2_keyring
        .dek_for(&KeyScope::Database)
        .expect("get tgt2 DEK");
    let mut page1 = restored2_bytes[..page_size as usize].to_vec();
    match sqlevfs::crypto::page::decrypt_page(&mut page1, 1, &tgt2_dek, reserve) {
        Ok(()) => {
            let expected = 0x41u8;
            if page1[..page_size as usize - reserve]
                .iter()
                .all(|&b| b == expected)
            {
                t.ok("restored2 page 1 content correct");
            } else {
                t.fail("restored2 page 1 content", &"data mismatch");
            }
        }
        Err(e) => t.fail("decrypt restored2 page 1", &e),
    }
}
