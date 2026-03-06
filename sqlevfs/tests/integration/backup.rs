use std::io::Cursor;

use sqlevfs::{
    backup,
    crypto::{keys::KeyScope, page},
    keyring::Keyring,
};

use crate::common::{make_provider, test_db_path};

#[test_log::test]
fn test_backup_create_verify_restore_rotate() -> anyhow::Result<()> {
    let temp = tempfile::TempDir::new()?;

    let src_key = test_db_path(&temp, "src.key");
    let bkp_key = test_db_path(&temp, "bkp.key");
    let tgt_key = test_db_path(&temp, "tgt.key");
    std::fs::write(&src_key, [0x11u8; 32])?;
    std::fs::write(&bkp_key, [0x22u8; 32])?;
    std::fs::write(&tgt_key, [0x33u8; 32])?;

    let db_path = test_db_path(&temp, "source.db");

    let page_size: u32 = 4096;
    let reserve: usize = 48;
    let page_count: usize = 4;

    let src_provider = make_provider(&src_key);
    let src_keyring = Keyring::new(src_provider.clone());
    let src_dek = src_keyring.dek_for(&KeyScope::Database)?;

    let mut db_bytes = vec![0u8; page_count * page_size as usize];
    for i in 0..page_count {
        let off = i * page_size as usize;
        let pattern = (i as u8).wrapping_add(0x41);
        db_bytes[off..off + page_size as usize - reserve].fill(pattern);
        page::encrypt_page(
            &mut db_bytes[off..off + page_size as usize],
            i as u32 + 1,
            &src_dek,
            reserve,
        )?;
    }
    std::fs::write(&db_path, &db_bytes)?;

    let bkp_provider = make_provider(&bkp_key);
    let mut backup_buf = Vec::new();
    backup::create_backup(
        &db_path,
        &mut backup_buf,
        &src_keyring,
        bkp_provider.as_ref(),
        page_size,
        reserve,
    )?;

    assert!(backup_buf.len() >= 8 + 4 + page_count * page_size as usize);
    assert_eq!(&backup_buf[..8], b"EVFSBKUP");

    let verify = backup::verify_backup(&mut Cursor::new(&backup_buf), bkp_provider.as_ref())?;
    assert_eq!(verify.page_count, page_count as u32);
    assert_eq!(verify.pages_ok, page_count as u32);
    assert_eq!(verify.pages_bad, 0);
    assert!(verify.is_ok());

    let wrong_provider = make_provider(&tgt_key);
    let wrong_verify =
        backup::verify_backup(&mut Cursor::new(&backup_buf), wrong_provider.as_ref());
    assert!(wrong_verify.is_err() || !wrong_verify.expect("verify result").is_ok());

    let tgt_provider = make_provider(&tgt_key);
    let tgt_keyring = Keyring::new(tgt_provider.clone());
    let restored_path = test_db_path(&temp, "restored.db");
    backup::restore_backup(
        &mut Cursor::new(&backup_buf),
        &restored_path,
        bkp_provider.as_ref(),
        &tgt_keyring,
    )?;

    let restored_bytes = std::fs::read(&restored_path)?;
    assert_eq!(restored_bytes.len(), page_count * page_size as usize);

    let tgt_dek = tgt_keyring.dek_for(&KeyScope::Database)?;
    for i in 0..page_count {
        let off = i * page_size as usize;
        let mut page_buf = restored_bytes[off..off + page_size as usize].to_vec();
        page::decrypt_page(&mut page_buf, i as u32 + 1, &tgt_dek, reserve)?;

        let expected = (i as u8).wrapping_add(0x41);
        let payload = &page_buf[..page_size as usize - reserve];
        assert!(payload.iter().all(|&b| b == expected));
    }

    let backup_file = test_db_path(&temp, "rotatable.evfs-backup");
    std::fs::write(&backup_file, &backup_buf)?;

    let new_kek = test_db_path(&temp, "new-bkp.key");
    std::fs::write(&new_kek, [0x44u8; 32])?;
    let new_provider = make_provider(&new_kek);

    backup::rotate_backup_kek(&backup_file, bkp_provider.as_ref(), new_provider.as_ref())?;

    let rotated_data = std::fs::read(&backup_file)?;
    let verify_new = backup::verify_backup(&mut Cursor::new(&rotated_data), new_provider.as_ref())?;
    assert!(verify_new.is_ok());

    let verify_old = backup::verify_backup(&mut Cursor::new(&rotated_data), bkp_provider.as_ref());
    assert!(verify_old.is_err() || !verify_old.expect("verify result").is_ok());

    let tgt2_key = test_db_path(&temp, "tgt2.key");
    std::fs::write(&tgt2_key, [0x55u8; 32])?;
    let tgt2_provider = make_provider(&tgt2_key);
    let tgt2_keyring = Keyring::new(tgt2_provider);

    let restored2_path = test_db_path(&temp, "restored2.db");
    backup::restore_backup(
        &mut Cursor::new(&rotated_data),
        &restored2_path,
        new_provider.as_ref(),
        &tgt2_keyring,
    )?;

    let restored2_bytes = std::fs::read(&restored2_path)?;
    let tgt2_dek = tgt2_keyring.dek_for(&KeyScope::Database)?;
    let mut first_page = restored2_bytes[..page_size as usize].to_vec();
    page::decrypt_page(&mut first_page, 1, &tgt2_dek, reserve)?;
    assert!(
        first_page[..page_size as usize - reserve]
            .iter()
            .all(|&b| b == 0x41u8)
    );

    Ok(())
}
