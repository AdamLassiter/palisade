//! Encrypted backup / restore.
//!
//! Backup files are self-contained: the header carries the wrapped
//! DEK so the backup can be restored anywhere the backup KEK is
//! available.

use std::{
    io::{Read, Write},
    path::Path,
};

use bincode::config;

use crate::{
    crypto::{
        envelope,
        keys::{Dek, WrappedDek},
        page as page_crypto,
    },
    keyring::Keyring,
    kms::KmsProvider,
};

const BACKUP_MAGIC: &[u8; 8] = b"EVFSBKUP";
const BACKUP_VERSION: u32 = 1;

/// Header at the start of every backup file.
#[derive(bincode::Encode, bincode::Decode)]
pub struct BackupHeader {
    pub version: u32,
    pub page_size: u32,
    pub page_count: u32,
    pub reserve_size: u32,
    /// The backup DEK, wrapped under the backup KEK.
    pub wrapped_dek: WrappedDek,
}

/// Create an encrypted backup.
///
/// Reads the source database (which is already encrypted on disk),
/// decrypts each page with the source keyring, re-encrypts under a
/// fresh backup DEK, and writes the result to `dest`.
pub fn create_backup(
    source_path: &Path,
    dest: &mut dyn Write,
    source_keyring: &Keyring,
    backup_kms: &dyn KmsProvider,
    page_size: u32,
    reserve: usize,
) -> anyhow::Result<()> {
    let raw = std::fs::read(source_path)?;
    anyhow::ensure!(
        raw.len() % page_size as usize == 0,
        "database size {} is not a multiple of page_size {page_size}",
        raw.len()
    );
    let page_count = raw.len() / page_size as usize;

    // Fresh DEK for the backup.
    let backup_dek = Dek::generate();
    let wrapped = envelope::wrap_dek(&backup_dek, backup_kms)?;

    let header = BackupHeader {
        version: BACKUP_VERSION,
        page_size,
        page_count: page_count as u32,
        reserve_size: reserve as u32,
        wrapped_dek: wrapped,
    };
    let mut header_bytes = vec![0u8; 2048];
    bincode::encode_into_slice(&header, &mut header_bytes, config::standard())?;

    // Write magic + header-length + header.
    dest.write_all(BACKUP_MAGIC)?;
    dest.write_all(&(header_bytes.len() as u32).to_le_bytes())?;
    dest.write_all(&header_bytes)?;

    // Process each page.
    for i in 0..page_count {
        let offset = i * page_size as usize;
        let mut page_buf = raw[offset..offset + page_size as usize].to_vec();
        let page_no = i as u32 + 1;

        // Skip decryption for page 1 if it's a fresh/plaintext DB.
        let needs_decrypt = !(page_no == 1 && is_plaintext_header(&page_buf));

        if needs_decrypt {
            let src_dek = source_keyring.dek_for(&crate::crypto::keys::KeyScope::Database)?;
            page_crypto::decrypt_page(&mut page_buf, page_no, &src_dek, reserve)?;
        }

        // Re-encrypt under backup DEK.
        page_crypto::encrypt_page(&mut page_buf, page_no, &backup_dek, reserve)?;

        dest.write_all(&page_buf)?;
    }

    dest.flush()?;
    log::info!("backup created: {page_count} pages");
    Ok(())
}

/// Restore from an encrypted backup.
///
/// Decrypts each page with the backup DEK (unwrapped via
/// `backup_kms`), then re-encrypts under the target keyring's
/// current DEK, and writes the restored database to `target_path`.
pub fn restore_backup(
    source: &mut dyn Read,
    target_path: &Path,
    backup_kms: &dyn KmsProvider,
    target_keyring: &Keyring,
) -> anyhow::Result<()> {
    // Read and validate magic.
    let mut magic = [0u8; 8];
    source.read_exact(&mut magic)?;
    anyhow::ensure!(&magic == BACKUP_MAGIC, "invalid backup file: bad magic");

    // Read header.
    let mut hdr_len_buf = [0u8; 4];
    source.read_exact(&mut hdr_len_buf)?;
    let hdr_len = u32::from_le_bytes(hdr_len_buf) as usize;
    anyhow::ensure!(hdr_len < 1024 * 1024, "header too large: {hdr_len}");

    let mut hdr_buf = vec![0u8; hdr_len];
    source.read_exact(&mut hdr_buf)?;
    let header: BackupHeader = bincode::decode_from_slice(&hdr_buf, config::standard())?.0;
    anyhow::ensure!(
        header.version == BACKUP_VERSION,
        "unsupported backup version: {}",
        header.version
    );

    let page_size = header.page_size as usize;
    let reserve = header.reserve_size as usize;
    let page_count = header.page_count as usize;

    // Unwrap the backup DEK.
    let backup_dek = envelope::unwrap_dek(&header.wrapped_dek, backup_kms)?;

    // Ensure the target keyring has a database DEK ready.
    let target_dek = target_keyring.dek_for(&crate::crypto::keys::KeyScope::Database)?;

    let mut output = Vec::with_capacity(page_count * page_size);

    for i in 0..page_count {
        let mut page_buf = vec![0u8; page_size];
        source.read_exact(&mut page_buf)?;
        let page_no = i as u32 + 1;

        // Decrypt with backup DEK.
        page_crypto::decrypt_page(&mut page_buf, page_no, &backup_dek, reserve)?;

        // Re-encrypt with target DEK.
        page_crypto::encrypt_page(&mut page_buf, page_no, &target_dek, reserve)?;

        output.extend_from_slice(&page_buf);
    }

    std::fs::write(target_path, &output)?;
    log::info!(
        "backup restored: {page_count} pages -> {}",
        target_path.display()
    );
    Ok(())
}

/// Verify a backup's integrity without fully restoring it.
///
/// Unwraps the DEK and attempts to decrypt every page, checking
/// that the AES-GCM auth tags validate.
pub fn verify_backup(
    source: &mut dyn Read,
    backup_kms: &dyn KmsProvider,
) -> anyhow::Result<VerifyResult> {
    let mut magic = [0u8; 8];
    source.read_exact(&mut magic)?;
    anyhow::ensure!(&magic == BACKUP_MAGIC, "bad magic");

    let mut hdr_len_buf = [0u8; 4];
    source.read_exact(&mut hdr_len_buf)?;
    let hdr_len = u32::from_le_bytes(hdr_len_buf) as usize;

    let mut hdr_buf = vec![0u8; hdr_len];
    source.read_exact(&mut hdr_buf)?;
    let header: BackupHeader = bincode::decode_from_slice(&hdr_buf, config::standard())?.0;

    let page_size = header.page_size as usize;
    let reserve = header.reserve_size as usize;
    let page_count = header.page_count as usize;

    let backup_dek = envelope::unwrap_dek(&header.wrapped_dek, backup_kms)?;

    let mut pages_ok: u32 = 0;
    let mut pages_bad: u32 = 0;

    for i in 0..page_count {
        let mut page_buf = vec![0u8; page_size];
        source.read_exact(&mut page_buf)?;
        let page_no = i as u32 + 1;

        match page_crypto::decrypt_page(&mut page_buf, page_no, &backup_dek, reserve) {
            Ok(()) => pages_ok += 1,
            Err(e) => {
                log::warn!("verify: page {page_no} failed: {e}");
                pages_bad += 1;
            }
        }
    }

    Ok(VerifyResult {
        page_count: page_count as u32,
        pages_ok,
        pages_bad,
    })
}

#[derive(Debug)]
pub struct VerifyResult {
    pub page_count: u32,
    pub pages_ok: u32,
    pub pages_bad: u32,
}

impl VerifyResult {
    pub fn is_ok(&self) -> bool {
        self.pages_bad == 0
    }
}

/// Rotate backup encryption: re-wrap the backup DEK under a new KEK
/// without re-encrypting every page.
///
/// This is O(1) - only the header is rewritten.
pub fn rotate_backup_kek(
    backup_path: &Path,
    old_kms: &dyn KmsProvider,
    new_kms: &dyn KmsProvider,
) -> anyhow::Result<()> {
    let data = std::fs::read(backup_path)?;
    anyhow::ensure!(
        data.len() >= 12 && &data[0..8] == BACKUP_MAGIC,
        "not a valid backup file"
    );

    let hdr_len = u32::from_le_bytes(data[8..12].try_into()?) as usize;
    let hdr_buf = &data[12..12 + hdr_len];
    let header: BackupHeader = bincode::decode_from_slice(hdr_buf, config::standard())?.0;

    // Unwrap DEK with old KEK, re-wrap with new KEK.
    let dek = envelope::unwrap_dek(&header.wrapped_dek, old_kms)?;
    let new_wrapped = envelope::wrap_dek(&dek, new_kms)?;

    let new_header = BackupHeader {
        wrapped_dek: new_wrapped,
        ..header
    };
    let mut new_hdr_bytes = vec![0u8; 2048];
    bincode::encode_into_slice(&new_header, &mut new_hdr_bytes, config::standard())?;

    // Rewrite the file: magic + new header + same page data.
    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(BACKUP_MAGIC);
    out.extend_from_slice(&(new_hdr_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&new_hdr_bytes);
    out.extend_from_slice(&data[12 + hdr_len..]);

    std::fs::write(backup_path, &out)?;
    log::info!("backup KEK rotated for {}", backup_path.display());
    Ok(())
}

fn is_plaintext_header(page: &[u8]) -> bool {
    page.len() >= 16 && &page[0..16] == b"SQLite format 3\0"
}

#[cfg(test)]
mod tests {
    use std::{io::Cursor, sync::Arc};

    use super::*;
    use crate::{crypto::keys::KeyScope, keyring::Keyring, kms::local::DeviceKeyProvider};

    fn test_provider(key: [u8; 32]) -> Arc<dyn KmsProvider> {
        // Write a temp keyfile.
        let dir = std::env::temp_dir().join("evfs-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!(
            "test-key-{}.bin",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, key).unwrap();
        Arc::new(DeviceKeyProvider::from_keyfile(path))
    }

    #[test]
    fn backup_round_trip() {
        let page_size: u32 = 4096;
        let reserve: usize = 32;
        let page_count = 4;

        // Create a fake encrypted database.
        let src_provider = test_provider([0xAA; 32]);
        let src_keyring = Arc::new(Keyring::new(src_provider.clone()));
        let src_dek = src_keyring.dek_for(&KeyScope::Database).unwrap();

        let mut db_bytes = vec![0u8; page_count * page_size as usize];
        for i in 0..page_count {
            let offset = i * page_size as usize;
            // Fill with recognizable pattern.
            let pattern = (i as u8).wrapping_add(1);
            db_bytes[offset..offset + page_size as usize - reserve].fill(pattern);
            let page_no = i as u32 + 1;
            crate::crypto::page::encrypt_page(
                &mut db_bytes[offset..offset + page_size as usize],
                page_no,
                &src_dek,
                reserve,
            )
            .unwrap();
        }

        // Write fake DB to disk.
        let dir = std::env::temp_dir().join("evfs-backup-test");
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("test.db");
        std::fs::write(&db_path, &db_bytes).unwrap();

        // Create backup.
        let backup_provider = test_provider([0xBB; 32]);
        let mut backup_buf = Vec::new();
        create_backup(
            &db_path,
            &mut backup_buf,
            &src_keyring,
            backup_provider.as_ref(),
            page_size,
            reserve,
        )
        .unwrap();

        // Verify backup.
        let verify =
            verify_backup(&mut Cursor::new(&backup_buf), backup_provider.as_ref()).unwrap();
        assert!(verify.is_ok());
        assert_eq!(verify.page_count, page_count as u32);

        // Restore backup to a new DB with a different key.
        let tgt_provider = test_provider([0xCC; 32]);
        let tgt_keyring = Arc::new(Keyring::new(tgt_provider.clone()));
        let restored_path = dir.join("restored.db");

        restore_backup(
            &mut Cursor::new(&backup_buf),
            &restored_path,
            backup_provider.as_ref(),
            &tgt_keyring,
        )
        .unwrap();

        // Verify restored DB decrypts correctly.
        let restored_bytes = std::fs::read(&restored_path).unwrap();
        let tgt_dek = tgt_keyring.dek_for(&KeyScope::Database).unwrap();

        for i in 0..page_count {
            let offset = i * page_size as usize;
            let mut page = restored_bytes[offset..offset + page_size as usize].to_vec();
            let page_no = i as u32 + 1;
            crate::crypto::page::decrypt_page(&mut page, page_no, &tgt_dek, reserve).unwrap();
            let expected = (i as u8).wrapping_add(1);
            assert!(
                page[..page_size as usize - reserve]
                    .iter()
                    .all(|&b| b == expected),
                "page {page_no} content mismatch after restore"
            );
        }

        // Cleanup.
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn kek_rotation_preserves_data() {
        let page_size: u32 = 4096;
        let reserve: usize = 32;

        let src_provider = test_provider([0x11; 32]);
        let src_keyring = Arc::new(Keyring::new(src_provider.clone()));
        let src_dek = src_keyring.dek_for(&KeyScope::Database).unwrap();

        let mut db_bytes = vec![0x42u8; page_size as usize];
        crate::crypto::page::encrypt_page(&mut db_bytes, 1, &src_dek, reserve).unwrap();

        let dir = std::env::temp_dir().join("evfs-rotate-test");
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("test.db");
        std::fs::write(&db_path, &db_bytes).unwrap();

        let old_kms = test_provider([0x22; 32]);
        let new_kms = test_provider([0x33; 32]);

        // Create backup with old KEK.
        let backup_path = dir.join("test.evfs-backup");
        let mut f = std::fs::File::create(&backup_path).unwrap();
        create_backup(
            &db_path,
            &mut f,
            &src_keyring,
            old_kms.as_ref(),
            page_size,
            reserve,
        )
        .unwrap();
        drop(f);

        // Rotate the backup KEK.
        rotate_backup_kek(&backup_path, old_kms.as_ref(), new_kms.as_ref()).unwrap();

        // Verify with new KEK succeeds.
        let data = std::fs::read(&backup_path).unwrap();
        let result = verify_backup(&mut Cursor::new(&data), new_kms.as_ref()).unwrap();
        assert!(result.is_ok());

        // Verify with old KEK fails.
        let result = verify_backup(&mut Cursor::new(&data), old_kms.as_ref());
        assert!(result.is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
