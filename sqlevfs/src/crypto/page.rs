use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};

use super::keys::Dek;

pub const TAG_LEN: usize = 16;
pub const MARKER: &[u8; 6] = b"EVFSv1";
pub const MARKER_LEN: usize = 6;

fn ensure_reserve(reserve: usize) -> anyhow::Result<()> {
    anyhow::ensure!(
        reserve >= TAG_LEN + MARKER_LEN,
        "reserve ({reserve}) must be >= {} (tag+marker)",
        TAG_LEN + MARKER_LEN
    );
    Ok(())
}

pub fn is_encrypted_page(page: &[u8], reserve: usize) -> bool {
    if reserve < TAG_LEN + MARKER_LEN || page.len() < reserve {
        return false;
    }
    let payload_len = page.len() - reserve;
    let mr = (payload_len + TAG_LEN)..(payload_len + TAG_LEN + MARKER_LEN);
    page.get(mr) == Some(MARKER.as_slice())
}

fn marker_range(payload_len: usize) -> std::ops::Range<usize> {
    (payload_len + TAG_LEN)..(payload_len + TAG_LEN + MARKER_LEN)
}

/// Encrypt a database page in place.
pub fn encrypt_page(
    page: &mut [u8],
    page_no: u32,
    dek: &Dek,
    reserve: usize,
) -> anyhow::Result<()> {
    ensure_reserve(reserve)?;
    let page_len = page.len();
    let payload_len = page_len - reserve;

    let nonce_bytes = page_nonce(page_no);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(dek.as_bytes())?;

    // Encrypt the payload portion only.
    let ciphertext = cipher
        .encrypt(nonce, &page[..payload_len])
        .map_err(|e| anyhow::anyhow!("page encrypt failed: {e}"))?;

    // ciphertext = encrypted_payload || tag
    let ct_len = ciphertext.len() - TAG_LEN;
    debug_assert_eq!(ct_len, payload_len);

    page[..ct_len].copy_from_slice(&ciphertext[..ct_len]);
    page[payload_len..payload_len + TAG_LEN].copy_from_slice(&ciphertext[ct_len..]);

    // Write marker after tag.
    let mr = marker_range(payload_len);
    page[mr].copy_from_slice(MARKER);

    Ok(())
}

/// Decrypt a database page in place.
pub fn decrypt_page(
    page: &mut [u8],
    page_no: u32,
    dek: &Dek,
    reserve: usize,
) -> anyhow::Result<()> {
    ensure_reserve(reserve)?;
    let page_len = page.len();
    let payload_len = page_len - reserve;

    // Verify marker before attempting AEAD decrypt.
    let mr = marker_range(payload_len);
    anyhow::ensure!(
        page.get(mr.clone()) == Some(MARKER.as_slice()),
        "missing EVFS marker"
    );

    let nonce_bytes = page_nonce(page_no);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(dek.as_bytes())?;

    // Reassemble the ciphertext+tag buffer aes-gcm expects.
    let mut buf = Vec::with_capacity(payload_len + TAG_LEN);
    buf.extend_from_slice(&page[..payload_len]);
    buf.extend_from_slice(&page[payload_len..payload_len + TAG_LEN]);

    let plaintext = cipher
        .decrypt(nonce, buf.as_ref())
        .map_err(|e| anyhow::anyhow!("page decrypt failed: {e}"))?;

    page[..plaintext.len()].copy_from_slice(&plaintext);
    // Zero out the tag area in the reserved region.
    page[payload_len..payload_len + TAG_LEN].fill(0);
    // Keep marker intact (it's in reserved bytes and helps detect encryption).

    Ok(())
}

/// Deterministic nonce from page number.
fn page_nonce(page_no: u32) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[0..4].copy_from_slice(&page_no.to_le_bytes());
    n
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::Dek;

    #[test]
    fn round_trip() {
        let dek = Dek::generate();
        let reserve = 32;
        let page_size = 4096;
        let mut page = vec![0xABu8; page_size];
        let original = page.clone();

        encrypt_page(&mut page, 1, &dek, reserve).unwrap();
        assert_ne!(
            &page[..page_size - reserve],
            &original[..page_size - reserve]
        );

        decrypt_page(&mut page, 1, &dek, reserve).unwrap();
        assert_eq!(
            &page[..page_size - reserve],
            &original[..page_size - reserve]
        );
    }

    #[test]
    fn round_trip_basic() {
        let dek = Dek::generate();
        let reserve = 32;
        let page_size = 4096;
        let mut page = vec![0xABu8; page_size];
        let original = page.clone();

        encrypt_page(&mut page, 1, &dek, reserve).unwrap();
        assert_ne!(
            &page[..page_size - reserve],
            &original[..page_size - reserve]
        );

        decrypt_page(&mut page, 1, &dek, reserve).unwrap();
        assert_eq!(
            &page[..page_size - reserve],
            &original[..page_size - reserve]
        );
    }

    #[test]
    fn round_trip_reserve_equals_tag_len() {
        let dek = Dek::generate();
        let reserve = TAG_LEN + MARKER_LEN;
        let page_size = 4096;
        let mut page = vec![0xCDu8; page_size];
        let original = page.clone();

        encrypt_page(&mut page, 5, &dek, reserve).unwrap();
        assert_ne!(
            &page[..page_size - reserve],
            &original[..page_size - reserve]
        );

        decrypt_page(&mut page, 5, &dek, reserve).unwrap();
        assert_eq!(
            &page[..page_size - reserve],
            &original[..page_size - reserve]
        );
    }

    #[test]
    fn tag_placement() {
        let dek = Dek::generate();
        let reserve = TAG_LEN + MARKER_LEN;
        let page_size = 4096;
        let mut page = vec![0x42u8; page_size];
        let payload_len = page_size - reserve;

        encrypt_page(&mut page, 1, &dek, reserve).unwrap();

        // Tag should be at [payload_len..payload_len+TAG_LEN]
        let tag = &page[payload_len..payload_len + TAG_LEN];
        // All-zero tag is unlikely from AES-GCM
        assert!(!tag.iter().all(|b| *b == 0));
    }

    #[test]
    fn reserved_area_preserved_after_decrypt() {
        let dek = Dek::generate();
        let reserve = TAG_LEN + MARKER_LEN;
        let page_size = 4096;
        let mut page = vec![0xFFu8; page_size];
        let payload_len = page_size - reserve;

        encrypt_page(&mut page, 1, &dek, reserve).unwrap();

        decrypt_page(&mut page, 1, &dek, reserve).unwrap();

        // After decrypt, the tag area should be zeroed
        let reserved_after = page[payload_len..].to_vec();
        assert!(
            reserved_after[..TAG_LEN].iter().all(|b| *b == 0),
            "tag area should be zeroed"
        );
    }

    #[test]
    fn wrong_key_fails() {
        let dek1 = Dek::generate();
        let dek2 = Dek::generate();
        let reserve = TAG_LEN + MARKER_LEN;
        let mut page = vec![0xCDu8; 4096];

        encrypt_page(&mut page, 1, &dek1, reserve).unwrap();
        assert!(decrypt_page(&mut page, 1, &dek2, reserve).is_err());
    }

    #[test]
    fn wrong_page_no_fails() {
        let dek = Dek::generate();
        let reserve = TAG_LEN + MARKER_LEN;
        let mut page = vec![0xEFu8; 4096];

        encrypt_page(&mut page, 1, &dek, reserve).unwrap();
        assert!(decrypt_page(&mut page, 2, &dek, reserve).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let dek = Dek::generate();
        let reserve = TAG_LEN + MARKER_LEN;
        let page_size = 4096;
        let mut page = vec![0x55u8; page_size];

        encrypt_page(&mut page, 1, &dek, reserve).unwrap();

        // Tamper with the ciphertext
        page[100] ^= 0xFF;

        assert!(decrypt_page(&mut page, 1, &dek, reserve).is_err());
    }

    #[test]
    fn tampered_tag_fails() {
        let dek = Dek::generate();
        let reserve = TAG_LEN + MARKER_LEN;
        let page_size = 4096;
        let mut page = vec![0x77u8; page_size];
        let payload_len = page_size - reserve;

        encrypt_page(&mut page, 1, &dek, reserve).unwrap();

        // Tamper with the tag
        page[payload_len] ^= 0xFF;

        assert!(decrypt_page(&mut page, 1, &dek, reserve).is_err());
    }

    #[test]
    fn different_page_numbers_produce_different_ciphertexts() {
        let dek = Dek::generate();
        let reserve = TAG_LEN + MARKER_LEN;
        let page_size = 4096;

        let mut page1 = vec![0x99u8; page_size];
        let mut page2 = page1.clone();

        encrypt_page(&mut page1, 1, &dek, reserve).unwrap();
        encrypt_page(&mut page2, 2, &dek, reserve).unwrap();

        // Different page numbers should produce different ciphertexts
        // (due to different nonces)
        assert_ne!(page1, page2);
    }

    #[test]
    fn same_page_number_same_plaintext_produces_same_ciphertext() {
        let dek = Dek::generate();
        let reserve = TAG_LEN + MARKER_LEN;
        let page_size = 4096;

        let mut page1 = vec![0x88u8; page_size];
        let mut page2 = page1.clone();

        encrypt_page(&mut page1, 1, &dek, reserve).unwrap();
        encrypt_page(&mut page2, 1, &dek, reserve).unwrap();

        // Same page number and plaintext should produce identical ciphertext
        assert_eq!(page1, page2);
    }

    #[test]
    fn reserve_too_small_fails() {
        let dek = Dek::generate();
        let reserve = TAG_LEN + MARKER_LEN - 1;
        let mut page = vec![0x11u8; 4096];

        let result = encrypt_page(&mut page, 1, &dek, reserve);
        assert!(result.is_err());
    }

    #[test]
    fn large_page_size() {
        let dek = Dek::generate();
        let reserve = TAG_LEN + MARKER_LEN;
        let page_size = 65536;
        let mut page = vec![0x33u8; page_size];
        let original = page.clone();

        encrypt_page(&mut page, 10, &dek, reserve).unwrap();
        assert_ne!(page, original);

        decrypt_page(&mut page, 10, &dek, reserve).unwrap();
        assert_eq!(
            &page[..page_size - reserve],
            &original[..page_size - reserve]
        );
    }

    #[test]
    fn small_page_size() {
        let dek = Dek::generate();
        let reserve = TAG_LEN + MARKER_LEN;
        let page_size = 512;
        let mut page = vec![0x44u8; page_size];
        let original = page.clone();

        encrypt_page(&mut page, 15, &dek, reserve).unwrap();
        decrypt_page(&mut page, 15, &dek, reserve).unwrap();
        assert_eq!(
            &page[..page_size - reserve],
            &original[..page_size - reserve]
        );
    }

    #[test]
    fn page_nonce_deterministic() {
        let nonce1 = page_nonce(42);
        let nonce2 = page_nonce(42);
        assert_eq!(nonce1, nonce2);
    }

    #[test]
    fn page_nonce_different_for_different_pages() {
        let nonce1 = page_nonce(1);
        let nonce2 = page_nonce(2);
        assert_ne!(nonce1, nonce2);
    }

    #[test]
    fn marker_written_and_checked() {
        let dek = Dek::generate();
        let reserve = 48;
        let mut page = vec![0x11u8; 4096];

        encrypt_page(&mut page, 2, &dek, reserve).unwrap();
        assert!(is_encrypted_page(&page, reserve));

        decrypt_page(&mut page, 2, &dek, reserve).unwrap();
        // Marker should still be present after decrypt.
        assert!(is_encrypted_page(&page, reserve));
    }

    #[test]
    fn decrypt_without_marker_fails() {
        let dek = Dek::generate();
        let reserve = 48;
        let mut page = vec![0u8; 4096]; // plaintext / no marker
        assert!(decrypt_page(&mut page, 2, &dek, reserve).is_err());
    }
}
