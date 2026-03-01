//! Page-level encryption helpers used by the VFS layer.
//!
//! Wraps the lower-level `crypto::page` primitives behind a single
//! `PageCryptor` handle so that `vfs.rs` has no direct knowledge of
//! cipher details.

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use crate::{
    crypto::{
        keys::KeyScope,
        page::{decrypt_page, encrypt_page, is_encrypted_page},
    },
    keyring::Keyring,
};

/// Thin handle over a [`Keyring`] that provides page-level encrypt /
/// decrypt in the form the VFS layer expects.
#[derive(Clone)]
pub struct PageCryptor {
    keyring: Arc<Keyring>,
    pub page_size: u32,
    pub reserve_size: usize,
    page_scope_map: Arc<RwLock<HashMap<u32, KeyScope>>>,
}

impl PageCryptor {
    pub fn new(keyring: Arc<Keyring>, page_size: u32, reserve_size: usize) -> Self {
        Self {
            keyring,
            page_size,
            reserve_size,
            page_scope_map: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Encrypt `buf` in-place for the given 1-based `page_no`.
    ///
    /// Page 1 is intentionally never encrypted because SQLite reads its
    /// header without going through the VFS codec.
    pub fn encrypt(&self, buf: &mut [u8], page_no: u32) -> anyhow::Result<()> {
        debug_assert_ne!(page_no, 0, "page numbers are 1-based");
        debug_assert_ne!(page_no, 1, "caller must guard against encrypting page 1");
        let dek = self
            .keyring
            .dek_for_page(page_no, self.page_scope_map.read().ok().as_deref())?;
        encrypt_page(buf, page_no, &dek, self.reserve_size)
    }

    /// Decrypt `buf` in-place for the given 1-based `page_no`.
    ///
    /// Returns `Ok(false)` when the page is not encrypted (e.g. freshly
    /// initialised file), `Ok(true)` on success.
    pub fn decrypt(&self, buf: &mut [u8], page_no: u32) -> anyhow::Result<bool> {
        debug_assert_ne!(page_no, 0, "page numbers are 1-based");
        if !is_encrypted_page(buf, self.reserve_size) {
            return Ok(false);
        }
        let dek = self
            .keyring
            .dek_for_page(page_no, self.page_scope_map.read().ok().as_deref())?;
        decrypt_page(buf, page_no, &dek, self.reserve_size)?;
        Ok(true)
    }

    /// Returns `true` when `buf` looks like an encrypted page.
    #[inline]
    pub fn is_encrypted(&self, buf: &[u8]) -> bool {
        is_encrypted_page(buf, self.reserve_size)
    }

    /// Notify the keyring of the main DB path so it can locate its
    /// sidecar key file.
    pub fn set_db_path(&self, path: &std::path::Path) {
        self.keyring.set_sidecar_path(path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_not_encrypted_for_zeroed_page() {
        use std::sync::Arc;

        use crate::{crypto::keys::KekId, kms::KmsProvider};

        struct FakeKms;
        impl KmsProvider for FakeKms {
            fn get_kek(&self) -> anyhow::Result<(KekId, Vec<u8>)> {
                Ok((KekId("k".into()), vec![0u8; 32]))
            }

            fn get_kek_by_id(&self, _: &KekId) -> anyhow::Result<Vec<u8>> {
                Ok(vec![0u8; 32])
            }
        }

        let keyring = Arc::new(Keyring::new(Arc::new(FakeKms)));
        let cryptor = PageCryptor::new(keyring, 4096, 32);
        let buf = vec![0u8; 4096];
        assert!(!cryptor.is_encrypted(&buf));
    }
}
