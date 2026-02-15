//! Helpers used by the VFS I/O layer.

use std::{collections::HashMap, sync::Arc};

use crate::{
    crypto::{
        keys::KeyScope,
        page::{decrypt_page, encrypt_page},
    },
    keyring::Keyring,
};

/// Shared context carried by every open file handle.
pub struct FileContext {
    pub keyring: Arc<Keyring>,
    pub page_size: u32,
    pub reserve_size: usize,
    pub encrypt_enabled: bool,
    /// Lazily-built map from btree root page → KeyScope.
    /// `None` means "use Database scope for everything".
    pub page_scope_map: Option<HashMap<u32, KeyScope>>,
}

impl FileContext {
    pub fn encrypt_page(&self, page: &mut [u8], page_no: u32) -> anyhow::Result<()> {
        let dek = self
            .keyring
            .dek_for_page(page_no, self.page_scope_map.as_ref())?;
        encrypt_page(page, page_no, &dek, self.reserve_size)
    }

    pub fn decrypt_page(&self, page: &mut [u8], page_no: u32) -> anyhow::Result<()> {
        let dek = self
            .keyring
            .dek_for_page(page_no, self.page_scope_map.as_ref())?;
        decrypt_page(page, page_no, &dek, self.reserve_size)
    }

    /// Build the page→scope map by querying sqlite_master.
    ///
    /// Called lazily on first read/write if per-table encryption is
    /// enabled. Requires a separate read of page 1 (the schema
    /// table) which is always encrypted under `KeyScope::Database`.
    pub fn build_page_scope_map(&mut self, root_pages: &[(String, u32)]) {
        let mut map = HashMap::new();
        for (table_name, root_page) in root_pages {
            map.insert(*root_page, KeyScope::Table(table_name.clone()));
        }
        self.page_scope_map = Some(map);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto::keys::KeyScope, tests::MockKmsProvider};

    // Helper to create a test FileContext
    fn create_test_context(with_map: bool) -> FileContext {
        let provider = MockKmsProvider::new();
        let keyring = Arc::new(Keyring::new(provider));

        let mut ctx = FileContext {
            keyring,
            page_size: 4096,
            reserve_size: 24,
            encrypt_enabled: true,
            page_scope_map: None,
        };

        if with_map {
            ctx.build_page_scope_map(&[("users".to_string(), 10), ("posts".to_string(), 20)]);
        }

        ctx
    }

    #[test]
    fn test_file_context_creation() {
        let ctx = create_test_context(false);
        assert_eq!(ctx.page_size, 4096);
        assert_eq!(ctx.reserve_size, 24);
        assert!(ctx.page_scope_map.is_none());
    }

    #[test]
    fn test_build_page_scope_map() {
        let mut ctx = create_test_context(false);
        assert!(ctx.page_scope_map.is_none());

        ctx.build_page_scope_map(&[
            ("users".to_string(), 10),
            ("posts".to_string(), 20),
            ("comments".to_string(), 30),
        ]);

        let map = ctx.page_scope_map.as_ref().unwrap();
        assert_eq!(map.len(), 3);
        assert_eq!(map.get(&10), Some(&KeyScope::Table("users".to_string())));
        assert_eq!(map.get(&20), Some(&KeyScope::Table("posts".to_string())));
        assert_eq!(map.get(&30), Some(&KeyScope::Table("comments".to_string())));
    }

    #[test]
    fn test_build_page_scope_map_empty() {
        let mut ctx = create_test_context(false);
        ctx.build_page_scope_map(&[]);

        let map = ctx.page_scope_map.as_ref().unwrap();
        assert_eq!(map.len(), 0);
    }

    #[test]
    fn test_encrypt_page_without_scope_map() -> Result<(), anyhow::Error> {
        let ctx = create_test_context(false);
        let mut page = vec![0u8; 4096];

        // Should succeed without scope map (uses Database scope)
        ctx.encrypt_page(&mut page, 1)?;
        Ok(())
    }

    #[test]
    fn test_encrypt_page_with_scope_map() -> Result<(), anyhow::Error> {
        let ctx = create_test_context(true);
        let mut page = vec![0u8; 4096];

        // Should succeed with scope map for mapped page
        ctx.encrypt_page(&mut page, 10)?;
        Ok(())
    }

    #[test]
    fn test_encrypt_unmapped_page_falls_back_to_database_scope() -> Result<(), anyhow::Error> {
        let ctx = create_test_context(true);
        let mut page = vec![0u8; 4096];

        // Page 99 not in map, should still work (uses Database scope)
        ctx.encrypt_page(&mut page, 99)?;
        Ok(())
    }

    #[test]
    fn test_decrypt_page_without_scope_map() {
        let ctx = create_test_context(false);
        let mut page = vec![0xAAu8; 4096];
        let original = page.clone();

        // Must encrypt first
        ctx.encrypt_page(&mut page, 1).unwrap();
        assert_ne!(page, original);

        // Now decrypt
        let result = ctx.decrypt_page(&mut page, 1);
        assert!(result.is_ok());
        // Verify plaintext is restored
        assert_eq!(
            &page[..4096 - ctx.reserve_size],
            &original[..4096 - ctx.reserve_size]
        );
    }

    #[test]
    fn test_decrypt_page_with_scope_map() {
        let ctx = create_test_context(true);
        let mut page = vec![0xBBu8; 4096];
        let original = page.clone();

        // Encrypt first
        ctx.encrypt_page(&mut page, 10).unwrap();
        assert_ne!(page, original);

        // Now decrypt
        let result = ctx.decrypt_page(&mut page, 10);
        assert!(result.is_ok());
        assert_eq!(
            &page[..4096 - ctx.reserve_size],
            &original[..4096 - ctx.reserve_size]
        );
    }

    #[test]
    fn test_decrypt_unmapped_page_falls_back_to_database_scope() {
        let ctx = create_test_context(true);
        let mut page = vec![0xCCu8; 4096];
        let original = page.clone();

        // Encrypt unmapped page (uses Database scope)
        ctx.encrypt_page(&mut page, 99).unwrap();

        // Decrypt same unmapped page
        let result = ctx.decrypt_page(&mut page, 99);
        assert!(result.is_ok());
        assert_eq!(
            &page[..4096 - ctx.reserve_size],
            &original[..4096 - ctx.reserve_size]
        );
    }

    #[test]
    fn test_encrypt_decrypt_round_trip_with_scope_map() {
        let ctx = create_test_context(true);
        let mut page = vec![0xDDu8; 4096];
        let original = page.clone();

        // Encrypt page 10 (users table)
        ctx.encrypt_page(&mut page, 10).unwrap();
        assert_ne!(page, original);

        // Decrypt page 10
        ctx.decrypt_page(&mut page, 10).unwrap();
        assert_eq!(
            &page[..4096 - ctx.reserve_size],
            &original[..4096 - ctx.reserve_size]
        );
    }

    #[test]
    fn test_multiple_encrypts_same_page() -> Result<(), anyhow::Error> {
        let ctx = create_test_context(false);
        let mut page1 = vec![42u8; 4096];
        let mut page2 = page1.clone();

        // Encrypt same page number twice, should use cached DEK
        ctx.encrypt_page(&mut page1, 5)?;
        ctx.encrypt_page(&mut page2, 5)?;

        Ok(())
    }

    #[test]
    fn test_different_pages_different_scopes() -> Result<(), anyhow::Error> {
        let ctx = create_test_context(true);
        let mut page1 = vec![0u8; 4096];
        let mut page2 = vec![0u8; 4096];

        // Different mapped pages should resolve to different scopes
        ctx.encrypt_page(&mut page1, 10)?; // users table
        ctx.encrypt_page(&mut page2, 20)?; // posts table

        Ok(())
    }

    #[test]
    fn test_page_scope_map_overwrite() {
        let mut ctx = create_test_context(false);

        ctx.build_page_scope_map(&[("users".to_string(), 10)]);
        let map1 = ctx.page_scope_map.as_ref().unwrap().clone();

        // Rebuild with different data
        ctx.build_page_scope_map(&[("posts".to_string(), 20), ("comments".to_string(), 30)]);
        let map2 = ctx.page_scope_map.as_ref().unwrap().clone();

        assert_ne!(map1, map2);
        assert_eq!(map1.len(), 1);
        assert_eq!(map2.len(), 2);
        assert!(map2.contains_key(&20));
        assert!(map2.contains_key(&30));
    }
}
