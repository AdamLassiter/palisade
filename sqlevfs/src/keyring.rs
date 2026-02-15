use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use bincode::config;
use parking_lot::RwLock;

use crate::{
    crypto::{
        envelope,
        keys::{Dek, KeyScope, WrappedDek},
    },
    kms::KmsProvider,
};

/// On-disk format: only wrapped DEKs, never plaintext.
#[derive(Clone, Default, bincode::Encode, bincode::Decode)]
pub struct PersistedKeyring {
    pub keys: HashMap<String, WrappedDek>,
}

/// Runtime keyring - holds unwrapped DEKs in memory.
pub struct Keyring {
    provider: Arc<dyn KmsProvider>,
    /// scope-string → plaintext DEK (zeroized on drop).
    cache: RwLock<HashMap<String, Dek>>,
    /// On-disk representation (wrapped DEKs).
    persisted: RwLock<PersistedKeyring>,
    /// Optional path to persist the keyring sidecar.
    sidecar_path: RwLock<Option<PathBuf>>,
}

impl Keyring {
    pub fn new(provider: Arc<dyn KmsProvider>) -> Self {
        Self {
            provider,
            cache: RwLock::new(HashMap::new()),
            persisted: RwLock::new(PersistedKeyring::default()),
            sidecar_path: RwLock::new(None),
        }
    }

    /// Bind this keyring to a sidecar file next to the database.
    /// Called when the VFS opens a database file.
    pub fn set_sidecar_path(&self, db_path: &Path) {
        let mut guard = self.sidecar_path.write();
        let sidecar = db_path.with_extension("evfs-keyring");
        // Try to load existing keyring.
        if sidecar.exists()
            && let Ok(data) = std::fs::read(&sidecar)
            && let Ok(kr) = bincode::decode_from_slice(&data, config::standard()).map(|r| r.0)
        {
            *self.persisted.write() = kr;
        }
        *guard = Some(sidecar);
    }

    /// Flush wrapped DEKs to the sidecar file.
    fn flush(&self) {
        let guard = self.sidecar_path.read();
        if let Some(ref path) = *guard {
            let persisted = self.persisted.read();
            if let Ok(data) = bincode::encode_to_vec(&*persisted, config::standard()) {
                let _ = std::fs::write(path, data);
            }
        }
    }

    /// Get or create the DEK for a given scope.
    pub fn dek_for(&self, scope: &KeyScope) -> anyhow::Result<Dek> {
        let key = scope.to_string();

        // Fast path.
        {
            let cache = self.cache.read();
            if let Some(dek) = cache.get(&key) {
                return Ok(dek.clone());
            }
        }

        // Slow path - acquire write lock.
        let mut cache = self.cache.write();
        // Double-check.
        if let Some(dek) = cache.get(&key) {
            return Ok(dek.clone());
        }

        let dek = {
            let persisted = self.persisted.read();
            if let Some(wrapped) = persisted.keys.get(&key) {
                envelope::unwrap_dek(wrapped, self.provider.as_ref())?
            } else {
                drop(persisted);
                let dek = Dek::generate();
                let wrapped = envelope::wrap_dek(&dek, self.provider.as_ref())?;
                self.persisted.write().keys.insert(key.clone(), wrapped);
                self.flush();
                dek
            }
        };

        cache.insert(key, dek.clone());
        Ok(dek)
    }

    /// Resolve which DEK to use for a given page number.
    ///
    /// `page_scope_map` maps root page numbers to scopes (built from
    /// sqlite_master). Pages not in the map use `Database` scope.
    pub fn dek_for_page(
        &self,
        page_no: u32,
        page_scope_map: Option<&HashMap<u32, KeyScope>>,
    ) -> anyhow::Result<Dek> {
        let scope = page_scope_map
            .and_then(|m| m.get(&page_no))
            .cloned()
            .unwrap_or(KeyScope::Database);
        self.dek_for(&scope)
    }

    /// Re-wrap all DEKs under the current KEK. Call this after a KEK
    /// rotation to update the persisted keyring.
    pub fn rewrap_all(&self) -> anyhow::Result<()> {
        let cache = self.cache.read();
        let mut persisted = self.persisted.write();
        for (scope_key, dek) in cache.iter() {
            let wrapped = envelope::wrap_dek(dek, self.provider.as_ref())?;
            persisted.keys.insert(scope_key.clone(), wrapped);
        }
        drop(persisted);
        drop(cache);
        self.flush();
        Ok(())
    }

    pub fn provider(&self) -> &dyn KmsProvider {
        self.provider.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::MockKmsProvider;

    #[test]
    fn test_new_keyring() {
        let provider = MockKmsProvider::new();
        let keyring = Keyring::new(provider.clone());
        assert_eq!(keyring.cache.read().len(), 0);
        assert_eq!(keyring.persisted.read().keys.len(), 0);
    }

    #[test]
    fn test_dek_for_new_scope() {
        let provider = MockKmsProvider::new();
        let keyring = Keyring::new(provider.clone());
        let scope = KeyScope::Database;

        let _dek = keyring.dek_for(&scope).unwrap();
        assert_eq!(keyring.cache.read().len(), 1);
        // DEK should be persisted (wrapped)
        assert_eq!(keyring.persisted.read().keys.len(), 1);
    }

    #[test]
    fn test_dek_cache_hit() {
        let provider = MockKmsProvider::new();
        let keyring = Keyring::new(provider.clone());
        let scope = KeyScope::Database;

        let dek1 = keyring.dek_for(&scope).unwrap();
        let wrap_count = *provider.wrap_count.lock().unwrap();

        let dek2 = keyring.dek_for(&scope).unwrap();
        // Should use cached DEK, no additional wrap
        assert_eq!(*provider.wrap_count.lock().unwrap(), wrap_count);
        assert_eq!(dek1, dek2);
    }

    #[test]
    fn test_multiple_scopes() {
        let provider = MockKmsProvider::new();
        let keyring = Keyring::new(provider.clone());

        let db_scope = KeyScope::Database;
        let table_scope = KeyScope::Table("users".to_string());

        let dek_db = keyring.dek_for(&db_scope).unwrap();
        let dek_table = keyring.dek_for(&table_scope).unwrap();

        // DEKs should be different
        assert_ne!(dek_db, dek_table);
        assert_eq!(keyring.cache.read().len(), 2);
        assert_eq!(keyring.persisted.read().keys.len(), 2);
    }

    #[test]
    fn test_dek_for_page_default_scope() {
        let provider = MockKmsProvider::new();
        let keyring = Keyring::new(provider.clone());

        let dek = keyring.dek_for_page(42, None).unwrap();
        // Should use Database scope when no map provided
        let dek_db = keyring.dek_for(&KeyScope::Database).unwrap();
        assert_eq!(dek, dek_db);
    }

    #[test]
    fn test_dek_for_page_with_map() {
        let provider = MockKmsProvider::new();
        let keyring = Keyring::new(provider.clone());

        let mut page_map = HashMap::new();
        let table_scope = KeyScope::Table("users".to_string());
        page_map.insert(42, table_scope.clone());

        let dek_page = keyring.dek_for_page(42, Some(&page_map)).unwrap();
        let dek_scope = keyring.dek_for(&table_scope).unwrap();
        assert_eq!(dek_page, dek_scope);

        // Page not in map should use Database scope
        let dek_unmapped = keyring.dek_for_page(99, Some(&page_map)).unwrap();
        let dek_db = keyring.dek_for(&KeyScope::Database).unwrap();
        assert_eq!(dek_unmapped, dek_db);
    }

    #[test]
    fn test_rewrap_all() {
        let provider = MockKmsProvider::new();
        let keyring = Keyring::new(provider.clone());

        keyring.dek_for(&KeyScope::Database).unwrap();
        keyring.dek_for(&KeyScope::Table("t1".to_string())).unwrap();

        let persisted_before = keyring.persisted.read().keys.clone();
        let keys_before: Vec<_> = persisted_before.values().cloned().collect();

        keyring.rewrap_all().unwrap();

        let persisted_after = keyring.persisted.read().keys.clone();
        let keys_after: Vec<_> = persisted_after.values().cloned().collect();

        // Should have same number of keys, but wrapped values changed
        assert_eq!(keys_before.len(), keys_after.len());
        assert_eq!(keys_before.len(), 2);
        // Values should differ (re-wrapped under potentially new KEK)
        assert_ne!(keys_before, keys_after);
    }

    #[test]
    fn test_provider_access() {
        let provider = MockKmsProvider::new();
        let keyring = Keyring::new(provider.clone());
        let _ = keyring.provider();
    }
}
