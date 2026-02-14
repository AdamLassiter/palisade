use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use parking_lot::RwLock;

use crate::{
    crypto::{
        envelope,
        keys::{Dek, KeyScope, WrappedDek},
    },
    kms::KmsProvider,
};

/// On-disk format: only wrapped DEKs, never plaintext.
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct PersistedKeyring {
    pub keys: HashMap<String, WrappedDek>,
}

/// Runtime keyring — holds unwrapped DEKs in memory.
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
            && let Ok(kr) = serde_json::from_slice::<PersistedKeyring>(&data)
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
            if let Ok(data) = serde_json::to_vec_pretty(&*persisted) {
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

        // Slow path — acquire write lock.
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
