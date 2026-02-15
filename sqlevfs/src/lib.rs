pub mod backup;
pub mod crypto;
pub mod policy;
pub mod io;
pub mod keyring;
pub mod kms;
pub mod vfs;

use std::{path::PathBuf, sync::Arc};

use keyring::Keyring;
use kms::KmsProvider;

/// Two high-level operational modes.
pub enum Mode {
    /// Single device - KEK from a local keyfile or passphrase.
    DeviceKey {
        keyfile: Option<PathBuf>,
        passphrase: Option<String>,
    },
    /// Multi-tenant SaaS - each tenant has a cloud KMS key.
    TenantKey {
        /// Cloud KMS key identifier (ARN, resource name, key URI, …).
        key_id: String,
        /// Region / endpoint override.
        endpoint: Option<String>,
    },
}

pub struct EvfsBuilder {
    pub name: String,
    pub page_size: u32,
    pub reserve_size: usize,
    pub provider: Arc<dyn KmsProvider>,
}

impl EvfsBuilder {
    pub fn new(mode: Mode) -> Self {
        let provider: Arc<dyn KmsProvider> = match mode {
            Mode::DeviceKey {
                keyfile,
                passphrase,
            } => {
                if let Some(path) = keyfile {
                    Arc::new(kms::local::DeviceKeyProvider::from_keyfile(path))
                } else if let Some(pw) = passphrase {
                    Arc::new(kms::local::DeviceKeyProvider::from_passphrase(&pw))
                } else {
                    panic!("DeviceKey mode requires keyfile or passphrase");
                }
            }
            Mode::TenantKey { key_id, endpoint } => {
                Arc::new(kms::cloud::CloudKmsProvider::new(key_id, endpoint))
            }
        };
        Self {
            name: "evfs".into(),
            page_size: 4096,
            reserve_size: 48, // 16 tag + 6 marker + 26 spare
            provider,
        }
    }

    pub fn page_size(mut self, size: u32) -> Self {
        self.page_size = size;
        self
    }

    pub fn reserve_size(mut self, size: usize) -> Self {
        self.reserve_size = size;
        self
    }

    pub fn vfs_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Register the VFS with SQLite. Returns the keyring for use with
    /// the backup API.
    pub fn register(self) -> anyhow::Result<Arc<Keyring>> {
        let keyring = Arc::new(Keyring::new(self.provider));
        vfs::register_evfs(
            &self.name,
            keyring.clone(),
            self.page_size,
            self.reserve_size,
        )?;
        Ok(keyring)
    }
}

/// Auto-register a default device-key VFS when loaded via LD_PRELOAD.
/// Set `EVFS_KEYFILE` or `EVFS_PASSPHRASE` to activate.
#[unsafe(no_mangle)]
pub extern "C" fn sqlite3_evfs_init(
    _db: *mut std::ffi::c_void,
    _err_msg: *mut *mut std::ffi::c_char,
    _api: *mut std::ffi::c_void,
) -> std::ffi::c_int {
    let _ = env_logger::try_init();

    let mode = if let Ok(path) = std::env::var("EVFS_KEYFILE") {
        Mode::DeviceKey {
            keyfile: Some(PathBuf::from(path)),
            passphrase: None,
        }
    } else if let Ok(pw) = std::env::var("EVFS_PASSPHRASE") {
        Mode::DeviceKey {
            keyfile: None,
            passphrase: Some(pw),
        }
    } else if let Ok(key_id) = std::env::var("EVFS_KMS_KEY_ID") {
        Mode::TenantKey {
            key_id,
            endpoint: std::env::var("EVFS_KMS_ENDPOINT").ok(),
        }
    } else {
        log::warn!("sqlite-evfs: no key source configured, not registering");
        return 1; // SQLITE_ERROR
    };

    match EvfsBuilder::new(mode).register() {
        Ok(_) => {
            log::info!("sqlite-evfs: VFS 'evfs' registered");
            0 // SQLITE_OK
        }
        Err(e) => {
            log::error!("sqlite-evfs: registration failed: {e}");
            1
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::{Arc, Mutex};

    use crate::{crypto::keys::KekId, kms::KmsProvider};

    // Mock KmsProvider for testing
    pub struct MockKmsProvider {
        pub wrap_count: Mutex<usize>,
        pub unwrap_count: Mutex<usize>,
    }

    impl MockKmsProvider {
        pub fn new() -> Arc<Self> {
            Arc::new(Self {
                wrap_count: Mutex::new(0),
                unwrap_count: Mutex::new(0),
            })
        }
    }

    impl KmsProvider for MockKmsProvider {
        fn get_kek(&self) -> anyhow::Result<(KekId, Vec<u8>)> {
            let kek_id = KekId("test".to_string());
            Ok((kek_id, vec![0xAA; 32])) // Dummy KEK
        }

        fn get_kek_by_id(&self, _id: &KekId) -> anyhow::Result<Vec<u8>> {
            Ok(vec![0xBB; 32]) // Dummy KEK
        }

        fn wrap_blob(&self, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
            *self.wrap_count.lock().unwrap() += 1;
            // Simple mock: prepend marker byte
            let mut result = vec![0xFF];
            result.extend_from_slice(plaintext);
            Ok(result)
        }

        fn unwrap_blob(&self, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
            *self.unwrap_count.lock().unwrap() += 1;
            // Simple mock: strip marker byte
            if ciphertext.is_empty() || ciphertext[0] != 0xFF {
                anyhow::bail!("invalid mock ciphertext")
            }
            Ok(ciphertext[1..].to_vec())
        }
    }
}
