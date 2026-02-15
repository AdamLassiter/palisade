use std::path::PathBuf;

use argon2::Argon2;
use parking_lot::Mutex;

use super::KmsProvider;
use crate::crypto::keys::KekId;

/// Device-local KEK provider. Reads a 32-byte key from a file, or
/// derives one from a passphrase via Argon2id.
pub struct DeviceKeyProvider {
    id: KekId,
    /// Cached KEK bytes - computed once, then reused.
    cached: Mutex<Option<Vec<u8>>>,
    source: KeySource,
}

enum KeySource {
    File(PathBuf),
    Passphrase(String),
}

/// Fixed salt for passphrase derivation. In production, store a
/// random salt alongside the database and pass it in.
const DEFAULT_SALT: &[u8; 16] = b"evfs-default-slt";

impl DeviceKeyProvider {
    pub fn from_keyfile(path: PathBuf) -> Self {
        let id = KekId(format!("device:file:{}", path.display()));
        Self {
            id,
            cached: Mutex::new(None),
            source: KeySource::File(path),
        }
    }

    pub fn from_passphrase(passphrase: &str) -> Self {
        let id = KekId("device:passphrase".into());
        Self {
            id,
            cached: Mutex::new(None),
            source: KeySource::Passphrase(passphrase.to_owned()),
        }
    }

    fn load_kek(&self) -> anyhow::Result<Vec<u8>> {
        match &self.source {
            KeySource::File(path) => {
                let bytes = std::fs::read(path)?;
                anyhow::ensure!(
                    bytes.len() == 32,
                    "keyfile must be exactly 32 bytes, got {}",
                    bytes.len()
                );
                Ok(bytes)
            }
            KeySource::Passphrase(pw) => {
                let mut kek = [0u8; 32];
                Argon2::default()
                    .hash_password_into(pw.as_bytes(), DEFAULT_SALT, &mut kek)
                    .map_err(|e| anyhow::anyhow!("argon2 failed: {e}"))?;
                Ok(kek.to_vec())
            }
        }
    }

    fn get_cached_or_load(&self) -> anyhow::Result<Vec<u8>> {
        let mut guard = self.cached.lock();
        if let Some(ref cached) = *guard {
            return Ok(cached.clone());
        }
        let kek = self.load_kek()?;
        *guard = Some(kek.clone());
        Ok(kek)
    }
}

impl KmsProvider for DeviceKeyProvider {
    fn get_kek(&self) -> anyhow::Result<(KekId, Vec<u8>)> {
        let bytes = self.get_cached_or_load()?;
        Ok((self.id.clone(), bytes))
    }

    fn get_kek_by_id(&self, id: &KekId) -> anyhow::Result<Vec<u8>> {
        anyhow::ensure!(
            id == &self.id,
            "unknown KEK id: {id:?} (expected {:?})",
            self.id
        );
        self.get_cached_or_load()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::*;

    #[test]
    fn test_from_keyfile_id() {
        let path = PathBuf::from("/test/key.bin");
        let provider = DeviceKeyProvider::from_keyfile(path.clone());
        assert_eq!(
            provider.id,
            KekId(format!("device:file:{}", path.display()))
        );
    }

    #[test]
    fn test_from_passphrase_id() {
        let provider = DeviceKeyProvider::from_passphrase("test");
        assert_eq!(provider.id, KekId("device:passphrase".into()));
    }

    #[test]
    fn test_load_from_keyfile() -> anyhow::Result<()> {
        let mut file = NamedTempFile::new()?;
        let key_bytes = [0xAAu8; 32];
        file.write_all(&key_bytes)?;
        file.flush()?;

        let provider = DeviceKeyProvider::from_keyfile(file.path().to_path_buf());
        let kek = provider.load_kek()?;

        assert_eq!(kek, key_bytes.to_vec());
        Ok(())
    }

    #[test]
    fn test_keyfile_wrong_size_short() -> anyhow::Result<()> {
        let mut file = NamedTempFile::new()?;
        file.write_all(&[0xAAu8; 16])?; // Wrong size
        file.flush()?;

        let provider = DeviceKeyProvider::from_keyfile(file.path().to_path_buf());
        let result = provider.load_kek();

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("exactly 32 bytes"));
        Ok(())
    }

    #[test]
    fn test_keyfile_wrong_size_long() -> anyhow::Result<()> {
        let mut file = NamedTempFile::new()?;
        file.write_all(&[0xBBu8; 64])?; // Wrong size
        file.flush()?;

        let provider = DeviceKeyProvider::from_keyfile(file.path().to_path_buf());
        let result = provider.load_kek();

        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_keyfile_not_found() {
        let provider = DeviceKeyProvider::from_keyfile(PathBuf::from("/nonexistent/path/key.bin"));
        let result = provider.load_kek();

        assert!(result.is_err());
    }

    #[test]
    fn test_passphrase_derivation() -> anyhow::Result<()> {
        let provider = DeviceKeyProvider::from_passphrase("test");
        let kek = provider.load_kek()?;

        // Should be 32 bytes
        assert_eq!(kek.len(), 32);
        // Should be non-zero
        assert!(!kek.iter().all(|b| *b == 0));
        Ok(())
    }

    #[test]
    fn test_passphrase_deterministic() -> anyhow::Result<()> {
        let provider1 = DeviceKeyProvider::from_passphrase("test");
        let provider2 = DeviceKeyProvider::from_passphrase("test");

        let kek1 = provider1.load_kek()?;
        let kek2 = provider2.load_kek()?;

        // Same passphrase should produce same KEK
        assert_eq!(kek1, kek2);
        Ok(())
    }

    #[test]
    fn test_different_passphrases_different_keys() -> anyhow::Result<()> {
        let provider1 = DeviceKeyProvider::from_passphrase("password1");
        let provider2 = DeviceKeyProvider::from_passphrase("password2");

        let kek1 = provider1.load_kek()?;
        let kek2 = provider2.load_kek()?;

        // Different passphrases should produce different KEKs
        assert_ne!(kek1, kek2);
        Ok(())
    }

    #[test]
    fn test_get_kek_from_keyfile() -> anyhow::Result<()> {
        let mut file = NamedTempFile::new()?;
        let key_bytes = [0xCCu8; 32];
        file.write_all(&key_bytes)?;
        file.flush()?;

        let provider = DeviceKeyProvider::from_keyfile(file.path().to_path_buf());
        let (id, kek) = provider.get_kek()?;

        assert_eq!(id, provider.id);
        assert_eq!(kek, key_bytes.to_vec());
        Ok(())
    }

    #[test]
    fn test_get_kek_from_passphrase() -> anyhow::Result<()> {
        let provider = DeviceKeyProvider::from_passphrase("mysecret");
        let (id, kek) = provider.get_kek()?;

        assert_eq!(id, KekId("device:passphrase".into()));
        assert_eq!(kek.len(), 32);
        Ok(())
    }

    #[test]
    fn test_get_kek_by_id_matching() -> anyhow::Result<()> {
        let mut file = NamedTempFile::new()?;
        let key_bytes = [0xDDu8; 32];
        file.write_all(&key_bytes)?;
        file.flush()?;

        let provider = DeviceKeyProvider::from_keyfile(file.path().to_path_buf());
        let (id, _) = provider.get_kek()?;

        let kek = provider.get_kek_by_id(&id)?;
        assert_eq!(kek, key_bytes.to_vec());
        Ok(())
    }

    #[test]
    fn test_get_kek_by_id_wrong_id() -> anyhow::Result<()> {
        let provider = DeviceKeyProvider::from_passphrase("test");
        let wrong_id = KekId("device:other".into());

        let result = provider.get_kek_by_id(&wrong_id);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unknown KEK"));
        Ok(())
    }

    #[test]
    fn test_caching_keyfile() -> anyhow::Result<()> {
        let mut file = NamedTempFile::new()?;
        let key_bytes = [0xEEu8; 32];
        file.write_all(&key_bytes)?;
        file.flush()?;

        let provider = DeviceKeyProvider::from_keyfile(file.path().to_path_buf());

        // First call loads from file
        let kek1 = provider.get_cached_or_load()?;

        // Delete the file
        drop(file);

        // Second call should use cache, not try to read file
        let kek2 = provider.get_cached_or_load()?;

        assert_eq!(kek1, kek2);
        Ok(())
    }

    #[test]
    fn test_caching_passphrase() -> anyhow::Result<()> {
        let provider = DeviceKeyProvider::from_passphrase("cached_test");

        // First call derives
        let kek1 = provider.get_cached_or_load()?;

        // Second call should use cache
        let kek2 = provider.get_cached_or_load()?;

        assert_eq!(kek1, kek2);

        // Verify cache is populated
        let cached = provider.cached.lock();
        assert!(cached.is_some());
        Ok(())
    }

    #[test]
    fn test_multiple_get_kek_calls() -> anyhow::Result<()> {
        let provider = DeviceKeyProvider::from_passphrase("multi_call");

        let (id1, kek1) = provider.get_kek()?;
        let (id2, kek2) = provider.get_kek()?;

        // Should return same ID and KEK
        assert_eq!(id1, id2);
        assert_eq!(kek1, kek2);
        Ok(())
    }

    #[test]
    fn test_get_kek_and_get_kek_by_id_consistency() -> anyhow::Result<()> {
        let provider = DeviceKeyProvider::from_passphrase("consistency");

        let (id, kek1) = provider.get_kek()?;
        let kek2 = provider.get_kek_by_id(&id)?;

        // Should return same KEK
        assert_eq!(kek1, kek2);
        Ok(())
    }

    #[test]
    fn test_passphrase_empty_string() -> anyhow::Result<()> {
        let provider = DeviceKeyProvider::from_passphrase("");
        let kek = provider.load_kek()?;

        // Should still produce 32 bytes
        assert_eq!(kek.len(), 32);
        Ok(())
    }

    #[test]
    fn test_passphrase_unicode() -> anyhow::Result<()> {
        let provider = DeviceKeyProvider::from_passphrase("🔐密码パスワード");
        let kek = provider.load_kek()?;

        // Should handle unicode passphrases
        assert_eq!(kek.len(), 32);
        Ok(())
    }
}
