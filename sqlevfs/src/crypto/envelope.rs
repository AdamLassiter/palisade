use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};

use super::keys::{Dek, WrappedDek};
use crate::kms::KmsProvider;

/// Wrap a DEK under the current KEK from the provider.
pub fn wrap_dek(dek: &Dek, provider: &dyn KmsProvider) -> anyhow::Result<WrappedDek> {
    let (kek_id, kek_bytes) = provider.get_kek()?;
    anyhow::ensure!(kek_bytes.len() == 32, "KEK must be 32 bytes");

    let cipher = Aes256Gcm::new_from_slice(&kek_bytes)?;
    let nonce_bytes = rand_nonce();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, dek.as_bytes().as_ref())
        .map_err(|e| anyhow::anyhow!("wrap encrypt failed: {e}"))?;

    Ok(WrappedDek {
        ciphertext,
        nonce: nonce_bytes,
        kek_id,
    })
}

/// Unwrap a DEK using the provider to resolve the KEK.
pub fn unwrap_dek(wrapped: &WrappedDek, provider: &dyn KmsProvider) -> anyhow::Result<Dek> {
    let kek_bytes = provider.get_kek_by_id(&wrapped.kek_id)?;
    anyhow::ensure!(kek_bytes.len() == 32, "KEK must be 32 bytes");

    let cipher = Aes256Gcm::new_from_slice(&kek_bytes)?;
    let nonce = Nonce::from_slice(&wrapped.nonce);
    let plaintext = cipher
        .decrypt(nonce, wrapped.ciphertext.as_ref())
        .map_err(|e| anyhow::anyhow!("unwrap decrypt failed: {e}"))?;

    anyhow::ensure!(plaintext.len() == 32, "DEK plaintext must be 32 bytes");
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&plaintext);

    Ok(Dek::from_bytes(buf))
}

fn rand_nonce() -> [u8; 12] {
    let mut n = [0u8; 12];
    getrandom::fill(&mut n).expect("getrandom failed");
    n
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::crypto::keys::KekId;

    // Mock KmsProvider for testing
    struct MockKmsProvider {
        kek: Vec<u8>,
        kek_id: String,
        call_count: Mutex<usize>,
    }

    impl MockKmsProvider {
        fn new(kek: Vec<u8>, kek_id: &str) -> Self {
            assert!(kek.len() == 32, "test KEK must be 32 bytes");
            Self {
                kek,
                kek_id: kek_id.to_string(),
                call_count: Mutex::new(0),
            }
        }

        fn new_default() -> Self {
            Self::new(vec![0xAAu8; 32], "kek-v1")
        }
    }

    impl KmsProvider for MockKmsProvider {
        fn get_kek(&self) -> anyhow::Result<(KekId, Vec<u8>)> {
            *self.call_count.lock().unwrap() += 1;
            Ok((KekId(self.kek_id.clone()), self.kek.clone()))
        }

        fn get_kek_by_id(&self, id: &KekId) -> anyhow::Result<Vec<u8>> {
            if id == &KekId(self.kek_id.clone()) {
                Ok(self.kek.clone())
            } else {
                anyhow::bail!("KEK not found")
            }
        }
    }

    #[test]
    fn test_wrap_unwrap_round_trip() {
        let provider = MockKmsProvider::new_default();
        let dek = Dek::generate();

        let wrapped = wrap_dek(&dek, &provider).unwrap();
        let unwrapped = unwrap_dek(&wrapped, &provider).unwrap();

        assert_eq!(dek, unwrapped);
    }

    #[test]
    fn test_wrap_sets_kek_id() {
        let provider = MockKmsProvider::new(vec![0xBBu8; 32], "kek-v2");
        let dek = Dek::generate();

        let wrapped = wrap_dek(&dek, &provider).unwrap();

        assert_eq!(wrapped.kek_id, KekId("kek-v2".to_string()));
    }

    #[test]
    fn test_wrap_produces_ciphertext() {
        let provider = MockKmsProvider::new_default();
        let dek = Dek::generate();

        let wrapped = wrap_dek(&dek, &provider).unwrap();

        // Ciphertext should be non-empty (plaintext + tag)
        assert!(!wrapped.ciphertext.is_empty());
        // AES-GCM produces plaintext_len + TAG_LEN
        assert_eq!(wrapped.ciphertext.len(), 32 + 16);
    }

    #[test]
    fn test_wrap_uses_random_nonce() {
        let provider = MockKmsProvider::new_default();
        let dek = Dek::generate();

        let wrapped1 = wrap_dek(&dek, &provider).unwrap();
        let wrapped2 = wrap_dek(&dek, &provider).unwrap();

        // Different wraps should have different nonces
        assert_ne!(wrapped1.nonce, wrapped2.nonce);
        // And thus different ciphertexts
        assert_ne!(wrapped1.ciphertext, wrapped2.ciphertext);
    }

    #[test]
    fn test_unwrap_with_wrong_kek_fails() {
        let provider1 = MockKmsProvider::new(vec![0xAAu8; 32], "kek-v1");
        let dek = Dek::generate();

        let wrapped = wrap_dek(&dek, &provider1).unwrap();

        // Try to unwrap with different KEK
        let provider2 = MockKmsProvider::new(vec![0xBBu8; 32], "kek-v1");
        let result = unwrap_dek(&wrapped, &provider2);

        assert!(result.is_err());
    }

    #[test]
    fn test_unwrap_with_missing_kek_fails() {
        let provider1 = MockKmsProvider::new(vec![0xCCu8; 32], "kek-v1");
        let dek = Dek::generate();

        let wrapped = wrap_dek(&dek, &provider1).unwrap();

        // Try to unwrap with provider that doesn't have this KEK
        let provider2 = MockKmsProvider::new(vec![0xDDu8; 32], "kek-v2");
        let result = unwrap_dek(&wrapped, &provider2);

        assert!(result.is_err());
    }

    #[test]
    fn test_unwrap_tampered_ciphertext_fails() {
        let provider = MockKmsProvider::new_default();
        let dek = Dek::generate();

        let mut wrapped = wrap_dek(&dek, &provider).unwrap();

        // Tamper with ciphertext
        wrapped.ciphertext[0] ^= 0xFF;

        let result = unwrap_dek(&wrapped, &provider);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrap_requires_32_byte_kek() {
        struct BadKmsProvider;

        impl KmsProvider for BadKmsProvider {
            fn get_kek(&self) -> anyhow::Result<(KekId, Vec<u8>)> {
                Ok((
                    KekId("bad".to_string()),
                    vec![0xAAu8; 16], // Wrong length
                ))
            }

            fn get_kek_by_id(&self, _id: &KekId) -> anyhow::Result<Vec<u8>> {
                Ok(vec![0xAAu8; 16])
            }
        }

        let provider = BadKmsProvider;
        let dek = Dek::generate();

        let result = wrap_dek(&dek, &provider);
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_deks_different_wrappings() {
        let provider = MockKmsProvider::new_default();
        let dek1 = Dek::generate();
        let dek2 = Dek::generate();

        let wrapped1 = wrap_dek(&dek1, &provider).unwrap();
        let wrapped2 = wrap_dek(&dek2, &provider).unwrap();

        assert_ne!(wrapped1.ciphertext, wrapped2.ciphertext);

        let unwrapped1 = unwrap_dek(&wrapped1, &provider).unwrap();
        let unwrapped2 = unwrap_dek(&wrapped2, &provider).unwrap();

        assert_eq!(dek1, unwrapped1);
        assert_eq!(dek2, unwrapped2);
    }

    #[test]
    fn test_wrapped_dek_structure() {
        let provider = MockKmsProvider::new_default();
        let dek = Dek::generate();

        let wrapped = wrap_dek(&dek, &provider).unwrap();

        // Verify structure
        assert_eq!(wrapped.nonce.len(), 12);
        assert_eq!(wrapped.ciphertext.len(), 48); // 32 + 16 tag
        assert_eq!(wrapped.kek_id, KekId("kek-v1".to_string()));
    }

    #[test]
    fn test_unwrap_invalid_plaintext_length() {
        let provider = MockKmsProvider::new_default();

        // Create a wrapped DEK with wrong plaintext length
        let short_plaintext = vec![0xAAu8; 16]; // Should be 32
        let nonce = rand_nonce();
        let cipher = Aes256Gcm::new_from_slice(&vec![0xBBu8; 32]).unwrap();
        let nonce_ref = Nonce::from_slice(&nonce);
        let ciphertext = cipher.encrypt(nonce_ref, short_plaintext.as_ref()).unwrap();

        let wrapped = WrappedDek {
            ciphertext,
            nonce,
            kek_id: KekId("kek-v1".to_string()),
        };

        let result = unwrap_dek(&wrapped, &provider);
        assert!(result.is_err());
    }

    #[test]
    fn test_same_dek_same_nonce_deterministic() {
        let provider = MockKmsProvider::new_default();
        let dek = Dek::generate();

        // Wrap twice and verify nonces are different (due to randomness)
        let w1 = wrap_dek(&dek, &provider).unwrap();
        let w2 = wrap_dek(&dek, &provider).unwrap();

        assert_ne!(w1.nonce, w2.nonce);
        // But both should unwrap to the same DEK
        assert_eq!(
            unwrap_dek(&w1, &provider).unwrap(),
            unwrap_dek(&w2, &provider).unwrap()
        );
    }
}
