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
    getrandom::getrandom(&mut n).expect("getrandom failed");
    n
}
