use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use super::KmsProvider;
use crate::crypto::keys::KekId;

/// Cloud KMS provider that talks to an HTTP endpoint.
///
/// Compatible with:
/// - AWS KMS (`GenerateDataKey` / `Decrypt`)
/// - Any KMS that exposes a similar JSON API
///
/// For production AWS use, swap the HTTP calls for the real SDK.
/// This implementation shows the protocol shape.
pub struct CloudKmsProvider {
    key_id: String,
    endpoint: Option<String>,
    /// Cache the last generated data key so we don't call KMS on
    /// every page write.
    cached_kek: Mutex<Option<(KekId, Vec<u8>)>>,
}

#[derive(Serialize)]
struct GenerateDataKeyRequest<'a> {
    #[serde(rename = "KeyId")]
    key_id: &'a str,
    #[serde(rename = "KeySpec")]
    key_spec: &'a str,
}

#[derive(Deserialize)]
struct GenerateDataKeyResponse {
    #[serde(rename = "KeyId")]
    key_id: String,
    #[serde(rename = "Plaintext")]
    plaintext: String, // base64
    #[serde(rename = "CiphertextBlob")]
    ciphertext_blob: String, // base64
}

#[derive(Serialize)]
struct DecryptRequest<'a> {
    #[serde(rename = "CiphertextBlob")]
    ciphertext_blob: &'a str,
}

#[derive(Deserialize)]
struct DecryptResponse {
    #[serde(rename = "Plaintext")]
    plaintext: String,
}

impl CloudKmsProvider {
    pub fn new(key_id: String, endpoint: Option<String>) -> Self {
        Self {
            key_id,
            endpoint,
            cached_kek: Mutex::new(None),
        }
    }

    fn base_url(&self) -> &str {
        self.endpoint
            .as_deref()
            .unwrap_or("https://kms.us-east-1.amazonaws.com")
    }

    fn generate_data_key(&self) -> anyhow::Result<(KekId, Vec<u8>)> {
        let url = self.base_url();
        let body = GenerateDataKeyRequest {
            key_id: &self.key_id,
            key_spec: "AES_256",
        };

        let resp: GenerateDataKeyResponse = ureq::post(url)
            .set("X-Amz-Target", "TrentService.GenerateDataKey")
            .set("Content-Type", "application/x-amz-json-1.1")
            .send_json(serde_json::to_value(&body)?)?
            .into_json()?;

        let plaintext = base64_decode(&resp.plaintext)?;
        anyhow::ensure!(
            plaintext.len() == 32,
            "KMS returned {} byte key, expected 32",
            plaintext.len()
        );

        // The KekId stores the ciphertext blob so we can decrypt it
        // later without needing the plaintext KEK.
        let id = KekId(resp.ciphertext_blob);
        Ok((id, plaintext))
    }

    fn decrypt_data_key(&self, ciphertext_b64: &str) -> anyhow::Result<Vec<u8>> {
        let url = self.base_url();
        let body = DecryptRequest {
            ciphertext_blob: ciphertext_b64,
        };

        let resp: DecryptResponse = ureq::post(url)
            .set("X-Amz-Target", "TrentService.Decrypt")
            .set("Content-Type", "application/x-amz-json-1.1")
            .send_json(serde_json::to_value(&body)?)?
            .into_json()?;

        base64_decode(&resp.plaintext)
    }
}

impl KmsProvider for CloudKmsProvider {
    fn get_kek(&self) -> anyhow::Result<(KekId, Vec<u8>)> {
        let mut guard = self.cached_kek.lock();
        if let Some(ref cached) = *guard {
            return Ok(cached.clone());
        }
        let result = self.generate_data_key()?;
        *guard = Some(result.clone());
        Ok(result)
    }

    fn get_kek_by_id(&self, id: &KekId) -> anyhow::Result<Vec<u8>> {
        // Check cache first.
        {
            let guard = self.cached_kek.lock();
            if let Some((ref cached_id, ref bytes)) = *guard
                && cached_id == id
            {
                return Ok(bytes.clone());
            }
        }
        // Call KMS Decrypt with the ciphertext blob stored in the id.
        self.decrypt_data_key(&id.0)
    }

    fn wrap_blob(&self, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let url = self.base_url();

        #[derive(Serialize)]
        struct EncryptRequest<'a> {
            #[serde(rename = "KeyId")]
            key_id: &'a str,
            #[serde(rename = "Plaintext")]
            plaintext: String,
        }

        #[derive(Deserialize)]
        struct EncryptResponse {
            #[serde(rename = "CiphertextBlob")]
            ciphertext_blob: String,
        }

        let body = EncryptRequest {
            key_id: &self.key_id,
            plaintext: base64_encode(plaintext),
        };

        let resp: EncryptResponse = ureq::post(url)
            .set("X-Amz-Target", "TrentService.Encrypt")
            .set("Content-Type", "application/x-amz-json-1.1")
            .send_json(serde_json::to_value(&body)?)?
            .into_json()?;

        base64_decode(&resp.ciphertext_blob)
    }

    fn unwrap_blob(&self, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let b64 = base64_encode(ciphertext);
        self.decrypt_data_key(&b64)
    }
}

fn base64_decode(input: &str) -> anyhow::Result<Vec<u8>> {
    // Minimal base64 decode without pulling in another crate.
    // In production, use the `base64` crate.
    use std::io::Read;
    let mut decoder = base64_reader::DecoderReader::new(input.as_bytes());
    let mut out = Vec::new();
    decoder.read_to_end(&mut out)?;
    Ok(out)
}

fn base64_encode(input: &[u8]) -> String {
    base64_writer::encode(input)
}

/// Minimal inline base64 so we don't need an extra crate.
mod base64_reader {
    use std::io::{self, Read};

    fn decode_byte(b: u8) -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    pub struct DecoderReader<'a> {
        input: &'a [u8],
        pos: usize,
    }

    impl<'a> DecoderReader<'a> {
        pub fn new(input: &'a [u8]) -> Self {
            Self { input, pos: 0 }
        }
    }

    impl Read for DecoderReader<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let mut written = 0;
            while written < buf.len() {
                // Skip whitespace / padding.
                while self.pos < self.input.len()
                    && (self.input[self.pos] == b'=' || self.input[self.pos].is_ascii_whitespace())
                {
                    self.pos += 1;
                }
                if self.pos >= self.input.len() {
                    break;
                }
                // Need up to 4 characters for a group.
                let mut group = [0u8; 4];
                let mut count = 0;
                while count < 4 && self.pos < self.input.len() {
                    let b = self.input[self.pos];
                    self.pos += 1;
                    if b == b'=' || b.is_ascii_whitespace() {
                        continue;
                    }
                    if let Some(val) = decode_byte(b) {
                        group[count] = val;
                        count += 1;
                    }
                }
                if count >= 2 && written < buf.len() {
                    buf[written] = (group[0] << 2) | (group[1] >> 4);
                    written += 1;
                }
                if count >= 3 && written < buf.len() {
                    buf[written] = (group[1] << 4) | (group[2] >> 2);
                    written += 1;
                }
                if count >= 4 && written < buf.len() {
                    buf[written] = (group[2] << 6) | group[3];
                    written += 1;
                }
            }
            Ok(written)
        }
    }
}

mod base64_writer {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub fn encode(input: &[u8]) -> String {
        let mut out = Vec::with_capacity(input.len().div_ceil(3) * 4);
        for chunk in input.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
            let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
            let triple = (b0 << 16) | (b1 << 8) | b2;
            out.push(TABLE[((triple >> 18) & 0x3F) as usize]);
            out.push(TABLE[((triple >> 12) & 0x3F) as usize]);
            if chunk.len() > 1 {
                out.push(TABLE[((triple >> 6) & 0x3F) as usize]);
            } else {
                out.push(b'=');
            }
            if chunk.len() > 2 {
                out.push(TABLE[(triple & 0x3F) as usize]);
            } else {
                out.push(b'=');
            }
        }
        String::from_utf8(out).unwrap()
    }
}
