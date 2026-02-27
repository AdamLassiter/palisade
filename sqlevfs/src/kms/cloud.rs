use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};
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
    Ok(BASE64_STANDARD.decode(input.as_bytes())?)
}

fn base64_encode(input: &[u8]) -> String {
    BASE64_STANDARD.encode(input)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        sync::{
            Arc,
            Mutex as StdMutex,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
    };

    use anyhow::Result;

    use super::*;

    fn spawn_mock_kms_server() -> (String, MockState) {
        #[derive(Clone, Default)]
        struct Inner {
            generate_calls: Arc<AtomicUsize>,
            decrypt_calls: Arc<AtomicUsize>,
            encrypt_calls: Arc<AtomicUsize>,
            // ciphertext_blob_b64 -> plaintext_b64
            decrypt_map: Arc<StdMutex<HashMap<String, String>>>,
            // if set, GenerateDataKey returns a plaintext with this length
            gdk_plaintext_len: Arc<StdMutex<Option<usize>>>,
        }

        #[derive(Clone, Default)]
        struct State(Inner);

        #[derive(Clone)]
        struct OutState {
            generate_calls: Arc<AtomicUsize>,
            decrypt_calls: Arc<AtomicUsize>,
            encrypt_calls: Arc<AtomicUsize>,
            decrypt_map: Arc<StdMutex<HashMap<String, String>>>,
            gdk_plaintext_len: Arc<StdMutex<Option<usize>>>,
        }

        impl OutState {
            fn set_generate_plaintext_len(&self, len: Option<usize>) {
                *self.gdk_plaintext_len.lock().unwrap() = len;
            }
        }

        fn write_json_ok(mut stream: TcpStream, body: serde_json::Value) {
            let body = body.to_string();
            let resp = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: application/x-amz-json-1.1\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\
                 \r\n\
                 {}",
                body.len(),
                body
            );
            let _ = stream.write_all(resp.as_bytes());
        }

        fn read_http_request(mut stream: &TcpStream) -> Result<(HashMap<String, String>, Vec<u8>)> {
            use std::collections::HashMap;

            let mut buf = Vec::new();
            let mut tmp = [0u8; 4096];

            // Read until we have headers.
            let header_end;
            loop {
                let n = stream.take(4096).read(&mut tmp)?;
                if n == 0 {
                    return Ok((HashMap::new(), Vec::new()));
                }
                buf.extend_from_slice(&tmp[..n]);

                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    header_end = pos;
                    break;
                }
                // Avoid unbounded growth in tests.
                if buf.len() > 1024 * 1024 {
                    return Ok((HashMap::new(), Vec::new()));
                }
            }

            let head = &buf[..header_end];
            let mut rest = buf[header_end + 4..].to_vec();

            let head_str = String::from_utf8_lossy(head);
            let mut headers = HashMap::new();

            for (i, line) in head_str.lines().enumerate() {
                if i == 0 {
                    continue; // request line
                }
                if let Some((k, v)) = line.split_once(':') {
                    headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
                }
            }

            let content_length = headers
                .get("content-length")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(0);

            // Read the remaining body bytes (exactly content_length).
            while rest.len() < content_length {
                let n = (&mut stream).read(&mut tmp)?;
                if n == 0 {
                    break;
                }
                rest.extend_from_slice(&tmp[..n]);
            }
            rest.truncate(content_length);

            Ok((headers, rest))
        }

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{}", addr);

        let state = State::default();

        let out = OutState {
            generate_calls: state.0.generate_calls.clone(),
            decrypt_calls: state.0.decrypt_calls.clone(),
            encrypt_calls: state.0.encrypt_calls.clone(),
            decrypt_map: state.0.decrypt_map.clone(),
            gdk_plaintext_len: state.0.gdk_plaintext_len.clone(),
        };

        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let (headers, body) = read_http_request(&stream).unwrap();
                let target = headers.get("x-amz-target").cloned().unwrap_or_default();

                if target.contains("GenerateDataKey") {
                    state.0.generate_calls.fetch_add(1, Ordering::SeqCst);

                    let len = state.0.gdk_plaintext_len.lock().unwrap().unwrap_or(32);

                    let plaintext = vec![0xAB; len];
                    let plaintext_b64 = base64_encode(&plaintext);

                    // For tests, just use a deterministic ciphertext blob.
                    let ciphertext_blob_raw = b"ciphertext-blob";
                    let ciphertext_blob_b64 = base64_encode(ciphertext_blob_raw);

                    // Allow decrypt of that ciphertext blob.
                    state
                        .0
                        .decrypt_map
                        .lock()
                        .unwrap()
                        .insert(ciphertext_blob_b64.clone(), plaintext_b64.clone());

                    write_json_ok(
                        stream,
                        serde_json::json!({
                            "KeyId": "test-key-id",
                            "Plaintext": plaintext_b64,
                            "CiphertextBlob": ciphertext_blob_b64,
                        }),
                    );
                    continue;
                }

                if target.contains("Decrypt") {
                    state.0.decrypt_calls.fetch_add(1, Ordering::SeqCst);

                    let v: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
                    let ciphertext_blob = v
                        .get("CiphertextBlob")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string();

                    let plaintext_b64 = state
                        .0
                        .decrypt_map
                        .lock()
                        .unwrap()
                        .get(&ciphertext_blob)
                        .cloned()
                        .unwrap_or_else(|| base64_encode(b""));

                    write_json_ok(
                        stream,
                        serde_json::json!({
                            "Plaintext": plaintext_b64,
                        }),
                    );
                    continue;
                }

                if target.contains("Encrypt") {
                    state.0.encrypt_calls.fetch_add(1, Ordering::SeqCst);

                    let v: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
                    let plaintext_b64 = v.get("Plaintext").and_then(|x| x.as_str()).unwrap_or("");

                    // Return a deterministic ciphertext blob derived from plaintext_b64.
                    // Ciphertext blob (raw bytes) = b"ct:" + decoded(plaintext_b64)
                    let pt = base64_decode(plaintext_b64).unwrap_or_default();
                    let mut ct = b"ct:".to_vec();
                    ct.extend_from_slice(&pt);
                    let ciphertext_blob_b64 = base64_encode(&ct);

                    // And allow decrypt of that ciphertext blob.
                    state
                        .0
                        .decrypt_map
                        .lock()
                        .unwrap()
                        .insert(ciphertext_blob_b64.clone(), plaintext_b64.to_string());

                    write_json_ok(
                        stream,
                        serde_json::json!({
                            "CiphertextBlob": ciphertext_blob_b64,
                        }),
                    );
                    continue;
                }

                // Unknown target: still respond with something.
                write_json_ok(stream, serde_json::json!({}));
            }
        });

        (
            url,
            MockState {
                generate_calls: out.generate_calls,
                decrypt_calls: out.decrypt_calls,
                encrypt_calls: out.encrypt_calls,
                decrypt_map: out.decrypt_map,
                gdk_plaintext_len: out.gdk_plaintext_len,
            },
        )
    }

    #[derive(Clone)]
    struct MockState {
        generate_calls: Arc<AtomicUsize>,
        decrypt_calls: Arc<AtomicUsize>,
        encrypt_calls: Arc<AtomicUsize>,
        decrypt_map: Arc<StdMutex<HashMap<String, String>>>,
        gdk_plaintext_len: Arc<StdMutex<Option<usize>>>,
    }

    impl MockState {
        fn set_generate_plaintext_len(&self, len: Option<usize>) {
            *self.gdk_plaintext_len.lock().unwrap() = len;
        }

        fn generate_calls(&self) -> usize {
            self.generate_calls.load(Ordering::SeqCst)
        }

        fn decrypt_calls(&self) -> usize {
            self.decrypt_calls.load(Ordering::SeqCst)
        }

        fn encrypt_calls(&self) -> usize {
            self.encrypt_calls.load(Ordering::SeqCst)
        }
    }

    #[test]
    fn base64_roundtrip_works() {
        let data = b"\x00\x01\x02hello\xff";
        let b64 = base64_encode(data);
        let decoded = base64_decode(&b64).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn get_kek_is_cached_after_first_call() {
        let (endpoint, state) = spawn_mock_kms_server();
        let p = CloudKmsProvider::new("alias/test".to_string(), Some(endpoint));

        let (id1, k1) = p.get_kek().unwrap();
        let (id2, k2) = p.get_kek().unwrap();

        assert_eq!(id1.0, id2.0);
        assert_eq!(k1, k2);

        assert_eq!(
            state.generate_calls(),
            1,
            "should only call GenerateDataKey once"
        );
        assert_eq!(state.decrypt_calls(), 0);
        assert_eq!(state.encrypt_calls(), 0);
    }

    #[test]
    fn get_kek_by_id_hits_cache_when_id_matches() {
        let (endpoint, state) = spawn_mock_kms_server();
        let p = CloudKmsProvider::new("alias/test".to_string(), Some(endpoint));

        let (id, k1) = p.get_kek().unwrap();
        let k2 = p.get_kek_by_id(&id).unwrap();

        assert_eq!(k1, k2);
        assert_eq!(state.generate_calls(), 1);
        assert_eq!(state.decrypt_calls(), 0, "cache should avoid Decrypt call");
    }

    #[test]
    fn get_kek_by_id_calls_decrypt_when_id_not_cached() {
        let (endpoint, state) = spawn_mock_kms_server();
        let p = CloudKmsProvider::new("alias/test".to_string(), Some(endpoint));

        // Put something into the decrypt map so decrypt returns non-empty.
        let plaintext = vec![0x11; 32];
        let plaintext_b64 = base64_encode(&plaintext);
        let ciphertext_blob_b64 = base64_encode(b"some-other-blob");
        state
            .decrypt_map
            .lock()
            .unwrap()
            .insert(ciphertext_blob_b64.clone(), plaintext_b64);

        let k = p.get_kek_by_id(&KekId(ciphertext_blob_b64)).unwrap();
        assert_eq!(k, plaintext);
        assert_eq!(state.decrypt_calls(), 1);
    }

    #[test]
    fn wrap_and_unwrap_roundtrip() {
        let (endpoint, state) = spawn_mock_kms_server();
        let p = CloudKmsProvider::new("alias/test".to_string(), Some(endpoint));

        let pt = b"top secret bytes".to_vec();
        let ct = p.wrap_blob(&pt).unwrap();
        let got = p.unwrap_blob(&ct).unwrap();

        assert_eq!(got, pt);
        assert_eq!(state.encrypt_calls(), 1);
        assert_eq!(state.decrypt_calls(), 1);
    }

    #[test]
    fn generate_data_key_errors_on_wrong_length_key() {
        let (endpoint, state) = spawn_mock_kms_server();
        state.set_generate_plaintext_len(Some(31)); // not 32

        let p = CloudKmsProvider::new("alias/test".to_string(), Some(endpoint));
        let err = p.get_kek().unwrap_err();
        let msg = err.to_string();

        assert!(
            msg.contains("expected 32"),
            "unexpected error message: {msg}"
        );
    }
}
