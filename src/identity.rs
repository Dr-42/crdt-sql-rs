use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use axum_extra::extract::cookie::CookieJar;

/// Loads the signing key from `node.key`, or generates and saves a new one.
pub fn load_or_generate_signing_key() -> SigningKey {
    if let Ok(bytes) = std::fs::read("node.key") {
        if bytes.len() == 32 {
            let arr: [u8; 32] = bytes.try_into().expect("node.key must be 32 bytes");
            return SigningKey::from_bytes(&arr);
        }
    }
    let signing_key = SigningKey::generate(&mut OsRng);
    std::fs::write("node.key", signing_key.to_bytes())
        .expect("Failed to write node.key — check filesystem permissions");
    println!("🔑 New Ed25519 keypair generated and saved to node.key");
    signing_key
}

/// Returns the hex-encoded SHA256 fingerprint of the verifying (public) key.
pub fn pubkey_fingerprint(vk: &VerifyingKey) -> String {
    let mut h = Sha256::new();
    h.update(vk.to_bytes());
    hex::encode(h.finalize())
}

pub fn verify_session(jar: &CookieJar, signing_key: &SigningKey) -> Option<String> {
    let cookie_val = jar.get("session")?.value().to_string();
    let mut parts = cookie_val.splitn(2, '.');
    let payload_b64 = parts.next()?;
    let sig_b64 = parts.next()?;

    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    let sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64).ok()?;
    let sig_arr: [u8; 64] = sig_bytes.try_into().ok()?;
    let sig = Signature::from_bytes(&sig_arr);

    signing_key
        .verifying_key()
        .verify(&payload_bytes, &sig)
        .ok()?;

    let payload_str = std::str::from_utf8(&payload_bytes).ok()?;
    let user_hash = payload_str.split(':').next()?.to_string();
    Some(user_hash)
}

pub fn urlencoding_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}
