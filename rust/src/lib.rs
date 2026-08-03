use wasm_bindgen::prelude::*;
use serde::{Deserialize, Serialize};

// Public for native (non-WASM) consumers: the mobile client's UniFFI wrapper
// crate (mobile-client/packages/crypto/rust) calls these pure-Rust modules
// directly, because the #[wasm_bindgen] facade below shadows `seal_secret` /
// `unseal_secret` with JsValue-typed versions that only make sense on WASM.
// Visibility-only change — the WASM/SDK boundary below is untouched.
pub mod sss;
pub mod utils;
pub mod crypto;
pub mod detect;
pub mod seal;

// Re-export core functionality
pub use utils::{CryptoError};
pub use sss::*;
// Export crypto functions
pub use crypto::*;
pub use detect::{DetectionHint, DETECTION_HINT_DOMAIN, DETECTION_TAG_LEN};
pub use seal::*;

// Re-export for JavaScript consumption
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

// Console logging macro for debugging
#[allow(unused_macros)]
macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

/// SSS share for reconstruction
#[derive(Serialize, Deserialize, Clone)]
pub struct SssShare {
    pub id: u8,
    pub data: Vec<u8>,
}

/// SSS share format validation
#[wasm_bindgen]
pub fn validate_share_format(
    share_id: u8,
    share_data: &[u8],
) -> bool {
    // Basic format validation for SSS shares
    share_id > 0 && !share_data.is_empty()
}

// === STANDALONE WASM FUNCTIONS ===

/// Report whether a 32-byte X25519 public key is usable for encryption, i.e.
/// not a small-order point. Lets the SDK validate each guardian's registered key
/// before sealing and name the offending guardian, instead of surfacing an
/// opaque crypto failure mid-seal.
#[wasm_bindgen]
pub fn is_usable_x25519_public_key(public_key: &[u8]) -> bool {
    match <[u8; 32]>::try_from(public_key) {
        Ok(key) => crypto::is_usable_x25519_public_key(&key),
        Err(_) => false,
    }
}

/// Derive a per-secret recipient detection hint toward a recipient's
/// long-term public key. Returns 40 bytes: ephemeral_pub(32) ‖ tag(8).
/// The recipient's key is never part of the result.
#[wasm_bindgen]
pub fn derive_detection_hint(recipient_public_key: &[u8]) -> Result<Vec<u8>, JsValue> {
    let key: [u8; 32] = recipient_public_key
        .try_into()
        .map_err(|_| JsValue::from_str("recipient public key must be exactly 32 bytes"))?;

    let hint = detect::derive_detection_hint(&key)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let mut result = Vec::with_capacity(32 + detect::DETECTION_TAG_LEN);
    result.extend_from_slice(&hint.ephemeral_pub);
    result.extend_from_slice(&hint.tag);
    Ok(result)
}

/// Test one secret's detection hint against a recipient private key.
/// Returns true iff the secret is addressed to this key.
#[wasm_bindgen]
pub fn scan_detection_hint(
    recipient_private_key: &[u8],
    ephemeral_pub: &[u8],
    tag: &[u8],
) -> Result<bool, JsValue> {
    let priv_key: [u8; 32] = recipient_private_key
        .try_into()
        .map_err(|_| JsValue::from_str("recipient private key must be exactly 32 bytes"))?;
    let eph: [u8; 32] = ephemeral_pub
        .try_into()
        .map_err(|_| JsValue::from_str("hint ephemeral key must be exactly 32 bytes"))?;

    detect::scan_hint(&priv_key, &eph, tag).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Recompute the recipiency proof `z = X25519(a, R)` for a secret's hint —
/// the value the chain checks when a recipient collects a rebate. 32 bytes.
#[wasm_bindgen]
pub fn recipiency_proof(
    recipient_private_key: &[u8],
    ephemeral_pub: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let priv_key: [u8; 32] = recipient_private_key
        .try_into()
        .map_err(|_| JsValue::from_str("recipient private key must be exactly 32 bytes"))?;
    let eph: [u8; 32] = ephemeral_pub
        .try_into()
        .map_err(|_| JsValue::from_str("hint ephemeral key must be exactly 32 bytes"))?;

    detect::recipiency_proof(&priv_key, &eph)
        .map(|z| z.to_vec())
        .map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Bind a recipiency proof to the address collecting with it — step 1 of
/// rebate collection. 32 bytes.
#[wasm_bindgen]
pub fn rebate_commitment(z: &[u8], collector_address_bytes: &[u8]) -> Vec<u8> {
    detect::rebate_commitment(z, collector_address_bytes).to_vec()
}

/// Generate a new keypair (standalone function)
#[wasm_bindgen]
pub fn generate_keypair() -> Result<Vec<u8>, JsValue> {
    let keypair = crypto::TimeflareKeypair::generate();
    let mut result = Vec::with_capacity(64);
    result.extend_from_slice(&keypair.to_bytes());
    result.extend_from_slice(&keypair.public_key_bytes());
    Ok(result)
}

/// Split secret using Shamir Secret Sharing (standalone function)
#[wasm_bindgen]
pub fn split_secret(secret: &[u8], threshold: u8, shares: u8) -> Result<JsValue, JsValue> {
    let share_vec = sss::split_secret(secret, threshold, shares)
        .map_err(|e| JsValue::from_str(&format!("SSS split failed: {}", e)))?;

    // Convert to JS-friendly format
    let js_shares: Vec<SssShare> = share_vec.iter().map(|share| SssShare {
        id: share.id,
        data: share.data.clone(),
    }).collect();

    serde_wasm_bindgen::to_value(&js_shares)
        .map_err(|e| JsValue::from_str(&format!("Serialization failed: {}", e)))
}

/// Reconstruct secret from shares (standalone function)
#[wasm_bindgen]
pub fn reconstruct_secret(shares_js: JsValue, threshold: u8) -> Result<Vec<u8>, JsValue> {
    let js_shares: Vec<SssShare> = serde_wasm_bindgen::from_value(shares_js)
        .map_err(|e| JsValue::from_str(&format!("Invalid shares format: {}", e)))?;

    let shares: Vec<sss::Share> = js_shares.into_iter()
        .map(|s| sss::Share { id: s.id, data: s.data })
        .collect();

    sss::combine_shares(&shares, threshold)
        .map_err(|e| JsValue::from_str(&format!("SSS reconstruction failed: {}", e)))
}

/// Encrypt data with public key (standalone function)
#[wasm_bindgen]
pub fn encrypt_with_public_key(data: &[u8], public_key_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
    if public_key_bytes.len() != 32 {
        return Err(JsValue::from_str("Public key must be 32 bytes"));
    }

    let public_key = TimeflarePublicKey::from_bytes(
        public_key_bytes.try_into()
            .map_err(|_| JsValue::from_str("Invalid public key format"))?
    );

    crypto::encrypt_for_public_key(data, &public_key)
        .map_err(|e| JsValue::from_str(&format!("Encryption failed: {}", e)))
}

/// Decrypt data with private key (standalone function)
#[wasm_bindgen]
pub fn decrypt_with_private_key(private_key_bytes: &[u8], encrypted_data: &[u8]) -> Result<Vec<u8>, JsValue> {
    if private_key_bytes.len() != 32 {
        return Err(JsValue::from_str("Private key must be 32 bytes"));
    }

    let keypair = crypto::TimeflareKeypair::from_bytes(
        private_key_bytes.try_into()
            .map_err(|_| JsValue::from_str("Invalid private key format"))?
    );

    keypair.decrypt(encrypted_data)
        .map_err(|e| JsValue::from_str(&format!("Decryption failed: {}", e)))
}

/// Extract public key from private key bytes (standalone function)
#[wasm_bindgen]
pub fn public_key_from_private(private_key_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
    if private_key_bytes.len() != 32 {
        return Err(JsValue::from_str("Private key must be 32 bytes"));
    }

    let keypair = crypto::TimeflareKeypair::from_bytes(
        private_key_bytes.try_into()
            .map_err(|_| JsValue::from_str("Invalid private key format"))?
    );

    Ok(keypair.public_key_bytes().to_vec())
}

/// Convert bytes to hex string (standalone function)
#[wasm_bindgen]
pub fn bytes_to_hex(data: &[u8]) -> String {
    hex::encode(data)
}

/// Generate HMAC for guardian share validation (standalone function)
#[wasm_bindgen]
pub fn generate_guardian_hmac(
    secret_id: &str,
    guardian_address: &str,
    share_data: &[u8],
) -> Vec<u8> {
    utils::generate_guardian_hmac(secret_id, guardian_address, share_data)
}

// === KEY-SHARE SEALING (see rust/src/seal.rs) ===

/// JS-facing guardian identity for seal_secret
#[derive(Serialize, Deserialize)]
pub struct JsGuardianRecipient {
    pub address: String,
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
}

/// JS-facing sealed key share
#[derive(Serialize, Deserialize)]
pub struct JsSealedKeyShare {
    pub guardian_address: String,
    #[serde(with = "serde_bytes")]
    pub encrypted_share: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub share_hmac: Vec<u8>,
}

/// JS-facing seal_secret result
#[derive(Serialize, Deserialize)]
pub struct JsSealedSecret {
    #[serde(with = "serde_bytes")]
    pub payload_ciphertext: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub secret_public_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub commitment: Vec<u8>,
    pub key_shares: Vec<JsSealedKeyShare>,
}

/// Seal a payload for time-locked distribution (key-share architecture):
/// inner-encrypt to the recipient, commit, generate the per-secret keypair,
/// outer-encrypt, split the per-secret private key, and encrypt + HMAC one
/// key share per guardian. The per-secret private key is discarded before
/// returning.
#[wasm_bindgen]
pub fn seal_secret(
    payload: &[u8],
    recipient_public_key: &[u8],
    guardians_js: JsValue,
    threshold: u8,
    secret_id: &str,
) -> Result<JsValue, JsValue> {
    let recipient: [u8; 32] = recipient_public_key
        .try_into()
        .map_err(|_| JsValue::from_str("Recipient public key must be 32 bytes"))?;

    let js_guardians: Vec<JsGuardianRecipient> = serde_wasm_bindgen::from_value(guardians_js)
        .map_err(|e| JsValue::from_str(&format!("Invalid guardians format: {}", e)))?;

    let guardians = js_guardians
        .into_iter()
        .map(|g| {
            let public_key: [u8; 32] = g
                .public_key
                .as_slice()
                .try_into()
                .map_err(|_| JsValue::from_str("Guardian public key must be 32 bytes"))?;
            Ok(seal::GuardianRecipient {
                address: g.address,
                public_key,
            })
        })
        .collect::<Result<Vec<_>, JsValue>>()?;

    let sealed = seal::seal_secret(payload, &recipient, &guardians, threshold, secret_id)
        .map_err(|e| JsValue::from_str(&format!("Seal failed: {}", e)))?;

    let js_sealed = JsSealedSecret {
        payload_ciphertext: sealed.payload_ciphertext,
        secret_public_key: sealed.secret_public_key.to_vec(),
        commitment: sealed.commitment.to_vec(),
        key_shares: sealed
            .key_shares
            .into_iter()
            .map(|ks| JsSealedKeyShare {
                guardian_address: ks.guardian_address,
                encrypted_share: ks.encrypted_share,
                share_hmac: ks.share_hmac,
            })
            .collect(),
    };

    serde_wasm_bindgen::to_value(&js_sealed)
        .map_err(|e| JsValue::from_str(&format!("Serialization failed: {}", e)))
}

/// Unseal a secret from revealed key-share envelopes: reconstruct the
/// per-secret private key, verify it against the stored public key (pass an
/// empty array to skip), strip the outer layer of the on-chain payload
/// ciphertext, and verify the commitment. Returns the INNER ciphertext —
/// the recipient decrypts it with decrypt_with_private_key as before.
#[wasm_bindgen]
pub fn unseal_secret(
    revealed_shares_js: JsValue,
    threshold: u8,
    payload_ciphertext: &[u8],
    commitment: &[u8],
    secret_public_key: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let revealed: Vec<serde_bytes::ByteBuf> = serde_wasm_bindgen::from_value(revealed_shares_js)
        .map_err(|e| JsValue::from_str(&format!("Invalid revealed shares format: {}", e)))?;
    let envelopes: Vec<Vec<u8>> = revealed.into_iter().map(|b| b.into_vec()).collect();

    let commitment: [u8; 32] = commitment
        .try_into()
        .map_err(|_| JsValue::from_str("Commitment must be 32 bytes"))?;

    let expected_pk: Option<[u8; 32]> = if secret_public_key.is_empty() {
        None
    } else {
        Some(
            secret_public_key
                .try_into()
                .map_err(|_| JsValue::from_str("Secret public key must be 32 bytes"))?,
        )
    };

    seal::unseal_secret(
        &envelopes,
        threshold,
        payload_ciphertext,
        &commitment,
        expected_pk.as_ref(),
    )
    .map_err(|e| JsValue::from_str(&format!("Unseal failed: {}", e)))
}

// Initialize WASM module
#[wasm_bindgen(start)]
pub fn main() {
    utils::set_panic_hook();
}
