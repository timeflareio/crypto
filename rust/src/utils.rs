use hmac::{Hmac, KeyInit, Mac as HmacMac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Error types for cryptographic operations
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("HMAC generation failed: {0}")]
    HmacFailed(String),
    #[error("Random generation failed")]
    RandomFailed,
    #[error("Key derivation failed")]
    KeyDerivationFailed,
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

/// Generate cryptographically secure random bytes
pub fn generate_random_bytes(length: usize) -> Result<Vec<u8>, CryptoError> {
    let mut bytes = vec![0u8; length];

    // Use getrandom directly for WASM compatibility
    getrandom::fill(&mut bytes).map_err(|_| CryptoError::RandomFailed)?;

    // Verify we got non-zero bytes (basic sanity check)
    if bytes.iter().all(|&b| b == 0) {
        return Err(CryptoError::RandomFailed);
    }

    Ok(bytes)
}

/// Generate HMAC matching the guardian Go implementation exactly — including
/// what it rejects: an empty secret ID, guardian address or share payload is
/// refused here for the same reason and at the same boundary as in
/// crypto/hmac.go, so the two implementations agree on what is taggable. The
/// corpus pins agreed outputs and so cannot pin a shared rejection; the empty
/// bound is asserted by both suites instead.
pub fn generate_guardian_hmac(
    secret_id: &str,
    guardian_address: &str,
    share_data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if secret_id.is_empty() {
        return Err(CryptoError::InvalidInput(
            "secret ID cannot be empty".to_string(),
        ));
    }
    if guardian_address.is_empty() {
        return Err(CryptoError::InvalidInput(
            "guardian address cannot be empty".to_string(),
        ));
    }
    if share_data.is_empty() {
        return Err(CryptoError::InvalidInput(
            "share data cannot be empty".to_string(),
        ));
    }

    // Step 1: Generate HMAC key (matching crypto/hmac.go)
    let mut key_hash = Sha256::new();
    key_hash.update(b"secrets"); // Module name
    key_hash.update(secret_id.as_bytes());
    key_hash.update(guardian_address.as_bytes());
    key_hash.update(b"hmac_salt");
    let hmac_key = key_hash.finalize();

    // Step 2: Generate HMAC (matching crypto/hmac.go)
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&hmac_key).unwrap();
    mac.update(share_data);
    mac.update(guardian_address.as_bytes());
    mac.update(secret_id.as_bytes());

    Ok(mac.finalize().into_bytes().to_vec())
}

/// Set up panic hook for better error messages in WASM
pub fn set_panic_hook() {
    // When the `console_error_panic_hook` feature is enabled, we can call the
    // `set_panic_hook` function at least once during initialization, and then
    // we will get better error messages if our code ever panics.
    //
    // For more details see
    // https://github.com/rustwasm/console_error_panic_hook#readme
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_panic_hook() {
        // Just verify the function can be called without panicking
        set_panic_hook();
    }

    #[test]
    fn test_hmac_generation() {
        let share = b"test share";
        let guardian_addr = "tmflr1guardian123";
        let secret_id = "secret-123";

        let hmac1 = generate_guardian_hmac(secret_id, guardian_addr, share).unwrap();
        let hmac2 = generate_guardian_hmac(secret_id, guardian_addr, share).unwrap();

        assert_eq!(hmac1, hmac2); // Should be deterministic
        assert_eq!(hmac1.len(), 32); // SHA256 output
    }

    /// The Go implementation refuses an empty secret ID, guardian address or
    /// share payload (crypto/hmac.go); this side must draw the line in the
    /// same place. The corpus cannot pin a rejection, so the bound is asserted
    /// from both suites — the Go side's is FuzzGenerateHMACAgreesWithVerify's
    /// empty seed.
    #[test]
    fn test_empty_inputs_are_refused() {
        for (secret_id, guardian_address, share_data) in [
            ("", "tmflr1guardian123", b"share".as_slice()),
            ("secret-123", "", b"share".as_slice()),
            ("secret-123", "tmflr1guardian123", b"".as_slice()),
        ] {
            let err = generate_guardian_hmac(secret_id, guardian_address, share_data)
                .expect_err("an empty input must be refused");
            assert!(matches!(err, CryptoError::InvalidInput(_)));
        }

        // The boundary sits exactly at empty: one byte of everything is taggable.
        assert!(generate_guardian_hmac("s", "g", b"x").is_ok());
    }

    #[test]
    fn test_random_bytes_generation() {
        let bytes1 = generate_random_bytes(32).unwrap();
        let bytes2 = generate_random_bytes(32).unwrap();

        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
        assert_ne!(bytes1, bytes2); // Should be different
    }

    #[test]
    fn test_guardian_hmac_compatibility() {
        // Test the exact same parameters as Go implementation
        let secret_id = "test_secret";
        let guardian_address = "tmflr1test";
        let share_data = vec![1, 2, 3, 4];

        let hmac = generate_guardian_hmac(secret_id, guardian_address, &share_data).unwrap();

        assert_eq!(hmac.len(), 32); // SHA256 HMAC length

        // Test deterministic behavior
        let hmac2 = generate_guardian_hmac(secret_id, guardian_address, &share_data).unwrap();
        assert_eq!(hmac, hmac2);
    }

    /// Shared cross-implementation vectors (vectors/hmac.json), also
    /// asserted by the Go suite (crypto/vectors_test.go). The consensus path
    /// in x/secrets uses the Go implementation; this test is what guarantees
    /// the two cannot drift apart silently.
    #[test]
    fn test_hmac_shared_vectors() {
        #[derive(serde::Deserialize)]
        struct HmacVector {
            name: String,
            secret_id: String,
            guardian_address: String,
            share_data_hex: String,
            expected_hmac_hex: String,
        }

        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors/hmac.json");
        let data = std::fs::read_to_string(path).expect("failed to read shared hmac vectors");
        let vectors: Vec<HmacVector> =
            serde_json::from_str(&data).expect("failed to parse shared hmac vectors");
        assert!(!vectors.is_empty(), "vector corpus must not be empty");

        for v in vectors {
            let share_data = hex::decode(&v.share_data_hex).expect("bad share hex");
            let expected = hex::decode(&v.expected_hmac_hex).expect("bad hmac hex");

            let got = generate_guardian_hmac(&v.secret_id, &v.guardian_address, &share_data)
                .expect("a pinned vector's inputs are taggable");
            assert_eq!(
                got, expected,
                "HMAC drifted from pinned vector '{}' — Go and Rust no longer agree",
                v.name
            );
        }
    }
}
