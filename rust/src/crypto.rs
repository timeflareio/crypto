/// Asymmetric encryption for Timeflare protocol
/// 
/// This module provides encryption for both guardian share encryption 
/// and recipient secret encryption with a consistent API.

use sha2::{Sha256, Digest};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use x25519_dalek::{PublicKey, StaticSecret};
use rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::utils::{CryptoError, generate_random_bytes};

/// WASM-compatible cryptographically secure RNG: a ChaCha20 CSPRNG seeded
/// from the platform entropy source (generate_random_bytes routes through
/// getrandom, whose wasm_js backend covers WASM targets). ChaCha20Rng
/// implements RngCore + CryptoRng, so no wrapper type is needed.
pub(crate) fn wasm_compatible_rng() -> Result<ChaCha20Rng, CryptoError> {
    let seed_bytes = generate_random_bytes(32)?;
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);
    Ok(ChaCha20Rng::from_seed(seed))
}

/// Universal keypair for all Timeflare asymmetric encryption
/// 
/// This keypair type is used for both guardian share encryption and 
/// recipient secret encryption. The same API serves all use cases.
/// 
/// # Example
/// ```rust
/// use timeflare_crypto::{TimeflareKeypair, encrypt_for_public_key};
/// 
/// let keypair = TimeflareKeypair::generate();
/// let data = b"secret data";
/// 
/// let encrypted = encrypt_for_public_key(data, &keypair.public_key()).unwrap();
/// let decrypted = keypair.decrypt(&encrypted).unwrap();
/// assert_eq!(data, decrypted.as_slice());
/// ```
#[derive(Clone)]
pub struct TimeflareKeypair {
    private_key: StaticSecret,
    public_key: PublicKey,
}

impl TimeflareKeypair {
    /// Generate a new keypair (same for guardians and recipients)
    /// 
    /// Uses cryptographically secure random number generation to create
    /// a new X25519 keypair suitable for all Timeflare encryption needs.
    pub fn generate() -> Self {
        // Use WASM-compatible RNG
        let mut rng = wasm_compatible_rng().expect("Failed to create RNG");
        let private_key = StaticSecret::random_from_rng(&mut rng);
        let public_key = PublicKey::from(&private_key);
        Self { private_key, public_key }
    }
    
    /// Get public key for sharing
    /// 
    /// Returns the public key component that can be safely shared
    /// with other parties for encryption purposes.
    pub fn public_key(&self) -> TimeflarePublicKey {
        TimeflarePublicKey(self.public_key)
    }
    
    /// Decrypt data encrypted for this keypair
    /// 
    /// Decrypts data that was encrypted using this keypair's public key.
    /// Works for both guardian shares and recipient secrets.
    /// 
    /// # Arguments
    /// * `encrypted_data` - Data encrypted with `encrypt_for_public_key`
    /// 
    /// # Returns
    /// * `Ok(Vec<u8>)` - The decrypted plaintext data
    /// * `Err(CryptoError)` - If decryption fails
    pub fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        decrypt_with_private_key(&self.private_key, encrypted_data)
    }
    
    /// Serialize private key to bytes for storage
    /// 
    /// Returns the private key as 32 bytes for secure storage.
    /// This should be stored securely and never shared.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.private_key.to_bytes()
    }
    
    /// Load keypair from private key bytes
    /// 
    /// Reconstructs a keypair from stored private key bytes.
    /// The public key is derived from the private key.
    /// 
    /// # Arguments
    /// * `bytes` - 32-byte private key
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        let private_key = StaticSecret::from(bytes);
        let public_key = PublicKey::from(&private_key);
        Self { private_key, public_key }
    }
    
    /// Get public key bytes for sharing
    /// 
    /// Returns the public key as 32 bytes that can be shared
    /// with other parties for encryption purposes.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public_key.to_bytes()
    }
}

/// Public key wrapper for type safety
/// 
/// Wraps an X25519 public key to provide a clean API and prevent
/// accidental misuse of key material.
#[derive(Clone, Copy)]
pub struct TimeflarePublicKey(PublicKey);

impl TimeflarePublicKey {
    /// Convert public key to bytes for transmission/storage
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
    
    /// Create public key from bytes
    /// 
    /// # Arguments
    /// * `bytes` - 32-byte X25519 public key
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(PublicKey::from(bytes))
    }
    
    /// Get the inner X25519 public key (for internal use)
    pub(crate) fn inner(&self) -> &PublicKey {
        &self.0
    }
}

/// Encrypt data for any public key
/// 
/// This single function handles encryption for all use cases in the Timeflare protocol.
/// Uses X25519 ECDH + ChaCha20Poly1305 AEAD.
/// 
/// # Algorithm
/// 1. Generate ephemeral X25519 keypair
/// 2. Perform ECDH with recipient's public key
/// 3. Derive ChaCha20Poly1305 key using SHA256(shared_secret || "timeflare_encryption")
/// 4. Encrypt with random nonce
/// 5. Return: ephemeral_public (32) + nonce (12) + ciphertext
/// 
/// # Arguments
/// * `data` - Data to encrypt
/// * `public_key` - Recipient's public key
/// 
/// # Returns
/// * `Ok(Vec<u8>)` - Encrypted data ready for transmission
/// * `Err(CryptoError)` - If encryption fails
pub fn encrypt_for_public_key(
    data: &[u8],
    public_key: &TimeflarePublicKey,
) -> Result<Vec<u8>, CryptoError> {
    // Generate ephemeral keypair for ECDH
    let mut rng = wasm_compatible_rng()?;
    let ephemeral_secret = StaticSecret::random_from_rng(&mut rng);

    let nonce = generate_random_bytes(12)?;
    let nonce: [u8; 12] = nonce
        .try_into()
        .map_err(|_| CryptoError::RandomFailed)?;

    encrypt_with_parts(data, public_key, ephemeral_secret, &nonce)
}

/// Reports whether `key` is usable as an X25519 public key for Timeflare
/// encryption: not a small-order point.
///
/// An exchange against a small-order point yields an all-zero shared secret, so
/// every key derived from it is publicly computable. Exposed so callers (the
/// TypeScript SDK) can check a guardian's registered key BEFORE sealing and
/// report which guardian is at fault, rather than discovering it as an opaque
/// failure part-way through. The authoritative rejection still lives in
/// `encrypt_for_public_key`; this is the same predicate, surfaced early.
pub fn is_usable_x25519_public_key(key: &[u8; 32]) -> bool {
    let probe = StaticSecret::from([0x42u8; 32]);
    probe.diffie_hellman(&PublicKey::from(*key)).was_contributory()
}

/// Deterministic encryption core with caller-supplied ephemeral key and nonce.
///
/// Production callers go through `encrypt_for_public_key`, which draws both
/// from the CSPRNG; this entry point exists so the shared cross-implementation
/// test vectors (vectors/encryption.json) can pin the full wire
/// format against the Go implementation.
fn encrypt_with_parts(
    data: &[u8],
    public_key: &TimeflarePublicKey,
    ephemeral_secret: StaticSecret,
    nonce_bytes: &[u8; 12],
) -> Result<Vec<u8>, CryptoError> {
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    // Perform ECDH to derive shared secret
    let shared_secret = ephemeral_secret.diffie_hellman(public_key.inner());

    // ⚠️ A non-contributory exchange means the recipient key is a small-order
    // point: the shared secret is all-zeros, so the key derived below would be
    // SHA256(0x00…00 || domain) — publicly computable, and the "ciphertext"
    // readable by anyone. x25519-dalek does NOT reject these; it returns the
    // all-zero secret and leaves the check to the caller. Failing loudly here is
    // the whole point: the chain rejects such keys at registration, but a client
    // must never be the component that fails silently.
    // See the chain repository's docs/spec.md, "Common Attack Vectors",
    // Small-Order Key Registration.
    if !shared_secret.was_contributory() {
        return Err(CryptoError::InvalidInput(
            "recipient public key is a small-order point: the shared secret would be publicly computable".to_string(),
        ));
    }

    // Derive encryption key from shared secret
    let mut hasher = Sha256::new();
    hasher.update(shared_secret.as_bytes());
    hasher.update(b"timeflare_encryption");
    let key_bytes = hasher.finalize();

    // Encrypt using ChaCha20Poly1305
    let cipher = ChaCha20Poly1305::new_from_slice(&key_bytes[..32])
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    let nonce = Nonce::from(*nonce_bytes);

    let ciphertext = cipher
        .encrypt(&nonce, data)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    // Return: ephemeral_public (32) + nonce (12) + ciphertext
    let mut result = Vec::with_capacity(32 + 12 + ciphertext.len());
    result.extend_from_slice(ephemeral_public.as_bytes());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Internal decryption helper
/// 
/// Handles the actual decryption logic.
fn decrypt_with_private_key(
    private_key: &StaticSecret, 
    encrypted_data: &[u8]
) -> Result<Vec<u8>, CryptoError> {
    if encrypted_data.len() < 44 {  // 32 + 12 minimum
        return Err(CryptoError::DecryptionFailed("Encrypted data too short".to_string()));
    }

    // Extract components: ephemeral_public (32) + nonce (12) + ciphertext
    let ephemeral_public_bytes: [u8; 32] = encrypted_data[0..32]
        .try_into()
        .map_err(|_| CryptoError::DecryptionFailed("Invalid ephemeral public key".to_string()))?;
    let ephemeral_public = PublicKey::from(ephemeral_public_bytes);
    
    let nonce = Nonce::try_from(&encrypted_data[32..44])
        .map_err(|_| CryptoError::DecryptionFailed("Invalid nonce".to_string()))?;
    let ciphertext = &encrypted_data[44..];

    // Recreate shared secret
    let shared_secret = private_key.diffie_hellman(&ephemeral_public);

    // The ephemeral key came from the ciphertext, so it is attacker-controlled.
    // A small-order value means whoever produced this ciphertext encrypted it
    // under a publicly computable key — it was never confidential to us, so
    // refuse it rather than silently "decrypting" it.
    if !shared_secret.was_contributory() {
        return Err(CryptoError::DecryptionFailed(
            "ephemeral public key is a small-order point: this ciphertext was not encrypted confidentially".to_string(),
        ));
    }

    // Derive decryption key
    let mut hasher = Sha256::new();
    hasher.update(shared_secret.as_bytes());
    hasher.update(b"timeflare_encryption");
    let key_bytes = hasher.finalize();

    // Decrypt
    let cipher = ChaCha20Poly1305::new_from_slice(&key_bytes[..32])
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed("Failed to decrypt data".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair1 = TimeflareKeypair::generate();
        let keypair2 = TimeflareKeypair::generate();
        
        // Keys should be different
        assert_ne!(keypair1.to_bytes(), keypair2.to_bytes());
        assert_ne!(keypair1.public_key_bytes(), keypair2.public_key_bytes());
    }

    #[test]
    fn test_encryption_decryption_roundtrip() {
        let keypair = TimeflareKeypair::generate();
        let data = b"test data for encryption";
        
        let encrypted = encrypt_for_public_key(data, &keypair.public_key()).unwrap();
        let decrypted = keypair.decrypt(&encrypted).unwrap();
        
        assert_eq!(data, decrypted.as_slice());
    }

    #[test]
    fn test_key_serialization() {
        let original = TimeflareKeypair::generate();
        let bytes = original.to_bytes();
        let restored = TimeflareKeypair::from_bytes(bytes);
        
        // Should encrypt/decrypt identically
        let data = b"serialization test";
        let encrypted = encrypt_for_public_key(data, &original.public_key()).unwrap();
        let decrypted = restored.decrypt(&encrypted).unwrap();
        
        assert_eq!(data, decrypted.as_slice());
    }


    #[test]
    fn test_public_key_bytes_roundtrip() {
        let keypair = TimeflareKeypair::generate();
        let pubkey_bytes = keypair.public_key_bytes();
        let pubkey = TimeflarePublicKey::from_bytes(pubkey_bytes);
        
        // Should be able to encrypt for the reconstructed public key
        let data = b"public key bytes test";
        let encrypted = encrypt_for_public_key(data, &pubkey).unwrap();
        let decrypted = keypair.decrypt(&encrypted).unwrap();
        
        assert_eq!(data, decrypted.as_slice());
    }

    #[test]
    fn test_encryption_different_each_time() {
        let keypair = TimeflareKeypair::generate();
        let data = b"randomness test";
        
        let encrypted1 = encrypt_for_public_key(data, &keypair.public_key()).unwrap();
        let encrypted2 = encrypt_for_public_key(data, &keypair.public_key()).unwrap();
        
        // Encrypted data should be different due to random nonce
        assert_ne!(encrypted1, encrypted2);
        
        // But both should decrypt to the same plaintext
        assert_eq!(data, keypair.decrypt(&encrypted1).unwrap().as_slice());
        assert_eq!(data, keypair.decrypt(&encrypted2).unwrap().as_slice());
    }

    #[test]
    fn test_invalid_encrypted_data() {
        let keypair = TimeflareKeypair::generate();
        
        // Test with data too short
        let result = keypair.decrypt(&[1, 2, 3]);
        assert!(result.is_err());
        
        // Test with invalid ciphertext
        let mut invalid_data = vec![0u8; 64]; // 32 + 12 + some data
        invalid_data[50] = 255; // Corrupt the ciphertext
        let result = keypair.decrypt(&invalid_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_large_data_encryption_performance() {
        let keypair = TimeflareKeypair::generate();
        
        // Test different sizes up to 1MB
        let test_sizes = vec![
            1_024,      // 1KB
            10_240,     // 10KB  
            100_000,    // ~100KB
            500_000,    // 500KB
            1_048_576,  // 1MB
        ];
        
        for size in test_sizes {
            // Generate test data with predictable pattern
            let mut test_data = Vec::with_capacity(size);
            for i in 0..size {
                test_data.push((i % 256) as u8);
            }
            
            // Encrypt the data
            let start_time = std::time::Instant::now();
            let encrypted = encrypt_for_public_key(&test_data, &keypair.public_key())
                .expect(&format!("Failed to encrypt {} bytes", size));
            let encrypt_duration = start_time.elapsed();
            
            // Verify encrypted size is correct (ephemeral_key + nonce + ciphertext + auth_tag)
            let expected_size = 32 + 12 + size + 16; // X25519 + ChaCha20Poly1305 overhead
            assert_eq!(encrypted.len(), expected_size, "Encrypted size mismatch for {} bytes", size);
            
            // Decrypt the data
            let start_time = std::time::Instant::now();
            let decrypted = keypair.decrypt(&encrypted)
                .expect(&format!("Failed to decrypt {} bytes", size));
            let decrypt_duration = start_time.elapsed();
            
            // Verify data integrity
            assert_eq!(test_data, decrypted, "Data corruption detected for {} bytes", size);
            
            // Performance logging (only visible with --nocapture)
            let encrypt_mbps = (size as f64 / 1_048_576.0) / encrypt_duration.as_secs_f64();
            let decrypt_mbps = (size as f64 / 1_048_576.0) / decrypt_duration.as_secs_f64();
            
            println!(
                "Size: {:>7} bytes | Encrypt: {:>6.2} MB/s ({:>6.2}ms) | Decrypt: {:>6.2} MB/s ({:>6.2}ms)",
                size,
                encrypt_mbps,
                encrypt_duration.as_millis(),
                decrypt_mbps, 
                decrypt_duration.as_millis()
            );
            
            // Performance assertions (should be reasonably fast)
            if size >= 100_000 { // Only check performance for larger data
                assert!(encrypt_duration.as_millis() < 1000, "Encryption too slow for {} bytes: {}ms", size, encrypt_duration.as_millis());
                assert!(decrypt_duration.as_millis() < 1000, "Decryption too slow for {} bytes: {}ms", size, decrypt_duration.as_millis());
            }
        }
    }

    /// Shared cross-implementation vectors (vectors/encryption.json),
    /// also asserted by the Go suite (crypto/vectors_test.go). Pins the full
    /// wire format — ephemeral_public(32) || nonce(12) || ciphertext+tag —
    /// and the key-derivation domain against the Go implementation used by
    /// the guardian daemon.
    #[test]
    fn test_encryption_shared_vectors() {
        #[derive(serde::Deserialize)]
        struct EncryptionVector {
            name: String,
            recipient_private_hex: String,
            recipient_public_hex: String,
            ephemeral_private_hex: String,
            nonce_hex: String,
            plaintext_hex: String,
            ciphertext_hex: String,
        }

        fn hex_32(s: &str) -> [u8; 32] {
            hex::decode(s).expect("bad hex").try_into().expect("must be 32 bytes")
        }

        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../vectors/encryption.json"
        );
        let data = std::fs::read_to_string(path).expect("failed to read shared encryption vectors");
        let vectors: Vec<EncryptionVector> =
            serde_json::from_str(&data).expect("failed to parse shared encryption vectors");
        assert!(!vectors.is_empty(), "vector corpus must not be empty");

        for v in vectors {
            let recipient = TimeflareKeypair::from_bytes(hex_32(&v.recipient_private_hex));
            let ephemeral = StaticSecret::from(hex_32(&v.ephemeral_private_hex));
            let nonce: [u8; 12] = hex::decode(&v.nonce_hex)
                .expect("bad nonce hex")
                .try_into()
                .expect("nonce must be 12 bytes");
            let plaintext = hex::decode(&v.plaintext_hex).expect("bad plaintext hex");
            let expected_ciphertext = hex::decode(&v.ciphertext_hex).expect("bad ciphertext hex");

            assert_eq!(
                recipient.public_key_bytes(),
                hex_32(&v.recipient_public_hex),
                "public key derivation drifted for vector '{}'",
                v.name
            );

            let got_ciphertext =
                encrypt_with_parts(&plaintext, &recipient.public_key(), ephemeral, &nonce)
                    .expect("deterministic encryption failed");
            assert_eq!(
                got_ciphertext, expected_ciphertext,
                "encryption drifted from pinned vector '{}' — Go and Rust no longer agree",
                v.name
            );

            let got_plaintext = recipient
                .decrypt(&expected_ciphertext)
                .expect("decryption of pinned vector failed");
            assert_eq!(
                got_plaintext, plaintext,
                "decryption drifted from pinned vector '{}'",
                v.name
            );
        }
    }

    #[test]
    fn test_large_data_different_recipients() {
        // Test that large data encrypted for different recipients produces different ciphertexts
        let recipient1 = TimeflareKeypair::generate();
        let recipient2 = TimeflareKeypair::generate();
        
        // Generate 100KB of test data
        let test_data: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
        
        let encrypted1 = encrypt_for_public_key(&test_data, &recipient1.public_key()).unwrap();
        let encrypted2 = encrypt_for_public_key(&test_data, &recipient2.public_key()).unwrap();
        
        // Should be different due to different recipients
        assert_ne!(encrypted1, encrypted2);
        
        // Each recipient should be able to decrypt their own
        let decrypted1 = recipient1.decrypt(&encrypted1).unwrap();
        let decrypted2 = recipient2.decrypt(&encrypted2).unwrap();
        
        assert_eq!(test_data, decrypted1);
        assert_eq!(test_data, decrypted2);
        
        // Cross-decryption should fail
        assert!(recipient1.decrypt(&encrypted2).is_err());
        assert!(recipient2.decrypt(&encrypted1).is_err());
    }
}
#[cfg(test)]
mod low_order_rejection {
    //! Hostile-input vectors from the shared corpus
    //! (vectors/low_order_keys.json), also asserted by the Go suite
    //! (crypto/vectors_test.go). Before this check existed, every key below
    //! produced an all-zero shared secret here while Go's curve25519 errored on
    //! it — a divergence no valid-input vector could catch.
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct KeyCase {
        name: String,
        key_hex: String,
    }

    #[derive(Deserialize)]
    struct LowOrderVectors {
        reject: Vec<KeyCase>,
        accept: Vec<KeyCase>,
    }

    fn load() -> LowOrderVectors {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors/low_order_keys.json");
        let data = std::fs::read_to_string(path).expect("failed to read low_order_keys.json");
        serde_json::from_str(&data).expect("failed to parse low_order_keys.json")
    }

    fn key_bytes(hex_str: &str) -> [u8; 32] {
        let raw = hex::decode(hex_str).expect("bad hex in vector");
        let mut out = [0u8; 32];
        out.copy_from_slice(&raw);
        out
    }

    #[test]
    fn rejects_every_low_order_vector() {
        let v = load();
        assert!(!v.reject.is_empty(), "vector corpus must not be empty");
        for case in &v.reject {
            let pk = TimeflarePublicKey::from_bytes(key_bytes(&case.key_hex));
            let err = encrypt_for_public_key(b"share material", &pk).expect_err(&format!(
                "{}: encryption must refuse a small-order recipient key",
                case.name
            ));
            assert!(
                matches!(err, CryptoError::InvalidInput(_)),
                "{}: expected InvalidInput, got {err:?}",
                case.name
            );
        }
    }

    #[test]
    fn the_exported_predicate_agrees_with_the_corpus() {
        // is_usable_x25519_public_key is what the TypeScript SDK calls before
        // sealing, so it must agree with the corpus exactly — a predicate that
        // said "usable" where encryption then refuses would send the SDK's
        // pre-flight check and the real crypto in opposite directions.
        let v = load();
        for case in &v.reject {
            assert!(
                !is_usable_x25519_public_key(&key_bytes(&case.key_hex)),
                "{}: predicate must report unusable",
                case.name
            );
        }
        for case in &v.accept {
            assert!(
                is_usable_x25519_public_key(&key_bytes(&case.key_hex)),
                "{}: predicate must report usable",
                case.name
            );
        }
    }

    #[test]
    fn accepts_ordinary_keys() {
        // Guards against over-rejection: the check must never refuse an honest
        // guardian's key.
        let v = load();
        for case in &v.accept {
            let pk = TimeflarePublicKey::from_bytes(key_bytes(&case.key_hex));
            assert!(
                encrypt_for_public_key(b"share material", &pk).is_ok(),
                "{}: a valid key must still encrypt",
                case.name
            );
        }
    }

    #[test]
    fn decryption_refuses_a_small_order_ephemeral() {
        // The ephemeral key travels in the ciphertext, so it is attacker-chosen.
        // A small-order value means the ciphertext was never confidential.
        let v = load();
        let recipient = TimeflareKeypair::generate();
        let mut forged = Vec::new();
        forged.extend_from_slice(&key_bytes(&v.reject[1].key_hex)); // ephemeral_public
        forged.extend_from_slice(&[0u8; 12]); // nonce
        forged.extend_from_slice(&[0u8; 32]); // ciphertext + tag (never reached)

        let err = recipient
            .decrypt(&forged)
            .expect_err("a small-order ephemeral must be refused");
        assert!(matches!(err, CryptoError::DecryptionFailed(_)));
    }
}
