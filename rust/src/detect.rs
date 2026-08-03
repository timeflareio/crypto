/// Recipient detection hints for Timeflare (see docs/planning recipient
/// privacy plan).
///
/// The recipient's long-term public key is never published on chain. Instead,
/// each secret carries a per-secret hint: a fresh X25519 ephemeral public key
/// `R` and an 8-byte tag over the Diffie–Hellman shared secret. Only the
/// holder of the recipient's PRIVATE key can recompute the tag (computational
/// Diffie–Hellman), so no observer can link secrets to a recipient — or to
/// each other. A creator wanting no discovery supplies random bytes, which
/// are indistinguishable from a real hint.
///
/// This is the same ephemeral-static X25519 exchange `encrypt_for_public_key`
/// already performs — composition of the audited primitive, no new
/// cryptography.
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::crypto::TimeflareKeypair;
use crate::utils::CryptoError;

/// Normative domain-separation string for hint tags (spec.md "Recipient
/// Discovery"). MUST match the Go implementation in crypto/detection_hint.go
/// byte-for-byte.
pub const DETECTION_HINT_DOMAIN: &[u8] = b"timeflare/detect/v1";

/// Tag length in bytes: 2^-64 scan false positives.
pub const DETECTION_TAG_LEN: usize = 8;

/// A per-secret recipient discovery hint: `(R, tag)`.
#[derive(Debug)]
pub struct DetectionHint {
    /// R — fresh X25519 ephemeral public key, one per secret.
    pub ephemeral_pub: [u8; 32],
    /// SHA256(domain ‖ X25519(e, A))[:8]
    pub tag: [u8; DETECTION_TAG_LEN],
}

/// Derive a detection hint toward a recipient's long-term public key `A`.
/// The ephemeral private key and the shared secret never leave this function;
/// the recipient's key is not part of the result and never touches the chain.
pub fn derive_detection_hint(recipient_public_key: &[u8; 32]) -> Result<DetectionHint, CryptoError> {
    // Fresh ephemeral keypair via the crate's WASM-compatible RNG path
    let ephemeral = TimeflareKeypair::generate();
    let ephemeral_pub = ephemeral.public_key_bytes();

    let e = StaticSecret::from(ephemeral.to_bytes());
    let shared = e.diffie_hellman(&PublicKey::from(*recipient_public_key));

    // A small-order recipient key yields an all-zero shared secret, so the tag
    // would be a constant that matches EVERY recipient rather than this one.
    if !shared.was_contributory() {
        return Err(CryptoError::InvalidInput(
            "recipient public key is a small-order point: the hint would match every recipient".to_string(),
        ));
    }

    Ok(DetectionHint {
        ephemeral_pub,
        tag: hint_tag(shared.as_bytes()),
    })
}

/// Test one secret's hint against a recipient private key: recompute
/// `shared = X25519(a, R)` and compare tags in constant time. Returns true
/// iff the secret is addressed to this key.
pub fn scan_hint(
    recipient_private_key: &[u8; 32],
    ephemeral_pub: &[u8; 32],
    tag: &[u8],
) -> Result<bool, CryptoError> {
    if tag.len() != DETECTION_TAG_LEN {
        return Ok(false);
    }

    let secret = StaticSecret::from(*recipient_private_key);
    let shared = secret.diffie_hellman(&PublicKey::from(*ephemeral_pub));

    // R is taken from chain state, so it is attacker-controlled. Against a
    // small-order R every recipient derives the same all-zero shared value, so
    // one hint would match everyone and the 2^-64 false-positive bound above
    // would become 1. Treat it as no match rather than an error: a poisoned hint
    // in the feed must not abort a scan over the other secrets.
    if !shared.was_contributory() {
        return Ok(false);
    }

    let expected = hint_tag(shared.as_bytes());

    // Constant-time comparison
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(tag.iter()) {
        diff |= a ^ b;
    }
    Ok(diff == 0)
}

fn hint_tag(shared: &[u8]) -> [u8; DETECTION_TAG_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(DETECTION_HINT_DOMAIN);
    hasher.update(shared);
    let digest = hasher.finalize();
    let mut tag = [0u8; DETECTION_TAG_LEN];
    tag.copy_from_slice(&digest[..DETECTION_TAG_LEN]);
    tag
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_matches() {
        let recipient = TimeflareKeypair::generate();
        let hint = derive_detection_hint(&recipient.public_key_bytes()).unwrap();

        let matched = scan_hint(
            &recipient.to_bytes(),
            &hint.ephemeral_pub,
            &hint.tag,
        )
        .unwrap();
        assert!(matched, "recipient must recognise a hint derived from their own key");
    }

    #[test]
    fn other_key_does_not_match() {
        let recipient = TimeflareKeypair::generate();
        let other = TimeflareKeypair::generate();
        let hint = derive_detection_hint(&recipient.public_key_bytes()).unwrap();

        let matched = scan_hint(&other.to_bytes(), &hint.ephemeral_pub, &hint.tag).unwrap();
        assert!(!matched, "a different private key must not match");
    }

    #[test]
    fn hints_are_unlinkable() {
        let recipient = TimeflareKeypair::generate();
        let h1 = derive_detection_hint(&recipient.public_key_bytes()).unwrap();
        let h2 = derive_detection_hint(&recipient.public_key_bytes()).unwrap();
        assert_ne!(h1.ephemeral_pub, h2.ephemeral_pub, "fresh ephemeral per secret");
        assert_ne!(h1.tag, h2.tag, "fresh tag per secret");
    }

    #[test]
    fn wrong_tag_length_is_no_match() {
        let recipient = TimeflareKeypair::generate();
        let hint = derive_detection_hint(&recipient.public_key_bytes()).unwrap();
        let matched = scan_hint(
            &recipient.to_bytes(),
            &hint.ephemeral_pub,
            &hint.tag[..4],
        )
        .unwrap();
        assert!(!matched);
    }
}

#[cfg(test)]
mod cross_impl_vector {
    use super::*;

    /// Pins the normative detection-hint vectors from the shared corpus
    /// (vectors/detection_hint.json). Rust is the sole live
    /// implementation of hint derivation/scanning (SDK via WASM); the vectors
    /// are kept in the shared corpus so any future second implementation
    /// (e.g. a Go SDK) re-implements against them rather than from scratch.
    #[test]
    fn matches_normative_vectors() {
        #[derive(serde::Deserialize)]
        struct DetectionHintVector {
            name: String,
            recipient_private_hex: String,
            ephemeral_public_hex: String,
            tag_hex: String,
        }

        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../vectors/detection_hint.json"
        );
        let data =
            std::fs::read_to_string(path).expect("failed to read shared detection-hint vectors");
        let vectors: Vec<DetectionHintVector> =
            serde_json::from_str(&data).expect("failed to parse shared detection-hint vectors");
        assert!(!vectors.is_empty(), "vector corpus must not be empty");

        for v in vectors {
            let priv_key = hex_32(&v.recipient_private_hex);
            let ephemeral_pub = hex_32(&v.ephemeral_public_hex);
            let tag = hex::decode(&v.tag_hex).unwrap();

            let matched = scan_hint(&priv_key, &ephemeral_pub, &tag).unwrap();
            assert!(
                matched,
                "normative vector '{}' must match — implementation drifted",
                v.name
            );
        }
    }

    /// Pins the commit–reveal arithmetic (vectors/rebate_commitment.json).
    /// The recipient's client computes both values here; the chain recomputes the
    /// commitment in Go (crypto/rebate_commitment.go) to authorise payment, so a
    /// drift between the two would make every rebate uncollectable.
    #[test]
    fn matches_normative_rebate_vectors() {
        #[derive(serde::Deserialize)]
        struct RebateVector {
            name: String,
            recipient_private_hex: String,
            ephemeral_public_hex: String,
            proof_hex: String,
            collector_address_hex: String,
            commitment_hex: String,
        }

        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../vectors/rebate_commitment.json"
        );
        let data = std::fs::read_to_string(path).expect("failed to read shared rebate vectors");
        let vectors: Vec<RebateVector> =
            serde_json::from_str(&data).expect("failed to parse shared rebate vectors");
        assert!(!vectors.is_empty(), "vector corpus must not be empty");

        for v in vectors {
            let priv_key = hex_32(&v.recipient_private_hex);
            let ephemeral_pub = hex_32(&v.ephemeral_public_hex);
            let collector = hex::decode(&v.collector_address_hex).unwrap();

            let proof = recipiency_proof(&priv_key, &ephemeral_pub).unwrap();
            assert_eq!(
                hex::encode(proof),
                v.proof_hex,
                "recipiency proof drifted on vector '{}'",
                v.name
            );

            let commitment = rebate_commitment(&proof, &collector);
            assert_eq!(
                hex::encode(commitment),
                v.commitment_hex,
                "rebate commitment drifted on vector '{}'",
                v.name
            );

            // The commitment binds to both inputs: change either and it must not
            // reproduce.
            let mut other_collector = collector.clone();
            other_collector[0] ^= 0x01;
            assert_ne!(
                rebate_commitment(&proof, &other_collector),
                commitment,
                "commitment must bind to the collector address"
            );
            let mut other_proof = proof;
            other_proof[0] ^= 0x01;
            assert_ne!(
                rebate_commitment(&other_proof, &collector),
                commitment,
                "commitment must bind to the proof"
            );
        }
    }

    fn hex_32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }
}

#[cfg(test)]
mod low_order_rejection {
    //! A small-order `R` makes one hint match EVERY recipient, voiding the
    //! 2^-64 false-positive property DETECTION_TAG_LEN documents. Vectors come
    //! from the shared corpus (vectors/low_order_keys.json), so Go and
    //! Rust cannot drift on which keys are refused.
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
    fn derivation_refuses_a_small_order_recipient_key() {
        let v = load();
        for case in &v.reject {
            let err = derive_detection_hint(&key_bytes(&case.key_hex)).expect_err(&format!(
                "{}: deriving toward a small-order key must fail",
                case.name
            ));
            assert!(matches!(err, CryptoError::InvalidInput(_)));
        }
    }

    #[test]
    fn derivation_still_works_for_ordinary_keys() {
        let v = load();
        for case in &v.accept {
            assert!(
                derive_detection_hint(&key_bytes(&case.key_hex)).is_ok(),
                "{}: an ordinary recipient key must still derive a hint",
                case.name
            );
        }
    }

    #[test]
    fn scanning_a_small_order_hint_never_matches() {
        // The chain now rejects such a hint at submission, but a scanner must not
        // depend on that: a poisoned R in the feed must read as "not mine"
        // rather than as a match, and must not abort the scan either.
        let v = load();
        let universal_tag = hint_tag(&[0u8; 32]);

        for case in &v.reject {
            let r = key_bytes(&case.key_hex);
            for i in 0..3 {
                let recipient = TimeflareKeypair::generate();
                let matched = scan_hint(&recipient.to_bytes(), &r, &universal_tag)
                    .expect("a poisoned hint must not abort the scan");
                assert!(
                    !matched,
                    "{} / recipient {i}: a small-order R must never match",
                    case.name
                );
            }
        }
    }

    #[test]
    fn ordinary_hints_still_round_trip() {
        let recipient = TimeflareKeypair::generate();
        let hint = derive_detection_hint(&recipient.public_key_bytes()).unwrap();
        assert!(scan_hint(&recipient.to_bytes(), &hint.ephemeral_pub, &hint.tag).unwrap());
    }
}

/// Normative domain-separation string for rebate collection commitments
/// (spec.md "Recipient Rebate"). MUST match the Go implementation in
/// crypto/rebate_commitment.go byte-for-byte.
pub const REBATE_COMMITMENT_DOMAIN: &[u8] = b"timeflare/rebate-commit/v1";

/// Recompute the recipiency proof `z = X25519(a, R)` for one secret's hint.
///
/// This is the value `scan_hint` derives internally, returned so the recipient
/// can prove recipiency on chain when collecting a rebate. A small-order `R`
/// yields a non-contributory exchange whose shared value matches every
/// recipient, so it is rejected rather than returned.
pub fn recipiency_proof(
    recipient_private_key: &[u8; 32],
    ephemeral_pub: &[u8; 32],
) -> Result<[u8; 32], CryptoError> {
    let secret = StaticSecret::from(*recipient_private_key);
    let shared = secret.diffie_hellman(&PublicKey::from(*ephemeral_pub));
    if !shared.was_contributory() {
        return Err(CryptoError::InvalidInput(
            "hint ephemeral key is a small-order point: it addresses every recipient".to_string(),
        ));
    }
    Ok(*shared.as_bytes())
}

/// Bind a recipiency proof to the address that will collect with it:
/// `SHA256(domain ‖ z ‖ collector address bytes)`.
///
/// Published a block before the proof itself, this is what stops an observer
/// lifting the proof out of a reveal transaction and taking the rebate: they
/// cannot produce a commitment for a proof they have not yet seen.
pub fn rebate_commitment(z: &[u8], collector: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(REBATE_COMMITMENT_DOMAIN);
    hasher.update(z);
    hasher.update(collector);
    hasher.finalize().into()
}
