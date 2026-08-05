/// Key-share sealing for Timeflare (see docs/planning key-share architecture)
///
/// The time-lock is a fresh single-use X25519 keypair per secret: the payload
/// is encrypted to the recipient (inner layer, unchanged), that ciphertext is
/// encrypted once more to the per-secret public key (outer layer), and the
/// per-secret PRIVATE key — 32 bytes — is what gets Shamir-split among the
/// guardians. Share size becomes independent of secret size.
///
/// These helpers compose the audited primitives in `crypto` and `sss` into the
/// single code path every client uses:
///
///   seal_secret:   payload → C_r → commitment → (pk_s, sk_s) → C → key shares
///   unseal_secret: key shares → sk_s → C_r (verified against the commitment)
///
/// No new cryptographic primitives are introduced.
use sha2::{Digest, Sha256};

use crate::crypto::{encrypt_for_public_key, TimeflareKeypair, TimeflarePublicKey};
use crate::sss;
use crate::utils::{generate_guardian_hmac, CryptoError};

/// Version byte of the key-share envelope. The envelope is
/// `version(1B) ‖ sss_id(1B) ‖ sk_s_share(32B)` = 34 bytes — versioned so a
/// future format (e.g. Feldman VSS commitments) is not a wire break.
pub const KEY_SHARE_ENVELOPE_VERSION: u8 = 1;

/// Exact length of a v1 plaintext key-share envelope.
pub const KEY_SHARE_ENVELOPE_LEN: usize = 34;

/// The X25519 private scalar is always 32 bytes; the raw `StaticSecret` bytes
/// are what is split (clamping happens at Diffie–Hellman time, so the bytes
/// round-trip exactly through split → combine).
const SECRET_KEY_LEN: usize = 32;

/// A guardian's identity and encryption key, as returned by Phase 1.
pub struct GuardianRecipient {
    pub address: String,
    pub public_key: [u8; 32],
}

/// One guardian's sealed key share, ready for MsgUserDistributeShares.
pub struct SealedKeyShare {
    pub guardian_address: String,
    /// The 34B envelope encrypted to the guardian's public key (~94B).
    pub encrypted_share: Vec<u8>,
    /// HMAC over the PLAINTEXT envelope — the chain's reveal/slash commitment.
    pub share_hmac: Vec<u8>,
}

/// Everything MsgUserDistributeShares needs, from one seal_secret call.
pub struct SealedSecret {
    /// C — the recipient-encrypted payload, encrypted once more to pk_s.
    /// Stored on chain exactly once.
    pub payload_ciphertext: Vec<u8>,
    /// pk_s — stored on the secret record for public fault attribution.
    pub secret_public_key: [u8; 32],
    /// SHA256(C_r) — verifies reconstruction without the recipient's key.
    pub commitment: [u8; 32],
    /// One sealed key share per guardian, in input order.
    pub key_shares: Vec<SealedKeyShare>,
}

/// Encode a v1 key-share envelope: `version ‖ sss_id ‖ share`.
pub fn encode_key_share(share: &sss::Share) -> Result<Vec<u8>, CryptoError> {
    if share.data.len() != SECRET_KEY_LEN {
        return Err(CryptoError::InvalidInput(format!(
            "key share must be {} bytes, got {}",
            SECRET_KEY_LEN,
            share.data.len()
        )));
    }
    let mut envelope = Vec::with_capacity(KEY_SHARE_ENVELOPE_LEN);
    envelope.push(KEY_SHARE_ENVELOPE_VERSION);
    envelope.push(share.id);
    envelope.extend_from_slice(&share.data);
    Ok(envelope)
}

/// Decode a v1 key-share envelope back into an SSS share.
pub fn decode_key_share(envelope: &[u8]) -> Result<sss::Share, CryptoError> {
    if envelope.len() != KEY_SHARE_ENVELOPE_LEN {
        return Err(CryptoError::InvalidInput(format!(
            "key-share envelope must be {} bytes, got {}",
            KEY_SHARE_ENVELOPE_LEN,
            envelope.len()
        )));
    }
    if envelope[0] != KEY_SHARE_ENVELOPE_VERSION {
        return Err(CryptoError::InvalidInput(format!(
            "unsupported key-share envelope version: {}",
            envelope[0]
        )));
    }
    Ok(sss::Share {
        id: envelope[1],
        data: envelope[2..].to_vec(),
    })
}

/// Seal a payload for time-locked distribution.
///
/// Performs, in order: inner encryption to the recipient, commitment over the
/// inner ciphertext, per-secret keypair generation, outer encryption to the
/// per-secret key, t-of-n split of the per-secret PRIVATE key, and per-guardian
/// envelope encryption + HMAC. The per-secret private key is dropped before
/// returning — after this call it exists only as guardian shares.
pub fn seal_secret(
    payload: &[u8],
    recipient_public_key: &[u8; 32],
    guardians: &[GuardianRecipient],
    threshold: u8,
    secret_id: &str,
) -> Result<SealedSecret, CryptoError> {
    if guardians.is_empty() {
        return Err(CryptoError::InvalidInput(
            "at least one guardian is required".to_string(),
        ));
    }
    if guardians.len() > u8::MAX as usize {
        return Err(CryptoError::InvalidInput(format!(
            "too many guardians: {}",
            guardians.len()
        )));
    }

    // Inner layer: payload → C_r (identical to the pre-key-share scheme)
    let recipient_key = TimeflarePublicKey::from_bytes(*recipient_public_key);
    let inner_ciphertext = encrypt_for_public_key(payload, &recipient_key)?;

    // Commitment binds the inner ciphertext — reconstruction integrity is
    // verifiable by anyone, while the randomised encryption deliberately
    // prevents plaintext-guess confirmation
    let commitment: [u8; 32] = Sha256::digest(&inner_ciphertext).into();

    // The time-lock: a fresh single-use keypair whose private key nobody keeps
    let secret_keypair = TimeflareKeypair::generate();
    let secret_public_key = secret_keypair.public_key_bytes();

    // Outer layer: C_r → C, the only copy of the secret material on chain
    let payload_ciphertext =
        encrypt_for_public_key(&inner_ciphertext, &secret_keypair.public_key())?;

    // Split the raw 32-byte private scalar t-of-n
    let sk_bytes = secret_keypair.to_bytes();
    let shares = sss::split_secret(&sk_bytes, threshold, guardians.len() as u8)
        .map_err(|e| CryptoError::InvalidInput(format!("key split failed: {}", e)))?;

    let mut key_shares = Vec::with_capacity(guardians.len());
    for (guardian, share) in guardians.iter().zip(shares.iter()) {
        let envelope = encode_key_share(share)?;
        let guardian_key = TimeflarePublicKey::from_bytes(guardian.public_key);
        let encrypted_share = encrypt_for_public_key(&envelope, &guardian_key)?;
        let share_hmac = generate_guardian_hmac(secret_id, &guardian.address, &envelope);
        key_shares.push(SealedKeyShare {
            guardian_address: guardian.address.clone(),
            encrypted_share,
            share_hmac,
        });
    }

    // secret_keypair (and sk_bytes) drop here — x25519-dalek zeroises the
    // scalar on drop; from now on sk_s exists only as the shares above
    Ok(SealedSecret {
        payload_ciphertext,
        secret_public_key,
        commitment,
        key_shares,
    })
}

/// Combine revealed key-share envelopes into the per-secret private key.
pub fn combine_key_shares(envelopes: &[Vec<u8>], threshold: u8) -> Result<[u8; 32], CryptoError> {
    let shares = envelopes
        .iter()
        .map(|e| decode_key_share(e))
        .collect::<Result<Vec<_>, _>>()?;

    let sk = sss::combine_shares(&shares, threshold)
        .map_err(|e| CryptoError::InvalidInput(format!("key reconstruction failed: {}", e)))?;

    sk.try_into().map_err(|v: Vec<u8>| {
        CryptoError::InvalidInput(format!(
            "reconstructed key must be {} bytes, got {}",
            SECRET_KEY_LEN,
            v.len()
        ))
    })
}

/// Unseal a secret from revealed key shares: reconstruct sk_s, optionally
/// verify it against the stored pk_s, strip the outer layer of the on-chain
/// payload ciphertext, and verify the commitment.
///
/// Returns the INNER ciphertext C_r — the public, verified reconstruction
/// result. Only the recipient can take the final step
/// (`decrypt_with_private_key(recipient_key, C_r)`), exactly as before.
pub fn unseal_secret(
    revealed_envelopes: &[Vec<u8>],
    threshold: u8,
    payload_ciphertext: &[u8],
    commitment: &[u8; 32],
    expected_secret_public_key: Option<&[u8; 32]>,
) -> Result<Vec<u8>, CryptoError> {
    let sk = combine_key_shares(revealed_envelopes, threshold)?;
    let keypair = TimeflareKeypair::from_bytes(sk);

    // Fault attribution: a reconstructed key matching pk_s while decryption or
    // the commitment fails is provable creator fault, not guardian fault
    if let Some(expected) = expected_secret_public_key {
        if &keypair.public_key_bytes() != expected {
            return Err(CryptoError::InvalidInput(
                "reconstructed key does not match the secret's public key".to_string(),
            ));
        }
    }

    let inner_ciphertext = keypair.decrypt(payload_ciphertext)?;

    let digest: [u8; 32] = Sha256::digest(&inner_ciphertext).into();
    if &digest != commitment {
        return Err(CryptoError::InvalidInput(
            "reconstructed payload does not match the on-chain commitment".to_string(),
        ));
    }

    Ok(inner_ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn test_guardians(n: usize) -> (Vec<GuardianRecipient>, Vec<TimeflareKeypair>) {
        let mut guardians = Vec::with_capacity(n);
        let mut keypairs = Vec::with_capacity(n);
        for i in 0..n {
            let kp = TimeflareKeypair::generate();
            guardians.push(GuardianRecipient {
                address: format!("tmflr1guardian{:02}", i),
                public_key: kp.public_key_bytes(),
            });
            keypairs.push(kp);
        }
        (guardians, keypairs)
    }

    /// Full round trip: seal → guardian decrypt → reveal → unseal → recipient decrypt.
    #[test]
    fn test_seal_unseal_round_trip() {
        let payload = b"the launch codes are 0000";
        let recipient = TimeflareKeypair::generate();
        let (guardians, guardian_keys) = test_guardians(5);
        let threshold = 3u8;
        let secret_id = "9f2c1a34-0000-4000-8000-000000000001";

        let sealed = seal_secret(
            payload,
            &recipient.public_key_bytes(),
            &guardians,
            threshold,
            secret_id,
        )
        .unwrap();

        assert_eq!(sealed.key_shares.len(), 5);
        // Envelope: 34B plaintext + 60B encryption overhead
        for ks in &sealed.key_shares {
            assert_eq!(ks.encrypted_share.len(), KEY_SHARE_ENVELOPE_LEN + 60);
            assert_eq!(ks.share_hmac.len(), 32);
        }
        // Payload ciphertext: payload + two 60B layers
        assert_eq!(sealed.payload_ciphertext.len(), payload.len() + 120);

        // Each guardian decrypts its envelope (what it holds off-chain and
        // later reveals); HMAC over the plaintext envelope must verify
        let mut revealed = Vec::new();
        for (i, kp) in guardian_keys.iter().enumerate().take(threshold as usize) {
            let envelope = kp.decrypt(&sealed.key_shares[i].encrypted_share).unwrap();
            assert_eq!(envelope.len(), KEY_SHARE_ENVELOPE_LEN);
            assert_eq!(envelope[0], KEY_SHARE_ENVELOPE_VERSION);
            let hmac = generate_guardian_hmac(secret_id, &guardians[i].address, &envelope);
            assert_eq!(hmac, sealed.key_shares[i].share_hmac);
            revealed.push(envelope);
        }

        // Anyone reconstructs and verifies C_r against the commitment
        let inner = unseal_secret(
            &revealed,
            threshold,
            &sealed.payload_ciphertext,
            &sealed.commitment,
            Some(&sealed.secret_public_key),
        )
        .unwrap();

        // Only the recipient reads the payload
        let decrypted = recipient.decrypt(&inner).unwrap();
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn test_unseal_with_any_threshold_subset() {
        let payload = vec![0x42u8; 1024];
        let recipient = TimeflareKeypair::generate();
        let (guardians, guardian_keys) = test_guardians(7);
        let secret_id = "9f2c1a34-0000-4000-8000-000000000002";

        let sealed = seal_secret(
            &payload,
            &recipient.public_key_bytes(),
            &guardians,
            3,
            secret_id,
        )
        .unwrap();

        // A non-contiguous subset (indices 1, 4, 6) must reconstruct
        let revealed: Vec<Vec<u8>> = [1usize, 4, 6]
            .iter()
            .map(|&i| {
                guardian_keys[i]
                    .decrypt(&sealed.key_shares[i].encrypted_share)
                    .unwrap()
            })
            .collect();

        let inner = unseal_secret(
            &revealed,
            3,
            &sealed.payload_ciphertext,
            &sealed.commitment,
            Some(&sealed.secret_public_key),
        )
        .unwrap();
        assert_eq!(recipient.decrypt(&inner).unwrap(), payload);
    }

    #[test]
    fn test_insufficient_shares_fail() {
        let recipient = TimeflareKeypair::generate();
        let (guardians, guardian_keys) = test_guardians(5);
        let secret_id = "9f2c1a34-0000-4000-8000-000000000003";

        let sealed = seal_secret(
            b"secret",
            &recipient.public_key_bytes(),
            &guardians,
            3,
            secret_id,
        )
        .unwrap();

        let revealed: Vec<Vec<u8>> = guardian_keys
            .iter()
            .enumerate()
            .take(2)
            .map(|(i, kp)| kp.decrypt(&sealed.key_shares[i].encrypted_share).unwrap())
            .collect();

        assert!(unseal_secret(
            &revealed,
            3,
            &sealed.payload_ciphertext,
            &sealed.commitment,
            Some(&sealed.secret_public_key),
        )
        .is_err());
    }

    /// A wrong reconstruction must fail loudly at every guard: pk_s check,
    /// outer AEAD, and commitment.
    #[test]
    fn test_tampered_share_fails() {
        let recipient = TimeflareKeypair::generate();
        let (guardians, guardian_keys) = test_guardians(5);
        let secret_id = "9f2c1a34-0000-4000-8000-000000000004";

        let sealed = seal_secret(
            b"secret",
            &recipient.public_key_bytes(),
            &guardians,
            3,
            secret_id,
        )
        .unwrap();

        let mut revealed: Vec<Vec<u8>> = guardian_keys
            .iter()
            .enumerate()
            .take(3)
            .map(|(i, kp)| kp.decrypt(&sealed.key_shares[i].encrypted_share).unwrap())
            .collect();

        // Corrupt one share's y-values (keep envelope shape valid)
        revealed[1][10] ^= 0xff;

        // With the pk_s check the tamper is caught before any decryption
        assert!(unseal_secret(
            &revealed,
            3,
            &sealed.payload_ciphertext,
            &sealed.commitment,
            Some(&sealed.secret_public_key),
        )
        .is_err());

        // Without it, the outer AEAD tag still fails the reconstruction
        assert!(unseal_secret(
            &revealed,
            3,
            &sealed.payload_ciphertext,
            &sealed.commitment,
            None,
        )
        .is_err());
    }

    #[test]
    fn test_commitment_mismatch_fails() {
        let recipient = TimeflareKeypair::generate();
        let (guardians, guardian_keys) = test_guardians(4);
        let secret_id = "9f2c1a34-0000-4000-8000-000000000005";

        let sealed = seal_secret(
            b"secret",
            &recipient.public_key_bytes(),
            &guardians,
            2,
            secret_id,
        )
        .unwrap();

        let revealed: Vec<Vec<u8>> = guardian_keys
            .iter()
            .enumerate()
            .take(2)
            .map(|(i, kp)| kp.decrypt(&sealed.key_shares[i].encrypted_share).unwrap())
            .collect();

        let wrong_commitment = [0u8; 32];
        assert!(unseal_secret(
            &revealed,
            2,
            &sealed.payload_ciphertext,
            &wrong_commitment,
            Some(&sealed.secret_public_key),
        )
        .is_err());
    }

    #[test]
    fn test_envelope_encode_decode() {
        let share = sss::Share {
            id: 7,
            data: vec![0xabu8; 32],
        };
        let envelope = encode_key_share(&share).unwrap();
        assert_eq!(envelope.len(), KEY_SHARE_ENVELOPE_LEN);
        assert_eq!(envelope[0], KEY_SHARE_ENVELOPE_VERSION);
        assert_eq!(envelope[1], 7);

        let decoded = decode_key_share(&envelope).unwrap();
        assert_eq!(decoded.id, share.id);
        assert_eq!(decoded.data, share.data);

        // Wrong version rejected
        let mut bad = envelope.clone();
        bad[0] = 2;
        assert!(decode_key_share(&bad).is_err());

        // Wrong length rejected
        assert!(decode_key_share(&envelope[..33]).is_err());
    }

    /// The raw scalar bytes must round-trip exactly through split → combine
    /// (normative: clamping happens at DH time, not at storage time).
    #[test]
    fn test_scalar_bytes_round_trip_exactly() {
        for _ in 0..10 {
            let kp = TimeflareKeypair::generate();
            let sk = kp.to_bytes();
            let shares = sss::split_secret(&sk, 3, 5).unwrap();
            let envelopes: Vec<Vec<u8>> = shares
                .iter()
                .map(|s| encode_key_share(s).unwrap())
                .collect();
            let recovered = combine_key_shares(&envelopes[..3], 3).unwrap();
            assert_eq!(recovered, sk);
        }
    }
}

/// Property and randomised-input tests for the seal/unseal pair.
///
/// `unseal_secret` is the client-side counterpart of the guardian's decrypt
/// path: every argument — the revealed envelopes, the payload ciphertext, the
/// commitment — comes from chain state, so all of it is attacker-influenced.
/// The properties assert the round trip holds for arbitrary inputs, that any
/// single-byte tamper is caught, and that no input reaches a panic.
///
/// Case count is `PROPTEST_CASES` (default 256). `make fuzz` raises it.
#[cfg(test)]
mod property_tests {
    use super::tests::test_guardians;
    use super::*;
    use proptest::prelude::*;

    const SECRET_ID: &str = "9f2c1a34-0000-4000-8000-0000000000ff";

    /// A `(threshold, guardians)` pair. The ceilings stay below the SSS bands of
    /// 16 and 32: every case seals afresh, which means a keypair and an X25519
    /// encryption per guardian, and the band extremes are already covered by the
    /// boundary unit tests above. What varies here is the relationship between
    /// the two, which is what the properties are about.
    fn threshold_and_guardians() -> impl Strategy<Value = (u8, usize)> {
        (2u8..=6).prop_flat_map(|threshold| {
            (
                Just(threshold),
                (threshold as usize)..=(threshold as usize + 6),
            )
        })
    }

    /// Seal `payload`, then decrypt `count` guardians' envelopes back to the
    /// plaintext form they later reveal on chain.
    fn seal_and_reveal(
        payload: &[u8],
        threshold: u8,
        guardian_count: usize,
        reveal: usize,
    ) -> (SealedSecret, Vec<Vec<u8>>, TimeflareKeypair) {
        let recipient = TimeflareKeypair::generate();
        let (guardians, guardian_keys) = test_guardians(guardian_count);
        let sealed = seal_secret(
            payload,
            &recipient.public_key_bytes(),
            &guardians,
            threshold,
            SECRET_ID,
        )
        .expect("valid parameters seal successfully");

        let revealed = guardian_keys
            .iter()
            .take(reveal)
            .enumerate()
            .map(|(i, kp)| kp.decrypt(&sealed.key_shares[i].encrypted_share).unwrap())
            .collect();

        (sealed, revealed, recipient)
    }

    /// The five scalar bits X25519 overwrites before use, as
    /// `(byte index, bit)` — RFC 7748 clears bits 0–2 of byte 0, clears bit 7
    /// of byte 31 and sets bit 6 of byte 31.
    const CLAMPED_BITS: [(usize, u32); 5] = [(0, 0), (0, 1), (0, 2), (31, 6), (31, 7)];

    /// Two sk_s values differing only in clamped bits are the same key.
    ///
    /// This is why reconstruction can succeed on a tampered share, and stating
    /// it here means the property test above is not the only place a reader
    /// learns of it. Nothing is lost by it: the recovered key, and so the
    /// recovered payload, is the correct one either way.
    #[test]
    fn clamped_scalar_bits_do_not_affect_the_key() {
        let base = [0x5au8; 32];
        let expected = TimeflareKeypair::from_bytes(base).public_key_bytes();

        for (byte, bit) in CLAMPED_BITS {
            let mut altered = base;
            altered[byte] ^= 1 << bit;
            assert_ne!(altered, base, "the flip must change the scalar bytes");
            assert_eq!(
                TimeflareKeypair::from_bytes(altered).public_key_bytes(),
                expected,
                "flipping byte {} bit {} must not change the derived key",
                byte,
                bit
            );
        }
    }

    /// Every bit outside that set does change the key, so the inert set is
    /// exactly five bits wide and no wider.
    #[test]
    fn unclamped_scalar_bits_do_affect_the_key() {
        let base = [0x5au8; 32];
        let expected = TimeflareKeypair::from_bytes(base).public_key_bytes();

        for byte in 0..32usize {
            for bit in 0..8u32 {
                if CLAMPED_BITS.contains(&(byte, bit)) {
                    continue;
                }
                let mut altered = base;
                altered[byte] ^= 1 << bit;
                assert_ne!(
                    TimeflareKeypair::from_bytes(altered).public_key_bytes(),
                    expected,
                    "flipping byte {} bit {} must change the derived key",
                    byte,
                    bit
                );
            }
        }
    }

    proptest! {
        /// The full protocol path holds for arbitrary payloads and arbitrary
        /// valid guardian arrangements: seal → guardians decrypt → reveal →
        /// unseal → recipient decrypts, ending at the original bytes.
        #[test]
        fn seal_then_unseal_is_the_identity(
            payload in prop::collection::vec(any::<u8>(), 0..=256),
            (threshold, guardian_count) in threshold_and_guardians(),
        ) {
            let (sealed, revealed, recipient) =
                seal_and_reveal(&payload, threshold, guardian_count, threshold as usize);

            let inner = unseal_secret(
                &revealed,
                threshold,
                &sealed.payload_ciphertext,
                &sealed.commitment,
                Some(&sealed.secret_public_key),
            )
            .expect("a threshold-sized reveal unseals");

            prop_assert_eq!(recipient.decrypt(&inner).unwrap(), payload);
        }

        /// Every guardian's HMAC binds its own plaintext envelope, so the chain
        /// can attribute a bad reveal to the guardian that made it.
        #[test]
        fn revealed_envelopes_match_their_hmacs(
            payload in prop::collection::vec(any::<u8>(), 1..=64),
            (threshold, guardian_count) in threshold_and_guardians(),
        ) {
            let recipient = TimeflareKeypair::generate();
            let (guardians, guardian_keys) = test_guardians(guardian_count);
            let sealed = seal_secret(
                &payload,
                &recipient.public_key_bytes(),
                &guardians,
                threshold,
                SECRET_ID,
            )
            .unwrap();

            for (i, kp) in guardian_keys.iter().enumerate() {
                let envelope = kp.decrypt(&sealed.key_shares[i].encrypted_share).unwrap();
                prop_assert_eq!(envelope.len(), KEY_SHARE_ENVELOPE_LEN);
                prop_assert_eq!(envelope[0], KEY_SHARE_ENVELOPE_VERSION);
                let hmac = generate_guardian_hmac(SECRET_ID, &guardians[i].address, &envelope);
                prop_assert_eq!(&hmac, &sealed.key_shares[i].share_hmac);
            }
        }

        /// Flipping any single bit of any revealed envelope cannot produce a
        /// *different* payload: the tamper is either caught, or it is inert.
        ///
        /// Inert is the interesting half, and it is not a defect. The shared
        /// secret is a raw X25519 scalar, and X25519 clamps before use — bits
        /// 0–2 of byte 0 and bits 6–7 of byte 31 are overwritten (RFC 7748), so
        /// a perturbation confined to them reconstructs a scalar that differs
        /// byte-wise while clamping to the same key. Reconstruction then
        /// succeeds and yields the correct payload, which is why the assertion
        /// is "never a wrong answer" rather than "always an error". Detecting
        /// the tamper itself is the guardian HMAC's job, not this path's — see
        /// `revealed_envelopes_match_their_hmacs`, which is what the chain
        /// checks before a reveal is accepted.
        #[test]
        fn a_tampered_envelope_never_yields_a_different_payload(
            payload in prop::collection::vec(any::<u8>(), 1..=64),
            (threshold, guardian_count) in threshold_and_guardians(),
            which: prop::sample::Index,
            byte_index: prop::sample::Index,
            bit in 0u32..8,
        ) {
            let (sealed, revealed, _) =
                seal_and_reveal(&payload, threshold, guardian_count, threshold as usize);

            let untampered = unseal_secret(
                &revealed,
                threshold,
                &sealed.payload_ciphertext,
                &sealed.commitment,
                Some(&sealed.secret_public_key),
            )
            .expect("the untampered reveal unseals");

            let mut tampered = revealed;
            let target = which.index(tampered.len());
            tampered[target][byte_index.index(KEY_SHARE_ENVELOPE_LEN)] ^= 1 << bit;

            match unseal_secret(
                &tampered,
                threshold,
                &sealed.payload_ciphertext,
                &sealed.commitment,
                Some(&sealed.secret_public_key),
            ) {
                Err(_) => {}
                Ok(inner) => prop_assert_eq!(inner, untampered),
            }
        }

        /// Flipping any single bit of the on-chain payload ciphertext never
        /// yields a different payload: the outer AEAD catches it, or — for the
        /// masked top bit of the outer ephemeral key's u-coordinate — it is
        /// inert and the commitment still holds. Same reasoning as
        /// `crypto::property_tests::MASKED_U_COORDINATE_BIT`.
        #[test]
        fn a_tampered_payload_ciphertext_never_yields_a_different_payload(
            payload in prop::collection::vec(any::<u8>(), 1..=64),
            (threshold, guardian_count) in threshold_and_guardians(),
            byte_index: prop::sample::Index,
            bit in 0u32..8,
        ) {
            let (sealed, revealed, _) =
                seal_and_reveal(&payload, threshold, guardian_count, threshold as usize);

            let untampered = unseal_secret(
                &revealed,
                threshold,
                &sealed.payload_ciphertext,
                &sealed.commitment,
                Some(&sealed.secret_public_key),
            )
            .expect("the untampered ciphertext unseals");

            let mut tampered = sealed.payload_ciphertext.clone();
            let index = byte_index.index(tampered.len());
            tampered[index] ^= 1 << bit;

            match unseal_secret(
                &revealed,
                threshold,
                &tampered,
                &sealed.commitment,
                Some(&sealed.secret_public_key),
            ) {
                Err(_) => {}
                Ok(inner) => prop_assert_eq!(inner, untampered),
            }
        }

        /// A commitment that does not match the reconstructed payload is
        /// refused. This is the check that lets anyone verify a reveal without
        /// holding the recipient's key.
        #[test]
        fn a_wrong_commitment_is_rejected(
            payload in prop::collection::vec(any::<u8>(), 1..=64),
            (threshold, guardian_count) in threshold_and_guardians(),
            commitment: [u8; 32],
        ) {
            let (sealed, revealed, _) =
                seal_and_reveal(&payload, threshold, guardian_count, threshold as usize);
            prop_assume!(commitment != sealed.commitment);

            prop_assert!(unseal_secret(
                &revealed,
                threshold,
                &sealed.payload_ciphertext,
                &commitment,
                None,
            ).is_err());
        }

        /// A reconstructed key that does not match the secret's published pk_s
        /// is refused before decryption is attempted — the fault-attribution
        /// path.
        #[test]
        fn a_wrong_secret_public_key_is_rejected(
            payload in prop::collection::vec(any::<u8>(), 1..=64),
            (threshold, guardian_count) in threshold_and_guardians(),
            expected: [u8; 32],
        ) {
            let (sealed, revealed, _) =
                seal_and_reveal(&payload, threshold, guardian_count, threshold as usize);
            prop_assume!(expected != sealed.secret_public_key);

            prop_assert!(unseal_secret(
                &revealed,
                threshold,
                &sealed.payload_ciphertext,
                &sealed.commitment,
                Some(&expected),
            ).is_err());
        }

        /// Fewer than `threshold` reveals cannot unseal.
        #[test]
        fn a_sub_threshold_reveal_is_rejected(
            payload in prop::collection::vec(any::<u8>(), 1..=64),
            (threshold, guardian_count) in threshold_and_guardians(),
        ) {
            let (sealed, revealed, _) =
                seal_and_reveal(&payload, threshold, guardian_count, threshold as usize - 1);

            prop_assert!(unseal_secret(
                &revealed,
                threshold,
                &sealed.payload_ciphertext,
                &sealed.commitment,
                Some(&sealed.secret_public_key),
            ).is_err());
        }

        /// A well-formed envelope round-trips through encode and decode.
        #[test]
        fn key_share_envelopes_round_trip(id in 1u8..=255, data: [u8; 32]) {
            let share = sss::Share { id, data: data.to_vec() };
            let envelope = encode_key_share(&share).unwrap();
            prop_assert_eq!(envelope.len(), KEY_SHARE_ENVELOPE_LEN);
            prop_assert_eq!(decode_key_share(&envelope).unwrap(), share);
        }

        /// Arbitrary bytes into the envelope parser: accepted only at the exact
        /// length and version, never panicking on anything else.
        #[test]
        fn decode_key_share_never_panics_on_arbitrary_input(
            envelope in prop::collection::vec(any::<u8>(), 0..=80),
        ) {
            let decoded = decode_key_share(&envelope);
            let well_formed = envelope.len() == KEY_SHARE_ENVELOPE_LEN
                && envelope[0] == KEY_SHARE_ENVELOPE_VERSION;
            prop_assert_eq!(decoded.is_ok(), well_formed);
        }

        /// Arbitrary envelopes and an arbitrary threshold into the reconstruction
        /// helper. The outcome is uninteresting; that it returns is the point.
        #[test]
        fn combine_key_shares_never_panics_on_arbitrary_input(
            envelopes in prop::collection::vec(
                prop::collection::vec(any::<u8>(), 0..=40),
                0..=12,
            ),
            threshold: u8,
        ) {
            let _ = combine_key_shares(&envelopes, threshold);
        }

        /// Every argument of `unseal_secret` arbitrary at once — the shape the
        /// SDK faces when chain state is hostile.
        #[test]
        fn unseal_secret_never_panics_on_arbitrary_input(
            envelopes in prop::collection::vec(
                prop::collection::vec(any::<u8>(), 0..=40),
                0..=12,
            ),
            threshold: u8,
            payload_ciphertext in prop::collection::vec(any::<u8>(), 0..=160),
            commitment: [u8; 32],
            expected: Option<[u8; 32]>,
        ) {
            let result = unseal_secret(
                &envelopes,
                threshold,
                &payload_ciphertext,
                &commitment,
                expected.as_ref(),
            );
            prop_assert!(result.is_err());
        }
    }
}
