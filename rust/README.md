# Timeflare Crypto Library

The client-side cryptographic implementation for the Timeflare protocol, compiled to WASM for the TypeScript SDK. This crate is the sole implementation of every client-side primitive (sealing, Shamir Secret Sharing, detection hints); the chain and guardian daemon use pure-Go implementations of the two primitives the server side needs (HMAC and asymmetric encryption), with byte-compatibility pinned by the shared `../vectors/` corpus.

## Overview

- **Shamir Secret Sharing (SSS)** over GF(256) with configurable thresholds (2–16 of 2–32)
- **Asymmetric encryption** using ephemeral X25519 ECDH + ChaCha20-Poly1305
- **Key-share sealing** (`seal_secret`/`unseal_secret`) — the four-layer encryption architecture from the chain repository's `docs/spec.md`
- **Detection hints** for unlinkable recipient discovery
- **Guardian HMAC commitments** for reveal verification and slashing evidence
- **WASM bindings** for JavaScript/browser integration (built with `wasm-pack`)

## Architecture

### Core Components

1. **`seal.rs`** — key-share architecture: encrypt payload to recipient, seal under a fresh per-secret key, split that key via SSS into per-guardian envelopes
2. **`sss.rs`** — Shamir Secret Sharing over GF(256)
3. **`crypto.rs`** — X25519 + ChaCha20-Poly1305 encryption (`TimeflareKeypair`, `encrypt_for_public_key`)
4. **`detect.rs`** — detection-hint derivation and scanning
5. **`utils.rs`** — guardian HMAC generation, secure randomness
6. **`lib.rs`** — WASM bindings

### WASM exports

`seal_secret`, `unseal_secret`, `generate_keypair`, `split_secret`, `reconstruct_secret`, `encrypt_with_public_key`, `decrypt_with_private_key`, `public_key_from_private`, `generate_guardian_hmac`, `derive_detection_hint`, `scan_detection_hint`, `validate_share_format`, `bytes_to_hex`, `is_usable_x` (rejects low-order X25519 points, mirroring the chain's contributory-key check), `recipiency_proof` (`z = X25519(recipient private key, hint ephemeral key)` — the rebate collection proof) and `rebate_commitment` (`SHA256(domain ‖ z ‖ collector address)` for `MsgRecipientCommitRebate`).

## Normative wire formats

These are protocol interfaces (see the chain repository's `docs/spec.md`), byte-exact across implementations:

- **Encryption**: `ephemeral_public(32) ‖ nonce(12) ‖ ChaCha20-Poly1305 ciphertext+tag`, key = `SHA256(X25519_shared ‖ "timeflare_encryption")`
- **Key-share envelope**: `version(1) ‖ sss_id(1) ‖ share(32)` = 34 bytes
- **Guardian HMAC**: key = `SHA256("secrets" ‖ secret_id ‖ guardian_address ‖ "hmac_salt")`, tag = `HMAC-SHA256(key, share ‖ guardian_address ‖ secret_id)`
- **Detection hint**: `R(32) ‖ SHA256("timeflare/detect/v1" ‖ X25519(e, A))[:8]`

## Cross-implementation drift prevention

The pure-Go server-side implementations (`../go/`) and this crate are kept byte-identical by the **shared vector corpus** in `../vectors/` (`hmac.json`, `encryption.json`, `detection_hint.json`), asserted by both test suites:

- Rust: `cargo test` (vector tests in `utils.rs`, `crypto.rs`, `detect.rs`)
- Go: `go test ./crypto/` (`vectors_test.go`)

Vectors are **append-only**. Any change to a shared primitive must update the spec, the vectors, and every implementation in the same PR — CI runs both suites whenever either implementation or the corpus changes, so a one-sided change fails the other side's pins.

## Building

```bash
# Run tests (includes shared-vector verification)
cargo test

# Build the WASM package for the TypeScript SDK (from the repo root)
make wasm
```

## Testing

~60 unit tests covering GF(256) field laws, boundary conditions, 1MB round-trips, tamper/failure paths, full seal→reveal→unseal cycles, and the shared cross-implementation vectors.
