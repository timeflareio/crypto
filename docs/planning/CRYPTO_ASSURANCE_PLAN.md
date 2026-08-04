# Cryptographic Assurance Plan

**Status**: Proposed (automated review, July 2026)
**Priority**: P1 — audit readiness
**Components**: `rust/src/sss.rs`, `rust/src/crypto.rs`, `rust/src/seal.rs`, `rust/src/detect.rs`, `rust/Cargo.toml`, `crypto/` (Go)
**Updated July 2026** (per `DONE_CONSENSUS_CRYPTO_PURE_GO_PLAN.md` Phase 4.2): the FFI is deleted — fuzzing redirects to the WASM-facing parsers; the dated-dalek/rand refresh has landed.
**Updated July 2026 (second pass, verified against the tree)**: Phases 3 and 4 are complete/moot — remaining scope is **Phase 1 (property tests) + Phase 2 (fuzzing, now including the Go `crypto/` package, an equal trust root since the pure-Go migration) + rulings on the open questions**.

## What this plan does

Raises the assurance level of the hand-written cryptographic core to what an external audit (and mainnet custody of real secrets) demands: property-based and fuzz testing for the from-scratch GF(256) Shamir implementation and the byte parsers on **both sides** — the WASM-facing Rust parsers and the pure-Go `crypto/` package the guardian daemon uses to process attacker-influenced envelope bytes. (Dead crypto surface and the dependency refresh are already done; cross-implementation drift is pinned by the shared vector corpus.)

## Why

The Rust crate is the trust root of the entire product — every secret's confidentiality reduces to `sss.rs` and `crypto.rs` being correct. The existing ~56 unit tests are genuinely good (field-law checks, boundary cases, tamper/failure paths, full seal→unseal round trips), but three gaps stand out:

1. **No property-based or fuzz testing anywhere** (no `proptest`, `quickcheck`, `arbitrary`, or `cargo-fuzz` in the repo). The two highest-risk targets:
   - `sss.rs`: a from-scratch GF(256) implementation (log/exp tables, Lagrange interpolation). Unit tests verify the field laws at sampled points; property tests can verify them universally (∀ a,b: a·b = b·a, a·a⁻¹ = 1, split→reconstruct = identity for arbitrary secrets/thresholds/share-subsets).
   - The WASM-facing parsers (`seal.rs::unseal_secret`, `crypto.rs::decrypt`, `detect.rs::scan_detection_hint`) — every function that parses attacker-controllable bytes. (The former priority target, `ffi.rs::reconstruct_secret`, was deleted with the FFI in the pure-Go migration.)
   - **The Go `crypto/` package** (added July 2026 — this plan predates the full weight of the pure-Go migration and originally covered Rust only): the guardian daemon decrypts attacker-influenced envelope bytes server-side via `crypto/encryption.go` and verifies HMACs via `crypto/hmac.go`. Go's native fuzzing (`go test -fuzz`) makes covering these parsers nearly free, and an auditor will examine both implementations, not just the Rust one.
2. ~~**Dated crypto dependencies**~~ **Resolved (July 2026)**: the RustCrypto 0.11 line, dalek 3 and rand_core 0.10 landed via the T3 audit gate, byte-compatibility proven by the shared vectors. The unused `pem`/`pkcs8` leftovers were removed on the same branch — verified absent from `Cargo.toml`.
3. ~~**Cross-implementation drift risk**~~ **Resolved (July 2026)**: the shared append-only corpus (`testdata/vectors/` — `hmac.json`, `encryption.json`, `detection_hint.json`) pins every primitive with two implementations, asserted by both suites; SSS has exactly one implementation again (`crypto/sss.go` was dead code, deleted).

None of this is a known bug; it is the difference between "tests pass" and "an auditor can be handed evidence".

## How

### Phase 1 — Property tests (proptest)

Add `proptest` as a dev-dependency and cover:

- GF(256) field laws universally (associativity, commutativity, distributivity, inverses, `exp(log(x)) = x`).
- SSS round-trip: arbitrary secret (1B–1MB weighted small), arbitrary valid `(threshold, shares)`, arbitrary threshold-sized share subset → exact reconstruction; arbitrary sub-threshold subset → no information leak assertion is not testable, but reconstruction must fail or produce ≠ secret (never panic).
- Envelope/seal round-trip: arbitrary payloads through `seal_secret`/`unseal_secret` with arbitrary guardian counts; mutate any single byte of any artefact → verification fails (never panics, never false-accepts).
- Encryption: arbitrary plaintext round-trips; truncated/oversized/bit-flipped ciphertexts decrypt to error, not panic.

### Phase 2 — Fuzzing (cargo-fuzz + Go native fuzzing)

Fuzz targets for every function that parses attacker-controllable bytes, on both sides:

**Rust (cargo-fuzz):**
- `crypto.rs::decrypt` (wire format `ephemeral_pub ‖ nonce ‖ ct`).
- `seal.rs::unseal_secret` (share envelopes + ciphertext + commitment as fuzz input — the priority target now the FFI parser is gone).
- `detect.rs::scan_detection_hint`.

**Go (`go test -fuzz`, no new tooling — added July 2026):**
- `crypto/encryption.go` decrypt path with arbitrary byte inputs (the guardian daemon feeds it envelope bytes taken from chain state).
- `crypto/hmac.go` verification with arbitrary inputs (must reject, never panic).

Run locally to saturation initially; add a scheduled CI job (short nightly runs) or OSS-Fuzz enrolment as follow-up. Go fuzz corpora commit naturally under `testdata/fuzz/` and replay as ordinary tests in `make test`.

### Phase 3 — Dependency refresh ✅ DONE (July 2026, deps-crypto-t3 branch)

*Completed as the first exercise of the T3 runbook: x25519-dalek 3, sha2 0.11,
hmac 0.13, chacha20poly1305 0.11, getrandom 0.4 (wasm_js backend), rand_chacha
0.10 — with the `rand` facade dropped entirely in favour of `rand_core` (only
trait re-exports were used). `pem`/`pkcs8` removed (unused). Byte compatibility
proven by the shared vector corpus and the cross-client devnet e2e. Original
phase text below (versions stale — predates the interim 2.x bumps).*

### Phase 3 (original) — Dependency refresh

1. ~~Upgrade `x25519-dalek` and `rand`~~ **Done (July 2026)** — landed via the T3 audit gate with vector-proven byte-compatibility; `cargo audit` is clean and gates CI.
2. ~~Remove `pem` and `pkcs8` (unused)~~ **Done (July 2026)** — removed on the T3 branch.

### Phase 4 — Cross-implementation vectors ✅ CLOSED (July 2026 — done/moot)

*The shared append-only corpus exists (`testdata/vectors/` — `hmac.json`,
`encryption.json`, `detection_hint.json`) and is asserted by both suites
(`rust/src/*` vector tests and `crypto/vectors_test.go`). The SSS differential
ask is moot: there is exactly one SSS implementation (Rust) — `crypto/`
contains no Shamir code to drift against. Original phase text below.*

- ~~Pin encrypt/decrypt vectors (fixed keys/nonce injection needed — add a test-only deterministic-nonce constructor) and SSS reconstruction vectors (fixed shares → secret) shared between Rust and any Go implementation, in a single `testdata/vectors/*.json` consumed by both test suites (extends the existing detection-hint pattern).~~
- ~~Differential tests: Rust-split → Go-reconstruct and Go-split → Rust-reconstruct (coordinates with CONSENSUS_CRYPTO_PURE_GO Phase 3).~~

## Open questions

1. **Zeroisation policy**: `sk_s` is zeroised on drop in `seal.rs`, but the guardian's decrypted envelopes, reconstructed secrets in WASM linear memory, and the TS SDK's `Uint8Array`s are not systematically wiped. Is memory-hygiene hardening in scope here, or an audit-finding to await? (WASM/JS gives weak guarantees anyway — worth an explicit documented position rather than silence.)
2. **VSS (verifiable secret sharing)**: the envelope version byte is reserved for a future Feldman/Pedersen upgrade. Out of scope here, but should this plan add the *test scaffolding* for versioned envelopes now so v2 doesn't fork the format handling?
3. **CI budget**: nightly fuzz jobs cost runner minutes; is a scheduled workflow acceptable, or run-to-saturation locally with committed corpora only?
4. **Constant-time review**: GF(256) table lookups are input-dependent memory accesses (classic timing side-channel). For this protocol the shares are processed client-side or by the share-owning guardian, so exploitability is limited — but an auditor will flag it. Document the accepted risk now or engineer around it?
