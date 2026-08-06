# Cryptographic Assurance — property tests and fuzzing — Plan

*Raises the hand-written cryptographic core from "the tests pass" to "an auditor
can be handed evidence": universal property tests over the from-scratch GF(256)
Shamir implementation, fuzz coverage of every function on both sides that parses
attacker-controlled bytes, and a written position on the two things testing
cannot reach.*

> **Status: done** — August 2026, executed on `worktree-crypto-assurance`. All
> three phases landed and `make verify && make test` is green. §5 records what
> the run found, including the empty-payload difference between the two
> implementations and the ruling that closed it.
> **Priority**: P1 — audit readiness. Nothing here fixes a known defect; it is
> the evidence an external audit and mainnet custody of real secrets will ask
> for, and it is cheapest to build before a corpus of live secrets exists.
> **Origin**: automated review of the crate, July 2026, carried forward with the
> repository when the primitives were lifted out of the monorepo.
> **Components**: `rust/src/sss.rs`, `rust/src/crypto.rs`, `rust/src/seal.rs`,
> `rust/src/detect.rs`, `rust/Cargo.toml`, `go/` (fuzz targets and
> `go/testdata/fuzz/` corpora), `Makefile` (new `fuzz` target), `README.md`.
> CI is deliberately untouched — see §3.

## 1. Why

Every secret's confidentiality reduces to this repository being correct, on both
sides: `sss.rs` and `crypto.rs` for the client, `go/encryption.go` and
`go/hmac.go` for the guardian daemon and the chain.

The 54 Rust and 19 Go unit tests are genuinely good — field laws at sampled
points, boundary cases, tamper and failure paths, full seal→unseal round trips —
and the shared corpus in `vectors/` pins the two implementations against each
other so neither can drift silently. Two gaps remain, and neither is closed by
adding more of the same:

- **Sampled is not universal.** `sss.rs` is a from-scratch GF(256)
  implementation — log/exp tables and Lagrange interpolation — and it is the
  only Shamir implementation in the project, deliberately. There is no second
  implementation to differential-test it against, so property tests over the
  field laws and the split→combine identity are the only universal check
  available to it.
- **Nothing feeds these parsers bytes they were not designed for.** Both sides
  take attacker-controlled input from chain state: the guardian daemon decrypts
  envelope bytes server-side through `DecryptShareWithPrivateKey`, and the WASM
  client unseals revealed envelopes, payload ciphertext and a commitment through
  `unseal_secret`. Every one of those paths must reject, never panic and never
  false-accept, for arbitrary input — and nothing asserts that today beyond the
  specific malformed cases someone thought to write down.

## 2. Phase 1 — property tests

Add `proptest` as a **dev-dependency** of the Rust crate. It compiles only for
`cargo test`, so it does not enter the WASM bundle and is not a cryptographic
dependency under the T3 gate.

Cover:

- **GF(256) field laws universally** — commutativity, associativity,
  distributivity, `a · a⁻¹ = 1`, and `exp(log(x)) = x` for all `x ≠ 0`.
- **split→combine is the identity.** Arbitrary secret (weighted towards small,
  bounded by `MAX_SECRET_SIZE`), arbitrary valid `(threshold, shares)` inside
  the declared bands — threshold 2–16, shares 2–32, `shares ≥ threshold` — and
  an arbitrary threshold-sized subset of the shares reconstructs the secret
  exactly.
- **Sub-threshold and malformed share sets fail safely.** Fewer than `threshold`
  shares, duplicated share IDs, mismatched share lengths, ID 0: each must return
  an error or a value ≠ the secret, and must never panic.
- **Seal round trip and tamper resistance.** Arbitrary payload through
  `seal_secret`/`unseal_secret` at arbitrary guardian counts; then flip any
  single byte of any artefact — an envelope, the payload ciphertext, the
  commitment — and assert the result is an error, never a panic and never a
  false accept.
- **Encryption round trip and malformed ciphertext.** Arbitrary plaintext round
  trips; truncated, oversized and bit-flipped ciphertexts return an error rather
  than panicking.

The `sss.rs` header claims "constant-time operations for critical paths", which
overclaims for the GF(256) table lookups. It is corrected here to match the
position §4 records, because a property test written against a doc comment that
misdescribes the code is written against the wrong thing.

## 3. Phase 2 — fuzzing

Everything here runs locally through `make`. There is no scheduled CI job: a
nightly fuzz run costs runner minutes indefinitely, and the durable value is the
corpus rather than the runner time. What CI gains is automatic — committed
corpora replay as ordinary tests under the existing `make test`, so no workflow
file changes.

**Go — `go test -fuzz`, no new tooling and no new component.** The targets are
ordinary test functions in `go/`:

- `FuzzDecryptShareWithPrivateKey` — arbitrary bytes as the envelope. This is
  the path the guardian daemon feeds from chain state.
- `FuzzVerifyHMAC` — arbitrary secret ID, guardian address, share data and
  expected tag. Must reject, never panic.
- `FuzzValidateX25519PublicKey` — arbitrary key bytes; must never panic, and its
  verdict must continue to agree with whether encryption fails, generalising
  `TestValidateX25519PublicKey_RejectionMatchesEncryptionFailure` from the fixed
  low-order set to arbitrary input.
- `FuzzDetectionTagMatches` and `FuzzRebateCommitmentMatches` — arbitrary
  lengths on both arguments must not panic.

**Rust — randomised input through the Phase 1 `proptest` harness**, not
`cargo-fuzz`. Coverage-guided fuzzing would mean a new `rust/fuzz/` crate — a
new build target — and a nightly toolchain alongside the `1.97.0` pin that
exists to keep WASM output reproducible. Neither is warranted while `proptest`
reaches the same parsers on the pinned stable toolchain. The targets are
`TimeflareKeypair::decrypt` (wire format `ephemeral_pub(32) ‖ nonce(12) ‖ ct`),
`decode_key_share` and `unseal_secret` (the 34-byte envelope, plus ciphertext
and commitment), `scan_hint`, and `combine_shares` — the last reachable from the
SDK through the `reconstruct_secret` facade. Each is fed arbitrary bytes and
must return an error, never panic and never false-accept.

**The `make fuzz` target** drives the saturation runs, and covers both sides:

- Each Go target in sequence — `go test -fuzz` accepts exactly one target per
  invocation, so a loop is the only shape available.
- The Rust suite with `PROPTEST_CASES` raised well above its default, which is
  what turns the Phase 1 harness into a soak rather than a check.
- `FUZZTIME` and the case count are overridable, so a long run before a release
  and a short one during development are the same target.

`fuzz` joins neither `verify` nor `test`: both are bounded and hermetic, and an
unbounded search belongs to a deliberate invocation. What `make test` does gain
is the regression half — seeds commit under `go/testdata/fuzz/` and replay under
`go test ./...`, so every crash found once is asserted forever, offline and at
no cost.

## 4. Phase 3 — the two positions testing cannot reach

Both are documented in `README.md` rather than engineered against. Silence reads
as an oversight; a written position reads as a decision, and an auditor will
raise both regardless of what the tests say.

- **Zeroisation.** `x25519-dalek` zeroises secret key material on drop
  (`seal.rs:161`), but the guardian's decrypted envelopes, reconstructed secrets
  in WASM linear memory and the SDK's `Uint8Array`s are not systematically
  wiped. Record what is erased, what is not, and why the browser runtime cannot
  promise more. Hardening waits for an audit finding rather than being
  anticipated here.
- **Constant-time behaviour.** The GF(256) log/exp tables are input-dependent
  memory accesses, the classic timing side-channel. Record it as an accepted
  risk: shares are processed client-side or by the guardian that already holds
  the share, so an attacker positioned to measure the timing already has the
  material the channel would leak. The `sss.rs` header claim is corrected to
  agree (§2).

## 5. What execution found

Fifty property and randomised-input tests on the Rust side and seven fuzz
targets on the Go side, run to saturation locally. No crash, no panic and no
false accept was found in either implementation. Three characteristics were,
none of them a defect in what the code does, all three now pinned by a test so
that changing them is deliberate:

- **Two single-bit tampers are inert rather than caught**, and the first
  formulation of the tamper properties was wrong to assert otherwise. X25519
  clamps the scalar (RFC 7748 clears bits 0–2 of byte 0 and rewrites bits 6–7 of
  byte 31) and masks the top bit of a public key's u-coordinate, so a
  perturbation confined to those positions reconstructs to the same key. The
  properties assert what actually matters — a tamper never yields a *different*
  payload — and `clamped_scalar_bits_do_not_affect_the_key`,
  `the_masked_u_coordinate_bit_does_not_change_the_plaintext` and their
  complements fix the inert set at exactly five bits and one bit respectively.
  Detecting envelope tampering is the guardian HMAC's job, and it does it.
- **`rebate_commitment` concatenates its two inputs without a length prefix**,
  so the split between `z` and the collector address is not itself committed to.
  Every call site passes a 32-byte `z` straight from X25519 and a fixed-length
  address, which is what makes the split unambiguous in practice.
  `rebate_commitment_does_not_commit_to_the_input_split` records the property so
  that a future call site with a variable-length argument fails a test rather
  than shipping.
- **The two implementations disagree on the empty payload.**
  `go/encryption.go:33` refuses to encrypt zero bytes; `encrypt_for_public_key`
  in Rust accepts them and round-trips correctly. The corpus pins agreed
  outputs and has no case for a rejection, which is how this has stayed
  invisible. `FuzzDecryptShareRoundTrip` now asserts the Go behaviour in both
  directions so it cannot drift further unnoticed.

  **Ruled by the owner (August 2026): Rust gains the guard.** An empty payload
  encrypts to a well-formed envelope carrying nothing, which every layer above
  treats as a real secret — the chain stores it, guardians bond against it, a
  recipient waits out the timer for nothing. `encrypt_for_public_key` now
  refuses it at the same boundary and with the same message as the Go entry
  point, and `seal_secret` inherits the rejection. No produced bytes change: an
  input that was accepted is now refused, and everything still accepted encrypts
  identically, so no existing secret, share or hint is affected.

  The chain needs no change. It caps the maximum payload (spec.md, 4,216B) and
  says nothing about a minimum; `message_distribute_shares.go` rejects an empty
  *ciphertext*, which an empty payload never produced — it yielded a valid
  120-byte one. Nothing on chain could observe the difference.

## 6. What this plan does not solve

- **No behaviour change.** If a property or fuzz failure turns out to need a
  byte-level fix to a shared primitive, that is a protocol change and it stops
  here — it needs the owner's confirmation, both implementations, vector
  updates, a chain `docs/spec.md` update and a coordinated consumer roll
  (`CLAUDE.md`). This plan covers finding such a thing, not landing the fix.
- **Information-theoretic secrecy is not testable this way.** A sub-threshold
  share set can be asserted not to reconstruct and not to panic; that it leaks
  nothing is a proof obligation, not a test.
- **Timing is not measured.** Property tests and fuzzers observe outputs, not
  memory-access patterns. §4 is the whole of the answer.
- **Lint and format conformance** belong to `done/DONE_RUST_HYGIENE_PLAN.md`,
  which explicitly scopes test coverage out to here. That plan has landed, so
  its `cargo fmt` pass — 858 lines across these same files — is already in
  `main` and cannot collide with the test modules this plan adds. Those modules
  do have to arrive `cargo fmt --check` and `clippy -D warnings` clean, since
  `make verify` now gates on both.
- **The corpus still cannot pin a shared rejection.** `encryption.json` is a
  list of accept cases — plaintext in, ciphertext out — so the empty-payload
  boundary of §5 is held by an assertion in each suite rather than by a vector.
  That is weaker than the rest of the corpus: the two suites agree today because
  both were written to, not because a shared file forces them to. Giving
  `encryption.json` a reject section, the shape `low_order_keys.json` already
  uses, would close it. It needs the owner's approval and is not done here.
