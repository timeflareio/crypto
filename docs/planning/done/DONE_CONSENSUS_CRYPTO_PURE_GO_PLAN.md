# Consensus & Server-Side Crypto: Pure Go Plan

**Status**: DONE — implemented July 2026 (`consensus-crypto-pure-go` branch). All
four phases landed: pure-Go HMAC + encryption in `crypto/` (chain and guardian,
no cgo), `sss.go`/`detection_hint.go`/`ffi_common.go`/`rust/src/ffi.rs` deleted,
the CLI made crypto-free (`request-guardians [detection-hint]` + `--random-hint`),
spec.md carries the normative encryption wire format, and the shared append-only
corpus (`testdata/vectors/`) is asserted by both suites with a CI `vectors` path
filter triggering Go *and* Rust jobs on any corpus change. One deliberate
deviation: Phase 0.3's randomised cross-language round-trip job was realised as
the fixed shared corpus + deterministic-injection constructors instead of a live
Rust↔Go CI harness — the corpus pins the full wire format on both sides, and
with the FFI gone a live round-trip would need bespoke orchestration for
marginal additional coverage. The Phase 4 coordination items (CRYPTO_ASSURANCE
fuzz-target redirect, RELEASE_ENGINEERING pure-Go assumptions) are applied.
**Priority**: P0 — consensus safety, pre-testnet
**Components**: `crypto/hmac.go`, `crypto/ffi_common.go`, `crypto/sss.go`, `x/secrets/keeper/keeper.go`, `guardian/`, `rust/src/{utils,crypto,ffi}.rs`, `make/artifacts.mk`, `.github/workflows/ci.yml`

## What this plan does

Removes cgo (the Rust FFI) from **both Go modules** — the chain and the guardian daemon — leaving Rust as the client-side implementation compiled to WASM only, and replaces "one implementation everywhere" with the discipline that actually prevents drift: a minimal duplicated surface, a single normative spec, one shared test-vector corpus, and differential tests in CI.

**Decision recorded**: the original Phase 2 question (keep the FFI in the guardian vs. port the guardian's crypto to Go) is resolved as **Option B** — the guardian goes pure Go too, and cgo is eliminated from the server side entirely.

## Why

### The consensus-safety problem

`VerifyShareHMAC` (`x/secrets/keeper/keeper.go:383`) is called inside two message handlers — `msg_server_reveal_share.go:84` and `msg_server_slash_guardian.go:99` — and routes through `crypto/hmac.go:25` → `ffiGenerateGuardianHMAC` (`crypto/ffi_common.go:131`), which is cgo into `libtimeflare_crypto.a`. Transaction validity therefore depends on a native Rust static library:

1. **Fork/halt risk**: any behavioural divergence between validators' builds of the Rust library (compiler version, target quirks, a dependency bump changing an edge case) is a consensus fault. The computation is deterministic in principle, but the risk surface is the whole FFI boundary — byte marshalling, error mapping, and any Rust panic crossing into cgo (undefined behaviour; a crash in a handler halts the node).
2. **Build/distribution burden**: every validator must build or obtain a matching `.a` per platform, complicating reproducible builds, releases, and cosmovisor upgrades.
3. **Unguarded pointer use**: the FFI wrappers dereference `&shareData[0]` with no internal length guard (safe only by caller convention).

### Why "one implementation" was never the drift defence it appeared to be

The single-Rust-implementation approach was chosen to prevent drift across chain, guardian, and SDK. But it never delivered that in practice:

- The Rust crate compiled to **WASM** (SDK) and to a **native static library** (chain/guardian) are already two artefacts from different toolchains for different targets — "same behaviour" is an assumption, not a tested guarantee.
- A second SSS implementation (`crypto/sss.go`) exists in Go anyway, with **no** cross-implementation vectors guarding it.
- The one place the codebase demonstrably *cannot* drift is where two implementations coexist under a pinned byte-exact vector (`detect.rs` ↔ `crypto/detection_hint.go`).

Drift is prevented by **specification + shared vectors + differential tests**, not by linking the same binary everywhere. This plan applies that lesson deliberately.

### The duplicated surface is tiny

Mapping each primitive to its consumers shows how little genuinely needs two implementations:

| Primitive | Chain (consensus) | Guardian | SDK (WASM) | Implementations after this plan |
|---|---|---|---|---|
| HMAC generate/verify | ✅ verify (reveal, slash evidence) | ✅ verify before accept | ✅ generate at seal | **Go + Rust** (vector-guarded) |
| X25519 + ChaCha20Poly1305 | ❌ | ✅ decrypt shares, keypair gen | ✅ encrypt/decrypt | **Go + Rust** (vector-guarded, per Option B) |
| SSS split/reconstruct | ❌ | ❌ (holds one share, never combines) | ✅ | **Rust only** |
| seal/unseal orchestration | ❌ | ❌ | ✅ | Rust only |
| Detection hints | shape-check only (no crypto) | ❌ | ✅ derive/scan | **Rust only** (Go copy deleted once the CLI takes hint bytes — see Phase 3) |

The HMAC scheme is ~20 lines of stdlib Go (`key = SHA256("secrets" ‖ secret_id ‖ guardian_address ‖ "hmac_salt")`, `tag = HMAC-SHA256(key, share ‖ guardian_address ‖ secret_id)`). The encryption scheme is ephemeral-X25519 ECDH → `SHA256(shared ‖ "timeflare_encryption")` → ChaCha20Poly1305 — implementable with `golang.org/x/crypto/curve25519` and `chacha20poly1305`, no exotic dependencies.

## How

### Phase 0 — Drift-prevention machinery (the foundation everything sits on)

1. **Normative spec text**: spec.md already states the HMAC construction byte-exactly; add equivalent normative wire-format text for the encryption scheme (`ephemeral_pub(32) ‖ nonce(12) ‖ ciphertext+tag`, key derivation, domain string). spec.md remains the authority; implementations cite it.
2. **One shared vector corpus, one physical location**: `testdata/vectors/*.json` at repo root (`hmac.json`, `encryption.json`; the detection-hint vector migrates in for consistency), **referenced** by the Rust, Go, and TS/WASM test suites — never copied, so copies cannot diverge. Vectors are append-only; editing or deleting one is a red-flag diff.
3. **Differential tests in CI**: a job that builds both implementations and round-trips randomised inputs — Go-generate → Rust-verify and Rust-generate → Go-verify for each shared primitive.
4. **The same-PR rule**: any change to a shared primitive touches spec + vectors + every implementation in one PR. CI enforces this mechanically — a one-sided change fails the other side's vector suite.
5. **Version bytes**: the envelope already carries one; any future algorithm change is a *new version* added explicitly to each implementation while old vectors keep passing forever. Silent behavioural change becomes unrepresentable.

### Phase 1 — Pure-Go HMAC on the consensus path

1. Implement `GenerateGuardianHMAC` in pure Go (stdlib `crypto/hmac`, `crypto/sha256`) in `crypto/`, byte-for-byte matching `rust/src/utils.rs`, proven by the Phase 0 vectors.
2. Switch `crypto/hmac.go` to the Go implementation.
3. Audit all `crypto/` imports from `x/secrets/` to confirm no other consensus-path call sites reach the FFI (`AutoRevealShare`/`keeper.go:519` is covered by the same switch — verify what else it pulls in).

### Phase 2 — Guardian goes pure Go (Option B, decided)

1. Port the guardian's crypto needs to Go: share decryption and keypair generation via `golang.org/x/crypto/curve25519` + `chacha20poly1305`, matching the Rust scheme byte-for-byte.
2. Encryption vectors require deterministic tests of a randomised scheme: add a test-only constructor with injectable ephemeral key + nonce on both sides (never exposed in the public API), so fixed vectors pin the full wire format; the differential round-trip (Rust-encrypt → Go-decrypt and vice versa) covers the randomised path.
3. Remove the FFI usage from `guardian/` and `crypto/ffi_common.go`. The guardian-improvements work (now DONE) already moved signing in-process; this completes the daemon's independence from native libraries.

### Phase 3 — Client crypto single source of truth

1. **Call-graph check completed (July 2026): `crypto/sss.go` is dead code.** Its `SplitSecret`/`ReconstructSecret` have zero callers across `x/`, `guardian/`, `app/`, `cmd/`, tests, and the rest of the `crypto` package. The private FFI SSS wrappers (`ffiSplitSecret`/`ffiReconstructSecret` in `crypto/ffi_common.go`) are equally caller-less. Delete all of them — SSS returns to exactly one implementation (`rust/src/sss.rs`, consumed via WASM), and the original single-implementation instinct fully survives where it is actually achievable.
2. The chain stores and compares share bytes; the guardian holds a single share and never combines — no Go-side SSS consumer exists or is planned. Any future one must arrive with spec text and vectors per Phase 0.
3. **Make the CLI crypto-free** (decided July 2026): `request-guardians` currently takes the recipient's public key and derives the detection hint natively (`x/secrets/client/cli/tx.go:466`) — the sole live consumer of `crypto/detection_hint.go`. Change its argument from `[recipient-public-key]` to `[detection-hint]` (hex of `R ‖ tag`, produced by the SDK tooling), add a `--random-hint` flag for devnet/testing (random bytes are a protocol-valid hint — the no-discovery pattern), then delete `crypto/detection_hint.go`. This is consistent with what the CLI already is: `distribute-shares` reads SDK-prepared share files rather than sealing natively, so the CLI is a transaction-assembly tool, not a crypto client. No devnet/e2e script invokes this command (verified July 2026 — the lifecycle and scenario suites drive creation through the SDK), so the argument change has no script fallout. The detection-hint vector **stays** in the shared corpus so any future Go consumer (e.g. a Go SDK) re-implements against it rather than from scratch.

### Phase 4 — Remove the FFI entirely

1. With no Go-side consumers, delete `rust/src/ffi.rs`, drop the `staticlib`/`cdylib`-for-FFI crate targets (keep what wasm-pack needs), and remove `crypto-ffi` from `make/artifacts.mk`, the chain/guardian build paths, and CI.
2. **Coordination — CRYPTO_ASSURANCE plan**: its priority fuzz target (`ffi.rs::reconstruct_secret`'s manual byte parser) becomes moot when the FFI is deleted; its fuzzing effort redirects to the WASM-facing parsers (`unseal_secret`, `decrypt`, `scan_detection_hint`). Update that plan when this phase lands.
3. **Coordination — RELEASE_ENGINEERING plan**: both released binaries become pure Go — cross-compilation, reproducible builds, and cosmovisor packaging all simplify; that plan should assume the pure-Go world.
4. The differential-test CI job (Phase 0.3) becomes the only place the Rust native build is still exercised on the server side — it builds the Rust crate as a test dependency only (open question 2 on placement).

## Decisions (all open questions resolved, July 2026)

1. **`crypto/sss.go` liveness** — resolved by call-graph check: dead code, as are the FFI SSS wrappers. Deleted in Phase 3.
2. **Differential-test placement** — decided: a job within `ci.yml`, path-filtered on `rust/` + `crypto/` (plus the shared `testdata/vectors/`), building the Rust crate natively as a test-only dependency.
3. **Detection-hint Go copy** — decided: **delete it** by making the CLI crypto-free (Phase 3, item 3). Its only live consumer is the `request-guardians` CLI command (`x/secrets/client/cli/tx.go:466`); the command switches to accepting pre-derived hint bytes (with a `--random-hint` devnet convenience), after which the Go copy is dead and goes the way of `sss.go`. The pinned vector remains in the shared corpus for any future Go consumer. Net effect: the Rust crate becomes the sole implementation of *every* client-side primitive, and the only vector-guarded duplications left are the two the server genuinely needs — HMAC (chain + guardian) and the encryption scheme (guardian, per Option B).
4. **Timing** — decided: lands before any public network launch. No testnet is imminent, so this sequences at the implementer's convenience — but it must precede testnet-1 genesis, as Phase 1 touches the consensus path (identical outputs expected, but free to change now and a coordinated upgrade later).
