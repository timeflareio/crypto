# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with
code in this repository.

**It is not the whole picture.** The project-wide rules — the working agreement,
the writing conventions (British English, VEIL is a token, never name the owner),
the plan-first mandate, specification authority, and how a change crosses a
repository boundary — are stated once in the workspace root `CLAUDE.md`, at
`~/dev/timeflareio/CLAUDE.md`, which loads alongside this file. Read it if you
are in a checkout that cannot see it.

## Project Overview

**timeflare crypto** holds the protocol's cryptographic primitives in two
implementations:

- **`go/`** — pure Go, consumed by the chain and the guardian. Imported as
  `github.com/timeflareio/crypto/go`. No cgo, deliberately: the chain needs
  deterministic, statically-linked builds, and cgo inside consensus code is a
  fork/halt risk (see `docs/planning/done/DONE_CONSENSUS_CRYPTO_PURE_GO_PLAN.md`).
- **`rust/`** — compiled to WASM for the TypeScript SDK, which cannot use the
  Go implementation.
- **`vectors/`** — the corpus that holds the two in agreement, owned and
  published here.

`go.mod` sits at the repository root rather than in `go/`, so one plain
`vX.Y.Z` tag serves all three published artefacts — Go module, WASM bundle and
vector corpus — and `go test ./...` works from the root.

## 🚨 A change to one implementation MUST land in the other

This is the single most important rule in this repository.

Two implementations of one concern is normally a defect. This one is forced —
the browser and mobile runtimes cannot execute the Go path, and the chain cannot
take a cgo dependency — so it is allowed to exist *only* because it is pinned
mechanically rather than by good intentions.

**The rule**: if you change what a shared primitive produces, accepts or
rejects in `go/`, the same change lands in `rust/` in the same PR, and vice
versa. Not a follow-up. Not an issue. The same PR. A PR that changes one side
alone is incomplete by definition, and `make test` is what proves you did both.

### Which primitives are shared

Not everything here is dual-implemented, and pretending otherwise would make
the rule easy to dismiss. **The corpus is the definition**: a primitive is
shared if and only if it has a vector file.

| Vector file | Shared primitive | Go | Rust |
|---|---|---|---|
| `hmac.json` | share HMAC derivation | ✅ | ✅ |
| `encryption.json` | X25519 + ChaCha20-Poly1305 envelope | ✅ | ✅ |
| `low_order_keys.json` | small-order public key rejection | ✅ | ✅ |
| `detection_hint.json` | detection tag derivation | ✅ | ✅ |
| `rebate_commitment.json` | commit–reveal arithmetic | ✅ | ✅ |

Shamir Secret Sharing, seal/unseal orchestration and hint scanning are
**Rust-only** — the chain never needs them and the guardian holds a single
share and never combines. Changing those needs no Go counterpart. If you find
yourself adding a Go counterpart for one of them, stop: that is a new shared
primitive, which needs a vector file and the owner's approval first.

### What this means in practice

- **Adding a shared primitive**: implement both sides, add a vector file, and
  assert it from both suites. One-sided is not landable.
- **Changing a shared primitive's output**: this is a protocol change — see the
  next section. It is not an implementation detail.
- **Refactoring one side**: allowed alone, provided output is unchanged and
  `make test` proves it.
- **Never** let one suite assert a vector the other ignores. That is drift with
  a green build, which is worse than drift with a red one.

### The corpus is owned here

`vectors/` belongs to this repository — it pins primitives implemented here, and
the generator that produces the cases is here
(`TestGenerateVectors` in `go/vectors_test.go`). There is no sync or verify step
against anyone else's copy, deliberately: this repository is self-contained, and
`make test` needs no network and no credentials.

Releases publish the corpus with a SHA-256 manifest, because downstream
implementations that reimplement these primitives for runtimes Go and WASM cannot
reach — the mobile client's native layer especially — assert it to prove they
interoperate. Adding cases is ordinary work. Changing an existing expected value
is the protocol change described below.

The chain repository keeps a separate corpus for chain semantics (gas, dials,
share bands, creation fees, wallet derivation). Those files are not mirrored here
and nothing here asserts them.

## 🚨 Byte-level primitive changes are protocol changes

A change to what these primitives *produce* is a wire-protocol change, not an
implementation detail — it invalidates every existing secret, share and hint.
Such a change requires:

1. Explicit confirmation from the owner before any code is written.
2. Both implementations changed together, with the matching vector updates, in
   the same PR (see the rule above).
3. A corresponding prose update to `docs/spec.md` **in the chain repo**, which
   describes the protocol that consumes these primitives. Link it at a pinned
   tag; never copy it here.
4. A coordinated roll of every consumer (chain, guardian, TypeScript SDK,
   mobile client).

Note where authority sits. The chain's `docs/spec.md` is the authority for
*protocol* rules — gas, dials, share bands, fees, lifecycle. The authority for
what these primitives actually produce is the code and the corpus **here**.
Nothing in this repository enforces or checks chain protocol rules, and nothing
here should start.

Refactors that provably preserve output are ordinary work. If you are not
certain a change preserves output, it does not.

The version number is the only signal consumers get, and the breaking axis is
reserved for exactly this — never spent on anything else. While on 0.x that axis
is the MINOR position (`0.1.0` → `0.2.0`); from 1.0.0 it is the MAJOR. See
"Versioning" in `README.md`, and
`docs/planning/done/DONE_RELEASE_STRATEGY_PLAN.md` for why.

This module versions independently of the chain: a release here neither waits
for nor implies a chain release. It stays on 0.x until the owner instructs
otherwise — do not propose 1.0.0.

## Essential Commands

- `make test` — both suites (Go + Rust) against the shared vectors; offline
- `make verify` — read-only Go checks (gofmt, imports, vet, golangci-lint)
- `make clean-code` — fix everything fixable
- `make wasm` — build the WASM bundle from the Rust crate into `pkg/`
- `make vectors-package` — package the owned corpus + manifest (used by releases)
- `make doctor` — check the local toolchain
- `make help` — grouped target list

`make test` runs both suites. Running only one proves nothing about drift.

## Specific to this repository

- **The Rust crate exists for the WASM and UniFFI targets only** and should not
  grow beyond them. The Go/Rust duplication here is the project's one sanctioned
  second implementation, and it is sanctioned *because* the corpus pins it — the
  general rule against new components (workspace root `CLAUDE.md`) is not
  relaxed for anything else in this repository.
- Plans live in `docs/planning/`, per its `README.md`.
