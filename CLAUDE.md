# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with
code in this repository.

## Project Overview

**timeflare crypto** holds the protocol's cryptographic primitives in two
implementations:

- **Pure-Go module at the repository root** — consumed by the chain and the
  guardian as `github.com/timeflareio/crypto`. No cgo, deliberately: the chain
  needs deterministic, statically-linked builds.
- **Rust crate in `rust/`** — compiled to WASM for the TypeScript SDK, which
  cannot use the Go implementation.

Both implement the same primitives: HMAC derivation, unified asymmetric
encryption (X25519 + ChaCha20-Poly1305), Shamir Secret Sharing, detection
hints and rebate commitments.

## 🚨 The two implementations must never drift

Two implementations of one concern is normally a defect. This one is forced —
the mobile and browser runtimes cannot execute the Go path — so it is allowed
to exist *only* because it is pinned mechanically:

**Both suites assert the same vendored vector corpus in `vectors/`.** If either
side changes behaviour by a single byte, `make test` fails on the side that
changed. Never weaken this. Never let one suite assert vectors the other does
not, and never make a primitive change in one language without the other.

The corpus is **owned by `timeflareio/chain`** (`testdata/vectors/`). This repo
vendors a pinned copy of the files its suites assert, refreshed only by
`make vectors-sync` and checked by `make vectors-verify`. Never hand-edit
`vectors/`.

## 🚨 Byte-level primitive changes are protocol changes

A change to what these primitives *produce* is a wire-protocol change, not an
implementation detail — it invalidates every existing secret, share and hint.
Such a change requires:

1. Explicit confirmation from the owner before any code is written.
2. A corresponding update to `docs/spec.md` **in the chain repo**, which is the
   single protocol authority for every repo. Link it at a pinned tag; never
   copy it here.
3. Matching vector updates landing in the chain repo, then a
   `make vectors-sync` here.
4. A coordinated roll of every consumer (chain, guardian, TypeScript SDK,
   mobile client).

Refactors that provably preserve output are ordinary work. If you are not
certain a change preserves output, it does not.

## Essential Commands

- `make test` — both suites (Go + Rust) against the vendored vectors
- `make verify` — all read-only checks (format, imports, vet, lint, clippy,
  vectors)
- `make clean-code` — fix everything fixable
- `make wasm` — build the WASM bundle from the Rust crate into `pkg/`
- `make vectors-verify` / `make vectors-sync` — corpus pin management
- `make doctor` — check the local toolchain
- `make help` — grouped target list

`make test` runs both suites. Running only one proves nothing about drift.

## 🚨 Plan-First Workflow (mandatory — everything)

All work is executed from an approved plan in `docs/planning/`. Code, docs,
dependency changes: every change traces to a plan the owner has approved.
Discussion is not approval — answering a question or receiving a favourable
reply is never licence to edit. Propose, wait for the ruling, fold it into a
plan, then execute. The only exception is a change the owner explicitly
requests in the moment, and even then the scope is exactly what was asked.

The rules for authoring and refining plans are in `docs/planning/README.md`.

## Important Instructions for Claude

- Do what has been asked; nothing more, nothing less
- NEVER create files unless explicitly asked to implement or code a solution
- When asked to "elaborate", "explain", or give "feedback", give verbal
  explanations only
- ALWAYS prefer editing existing files over creating new ones
- **🚨 CRITICAL: When asked to create a "plan", ONLY create the plan document —
  DO NOT start implementing**
- **Always wait for explicit approval** before proceeding from planning to
  implementation
- **🚨 CRITICAL: Keep the architecture minimal.** Never introduce a new
  component (module, package, service, binary, build target, or second
  implementation) without arguing the case and getting explicit confirmation
  first. Default to extending what exists. Where duplication is genuinely
  unavoidable — as with the Go/Rust split here — it must be pinned by shared
  test data so it cannot drift.
- **Documentation Language**: ALL documentation must use British English
- **Spelling Standard**: use `-ise` endings (organise, realise), `-our`
  endings (behaviour), `-sation` endings (organisation)
- **🚨 VEIL is a token, never money.** Do not use "money", "cash", "funds",
  "payment" or any currency framing for VEIL — in code, comments,
  documentation, plans, commit messages or conversation. Say "token", "VEIL",
  "uveil", "balance", "amount", "fee", "cost", "bond", "reward" or "rebate".
  This is not a style preference: describing a token as money makes a
  regulatory claim the project does not make.
- **🚨 NEVER name the owner.** No personal name appears anywhere in the
  repository — not in code, comments, documentation, plans, commit messages or
  test fixtures. Decisions are attributed to **"the owner"**
  (`(owner, July 2026)`, "ruled by the owner"), never to a person. This covers
  every form: given name, surname, handle, email address, and machine paths
  that embed a username.
- NEVER create code in production code spaces purely for the purpose of tests
- Favour Go for server-side work; the Rust crate exists for the WASM target
  only and should not grow beyond it
