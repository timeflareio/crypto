# Rust Crate Hygiene — rustfmt and clippy — Plan

*Brings `rust/` up to `cargo fmt --check` and `cargo clippy -D warnings`, then
adds both to `make verify` and CI. The crate has never been gated on either:
the monorepo's Rust CI job ran `cargo test` and `cargo audit` only, so the debt
arrived with the lift rather than being created by it.*

> **Status: ready** — August 2026. Created alongside the phase-1 lift; scope is
> known and small, and every open item is settled.
> **Priority**: P3 — pure hygiene. No behaviour change, no consumer impact.
> Worth doing because an ungated formatter is a permanent source of diff noise,
> and because one of the six clippy findings marks genuinely dead code.
> **Origin**: discovered during the phase-1 crypto lift (multi-repo migration
> plan, in the monorepo). The lift deliberately did *not* fix this: applying
> `cargo fmt` rewrites 858 lines, which would have buried the 12 meaningful
> lines of the lift diff, so the debt was split out here.
> **Components**: `rust/src/*.rs`, `Makefile` (`verify` and `clean-code`
> targets), `.github/workflows/ci.yml`.
>
> Every figure below is measured against the crate as it stands, on the pinned
> `1.97.0` toolchain.

## 1. Why this is not cosmetic

All three parts have consequences beyond tidiness:

- **An ungated formatter guarantees future noise.** Every contributor whose
  editor runs rustfmt on save produces reformatting churn mixed into unrelated
  changes, which is exactly what makes a diff unreviewable. Formatting once and
  gating it is what stops that.
- **`clippy::absurd_extreme_comparisons` marks dead code, and already fails the
  build.** `MIN_SECRET_SIZE` is `0` (`sss.rs:40`) and `validate_secret_size`
  tests `if size < MIN_SECRET_SIZE` on a `usize` (`sss.rs:272`), which can never
  be true. The behaviour is correct — empty secrets are deliberately allowed —
  but the guard is vacuous and reads as though it validates something. The lint
  is deny-by-default, so `make rust-lint` fails on it today without any
  `-D warnings` gate, and clippy aborts the compilation there.

  The guard stays, annotated (ruled by the owner, August 2026). Removing it
  makes `validate_secret_size` asymmetric — every other bound checks both ends —
  and a later change to `MIN_SECRET_SIZE` would then silently have no guard. It
  is also the only place `SssError::SecretTooSmall` (`sss.rs:66`) is
  constructed, and because `lib.rs` re-exports the module with `pub use sss::*`
  the variant would stay publicly reachable, so nothing would flag it as
  unreachable. The lint is right that the code is dead; the code is right that
  the shape should stay.
- **Toolchain pinning is a prerequisite, and it is in place.** rustfmt and
  clippy output vary by toolchain version, so gating on them without a pin makes
  CI fail whenever the runner's stable moves. `rust/rust-toolchain.toml` pins
  `1.97.0` and declares `rustfmt` and `clippy` — it arrived with the release
  strategy work, which needed it for reproducible WASM output
  (`done/DONE_RELEASE_STRATEGY_PLAN.md` §3).

  It governs CI as well, though not legibly. Both jobs install
  `dtolnay/rust-toolchain@stable`, which runs `rustup default` and never exports
  `RUSTUP_TOOLCHAIN`; a toolchain file outranks `rustup default`, so every cargo
  command run from `rust/` resolves to 1.97.0 anyway. The workflow reads as
  unpinned while behaving as pinned — so §3 has it say so in a comment, rather
  than restate the version somewhere it could drift out of agreement with the
  file that would win regardless.

## 2. The findings

`cargo clippy --all-targets` reports six distinct lints across eight sites:

| Lint | Where | Nature |
|---|---|---|
| `absurd_extreme_comparisons` | `sss.rs:272` | vacuous guard — see §1 |
| `empty_line_after_doc_comments` | `crypto.rs:4`, `sss.rs:33` | doc comment detached from its item |
| `needless_range_loop` | `sss.rs:905` | index loop over a slice |
| `map_clone` | `sss.rs:204` | `.map(\|s\| *s)`, which is `.copied()` |
| `expect_fun_call` | `crypto.rs:406`, `crypto.rs:416` | `expect(&format!(…))` allocates eagerly |
| `redundant_pattern_matching` | `sss.rs:672` | `matches!(…, Ok(_))` |

Clippy's raw output shows twelve diagnostics, because the lib and lib-test
builds each report the lints they share. Eight distinct sites is the work.

The deny-by-default `absurd_extreme_comparisons` aborts the run, so that list is
only complete because it was re-collected with the lint suppressed and nothing
further surfaced. Anyone re-measuring should suppress it too; otherwise a short
list reads as good news when it is really an early exit.

None changes behaviour. `empty_line_after_doc_comments` is the only one that
currently *misleads* a reader: the module doc comments heading `crypto.rs` and
`sss.rs` are parsed as documenting the `use` statement below them, so both
modules render undocumented and 33 lines of `sss.rs` constraint documentation
attach to an import.

## 3. Sequence

1. **Delete the trailing space that stops rustfmt.** `cargo fmt` does not
   currently complete: it exits with `error[internal]: left behind trailing
   whitespace`, pointing at the trailing space after `decrypt_mbps,` in the
   `println!` in `crypto.rs`. rustfmt does not format macro call arguments, so
   it cannot strip that space itself — it formats every other file, writes them,
   and `cargo fmt --check` still fails. Removing the one character by hand is
   what makes step 2 reach a clean state rather than a differently-dirty one.
2. `cargo fmt` as a single mechanical commit, nothing else in it, so review is
   "formatting only" and the churn is never mixed with logic. Expect 858 lines:
   `sss.rs` 463, `crypto.rs` 219, `seal.rs` 61, `lib.rs` 59, `detect.rs` 37,
   `utils.rs` 19. Steps 1 and 2 land together — a commit that leaves
   `cargo fmt --check` red is not the mechanical commit it claims to be.
3. Fix the six clippy findings as a second commit, one concern per hunk. Four
   are mechanical; `absurd_extreme_comparisons` is silenced in place with
   `#[allow(clippy::absurd_extreme_comparisons)]` and a comment recording why
   the guard is deliberately vacuous (see §1).

   `empty_line_after_doc_comments` stops firing after step 2, because the blank
   line it keys on is what rustfmt removes. The defect it named survives and
   gets worse: the module doc then sits directly above whichever `use` rustfmt
   sorted beneath it, documenting an import. Fix it by inspection — inner
   `//!` comments at the top of `sss.rs` and `crypto.rs` — and do not read the
   shorter clippy output as five findings.
4. Re-run `make test` — both suites, so the vector corpus proves the primitives
   still produce identical bytes. This is the acceptance gate: **if any vector
   fails, the change was not behaviour-preserving and must be reverted**, since
   a byte-level primitive change is a protocol change requiring an entirely
   different process (see `CLAUDE.md`).
5. Wire the targets into the Makefile:
   - add `rust-format-check` and `rust-lint` to `verify`;
   - add `rust-format` to `clean-code`, which reaches nothing today, so that a
     contributor whose `verify` just failed has a `make` route to fix it — the
     same relationship `go-format` has to `go-format-check`;
   - delete both notes: the `@echo` that `verify` prints, and the comment block
     above the `verify` target explaining why the Rust checks are absent.
6. Add both to the CI job. The toolchain step keeps `@stable`, since the
   toolchain file already governs (see §1), and gains a comment saying so. It
   sheds its `components: rustfmt, clippy` input, which `rust-toolchain.toml`
   declares for the toolchain that actually runs.

7. Correct the secret-size bounds in the `sss.rs` module documentation. It
   states a 1-byte minimum, which contradicts the `MIN_SECRET_SIZE` beside it
   and the ruling in §1 that empty secrets are valid. The 1MB maximum is
   accurate but reads as a protocol bound; it is a memory guard, and the
   protocol splits a 32-byte X25519 scalar (`chain/docs/spec.md`, key-share
   architecture). Documentation only — the constants do not move, since
   changing either is a byte-level primitive change and neither bound is
   reachable through any protocol path.

Steps 2 and 3 are reproducible against the declared toolchain, and CI resolves
to that same toolchain.

Step 7 is not lint or format work. It is folded in because step 3 rewrites the
doc block it lives in, and leaving a known-false bound in lines being rewritten
would be worse than the drift the rest of this plan removes (owner, August
2026).

## 4. What this plan does not solve

- **The Go side is already clean** and gated (`gofmt`, `goimports`, `go vet`,
  `golangci-lint` all run in `verify` today). This plan is Rust-only.
- **It does not touch test *coverage* or test quality** in the crate, only lint
  and format conformance. If the clippy pass surfaces genuinely questionable
  logic beyond the vacuous guard, that becomes its own plan rather than being
  fixed opportunistically here.
- **`git blame` attribution for the reformatted lines is not preserved.** The
  formatting commit becomes the blame origin for roughly a third of `sss.rs`
  and `crypto.rs`; the repository keeps no ignore-revs list (ruled by the owner,
  August 2026).
