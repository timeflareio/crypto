# Rust Crate Hygiene — rustfmt and clippy — Plan

*Brings `rust/` up to `cargo fmt --check` and `cargo clippy -D warnings`, then
adds both to `make verify` and CI. The crate has never been gated on either:
the monorepo's Rust CI job ran `cargo test` and `cargo audit` only, so the debt
arrived with the lift rather than being created by it.*

> **Status: refining** — created August 2026 alongside the phase-1 lift. The
> scope is known and small; §4 asks two questions before it is executable.
> **Priority**: P3 — pure hygiene. No behaviour change, no consumer impact.
> Worth doing because an ungated formatter is a permanent source of diff noise,
> and because one of the six clippy findings marks genuinely dead code.
> **Origin**: discovered during the phase-1 crypto lift (multi-repo migration
> plan, in the monorepo). The lift deliberately did *not* fix this: applying
> `cargo fmt` produced ~880 lines of churn that would have buried the 12
> meaningful lines of the lift diff, so the debt was split out here.
> **Components**: `rust/src/*.rs`, `Makefile` (`verify` target),
> `.github/workflows/ci.yml`, and a new `rust/rust-toolchain.toml`.

## 1. Why this is not cosmetic

Two of the three parts have consequences beyond tidiness:

- **An ungated formatter guarantees future noise.** Every contributor whose
  editor runs rustfmt on save produces reformatting churn mixed into unrelated
  changes, which is exactly what makes a diff unreviewable. Formatting once and
  gating it is what stops that.
- **`clippy::absurd_extreme_comparisons` marks dead code.** `MIN_SECRET_SIZE`
  is `0` and `sss.rs` tests `if size < MIN_SECRET_SIZE` on a `usize`, which can
  never be true. The behaviour is correct — empty secrets are deliberately
  allowed — but the guard is vacuous and reads as though it validates
  something. Either it goes, or it says in a comment that it is deliberately
  vacuous for symmetry with the `MAX_SECRET_SIZE` check.
- **Toolchain pinning is a prerequisite, not a nicety.** rustfmt and clippy
  output vary by toolchain version, so gating on them without a pinned
  toolchain makes CI fail when the runner's stable moves. A
  `rust-toolchain.toml` must land in the same change. This also serves the
  release plan's reproducible-WASM requirement
  (`PENDING_RELEASE_STRATEGY_PLAN.md` §3).

## 2. The findings

`cargo clippy --all-targets` reports six distinct lints (13 occurrences):

| Lint | Where | Nature |
|---|---|---|
| `absurd_extreme_comparisons` | `sss.rs` | vacuous guard — see §1 |
| `empty_line_after_doc_comments` | `crypto.rs` | doc comment detached from its item |
| `needless_range_loop` | `sss.rs` | index loop over a slice |
| `map_clone` | `sss.rs` | `.map(|&i| x[i].clone())` |
| `expect_fun_call` | `crypto.rs` | `expect(&format!(…))` allocates eagerly |
| `redundant_pattern_matching` | `sss.rs` | `matches!(x, Ok(_))` |

None changes behaviour. `empty_line_after_doc_comments` is the only one that
currently *misleads* a reader: the doc comment at the top of `crypto.rs`
documents the module but is parsed as documenting the `use` statement below it,
which is also why rustfmt reorders it oddly.

## 3. Sequence

1. Add `rust/rust-toolchain.toml` pinning the toolchain (channel + `rustfmt`,
   `clippy` components).
2. `cargo fmt` as a single mechanical commit, nothing else in it, so review is
   "formatting only" and the churn is never mixed with logic.
3. Fix the six clippy findings as a second commit, one concern per hunk.
4. Re-run `make test` — both suites, so the vector corpus proves the primitives
   still produce identical bytes. This is the acceptance gate: **if any vector
   fails, the change was not behaviour-preserving and must be reverted**, since
   a byte-level primitive change is a protocol change requiring an entirely
   different process (see `CLAUDE.md`).
5. Add `rust-format-check` and `rust-lint` to `verify`; remove the note the
   Makefile currently prints.
6. Add clippy and fmt to the CI job.

## 4. Open questions

1. **Does the vacuous `MIN_SECRET_SIZE` guard go, or get documented?**
   *Recommendation*: keep it and add `#[allow(clippy::absurd_extreme_comparisons)]`
   with a comment. Removing it makes the validation function asymmetric — every
   other bound checks both ends — and a future change to `MIN_SECRET_SIZE`
   would then silently have no guard. The lint is right that the code is dead;
   the code is right that the shape should stay.

2. **Which toolchain channel gets pinned?** `stable` with a specific version
   (e.g. `1.97.0`) is reproducible but needs periodic bumping, and each bump
   can introduce new clippy lints — i.e. it makes toolchain updates a T1-style
   routine rather than a no-op. *Recommendation*: pin an exact stable version
   and let Dependabot-style routine bumps carry it, accepting that a bump may
   come with lint fixes attached. Unpinned `stable` trades reproducibility for
   convenience in exactly the place reproducibility matters (the WASM artefact).

## 5. What this plan does not solve

- **The Go side is already clean** and gated (`gofmt`, `goimports`, `go vet`,
  `golangci-lint` all run in `verify` today). This plan is Rust-only.
- **It does not touch test *coverage* or test quality** in the crate, only lint
  and format conformance. If the clippy pass surfaces genuinely questionable
  logic beyond the vacuous guard, that becomes its own plan rather than being
  fixed opportunistically here.
