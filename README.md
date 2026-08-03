# timeflare crypto

Cryptographic primitives for the [timeflare](https://github.com/timeflareio/chain)
time-locked secret reveal protocol, in two implementations that are held
byte-identical by a shared vector corpus.

| Implementation | Path | Consumed by |
|---|---|---|
| Pure Go (no cgo) | repository root | the chain and the guardian, as `github.com/timeflareio/crypto` |
| Rust → WASM | `rust/` | the TypeScript SDK, and through it the mobile client |

Primitives: HMAC derivation, unified asymmetric encryption (X25519 +
ChaCha20-Poly1305), Shamir Secret Sharing, detection hints, rebate commitments.

## Why two implementations

Two implementations of one concern is normally a defect. This one is forced: the
browser and mobile runtimes cannot execute the Go path, and the chain cannot
take a cgo dependency. The duplication is allowed to exist only because it is
pinned mechanically rather than by discipline.

`vectors/` holds a corpus of known-answer test cases that **both** suites
assert. If either implementation changes what it produces — by a single byte —
`make test` fails on the side that changed. That is the whole safety property of
this repository, and it is why the two implementations live together rather than
in separate repos.

## Quick start

```sh
make doctor    # check the toolchain (go, cargo, wasm-pack, gh)
make test      # run BOTH suites against the vendored vectors
make verify    # read-only checks: format, imports, vet, lint, clippy, vectors
make wasm      # build the WASM bundle into pkg/
make help      # grouped target list
```

Running only one suite proves nothing about drift. `make test` runs both.

## Consuming this module

**Go** — an ordinary pinned require:

```sh
go get github.com/timeflareio/crypto@v0.0.1
```

While this repository is private, consumers need `GOPRIVATE=github.com/timeflareio/*`
and credentials for the module fetch — locally an SSH rewrite
(`git config --global url."git@github.com:".insteadOf "https://github.com/"`),
in CI a token secret with read access here.

**WASM** — released as a build artefact per tag rather than built by consumers;
the TypeScript SDK pins a version and downloads it, so SDK contributors need no
Rust toolchain.

## The vector corpus

The corpus is **owned by the chain repository** (`timeflareio/chain`,
`testdata/vectors/`), because the protocol surface — specification, protobuf
definitions and conformance vectors — belongs together. This repository vendors
a pinned copy of the subset its two suites assert, recorded in
`VECTORS_VERSION`:

```sh
make vectors-verify                          # check the copy against the pinned release
make vectors-sync VECTORS_VERSION=v0.1.0     # refresh from a chain release
```

Never hand-edit `vectors/`. A change to the corpus lands in the chain repo
first, then arrives here as a sync.

## Documentation

`docs/spec.md` in the chain repository is the single protocol authority for
every timeflare repository. It is deliberately not copied here — link it at a
pinned tag instead. Design plans for this component live in `docs/planning/`.

## Provenance

Lifted from the timeflare monorepo at
`3c3bda1db7847e81e48cd454dbfcf2db18027863`. Git history is deliberately not
carried across; the monorepo remains the complete historical record and design
log. Completed plans that shaped this component travel with it, in
`docs/planning/done/`.

## Licence

MIT (see `rust/Cargo.toml`; a repository-level licence file is pending).
