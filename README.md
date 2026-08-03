# timeflare crypto

Cryptographic primitives for the [timeflare](https://github.com/timeflareio/chain)
time-locked secret reveal protocol, in two implementations that are held
byte-identical by a shared vector corpus.

| Implementation | Path | Consumed by |
|---|---|---|
| Pure Go (no cgo) | `go/` | the chain and the guardian, as `github.com/timeflareio/crypto/go` |
| Rust → WASM | `rust/` | the TypeScript SDK, and through it the mobile client |

The corpus that holds the two in agreement is in `vectors/`. `go.mod` sits at the
repository root rather than in `go/`, so one plain `vX.Y.Z` tag serves both the
Go module and the WASM asset, and `go test ./...` works from the root.

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
make doctor    # check the toolchain (go, cargo, rustc, wasm-pack)
make test      # run BOTH suites against the shared vectors
make verify    # read-only checks: gofmt, imports, vet, golangci-lint
make wasm      # build the WASM bundle into pkg/
make help      # grouped target list
```

Running only one suite proves nothing about drift. `make test` runs both.

Both are offline and hermetic — this repository owns everything it asserts, so
no network access or credentials are needed to prove it correct.

## Consuming this module

**Go** — an ordinary pinned require. The import path carries the `/go`
subdirectory; the package is still named `crypto`, so an explicit alias reads
best:

```sh
go get github.com/timeflareio/crypto/go@v0.0.1
```

```go
import crypto "github.com/timeflareio/crypto/go"
```

While this repository is private, consumers need `GOPRIVATE=github.com/timeflareio/*`
and credentials for the module fetch — locally an SSH rewrite
(`git config --global url."git@github.com:".insteadOf "https://github.com/"`),
in CI a token secret with read access here.

**WASM** — released as a build artefact per tag rather than built by consumers;
the TypeScript SDK pins a version and downloads it, so SDK contributors need no
Rust toolchain.

## Versioning

**One tag, three artefacts.** The Go module, the WASM bundle and the vector
corpus share a single version line. They come from one tree, so a Rust-only
change does bump the Go module for no functional reason — accepted deliberately,
because a no-op version bump costs a consumer nothing, whereas several tag
namespaces in one repository costs everyone something.

**This module versions independently of the chain.** A release here neither
waits for nor implies a chain release; it is a dependency with its own upgrade
path, and nothing here enforces or checks chain protocol rules.

**A change to what the primitives produce is not an implementation detail.** It
invalidates every existing secret, share and hint in the wild, so it is a
protocol change: it needs the owner's explicit approval, a `docs/spec.md`
update in the chain repository, matching vector updates, and a coordinated roll of every
consumer. The version number carries that signal and nothing else does:

| | Behaviour-preserving change | Primitive output changes |
|---|---|---|
| **While on 0.x** (now) | PATCH — `0.1.0` → `0.1.1` | MINOR — `0.1.0` → `0.2.0` |
| **From 1.0.0 onward** | MINOR or PATCH | MAJOR |

The rule is that the breaking axis is *reserved* for primitive changes and never
spent on anything else, so seeing it move means exactly one thing. Note that the
axis differs before and after 1.0: under semver, 0.x expresses breakage in the
minor position.

**0.x is deliberate and stays until instructed.** It means there is no
compatibility promise yet. Going to 1.0.0 is a commitment, not a milestone to
drift into — `release.yml` refuses a tag outside 0.x so that crossing it has to
be a decision recorded in this file first.

## The vector corpus

`vectors/` is **owned here**, because this is where the primitives it pins are
implemented — twice, and the corpus is what stops those two copies diverging. The
generator that produces the cases lives here too
(`TestGenerateVectors` in `go/vectors_test.go`).

It is also a **published artefact**. Downstream implementations that reimplement
these primitives for runtimes the Go and WASM builds cannot reach — the mobile
client's native crypto layer, and the TypeScript SDK's own checks — pin a release
and assert the corpus to prove they interoperate:

```
timeflare-crypto-vectors-vX.Y.Z.tar.gz     # the five files, per release
timeflare-crypto-vectors-vX.Y.Z.sha256     # per-file manifest
```

Vectors are append-only. Adding cases is ordinary work; **changing an existing
expected value means the primitives now produce different bytes**, which
invalidates every secret, share and hint in the wild — see Versioning above.

The chain repository keeps its own, separate corpus for chain semantics (gas,
dials, share bands, creation fees, wallet derivation). Those files are not
mirrored here and nothing here asserts them: this repository defines primitives
others depend on, and depends on none of them.

## Documentation

`docs/spec.md` in the chain repository specifies the protocol that consumes
these primitives, and describes their wire format in prose. It is deliberately
not copied here — link it at a pinned tag instead. This repository is not a
consumer of it: the authority for what the primitives actually produce is the
code and the corpus in this repository. Design plans live in `docs/planning/`.

## Provenance

Lifted from the timeflare monorepo at
`3c3bda1db7847e81e48cd454dbfcf2db18027863`. Git history is deliberately not
carried across; the monorepo remains the complete historical record and design
log. Completed plans that shaped this component travel with it, in
`docs/planning/done/`.

## Licence

MIT — see [LICENSE](LICENSE). The Rust crate declares the same in
`rust/Cargo.toml`.
