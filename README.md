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

**WASM** — released as a build artefact per tag rather than built by consumers;
the TypeScript SDK pins a version and downloads it, so SDK contributors need no
Rust toolchain.

## Versioning

**One tag, two artefacts.** The Go module and the WASM package share a single
version line. They come from one tree, so a Rust-only change does bump the Go
module for no functional reason — accepted deliberately, because a no-op version
bump costs a consumer nothing, whereas several tag namespaces in one repository
costs everyone something.

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

**Two of the five travel.** An implementation outside this repository asserts
`low_order_keys.json` — the SDK's TypeScript guard, which refuses a small-order
guardian key before the WASM boundary so the creator learns which guardian is at
fault — and `rebate_commitment.json`, which the mobile app computes in TypeScript.
Both ship inside the WASM package, so a consumer that resolves the package has
them:

```
@timeflareio/crypto
└── vectors/
    ├── low_order_keys.json
    └── rebate_commitment.json
```

The other three — `hmac.json`, `encryption.json`, `detection_hint.json` — hold the
Go and Rust suites in this repository against each other. Both suites are here, so
those files reach no consumer and are not published. The mobile client's native
layer wraps this crate through UniFFI rather than reimplementing it, which is why
it needs a fixture for the binding rather than the corpus.

Vectors are append-only. Adding cases is ordinary work; **changing an existing
expected value means the primitives now produce different bytes**, which
invalidates every secret, share and hint in the wild — see Versioning above.

The chain repository keeps its own, separate corpus for chain semantics (gas,
dials, share bands, creation fees, wallet derivation). Those files are not
mirrored here and nothing here asserts them: this repository defines primitives
others depend on, and depends on none of them.

## Security posture

Two properties an auditor will ask about are not delivered by this code, and are
recorded here so the position is a decision rather than an omission. Neither is a
known vulnerability; both are limits worth stating plainly.

**Secret material is not systematically erased from memory.** The X25519 secret
key type zeroises on drop, so the per-secret private key `sk_s` is cleared once
sealing returns. Nothing else is: a guardian's decrypted envelope, a
reconstructed secret sitting in WASM linear memory, and the `Uint8Array`s the
TypeScript SDK hands back all persist until the allocator reuses the pages. In a
browser this is close to unavoidable — JavaScript exposes no way to guarantee a
buffer is overwritten, garbage collection may copy a value before any wipe runs,
and WASM linear memory is a plain `ArrayBuffer` the host may snapshot. Hardening
the paths that *are* under this repository's control is deferred rather than
refused; the trigger for doing it is an audit finding that names a reachable
attacker, not a general wish for hygiene.

**GF(256) arithmetic is not constant-time.** The Shamir implementation multiplies
and divides through log/exp lookup tables, so operand values steer memory
accesses and the timing is data-dependent — the classic table-lookup side
channel. The accepted-risk argument is about who is positioned to measure it:
splitting happens client-side on the machine that already holds the secret, and
combining happens where a threshold of shares has already been gathered, so an
attacker able to time these operations holds the material the channel would
leak. That argument is about *this* protocol's deployment, not about the
technique being safe; a future component that performed share arithmetic on
input it did not already own would need this revisited before shipping.

## Assurance

Beyond the unit suites and the vector corpus, both implementations carry
property-based and randomised-input tests. The Rust crate uses `proptest` to
check the GF(256) field laws universally, the split→combine identity across
arbitrary thresholds and share subsets, and the seal/unseal round trip under
arbitrary tampering. The Go package uses native fuzzing (`go test -fuzz`) against
the parsers the guardian daemon points at chain state.

```bash
make test    # both suites, plus every committed fuzz seed and regression case
make fuzz    # search for new ones — FUZZTIME=5m PROPTEST_CASES=100000
```

`make fuzz` is a deliberate, unbounded run and is in neither `verify` nor `test`.
Its output that matters is the corpus, not the run: crashes are committed as
seeds under `go/testdata/fuzz/` and `rust/proptest-regressions/`, where `make
test` replays them for good, offline and at no cost. There is no scheduled
fuzzing job in CI by decision — a nightly run spends runner minutes indefinitely
to rediscover what a committed seed already asserts.

## Documentation

`docs/spec.md` in the chain repository specifies the protocol that consumes
these primitives, and describes their wire format in prose. This repository is not a
consumer of it: the authority for what the primitives actually produce is the
code and the corpus in this repository. Design plans live in `docs/planning/`.

## Licence

MIT — see [LICENSE](LICENSE). The Rust crate declares the same in
`rust/Cargo.toml`.
