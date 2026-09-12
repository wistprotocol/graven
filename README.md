# graven

The signed Delta format targets [WIST specification revision `b96e21fe97b591075c369db17346df81292a8158`](https://github.com/wistprotocol/spec/tree/b96e21fe97b591075c369db17346df81292a8158). Object version `1.0.0` alone does not identify a compatible draft.

WIST Protocol consumer and MCP server. Graven cold-syncs a verified Snapshot,
then applies incremental Blocks to a separate SQLite index per Log (WIST-3 §8).
`serve` exposes the merged index with per-record provenance to an LLM agent
over MCP. Verification checks and limits are listed
[below](#what-sync-verifies).

Subcommands: `follow --anchor <url|path> --log <base-url> --dir <dir>`
(register the log in `<dir>/logs.json` if new, cold-sync if never synced,
sync incrementally otherwise; `--tier1` sticky-enables Tier 1 import for
that log, `--allow-http` allows plaintext HTTP to loopback hosts only),
`sync --dir <dir>` (bare form re-syncs every log already in `logs.json`;
given `--anchor`/`--log` it does exactly what `follow` does for that one
log), `serve --dir <dir>` (MCP server over stdio against every synced log
in the store), `pack import --dir <dir> --log-id <id> --pack <pack.json>
--key <publisher-b64u-key>` (verify and import a signed embedding
companion pack against one already-synced log).

## Store layout

`<dir>/logs.json` is the log registry: one entry per followed log
(`log_id`, `anchor`, `base`, sticky `tier1`). Each log gets its own
`<dir>/logs/<sanitized-log-id>/` holding `index.sqlite` (records, and,
where `--tier1` is on, `extracts`/`links`/FTS tables) and `sync.json`
(`log_position`, head block number/hash, `content_digest`). Publisher
declarations seen while syncing are persisted in `index.sqlite` too, so an
incremental sync reloads the key history without re-walking the chain from
genesis. A log id that would escape its directory is rejected before
anything is written. A directory in the earlier single-log layout
(top-level `index.sqlite`/`sync.json`, no `logs.json`) is migrated into
this layout automatically on the next `sync`/`follow`, and rolled back
cleanly if that sync then fails.

## What sync verifies

Chain-level: every Block's signature, hash chain, and Merkle root; the
checkpoint's signature and its binding to the head Block; on cold start,
the snapshot index/manifest/state signatures and the recomputed
`content_digest`/`state_digest` against the manifest's claims. Any
mismatch fails the sync closed and, on an already-migrated directory,
rolls the migration back.

Per-delta, independently of the above (WIST-1 §5.2): each delta's
`sig.key_id` must resolve to a key in its publisher's key set as of the
sealing height; that key's `valid_from` must not be after the delta's
`observed_at`. Verification selects history by the canonical signed
`publisher` and checks its literal URL scope; shared keys and reused
identifiers in other domains cannot change authorship. Malformed or
unauthorized Deltas are ignored without advancing their chains.

The chain of Publisher Declarations that produced that
key set must itself be well-formed — `seq` and `prev_declaration` strictly
monotonic and hash-linked, an ordinary rotation (signed by the prior key
set) carrying `recovery_keys` byte-identical to its predecessor's (or
introducing them for the first time), and a declaration signed by a
`recovery_keys` entry opening a 7-day recovery window that takes
precedence over any ordinary declaration sealed inside it. A declaration
under keys the history doesn't recognize is still accepted as a fresh
identity, but yields to a still-open recovery window. An invalid Declaration
fails the sync. Full recovery replay and materialization preference among
overlapping scoped Publishers remain separate validation requirements.

## Companion packs

A pack is a signed envelope, `{"pack": {...}, "sig": {...}}` (verified the
same way as every other WIST envelope, against a key the caller supplies
explicitly with `--key`: trust in a pack is trust in its publisher, the
protocol makes no claim about vector correctness). `pack` fields:
`wist_version`; `content_digest` and `log_position`, binding the pack to
one exact synced snapshot of one log (WIST-3 §7) — `pack import` rejects a
mismatch with the local `sync.json`; `model` (`name`, `version`,
`weights_hash`, `dim`, `quantization`, `metric` — one of
`cosine`/`dot`/`euclidean` — `source`); `vectors` (`path`, `sha256`,
`bytes`, `count`) describing a zstd-compressed JSONL file alongside the
pack, one row per vector: `{"delta_id", "url", "publisher", "vector":
[f32, ...]}`. Import verifies, in order: the envelope signature, the
snapshot binding, the vectors file's hash and byte length, the row count
and every vector's length against `dim`, then imports only rows whose
`delta_id` matches a locally-known record (rows for records the log
doesn't hold, or withdrawn since, are skipped and counted) — a pack with
zero importable rows is rejected outright. `similar_records` scores
against one log's imported pack; scores never merge across packs or logs,
since a pack binds one snapshot of one chain and nothing about "similar"
survives mixing two.

## MCP tools

`serve` exposes: `search` (full-text over titles/abstracts, and over Tier
1 extract text where imported), `get_record`, `get_extract` (Tier 1 body
text), `get_links` (declared outbound links, Tier 1), `similar_records`
(nearest neighbors by an imported companion pack). Merging across logs
happens at query time, in two steps: rows sharing one `delta_id` collapse
into one, with `provenance` listing every log that carries it (`log_id`,
`synced_height`, `weight` — `weight` is never merged, since it's derived
per log from that log's own sanction/reputation state); rows for the same
URL and publisher but different `delta_id` (logs that diverged, or synced
to different heights) resolve to whichever has the later `observed_at`,
`delta_id` breaking ties (WIST-3 §8).

## Install

```sh
npx wist-graven sync --dir ./store --anchor <anchor> --log <base-url>
```

or `npm install -g wist-graven` — `postinstall` downloads the prebuilt
`graven` binary for your platform from the matching GitHub release
(`wistprotocol/graven`) and verifies it against the published `.sha256`.
The same six target archives (linux/macOS/Windows × x64/arm64,
`cargo-dist`) are attached directly to each GitHub release for anyone not
going through npm. To build from source: `cargo build -p graven` (needs
`../core` as a sibling checkout — see Build & test below).

## Build & test

```bash
cargo build
cargo test
```

Conformance tests read the spec repo's schemas/vectors from `../spec`
(sibling checkout) by default, or from `WIST_SPEC_DIR` if set. Building also
resolves `wist-core` from `../core`. The `e2e` workspace member additionally
drives real `spake` and `clave` binaries end to end, so `../spake` and
`../clave` must also be sibling checkouts (`SPAKE_BIN`/`CLAVE_BIN` override
the binary paths; it validates artifacts against the spec's schemas via
`WIST_SPEC_DIR`, requiring `jsonschema`, `rfc8785`, and `cryptography` on
`PATH`'s python3 — set `CI=1` to hard-fail instead of skipping when they're
missing).

## Verification

```bash
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace
cargo deny check
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

## Spec

Protocol definitions live in the sibling [spec repo](../spec) — Graven is a
consumer of all three: WIST-1 deltas, WIST-2 site publication, and WIST-3
logbook & distribution (sync, snapshots, proofs).

## CI & releases

`.github/workflows/ci.yml` checks out `core`, `spec`, `spake`, and `clave`
from `wistprotocol/*` (sibling clones).
Release and workflow-regeneration procedures: [RELEASING.md](RELEASING.md).
