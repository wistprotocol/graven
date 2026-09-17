# graven

The signed Delta format targets [WIST specification revision `d75bd49abcfbbe6a672e4fb695e078b489f51ba7`](https://github.com/wistprotocol/spec/tree/d75bd49abcfbbe6a672e4fb695e078b489f51ba7). Object version `1.0.0` alone does not identify a compatible draft.

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
where `--tier1` is on, `extracts`/`links`/FTS tables) whose `sync_state`
row is the sync cursor (`log_position`, head block number/hash,
`content_digest`, the schedule position); `sync.json` beside it mirrors
that row for readers of the file and is rewritten after each commit.
Publisher declarations, chain tips, Aggregator keys, parameters and
withdrawals are persisted in `index.sqlite` too, so an incremental sync
reloads them without re-walking the chain from genesis.
Every incremental sync commits the cursor, keys, parameters and index
rows in one transaction, so a sync that cannot commit leaves all of them
at the previous head; a cold start builds the whole index, cursor
included, in `index.sqlite.verifying` and renames it into place with the
directory synced, so a crash leaves either no store or a complete one,
and a stale verifying file is replaced by the next cold start. A store
that predates the row is read from its `sync.json` and imported on its
next sync. A log id that would escape its directory is rejected before
anything is written. A directory in the earlier single-log layout
(top-level `index.sqlite`/`sync.json`, no `logs.json`) is migrated into
this layout automatically on the next `sync`/`follow`, and rolled back
cleanly if that sync then fails.

## What sync verifies

Every protocol input — the Log Anchor, checkpoint, Block files, Snapshot
index, manifest and state, Payloads, companion packs and the store's own
retained JSON — is rejected when any object at any depth repeats a decoded
member name, escaped spellings included, before field, signature or replay
checks see a parsed value (WIST-1 §4, RFC 8785 §3.1); a rejected Payload
supplies no record fields, and a rejected Log file fails the sync.

Chain-level: every Block's signature, hash chain, and Merkle root; the
checkpoint's signature and its binding to the head Block; on cold start,
the snapshot index/manifest/state signatures and the recomputed
`content_digest`/`state_digest` against the manifest's claims. Each Block
file must be one standard Zstandard frame whose declared size is present
and within the accepted transport bound, decoded through core's shared
decoder (WIST-3 §6, ADR-0021), and must carry canonical JCS bytes; each
`sealed_at` must be a whole-second literal-`Z` Log timestamp on the
accepted cadence grid, strictly increasing (WIST-3 §3.1, ADR-0022).
Log-signed `parameter_change` acts replay through core's accepted-schedule
rules (WIST-4 §9, ADR-0020): rejected amendments are ignored, an amendment
cannot cut the cap below a Block already sealed, and a Block above the cap
in force at its instant fails the sync. The accepted schedule, the largest
Block seen and the previous instant persist in the sync cursor and the
`parameters` table; a cold start seeds the schedule from the Snapshot's
`parameter` tuples, so pending amendments survive. Any mismatch fails the
sync closed and, on an already-migrated directory, rolls the migration back.

Per-delta, independently of the above, in WIST-1 §7's order: complete
field validation under `delta.schema.json` (`WIST1-E14`), wire major `1`
support with same-major minor and patch values accepted (`WIST1-E15`,
ADR-0030), the presence rules and the URL and commitment caps the accepted
schedule holds at the Block's `sealed_at` (`WIST1-E09`/`E07`/`E11`/`E04`),
then the WIST-1 §5.2 binding: `sig.key_id` must resolve to a key in its
publisher's key set as of the sealing height, and that key's `valid_from`
must not be after the delta's `observed_at` under the Publisher timestamp
profile's exact fraction and offset arithmetic (ADR-0026). Verification
selects history by the canonical signed `publisher` and checks its literal
URL scope; shared keys and reused identifiers in other domains cannot
change authorship. Last, WIST-1 §3.4's clock check uses the committing
Block's `sealed_at` and the `clock_skew_seconds` accepted at that instant
(`WIST1-E06`); no wall clock takes part. Deltas failing any of these are
ignored without advancing their chains.

The chain of Publisher Declarations that produced that
key set must itself be well-formed — `seq` and `prev_declaration` strictly
monotonic and hash-linked, every key identifier occurring once across
`keys` and `recovery_keys` with no public key in both sets (`WIST1-E08`,
ADR-0023), an ordinary rotation carrying `recovery_keys` byte-identical to
its predecessor's (or introducing them for the first time), and a
declaration signed by a `recovery_keys` entry opening a 7-day recovery
window that takes precedence over any ordinary declaration sealed inside
it. The signer is resolved by `sig.key_id` among the usable previous
signing and recovery bindings and the incoming signing bindings (keys that
are not canonical, non-small-order Ed25519 points are excluded; `WIST1-E02`
names none, `WIST1-E01` verifies under none), and continuity follows the
authenticated public bytes: a renamed signing key is an ordinary rotation,
a renamed recovery key keeps recovery authority, and an unknown key is a
fresh identity that cannot alter a protected recovery set and yields to a
still-open recovery window. An invalid Declaration fails the sync. On cold start the Snapshot's `declaration` tuple supplies the
accepted sequence floor every later Declaration must exceed, and a
`recovery_window` tuple restores the recovery-chain head at its own height
with the window end on it (WIST-3 §§7/8); a `withdrawal` tuple is recorded
in the `withdrawals` table and removes the content it names from the
adopted index, so a Consumer resuming above the withdrawal's Block excludes
it exactly as a replaying one does (WIST-3 §6.2); a `label` tuple is parsed
and carried no further.

Registry Updates carry four acts (WIST-4 §3). Only `aggregator_key_add`
and `aggregator_key_remove` must verify under an Aggregator key for the
Block to stand; a `parameter_change` replays through the accepted schedule
above and a `payload_withdrawal` replays through core's withdrawal
engine under the Aggregator key valid at its Block — field, version and
authenticity failures and a Delta of another Publisher or sealed above
the act are ignored with their WIST-4 §5.1 code — then records the
withdrawn Delta at the earliest Block that withdrew it and removes its
record, extracts, links and embeddings; a withdrawal sealed in the same
Block as the Delta it names keeps that Delta from materializing at all.
A Delta sealed below the Blocks the sync walked cannot be checked
against the act, since no Snapshot tuple names sealed Deltas, and such
an act is read as consistent. A `label` Entry is verified as part of the Block and otherwise left
alone. Full recovery replay and materialization preference among
overlapping scoped Publishers remain separate validation requirements.

## Companion packs

A pack is a signed envelope, `{"pack": {...}, "sig": {...}}` (verified the
same way as every other WIST envelope, against a key the caller supplies
explicitly with `--key`: trust in a pack is trust in its publisher, the
protocol makes no claim about vector correctness). `pack` fields:
`wist_version`; `content_digest` and `log_position`, binding the pack to
one exact synced snapshot of one log (WIST-3 §7) — `pack import` rejects a
mismatch with the local sync cursor; `model` (`name`, `version`,
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
`synced_height`); rows for the same
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
`../clave` must also be sibling checkouts, rebuilt from their current
sources on every run (`SPAKE_BIN`/`CLAVE_BIN` override the binary paths and
skip that build); it seals on the default hourly cadence grid at explicit
instants (`clave seal --at`), advancing Log time by whole hours while
Deltas keep wall-clock `observed_at` values; it validates artifacts against the spec's schemas via
`WIST_SPEC_DIR`, requiring `jsonschema`, `rfc8785`, and `cryptography` on
`PATH`'s python3 — set `CI=1` to hard-fail instead of skipping when they're
missing). The same crate's `baseline` binary drives the pipeline at scale
for capacity measurements: `cargo run -p e2e --bin baseline -- --domains N
--pages M [--changed-percent P] [--body-words W] [--extra-empty-seals K]
[--no-tier1] [--out report.json]` publishes N loopback sites of M pages
through the publisher, ingests them through one aggregator behind a
request-counting proxy, seals, cold-starts a consumer, changes P percent of
the pages, seals again, seals K further empty Blocks, verifies the history
and catches the consumer up, reporting wall seconds, bytes and request
counts per stage together with every repository revision it ran. Set
`WIST_BUILD_PROFILE=release` to build and time release executables.

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
