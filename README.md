# graven

The signed Delta format targets [WIST specification revision `0127b0f2e5420e167a15d3f7afae6ed81030e158`](https://github.com/wistprotocol/spec/tree/0127b0f2e5420e167a15d3f7afae6ed81030e158). Object version `1.0.0` alone does not identify a compatible draft.

WIST Protocol consumer and MCP server. Graven cold-syncs a verified Snapshot,
then applies incremental Epochs to a separate SQLite index per Log (WIST-3 §8).
`serve` exposes the merged index with per-record provenance to an LLM agent
over MCP. Verification checks and limits are listed
[below](#what-sync-verifies).

Subcommands: `follow --anchor <url|path> --log <base-url> --dir <dir>`
(register the log in `<dir>/logs.json` if new, cold-sync if never synced,
sync incrementally otherwise; `--tier1` sticky-enables Tier 1 import for
that log, `--allow-http` allows plaintext HTTP to loopback hosts only,
`--mirror <base-url>` adds a further source for the log's static files
and `--witness <name+key-id+key>` sets the Witness roster this Consumer
trusts, both repeatable),
`sync --dir <dir>` (bare form re-syncs every log already in `logs.json`;
given `--anchor`/`--log` it does exactly what `follow` does for that one
log), `serve --dir <dir>` (MCP server over stdio against every synced log
in the store), `pack import --dir <dir> --log-id <id> --pack <pack.json>
--key <publisher-b64u-key>` (verify and import a signed embedding
companion pack against one already-synced log).

## Store layout

`<dir>/logs.json` is the log registry: one entry per followed log
(`log_id`, `anchor`, `base`, sticky `tier1`, the `mirrors` tried when one
source does not hold a file, and the `witnesses` roster). Every Log path
is resolved under its base's own path, so a Mirror serving the Log at
`https://cdn.example/wist/` is read at `https://cdn.example/wist/tile/…`. Each log gets
its own `<dir>/logs/<sanitized-log-id>/` holding `index.sqlite` (records,
and, where `--tier1` is on, `extracts`/`links`/FTS tables) whose
`sync_state` row is the sync cursor: the verified head's `epoch_number`,
the tree size it states as `tree_size`, its `root` in the
`sha256:`+hex form, whether the acceptance was `unwitnessed`, the
`content_digest` and the schedule position. `sync.json` beside it mirrors
that row for readers of the file and is rewritten after each commit.
The `checkpoints` table holds every Checkpoint the Consumer acted on,
note and signature lines verbatim, so the rollback comparison and an
equivocation bundle survive a restart; `tree_tiles` holds the tree
hashes it verified, so continuing needs no refetch of the Log's history.
Publisher declarations, chain tips, the Aggregator key registry — every
key the Log admitted, the genesis key and retired ones included, with
the heights that bound each one's validity and the accepted acts that
set them, so a reload re-authenticates the registry from the Anchor's
genesis key, restores no key a removal retired, and judges a Checkpoint
at any height under the keys valid there — parameters and withdrawals
are persisted in `index.sqlite` too, so an incremental sync
reloads them without re-walking the Log from genesis. A `sync_state` row
written before the Log became one growing tree — one naming a Block hash
where a tree size and root now stand — before its fields were renamed
to `epoch_number`/`tree_size`, or before the key registry kept those
acts, which no store can supply after the fact — is refused with an
instruction to remove the log's directory and follow the Log again,
never reinterpreted.
A divergence leaves an evidence bundle under
`<dir>/logs/<sanitized-log-id>/evidence/`: `equivocation-epoch-<N>/` with
the retained and offered Checkpoint notes, or `divergence-epoch-<N>/`
with the Checkpoints and, where the form needs them, the tiles that
reproduce the larger root. It also writes `halt.json` beside them: from
that point the Consumer applies nothing more from that Aggregator and
every later sync of the log exits with `WIST3-E02` naming the evidence,
until the operator removes the log's directory. What was already applied
stays queryable, and every MCP provenance row carries `halted`.
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

Every JSON protocol input — the Log Anchor, the Entries an entry bundle
carries, the Snapshot index, manifest and state, Payloads, companion
packs and the store's own retained JSON — is rejected when any object at
any depth repeats a decoded member name, escaped spellings included,
before field, signature or replay checks see a parsed value (WIST-1 §4,
RFC 8785 §3.1); a rejected Payload supplies no record fields, and a
rejected Log file fails the sync.

Tree-level (WIST-3 §§3–6): the head Checkpoint is the five-line signed
note of §5, and every archived Checkpoint between the verified head and
it is fetched and verified in `epoch_number` order — sequential numbering,
a tree that never shrinks, a strictly increasing `sealed_at` on the
cadence grid in force at the previous Epoch, the Consistency Proof from
the previous tree size with the size-0 root compared rather than skipped,
the Epoch's Entries against the leaf range `size(N-1)`..`size(N)` of the
tree the Checkpoint states, then the Log's signature under the Aggregator
keys valid at N. Epoch N's key acts apply first, in canonical Entry
index order, each authenticated under the keys valid at N−1; every other
Registry Update of the Epoch, and Checkpoint N itself, is authenticated
under the keys valid at N. A key act that fails — a `key_id` or note key
ID the Log already admitted, a removal of a key not valid at N−1 — is
ignored as `WIST4-E04`, one no key valid at N−1 signed as `WIST4-E11`,
and the Epoch stays valid. Tiles and entry bundles are kept only where
they recompute the Checkpoint's root; a partial tile or bundle is fetched
only at the width a Checkpoint's size requires, with the full one as the
fallback. A tile over 8 192 octets, an entry bundle over 16 777 472, an
Entry over 65 535 or an Epoch over the transport bound its verified prefix
derives is refused while the response streams, before the octets past the
bound are buffered (`WIST3-E03`). A Checkpoint at or below the verified head
adopts nothing and is no error, and the head is fetched from the next
source; one whose note text differs from the one retained at its
`epoch_number` is equivocation only where a key valid at *that
Checkpoint's own height* signs it — `WIST3-E02`, which halts the Log and
leaves an evidence bundle — and is otherwise `WIST3-E03` against the
source that served it, preserved as nothing. The same rule governs every
divergence above the head: two Checkpoints stating one tree size and
different roots, a tree below the Epoch before it, a tree that does not
extend the verified head's, a failed Consistency Proof and a size-0
Checkpoint stating another root than `SHA-256("")` are `WIST3-E02` with
their evidence when the offered Checkpoint authenticates under the keys
valid at its height (at the verified head's, where the Consumer has not
reached that height), and `WIST3-E03` against the source otherwise. A
fork's tiles are fetched into a scratch tree and never written over the
tiles the Consumer has verified. On cold start, the Snapshot index,
manifest and state file are held to their schemas and to each other, the
`content_digest` and `state_digest` recomputed from the files served
beside the manifest are held to the manifest's claims, and the Checkpoint
at the manifest's `epoch_number`
must state its `tree_size` and `root_hash` (`WIST3-E02` otherwise). The
state file's `aggregator_key` tuples are authenticated from the Anchor's
genesis key before any of them is used — each carries the accepted act
that admitted or retired its key, and WIST-3 §7's five rules chain every
act to the genesis key — and the three documents' own signatures are
verified only once the Checkpoint to adopt is settled, under the keys
valid at that Checkpoint's height (WIST-3 §3.4, §8 step 8). Each of
those failures is `WIST3-E04` against the whole Snapshot: it is
re-fetched from the next source, and nothing it carries is written. A
signature naming a tuple's key that the tuples' own copy of that key
rejects verifies at no height and is refused as soon as the tuples are
authenticated. A cold start that commits no state leaves the Log
unregistered where this run was the one that registered it; one that
adopted a Checkpoint keeps the registration and reports a failure above
that head as an incremental sync does. A sync reads no Mirror list.
The Checkpoint a Consumer adopts as its head must carry Cosignatures
from at least `checkpoint_witness_quorum` distinct Witnesses of its
roster, read as in force at that Checkpoint's `sealed_at` (WIST-3 §5,
WIST-4 §5). The roster is this Consumer's configuration, supplied as
`--witness <name>+<hex key id>+<base64 key>` verifier-key strings and
never read from the Log; it is empty by default, which at the quorum of
0 this edition starts at adopts the head and records the acceptance as
unwitnessed. A Checkpoint short of the quorum is neither evidence nor an
error: the head stands, nothing above its tree size is applied, and the
next run tries again. The acceptance is recorded as `unwitnessed` with
the Checkpoint it belongs to, in the `checkpoints` row of the Epoch
adopted — a Checkpoint verified on the way to the head but never adopted
carries no such record — and in the sync cursor for the head; the sync
report and every MCP provenance row carry it. Staleness is judged on the
newest Checkpoint the Consumer can accept: the one it adopted, or the
verified head it kept where everything above it was short of the quorum
or no source served a head at all.

Log-signed `parameter_change` acts replay through core's accepted-schedule
rules (WIST-4 §9, ADR-0020): rejected amendments are ignored, an amendment
cannot cut the cap below an Epoch already sealed, and an Epoch above the cap
in force at its instant fails the sync. The accepted schedule, the largest
Epoch seen and the previous instant persist in the sync cursor and the
`parameters` table; a cold start seeds the schedule from the Snapshot's
`parameter` tuples, so pending amendments survive. Any mismatch fails the
sync closed and, on an already-migrated directory, rolls the migration back.

Log-signed `suffix_list_update` acts replay through core's suffix-list
rules (WIST-4 §3.1): an accepted act's file is fetched from
`/log/suffix-lists/<hex>.dat`, verified to hash to its identifier
(`WIST3-E03`) and held in the `suffix_lists` table, a file no source
serves fails the sync (`WIST3-E01`), and an act the Log key does not
authenticate or whose `bytes` disagrees with the file is ignored with
its code. Every walked Epoch's `publisher_delta`, `label` and `dispute`
Entries are counted per Registrable Domain under the snapshot in force
at it against `domain_epoch_entries_max`, and its `label` and `dispute`
Entries against `labeler_epoch_entries_max` (WIST-3 §3.2); an Epoch over
either fails the sync (`WIST3-E03`). Before the first accepted act every
Canonical Host is its own unit. A cold start adopts the Snapshot's
`suffix_list` tuple and obtains its file before the first walked Epoch.

Per-delta, independently of the above, in WIST-1 §7's order: complete
field validation under `delta.schema.json` (`WIST1-E14`), wire major `1`
support with same-major minor and patch values accepted (`WIST1-E15`,
ADR-0030), the presence rules and the URL and commitment caps the accepted
schedule holds at the Epoch's `sealed_at` (`WIST1-E09`/`E07`/`E11`/`E04`),
then the WIST-1 §5.2 binding: `sig.key_id` must resolve to a key in its
publisher's key set as of the sealing height, and that key's `valid_from`
must not be after the delta's `observed_at` under the Publisher timestamp
profile's exact fraction and offset arithmetic (ADR-0026). Verification
selects history by the canonical signed `publisher` and checks its literal
URL scope; shared keys and reused identifiers in other domains cannot
change authorship. Last, WIST-1 §3.4's clock check uses the committing
Epoch's `sealed_at` and the `clock_skew_seconds` accepted at that instant
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
adopted index, so a Consumer resuming above the withdrawal's Epoch excludes
it exactly as a replaying one does (WIST-3 §6.2); a `label` tuple is parsed
and carried no further.

Registry Updates carry four acts (WIST-4 §3). Only `aggregator_key_add`
and `aggregator_key_remove` must verify under an Aggregator key for the
Epoch to stand; a `parameter_change` replays through the accepted schedule
above and a `payload_withdrawal` replays through core's withdrawal
engine under the Aggregator key valid at its Epoch — field, version and
authenticity failures and a Delta of another Publisher or sealed above
the act are ignored with their WIST-4 §5.1 code — then records the
withdrawn Delta at the earliest Epoch that withdrew it and removes its
record, extracts, links and embeddings; a withdrawal sealed in the same
Epoch as the Delta it names keeps that Delta from materializing at all.
A Delta sealed below the Epochs the sync walked cannot be checked
against the act, since no Snapshot tuple names sealed Deltas, and such
an act is read as consistent. A `label` or `dispute` Entry is validated under its signer's Declaration
at the Epoch as the Aggregator validated it — fields, the registry name,
self-labeling, the disputed Label's sealing and authority, the signature,
and `asserted_at` within the Epoch's `sealed_at` plus the
`clock_skew_seconds` in force then, the bound a sealed Delta's
`observed_at` meets (WIST-1 §3.4) — and one that fails is ignored like a
forked Delta (WIST-2 §3.3). The
index keeps every walked Label and dispute, the current Label per
(labeler, subject, name) and the current dispute per (Label ID,
disputant) by `asserted_at` and Log order, a cold start adopting the
Snapshot's `label` and `dispute` tuples with the Label IDs they carry,
so a later dispute of an adopted Label is checked as a walked one is. The
`labelers` table counts each Labeler's walked Labels, retractions,
distinct subjects and first and last sealed heights (WIST-3 §7's
statistics, recomputed locally). `subscribe --labeler` names the
Labelers the index applies, kept in `labelers.json`; each sync fetches
their label definitions from `labels/definitions/<hex>.json`, keeping
the newest that verifies, so `get_labels` reports the treatment a
Labeler declares and `inform` where none does (WIST-4 §6). Full recovery
replay and materialization preference among overlapping scoped
Publishers remain separate validation requirements.

## Labels through MCP

`get_labels` returns the current, unretracted, unexpired Labels sealed
about a subject by subscribed Labelers — with value, expiry, Delta
binding, treatment and the labeled domain's disputes — and
`every_labeler` widens it to every Labeler walked; `list_labelers`
returns each Labeler's statistics and whether it is subscribed. Labels
are transported beside the records and never applied to them.

## Ranking profiles

A search is ranked by a profile: a JSON file naming the signals it reads
and how it combines them. Text relevance comes from FTS5's BM25 over
titles, abstracts and extracts, normalized within the result set; trust
is propagated from seed domains — the domains the profile's Labelers
(its `labelers`, or the subscription list when empty) agree on with
`wist:trust-seed`, at least `agreement_k` of them, plus the profile's
own `seeds` — along the signed link graph between Registrable Domains
under the suffix-list snapshot in force, each link weighted by its age
at the head; distrust is propagated backward from `wist:distrust-seed`
domains and the profile's `distrust_seeds`, so a domain that links to a
bad seed inherits it; a trust seed that links to distrusted or
spam-labeled domains vouches for less. In-links are counted per domain
with age decay and damped by their growth rate over
`growth_window_epochs`, death rates are reported beside them, domain
age is read from the first sealed Declaration or, where a fresh identity
has taken effect, from its activation height (WIST-4 §8), and freshness
from the record's seal height. Two readings WIST-4 §6 recommends are
profile fields: a `wist:mismatch` or `wist:unavailable` Label counts
against a subject only once it has been live through
`persistence_epochs` consecutive Epochs, two by default, and a Labeler
with no sealed Entry within `labeler_inactive_epochs`, 720 by default,
is ignored. The score is relevance × (`trust_floor` + `trust`
× trust) × (1 + `inlinks` × in-links) × freshness × (1 − `distrust` ×
distrust) × (1 − `mismatch` where one counts), after the filters: distrust above a threshold, spam labels,
domains younger than `min_age_epochs`, and, for a strict profile, any
domain no trust reaches. Every hit carries its score, its signals and
an explanation, so a profile and the synced heights in the hit's
provenance reproduce the rank.

Four profiles ship in the binary: `default` (relevance scaled by seeded
trust, distrust, spam and age as filters, freshness, no
personalization), `text-only`, `personal-seeds` (the default with the
operator's own seeds, edited in a copy under `profiles/`) and
`strict-trusted-graph`. `graven profile list|show|use` selects the
profile an install answers with, `profiles/<name>.json` in the store
directory overrides or adds one, and `search`'s `profile` parameter
selects one per query; `list_profiles` reports them with author,
license and `superseded_by`. `profile use` records the choice as `active`
in `<dir>/profile.json`; a query naming no profile uses it, or `default`
where none is recorded. The ranking index — record seal heights,
in-links with the height each was sealed at and the in-links each
domain gained and lost per height — is kept by the sync from tier-1
links, so link signals need the extract tier.

## Companion packs

A pack is a signed envelope, `{"pack": {...}, "sig": {...}}` (verified the
same way as every other WIST envelope, against a key the caller supplies
explicitly with `--key`: trust in a pack is trust in its publisher, the
protocol makes no claim about vector correctness). `pack` fields:
`wist_version`; `content_digest` and `tree_size`, binding the pack to
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
`synced_height`, and `unwitnessed` where that log's head was adopted with
no Cosignature from a Witness this Consumer trusts); rows for the same
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
missing). It then reads the served Log with an independent client,
`e2e/tlog-client`, built on Go's `golang.org/x/mod/sumdb/note` and `tlog`:
the head Checkpoint's signature under the Log's verifier key, the root
recomputed from the tiles, an Inclusion Proof for every leaf and a
Consistency Proof from every smaller size; it reads the Log once before
the Log rotates its own signing keys and once after, each time under the
verifier key of a key valid at the head it reads. It needs a Go toolchain
and is skipped without one, or fails under `CI=1`. A second suite in the same crate drives the Consumer against
an Aggregator with no Publisher: a cold start at a Snapshot's Epoch
followed by continuous sync, a source serving an old head leaving the
verified head where it is, and a Checkpoint adopted only once a Witness
in the roster has cosigned it — with a minimal in-process Witness
answering [tlog-witness] `add-checkpoint` with a cosignature/v1 line.
The same crate's `baseline` binary drives the pipeline at scale
for capacity measurements: `cargo run -p e2e --bin baseline -- --domains N
--pages M [--changed-percent P] [--body-words W] [--extra-empty-seals K]
[--no-tier1] [--out report.json]` publishes N loopback sites of M pages
through the publisher, ingests them through one aggregator behind a
request-counting proxy, seals, cold-starts a consumer, changes P percent of
the pages, seals again, seals K further empty Epochs, verifies the history
and catches the consumer up, reporting wall seconds, bytes and request
counts per stage (each seal stage also carries the aggregator's own seal
and Snapshot production seconds, parsed from `clave seal`'s output)
together with every repository revision it ran. Set
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
