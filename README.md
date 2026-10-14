# graven

The publication format — Declarations, Collections, Catalogs, Items and Payloads — targets [WIST specification revision `f4acfefbe7d3cdb8e82ed34053377159d8782890`](https://github.com/wistprotocol/spec/tree/f4acfefbe7d3cdb8e82ed34053377159d8782890). Object version `1.0.0` alone does not identify a compatible draft.

WIST Protocol consumer and MCP server. Graven cold-syncs a verified Snapshot,
then applies incremental Epochs to a separate SQLite index per Log (WIST-3 §8).
`serve` exposes the index of every followed Log, combined per Publisher
and URL, with per-record provenance to an LLM agent over MCP. Verification checks and limits are listed
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
companion pack against one already-synced log), `subscribe --dir <dir>
[--labeler <domain>]` and `unsubscribe --dir <dir> --labeler <domain>`
(the Labelers the index applies; `subscribe` without `--labeler` lists
them), and `profile list --dir <dir>` and `profile show|use --dir <dir>
--name <profile>` (the ranking profiles below).

## Store layout

`<dir>/logs.json` is the log registry: one entry per followed log
(`log_id`, `anchor`, `base`, sticky `tier1`, the `mirrors` tried when one
source does not hold a file, and the `witnesses` roster). Every Log path
is resolved under its base's own path, so a Mirror serving the Log at
`https://cdn.example/wist/` is read at `https://cdn.example/wist/tile/…`. Each log gets
its own `<dir>/logs/<sanitized-log-id>/` holding `index.sqlite` (the
`records` table, and, where `--tier1` is on, `extracts`/`links`/FTS tables)
whose
`sync_state` row is the sync cursor: the verified head's `epoch_number`,
the tree size it states as `tree_size`, its `root` in the
`sha256:`+hex form, whether the acceptance was `unwitnessed`, the
`content_digest` and the schedule position. `sync.json` beside it mirrors
that row for readers of the file and is rewritten after each commit.
The `checkpoints` table holds every Checkpoint the Consumer acted on,
note and signature lines verbatim, so the rollback comparison and an
equivocation bundle survive a restart; `tree_tiles` holds the tree
hashes it verified, so continuing needs no refetch of the Log's history.
`records` holds one row per materialized record (WIST-3 §7): `url`,
`publisher`, `item_id`, `observed_at`, `attested_at`, `title`, `abstract`,
`lang`, `collection` and `generated_at`, the instant of the Catalog the
record's Item was proved against. `state_tuples` holds the Log-derived
publication state as WIST-3 §7's state tuples — Declarations, latest
Catalogs, records, removal states, withdrawals and accepted Registry
Update IDs — rewritten whole after each adopted Epoch; every run resumes
the replay from them. `sealed_items` and `sealed_label_ids` hold the Items
and Label IDs of the Epochs the Consumer walked, and the sync cursor's
`walk_floor` the Epoch of the Snapshot it was installed from.
Publisher Declarations, the Aggregator key registry — every
key the Log admitted, the genesis key and retired ones included, with
the heights that bound each one's validity and the accepted acts that
set them, so a reload re-authenticates the registry from the Anchor's
genesis key, restores no key a removal retired, and judges a Checkpoint
at any height under the keys valid there — parameters and withdrawals,
keyed by Item ID, are persisted in `index.sqlite` too, so an incremental
sync reloads them without re-walking the Log from genesis. A `sync_state`
row written in a superseded format — before the Log became one growing
tree, before its fields were renamed to `epoch_number`/`tree_size`,
before the key registry kept each key's accepted acts, before records
were keyed by Item ID, or before link rows and Item sightings were kept
per Item — is refused with an instruction to remove the
log's directory and follow the Log again, never reinterpreted.
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
`content_digest` and `state_digest` recomputed from the files the manifest
lists are held to the manifest's claims, and the Checkpoint
at the manifest's `epoch_number`
must state its `tree_size` and `root_hash` (`WIST3-E02` otherwise). The
state file's `aggregator_key` tuples are authenticated from the Anchor's
genesis key before any of them is used — each carries the accepted act
that admitted or retired its key, and WIST-3 §7's five rules chain every
act to the genesis key — and the three documents' own signatures are
verified only once the Checkpoint to adopt is settled, under the keys
valid at that Checkpoint's height (WIST-3 §3.4, §8 step 8). The state
file and every listed file are fetched relative to the directory of the
index entry's `manifest_url` (WIST-3 §6). A sharded manifest (WIST-3 §7)
must carry one digest per shard, a `shard` index below the shard count on
every file, every file under the `shard-<i>/` directory its `shard` names,
and each shard's `tier0/index.sqlite`. The Consumer fetches every shard:
the records of all tier-0 files are merged into one index, each shard's
digest is recomputed over the records the Publisher-domain rule assigns
to it, `content_digest` over all of them, and a record filed in another
shard than the rule's is refused; tier-1 extracts and links are imported
from every shard. A partial Consumer holding a subset of shards is not
implemented. Each of
those failures is `WIST3-E04` against the whole Snapshot: it is
re-fetched from the next source, and nothing it carries is written. A
signature naming a tuple's key that the tuples' own copy of that key
rejects verifies at no height and is refused as soon as the tuples are
authenticated. A cold start that commits no state leaves the Log
unregistered where this run was the one that registered it; one that
adopted a Checkpoint keeps the registration and reports a failure above
that head as an incremental sync does. A store whose verified head lags
the newest Checkpoint by at least N Epochs reads the Snapshot index; when
the newest Snapshot stands at least N Epochs above the head, it is
installed as a cold start installs it, after its `aggregator_key` tuples
are checked against the held registry (WIST-3 §7) and its Checkpoint
against the held tree (a tree that does not extend the head is
`WIST3-E02`), and replaces the store atomically. A rejected Snapshot is
reported and the sync walks instead; `--catch-up-epochs <N>` on `follow`
or `sync` sets N (default 720). A sync reads no Mirror list.
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
is rejected (see Publication replay). The accepted schedule, the largest
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
its code. Every walked Epoch's `publisher_catalog`, `publisher_item`,
`label` and `dispute` Entries are counted per Registrable Domain under
the suffix-list snapshot in force at it against
`domain_epoch_entries_max`, and its `label` and `dispute` Entries against
`labeler_epoch_entries_max` (WIST-3 §3.2); an Epoch over either is
rejected (`WIST3-E03`). Before the first accepted act every
Canonical Host is its own unit. A cold start adopts the Snapshot's
`suffix_list` tuple and obtains its file before the first walked Epoch.

## Publication replay

Each walked Epoch is judged by core's replay of WIST-3 §8, the same
judgment an Aggregator's history check runs: with the parameters, the
suffix list and the Aggregator keys in force at the Epoch, after the
Epoch's key acts, `parameter_change` and `suffix_list_update` acts apply,
it judges Publisher Declarations, Catalogs (`publisher_catalog`) against
their Collection's keys and scope, Items (`publisher_item`) against the
Catalog their inclusion proof names, `payload_withdrawal` acts, Labels
and disputes. An Entry that fails its checks is ignored, reported on
stderr with its codes, and changes no state. An Epoch the replay rejects,
or one over the smallest `epoch_cap_bytes` in force at its `sealed_at`
or at any accepted later `effective_at` (`WIST3-E03`), applies its key
acts alone: the walk continues past it, its Checkpoint is judged under
the keys those acts leave valid, and the sync report lists it with its
codes (WIST-3 §3.3). The store changes only once a Checkpoint is
adopted, and Entries above the adopted tree size are not applied.

`records` holds exactly the materialized records of the replayed state:
a valid Item of kind `page` makes the record of its Publisher and URL; a
`removed` Item, a Collection narrowed so the URL leaves its scope and a
base Catalog remove it; a withdrawal hides the record of the Item it
names; and of the records of one URL, self-declaration and then the
nearest ancestor decide the one materialized (WIST-3 §7, One URL, one
Publisher). A record's content — title, abstract and, with `--tier1`,
extract and links — comes from `/payloads/<item-id-hex>.json`, verified
against its Item's commitment under the size caps of the Epoch that first
sealed the Item (WIST-1 §3.6). A Payload no source serves or that fails
verification leaves the row without content and never fails the sync;
every later sync retries it. A row that leaves or changes Item takes its
extracts, links and embeddings with it.

A Publisher's chain of Declarations, which supplies the keys its
Collections and Labels are judged under, must be well-formed — `seq` and `prev_declaration` strictly
monotonic and hash-linked, every key identifier occurring once across
`keys` and `recovery_keys` with no public key in both sets (`WIST1-E08`,
ADR-0023), an ordinary rotation carrying `recovery_keys` byte-identical to
its predecessor's (or introducing them for the first time), and a
declaration signed by a `recovery_keys` entry opening a recovery
window of `recovery_window_days` (7 by default) that takes precedence
over any ordinary declaration sealed inside it. The signer is resolved by `sig.key_id` among the usable previous
signing and recovery bindings and the incoming signing bindings (keys that
are not canonical, non-small-order Ed25519 points are excluded; `WIST1-E02`
names none, `WIST1-E01` verifies under none), and continuity follows the
authenticated public bytes: a renamed signing key is an ordinary rotation,
a renamed recovery key keeps recovery authority, and an unknown key is a
fresh identity that cannot alter a protected recovery set and yields to a
still-open recovery window.

On cold start the Snapshot's state tuples seed the replay: `declaration`
tuples supply the accepted sequence floor every later Declaration must
exceed, a `recovery_window` tuple restores the recovery-chain head at its
own height with the window end on it, `collection`, `record` and
`removal` tuples restore the latest Catalogs, records and removal states,
and `withdrawal` tuples the withdrawn Items (WIST-3 §§7/8). `records` is
built from the records those tuples materialize: a tier-0 row supplies
content only where its URL, Publisher and Item ID match one, other rows
are dropped, and a record with no matching row fetches its Payload;
`collection` and `generated_at` come from the `record` tuples.

Registry Updates carry four acts (WIST-4 §3). Only `aggregator_key_add`
and `aggregator_key_remove` must verify under an Aggregator key for the
Epoch to stand; a `parameter_change` replays through the accepted schedule
above, and a `payload_withdrawal`, naming an Item ID, is judged by the
replay under the Aggregator key valid at its Epoch — field, version and
authenticity failures and an Item of another Publisher are ignored with
their code — and records the withdrawn Item at the earliest Epoch that
withdrew it. A `label` or `dispute` Entry is judged by the replay under
its signer's Declaration at the Epoch (WIST-2 §3.3); one that fails is
ignored. A Label's `delta`, an Item ID, binds it to one publication: the
Label applies only while the subject URL's record carries that Item. The
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
Labeler declares and `inform` where none does (WIST-4 §6).

## Labels through MCP

`get_labels` returns the current, unretracted, unexpired Labels sealed
about a subject by subscribed Labelers — with value, expiry, the Item ID
a Label is bound to as `delta`, treatment and the labeled domain's
disputes — and
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
one exact Snapshot of one log (WIST-3 §7) — `pack import` rejects a
pack that does not name the Snapshot the store installed; `model`
(`name`, `version`, `weights_hash`, `dim`, `quantization`, `metric` — one of
`cosine`/`dot`/`euclidean` — `source`); `vectors` (`path`, `sha256`,
`bytes`, `count`) describing a zstd-compressed JSONL file alongside the
pack, one row per vector: `{"item_id", "url", "publisher", "vector":
[f32, ...]}`. Import verifies, in order: the envelope signature, the
snapshot binding, the vectors file's hash and byte length, the row count
and every vector's length against `dim`, then imports only rows whose
`item_id`, `url` and `publisher` match a record the log materializes
(other rows are skipped and counted) — a pack with zero importable rows
is rejected outright. Imported rows are kept in `embeddings(item_id, url, publisher,
vector)`; a later sync that withdraws an Item, or removes or replaces the
record carrying it, deletes its row. `similar_records` scores
against one log's imported pack; scores never merge across packs or logs,
since a pack binds one Snapshot of one log and nothing about "similar"
survives mixing two.

## MCP tools

`serve` exposes: `search` (full-text over titles/abstracts, and over Tier
1 extract text where imported, ranked by a profile), `check_coverage`,
`list_profiles`, `get_record`, `get_extract` (Tier 1 body text),
`get_links` (declared outbound links, Tier 1), `similar_records` (nearest
neighbors by an imported companion pack), `get_labels` and
`list_labelers`. A record carries `url`, `publisher`, `item_id`,
`observed_at`, `title`, `abstract`, `collection`, `attested_at`,
`generated_at` and `provenance`: the logs holding it, each with `log_id`,
`synced_height`, `unwitnessed` where that log's head was adopted with no
Cosignature from a Witness this Consumer trusts, and `halted`.

Logs combine at query time (WIST-3 §7, Several Logs). An Item has one
Item ID in every Log, so the logs holding one Item hold one record. For
one Publisher and URL the record shown is the state proved against the
latest Catalog — the later `generated_at`, then the greater Catalog ID —
among the logs holding a record or a removal state for it, the greater
Item ID deciding between states of one Catalog; where that state is a
removal, or no log materializes its record, the Publisher shows nothing
for the URL. Of the Publishers left for one URL, the URL's own host is
taken where present, then the nearest ancestor, then the least domain. A
Label bound by `delta` applies against that record. Ranking signals and
embeddings stay each log's own: a search hit is scored by each log
holding its record, the highest score kept, and `similar_records` scores
within one log.

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
resolves `wist-core` from `../core`. The `e2e` workspace member drives
real `spake` and `clave` binaries, so `../spake` and `../clave` must also be
sibling checkouts, rebuilt from their current sources on every run
(`SPAKE_BIN`/`CLAVE_BIN` override the binary paths and skip that build; set
`WIST_BUILD_PROFILE=release` to build release executables). Sites are
served from a loopback proxy and Logs seal on the default hourly cadence
grid at explicit instants (`clave seal --at`), advancing Log time by whole
hours while Catalogs keep wall-clock `generated_at` values.

`e2e/tests/e2e.rs` runs the publication pipeline end to end. Each Publisher
runs `spake init`, signs its due Catalogs (`spake publish`) and pings;
Collections other than the implicit `default` are added with `spake
collection add` once the first Declaration is sealed, and pages are
published with `spake emit --complete` over marked pages and `spake publish
--stream`. Each Aggregator pulls on the Ping, and the test waits for a pull
after it whose status lists no rejection beyond the expected ones. The
Consumer cold-starts from a Snapshot (`graven follow`) and continues with
`graven sync`; after every sync the `records` rows of each Log equal the
records the Replay resumed from the store materializes. The tests cover:

- a page published through two Logs, read over MCP with its `item_id`,
  `collection`, `attested_at` and `generated_at` and with one provenance
  entry per Log; its update, the removal of a page, an Aggregator's
  `payload_withdrawal` leaving the record seen in the other Log alone, a
  Publisher's withdrawal with `--unpublish`, an Aggregator restart, and a
  publication from a fresh environment;
- a Labeler's Labels and definition, a dispute, subscription, link
  ranking under the `default` and `text-only` profiles, a Label counting
  only once live through two consecutive Epochs, and the selected profile
  persisting;
- a Publisher key rotation and a hijacked Declaration sealed as pending,
  then reversed with `spake rotate --restore`, keeping the records;
- an Aggregator key added and the genesis key removed, the Checkpoints'
  signers at each step, a Consumer cold-started after the removal holding
  the same records as the one that followed, and a Snapshot signed by the
  removed key refused with `WIST3-E04`;
- a declared Collection sealing its emissions and refusing an Item
  outside its Scope, a narrowed Scope removing records at its Epoch while
  a reversed pending narrowing removes none, and Collection keys signing
  only their own Collection while a removed delegate key signs nothing;
- a stale Catalog and one beyond the clock refused and an equal one
  served again read as idempotent, one Catalog sealed by two Logs read as
  one record with the latest Catalog deciding between them, and a
  Publisher state directory restored from the served tree changing no
  Item;
- a Consumer resumed from a Snapshot holding a masked record and the
  replaying Consumer's `attested_at`, a retracted Label staying retracted
  against an earlier Label on both Consumer paths, a withdrawal filed with
  two Logs under one legal basis sealed by each, a change above the
  per-domain capacity sealing over several Epochs with each Entry
  verifying alone, and a recovery window queuing Catalogs of both keys
  with settlement sealing the latest survivor;
- a pull obtaining the latest list by a chain of `change_chain_max`
  change lists without fetching a tree file, and a chain missing a change
  list, or a base more than `change_chain_max` change lists behind, giving
  up the chain with `WIST2-E08` while the tree walk accepts the Catalog.

Each test validates the served artifacts against the spec's schemas and
conformance reference with `e2e/validate_artifacts.py` through
`WIST_SPEC_DIR`, requiring `jsonschema`, `rfc8785` and `cryptography` on
`PATH`'s python3 or in the spec's `tools/.venv`. The publication and
Aggregator-key tests also read the served Log with an independent client,
`e2e/tlog-client`, the latter under the verifier key of the key that
remains after the removal, built on Go's
`golang.org/x/mod/sumdb/note` and `tlog`: the head Checkpoint's signature,
the root recomputed from the tiles, an Inclusion Proof for every leaf and a
Consistency Proof from every smaller size. Either is skipped when its
toolchain is missing, or fails under `CI=1`. Each test writes a run record
under Cargo's `CARGO_TARGET_TMPDIR`, naming the scenarios it exercised and
the revision of every repository it ran.

`e2e/tests/consumer_sync.rs` drives the Consumer against an Aggregator with
no Publisher: a cold start at a Snapshot's Epoch followed by continuous
sync, a source serving an old head leaving the verified head where it is,
and a Checkpoint adopted only once a Witness in the roster has cosigned it
— with a minimal in-process Witness answering [tlog-witness]
`add-checkpoint` with a cosignature/v1 line.

The crate's `baseline` binary drives the pipeline at scale for capacity
measurements: `cargo run -p e2e --bin baseline -- --domains N --pages M
[--large-domains L --large-pages Q] [--changed-percent P] [--body-words W]
[--extra-empty-seals K] [--snapshot-shards S] [--compare-rebuild]
[--withdraw] [--update-by chain|walk] [--tree-bound [--tree-bound-items I]]
[--work-dir DIR] [--keep] [--no-tier1] [--skip-consumer] [--out
report.json]` writes N
loopback sites of M marked pages, publishes each into its `default`
Collection, ingests them through one Aggregator behind a request-counting
proxy, seals, cold-starts a Consumer, changes P percent of the pages,
publishes and seals again, seals K further empty Epochs, verifies the
history and catches the Consumer up, reporting wall seconds, bytes and
request counts per stage together with the revision of every repository it
ran. Each seal stage runs `clave seal --no-snapshot` and then `clave
snapshot` as separate processes, reporting each one's wall seconds and peak
resident set size in kB (`null` off Unix), the seconds, shard, byte and
Payload-read counters parsed from their output (`null` for a line the
executable did not print), and the sizes of the Aggregator's SQLite
database, its write-ahead log and its Snapshot directories.
`--snapshot-shards` sets the store's `snapshot_shard_count` before
ingestion (one shard otherwise). `--skip-consumer` omits the three Consumer
stages. `--compare-rebuild` adds a full Snapshot rebuild at the same head
(`clave snapshot --rebuild`) per seal stage, reported under
`snapshot_rebuild`. `--withdraw` then withdraws the Item of the first
site's first page and reports one more seal stage under `withdrawal`, with
the storage sizes before it under `before`. `--work-dir` places the
temporary directory inside DIR, and `--keep` leaves it in place and prints
its path on standard error; the report names no host, path or hardware.
`--large-domains` adds L sites of Q pages each, reported apart from the N
sites. `--update-by walk` deletes the served change lists before the
update pull, so the Aggregator walks each tree; `chain`, the default,
keeps them. `--tree-bound` adds one site whose Collection serves a
hand-built tree with buckets filled to `tree_file_cap_bytes` and I Items
(1 024 by default) held singly at `tree_depth_max`, reported under
`tree_bound`.

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
consumer of all three: WIST-1 Declarations, Catalogs, Items and Payloads,
WIST-2 site publication and Labels, and WIST-3 logbook & distribution
(sync, replay, snapshots, proofs).

## CI & releases

`.github/workflows/ci.yml` checks out `core`, `spec`, `spake`, and `clave`
from `wistprotocol/*` (sibling clones).
Release and workflow-regeneration procedures: [RELEASING.md](RELEASING.md).
