# e2e

## Sustained load

The `sustained` binary runs one sustained-load scenario against one
aggregator through the real `spake`, `clave` and `graven` executables and
reports measurements and pass/fail checks as JSON. Figures from one machine
compare with each other, not with another machine's.

```
WIST_BUILD_PROFILE=release cargo run --release -p e2e --bin sustained -- \
  --scenario <skew|backfill|hosts|saturation|drainage|memory> [flags] [--out report.json]
```

Loopback sites are served through a request-counting proxy that can delay,
refuse with `503`, hold open or close the connections of chosen hosts; a
refused, held or closed request counts as a request of 0 octets. The
aggregator runs `clave serve --no-seal`; the harness seals with
`clave seal --at <instant> --no-snapshot` followed by `clave snapshot`,
advancing the sealing instant by one 3 600 s cadence per seal (or to the
next grid instant after the wall clock, whichever is later) instead of
waiting for the cadence.

Every scenario first publishes and ingests all its sites and seals that
ingest. A round then rewrites each participating site's changed pages,
republishes the sites in parallel, pings each one in turn until admitted,
waits until every pinged domain is pulled by a pull that started after its
republish finished, and seals one Epoch. Each round
reports the seconds until all domains were pulled after the last ping, ping
refusals, site requests and octets per changed Item by domain class, the
seal's seconds and peak resident set size, the Epoch's Entries and octets
by Entry type (governance and Label Entries also apart), the aggregator's
peak resident set size over the round, and the latency of
`/status/<host>` for one healthy host sampled every 250 ms (p50, p99, max;
a failed or timed-out request counts as the 30 s client timeout, and a
round without samples fails its latency check; the ingest stage pings the
sampled host first and samples once its status exists, since the endpoint
answers 404 for a domain never pulled), over the whole round and,
as `seal_status_latency`, over its seal and Snapshot alone. Every seal
report carries `replanned`, how many times the seal re-planned because a
write changed its inputs between its plan and its commit (`replanned N
times` on `clave seal`'s standard output; 0 without the line) and
`replan_conflicts`, per discarded plan the publishers whose waiting state
changed under it (`plan conflict: a, b` lines; `<epoch>` and `<local
bounds>` name the other two inputs the check reads), and
`merged_publishers`, how many publishers' concurrent pulls the seal merged
into its plan at commit instead of re-planning (`plan merged: a, b`). Every round
also reports `seal_started_after_last_ping_seconds` and
`pulls_during_seal`, the domains whose pull completed between the seal's
start and its exit.

Every round and seal also reports `longest_write_lock_ms`: the longest hold
of the store's write lock, in milliseconds, across the aggregator
(`write lock held N ms` lines on `clave serve`'s standard error) and the
seal process (the same line on `clave seal`'s standard output) since the
previous round or seal ended; it is `null` when neither reports a hold, as
with an aggregator that prints no such line. The report's top-level
`longest_write_lock_ms` is the maximum over the whole run, extra seals
included. No check applies to it.

### Common flags

| Flag | Default | Meaning |
|---|---|---|
| `--quick` | off | Halve every size default (domains, pages, rounds, Items, record and Epoch counts), rounding up; given flags are not halved |
| `--changed-percent` | 10 (100 in `saturation`) | Share of a domain's pages changed per round |
| `--body-words` | 200 | Words per page body |
| `--round-bound-seconds` | 300 | How long a round waits for its pulls, and the pull bound its checks apply |
| `--status-bound-ms` | 500 | Bound on the status endpoint's p99 latency |
| `--labelers` | 0 (2 in `skew`) | Labeler sites, each publishing `--labels-per-round` (20) `wist:spam` Labels on random pages per round |
| `--seal-during-pulls` | off | `skew` only: start each round's seal right after its pings, while its pulls run, instead of after every pinged domain is pulled; the governance acts of the middle rounds run before that seal. Measures the seal's re-plan rate under concurrent pulls |
| `--work-dir DIR`, `--keep` | | Place, and keep, the temporary directory; a run whose data exceeds the temporary filesystem (a 200 000-page backfill writes several GB) needs a directory on disk |
| `--out PATH` | | Write the JSON report there; without it the report goes to standard output |

The report carries the scenario, the raw arguments, the resolved
`parameters`, `build_profile`, `revisions` of every repository and
`stages` (`publish`, `ingest` and one stage named after the scenario, which
holds its rounds and `checks`). Standard output gets one line per round and
one per check. The process exits with status 1 when a check fails and
prints the failing checks on standard error.

### Scenarios

**`skew`**: `--domains` 200 × `--pages` 50, `--rounds` 5. Each round the top
1 % of domains (at least one) make half the round's changed pages; they hold
as many pages as that share needs. At the middle round the aggregator queues
a `quota_base` parameter change and adds a Log key, and removes that key the
round after. Checks: every round's domains pulled within the round bound;
every seal completes within one 3 600 s cadence; status p99 under the
bound.

**`backfill`**: `--domains` 100 × `--pages` 10, `--rounds` 3 at least, plus
one domain of `--backfill-pages` 20 000 that first publishes in round 1.
Rounds continue until the backfill is sealed. The capacity is
`domain_epoch_entries_max` at its specified default, 10 000, which counts
the domain's Catalog Entry with its Items. Checks: every small domain's
changed Items seal in the Epoch right after their round; the backfill's
Items are all sealed after exactly ceil((Items + 1) / 10 000) Epochs; no
Epoch carries more than 10 000 of that domain's Entries.

**`hosts`**: `--domains` 100 × `--pages` 20, one update round after the
ingest. `--slow` 5 hosts answer after `--delay-ms` 2 000 per request,
`--failing` 5 answer `503`, `--hanging` 2 hold each connection
`--hang-seconds` 20 and close it unanswered. Every timer starts at the
round's last ping. Checks: every healthy host pulled within
`--healthy-bound-seconds` 60; each failing and hanging host shows a
`WIST2-E01` rejection dated after its republish within the round bound, and
its site is requested again without a new ping within
`--retry-wait-seconds` 150 of that rejection's first observation; status p99
under the bound; the aggregator's peak resident set size reported.

**`saturation`**: `--domains` 1 000 × `--pages` 5 ingested, plus as many
fresh sites published but never pinged. `--ping-threads` 8 send one Ping
per fresh domain as fast as they can (first-contact Pings, which the
aggregator refuses with `503` while its pending queue is full), each
refused domain pinged again after its `Retry-After`. The same flood then
repeats for the ingested sites after every page changed (a Ping for a domain
the aggregator already pulled joins that domain's schedule and is not
refused). Then a local `epoch_cap_bytes` bound (`clave bound`) of a sixth of
the estimated pending octets, at least the 65 537 floor, spreads both floods'
Entries over several Epochs, sealed until one comes out empty. Checks: the
first-contact flood is refused at least once and every refused domain is
admitted on a later Ping; every domain of both floods pulled within the
round bound; at least five Epochs carry the Entries; every Epoch's octets
(each Entry's JCS serialization plus two) within the bound; each
first-contact and changed Item and each domain's Catalog sealed exactly
once; status p99 under the bound during the seals.

**`drainage`**: `--domains` 100 × `--pages` 20; `--steady-rounds` 2, then
the aggregator stops for `--outage-rounds` 3 rounds in which sites
republish and their pings fail, then restarts, every domain is pinged again
and `--recovery-rounds` 3 follow. Checks: no Ping admitted during the
outage; every domain pulled within outage rounds × the mean steady round's
seconds of the restart; each recovery round's changed Items sealed in the
Epoch right after it; status p99 under the bound. The first recovery round's
report carries `backlog_overlap`, since backlog pulls inflate its request
and per-Item figures.

**`memory`**: one fresh Log per cell of `--records` 1000,10000 ×
`--epochs` 1,20, the records spread over `--domains-per-cell` 100 domains
plus one 10-page probe domain. After the ingest and the extra empty Epochs
it measures the aggregator's peak over one update pull of the probe domain,
the peak of one empty seal, of one `clave snapshot` of the unchanged state
and of a Consumer cold start, then restarts the aggregator and reports a
second probe pull's peak beside the resident size it started from. Checks:
the probe pull's increase (peak minus the resident size before the pull) at
the most records at most 1.5 × its increase at the fewest, per Epoch count; the empty
seal's peak at the most Epochs at most 1.1 × at the fewest, per record
count.

### Smoke runs

```
for scenario in skew backfill hosts saturation drainage memory; do
  WIST_BUILD_PROFILE=release cargo run --release -p e2e --bin sustained -- \
    --scenario "$scenario" --quick --out "sustained-$scenario.json"
done
```
