use e2e::{
    after_this_second, change_parameter, consumer_report, fetch_status, graven_bin, host_name,
    label_command, log_entries_report, log_keys, log_tree_size, now_rfc3339, peak_rss_kb,
    ping_once, ping_until_admitted, poll_until, pulled_each_since, pulled_within, requests_report,
    reset_peak_rss, resolve_sibling_bin, revisions, round_report, run, run_measured, s,
    serve_sites_with_behaviors, snapshot_report, start_aggregator, sync_args, timed,
    wait_until_after, write_changed_pages, write_pages, Aggregator, AppendedText, Behaviors,
    Failure, HostBehavior, PingOutcome, RequestLog, SealStage, Site, SiteCounters, WRITE_LOCK_HELD,
};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const CADENCE_SECONDS: i64 = 3600;
// WIST-3 §3.2: `domain_epoch_entries_max` defaults to 10 000; the aggregator serves no endpoint
// stating the parameters in force.
const DOMAIN_EPOCH_ENTRIES_DEFAULT: usize = 10_000;
// WIST-3 §3.2: `labeler_epoch_entries_max` defaults to 1 000 Label and dispute Entries per
// Labeler per Epoch.
const LABELER_EPOCH_ENTRIES_DEFAULT: usize = 1000;
// WIST-4 §5: the Parameter Registry floor of `epoch_cap_bytes`.
const EPOCH_CAP_FLOOR: u64 = 65_537;
const PROBE_PAGES: usize = 10;
const RATIO_FLOOR_KB: u64 = 8192;
const STATUS_TIMEOUT: Duration = Duration::from_secs(30);
// WIST-4 §5: a parameter change's effective_at is at least `param_grace_days` (default 7) after
// the sealed_at of the Epoch sealing it.
const PARAM_GRACE_SECONDS: i64 = 7 * 86_400;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scenario {
    Skew,
    Backfill,
    Hosts,
    Saturation,
    Drainage,
    Memory,
}

impl Scenario {
    fn parse(value: &str) -> Self {
        match value {
            "skew" => Scenario::Skew,
            "backfill" => Scenario::Backfill,
            "hosts" => Scenario::Hosts,
            "saturation" => Scenario::Saturation,
            "drainage" => Scenario::Drainage,
            "memory" => Scenario::Memory,
            other => panic!(
                "--scenario takes skew, backfill, hosts, saturation, drainage or memory, not {other}"
            ),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Scenario::Skew => "skew",
            Scenario::Backfill => "backfill",
            Scenario::Hosts => "hosts",
            Scenario::Saturation => "saturation",
            Scenario::Drainage => "drainage",
            Scenario::Memory => "memory",
        }
    }
}

#[derive(Default)]
struct Args {
    scenario: Option<Scenario>,
    quick: bool,
    seal_during_pulls: bool,
    domains: Option<usize>,
    pages: Option<usize>,
    rounds: Option<usize>,
    changed_percent: Option<usize>,
    body_words: Option<usize>,
    round_bound_seconds: Option<u64>,
    status_bound_ms: Option<f64>,
    labelers: Option<usize>,
    labels_per_round: Option<usize>,
    backfill_pages: Option<usize>,
    slow: Option<usize>,
    delay_ms: Option<u64>,
    failing: Option<usize>,
    hanging: Option<usize>,
    hang_seconds: Option<u64>,
    healthy_bound_seconds: Option<u64>,
    retry_wait_seconds: Option<u64>,
    ping_threads: Option<usize>,
    steady_rounds: Option<usize>,
    outage_rounds: Option<usize>,
    recovery_rounds: Option<usize>,
    records: Option<Vec<usize>>,
    epochs: Option<Vec<usize>>,
    labels: Option<Vec<usize>>,
    domains_per_cell: Option<usize>,
    work_dir: Option<PathBuf>,
    keep: bool,
    out: Option<PathBuf>,
}

fn list(value: &str, flag: &str) -> Vec<usize> {
    value
        .split(',')
        .map(|part| {
            part.trim()
                .parse()
                .unwrap_or_else(|_| panic!("{flag} takes a comma list of counts"))
        })
        .collect()
}

fn args() -> Args {
    parse_args(std::env::args().skip(1))
}

fn parse_args(flags: impl IntoIterator<Item = String>) -> Args {
    let mut args = Args::default();
    let mut it = flags.into_iter();
    while let Some(flag) = it.next() {
        let mut value = || it.next().unwrap_or_else(|| panic!("{flag} needs a value"));
        macro_rules! number {
            ($field:ident) => {
                args.$field = Some(value().parse().expect(&flag))
            };
        }
        match flag.as_str() {
            "--scenario" => args.scenario = Some(Scenario::parse(&value())),
            "--quick" => args.quick = true,
            "--seal-during-pulls" => args.seal_during_pulls = true,
            "--domains" => number!(domains),
            "--pages" => number!(pages),
            "--rounds" => number!(rounds),
            "--changed-percent" => number!(changed_percent),
            "--body-words" => number!(body_words),
            "--round-bound-seconds" => number!(round_bound_seconds),
            "--status-bound-ms" => number!(status_bound_ms),
            "--labelers" => number!(labelers),
            "--labels-per-round" => number!(labels_per_round),
            "--backfill-pages" => number!(backfill_pages),
            "--slow" => number!(slow),
            "--delay-ms" => number!(delay_ms),
            "--failing" => number!(failing),
            "--hanging" => number!(hanging),
            "--hang-seconds" => number!(hang_seconds),
            "--healthy-bound-seconds" => number!(healthy_bound_seconds),
            "--retry-wait-seconds" => number!(retry_wait_seconds),
            "--ping-threads" => number!(ping_threads),
            "--steady-rounds" => number!(steady_rounds),
            "--outage-rounds" => number!(outage_rounds),
            "--recovery-rounds" => number!(recovery_rounds),
            "--records" => args.records = Some(list(&value(), "--records")),
            "--epochs" => args.epochs = Some(list(&value(), "--epochs")),
            "--labels" => args.labels = Some(list(&value(), "--labels")),
            "--domains-per-cell" => number!(domains_per_cell),
            "--work-dir" => args.work_dir = Some(PathBuf::from(value())),
            "--keep" => args.keep = true,
            "--out" => args.out = Some(PathBuf::from(value())),
            other => panic!("unknown flag {other}"),
        }
    }
    args
}

impl Args {
    fn scenario(&self) -> Scenario {
        self.scenario
            .unwrap_or_else(|| panic!("--scenario is required"))
    }

    fn size(&self, given: Option<usize>, default: usize) -> usize {
        given.unwrap_or(if self.quick {
            default.div_ceil(2)
        } else {
            default
        })
    }

    fn sizes(&self, given: &Option<Vec<usize>>, default: &[usize]) -> Vec<usize> {
        given.clone().unwrap_or_else(|| {
            default
                .iter()
                .map(|&value| self.size(None, value))
                .collect()
        })
    }

    fn body_words(&self) -> usize {
        self.body_words.unwrap_or(200)
    }

    fn changed_percent(&self, default: usize) -> usize {
        self.changed_percent.unwrap_or(default)
    }

    fn round_bound(&self) -> Duration {
        Duration::from_secs(self.round_bound_seconds.unwrap_or(300))
    }

    fn status_bound_ms(&self) -> f64 {
        self.status_bound_ms.unwrap_or(500.0)
    }

    fn labels_per_round(&self) -> usize {
        self.labels_per_round.unwrap_or(20)
    }
}

struct Bins {
    spake: PathBuf,
    clave: PathBuf,
    graven: PathBuf,
}

struct Check {
    name: String,
    pass: bool,
    observed: Value,
    bound: String,
}

impl Check {
    fn new(name: &str, pass: bool, observed: Value, bound: impl Into<String>) -> Self {
        Check {
            name: name.into(),
            pass,
            observed,
            bound: bound.into(),
        }
    }

    fn report(&self) -> Value {
        json!({
            "name": self.name,
            "pass": self.pass,
            "observed": self.observed,
            "bound": self.bound,
        })
    }
}

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407)
            | 1)
    }

    fn below(&mut self, bound: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 % bound as u64) as usize
    }
}

struct Clock {
    last: Option<i64>,
}

impl Clock {
    fn peek_at(&self, now: i64) -> i64 {
        let next_hour = now.div_euclid(CADENCE_SECONDS) * CADENCE_SECONDS + CADENCE_SECONDS;
        self.last
            .map_or(next_hour, |last| (last + CADENCE_SECONDS).max(next_hour))
    }

    fn next_at(&mut self, now: i64) -> i64 {
        let at = self.peek_at(now);
        self.last = Some(at);
        at
    }

    fn effective_after_grace(&self, now: i64) -> i64 {
        self.peek_at(now) + PARAM_GRACE_SECONDS + CADENCE_SECONDS
    }

    fn next(&mut self) -> String {
        instant(self.next_at(jiff::Timestamp::now().as_second()))
    }

    fn skip(&mut self, cadences: usize) {
        if let Some(last) = self.last.as_mut() {
            *last += CADENCE_SECONDS * cadences as i64;
        }
    }
}

fn instant(unix: i64) -> String {
    jiff::Timestamp::from_second(unix)
        .expect("a sealing instant is in range")
        .to_string()
}

fn percentile(sorted: &[f64], p: f64) -> Option<f64> {
    if sorted.is_empty() {
        return None;
    }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    Some(sorted[rank.clamp(1, sorted.len()) - 1])
}

fn latency_report(mut samples: Vec<f64>, errors: u64) -> Value {
    samples.sort_by(f64::total_cmp);
    json!({
        "samples": samples.len(),
        "errors": errors,
        "p50_ms": percentile(&samples, 50.0),
        "p99_ms": percentile(&samples, 99.0),
        "max_ms": samples.last(),
    })
}

struct StatusSampler {
    stop: Arc<AtomicBool>,
    handle: std::thread::JoinHandle<(Vec<f64>, u64)>,
}

impl StatusSampler {
    fn start(base: &str, host: &str) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let url = format!("{base}/status/{host}");
        let handle = std::thread::spawn(move || {
            let http = reqwest::blocking::Client::builder()
                .timeout(STATUS_TIMEOUT)
                .build()
                .expect("status client");
            let mut samples = Vec::new();
            let mut errors = 0;
            while !stopped.load(Ordering::Relaxed) {
                let start = Instant::now();
                match http.get(&url).send() {
                    Ok(response) if response.status().is_success() => {
                        let _ = response.bytes();
                        samples.push(start.elapsed().as_secs_f64() * 1000.0);
                    }
                    _ => {
                        errors += 1;
                        samples.push(STATUS_TIMEOUT.as_secs_f64() * 1000.0);
                    }
                }
                std::thread::sleep(Duration::from_millis(250));
            }
            (samples, errors)
        });
        StatusSampler { stop, handle }
    }

    fn finish(self) -> Value {
        self.stop.store(true, Ordering::Relaxed);
        let (samples, errors) = self.handle.join().expect("status sampler");
        latency_report(samples, errors)
    }
}

fn parallel<T: Sync>(items: &[T], work: impl Fn(&T) + Sync) {
    let workers = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(4)
        .min(items.len().max(1));
    let next = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some(item) = items.get(i) else { break };
                work(item);
            });
        }
    });
}

fn changed_indices(count: usize, pages: usize, round: usize) -> Vec<usize> {
    (0..count.min(pages))
        .map(|j| (round * count + j) % pages)
        .collect()
}

fn changed_count(pages: usize, percent: usize) -> usize {
    (pages * percent).div_ceil(100)
}

struct Participant<'a> {
    site: &'a Site,
    changed: Vec<usize>,
    items: usize,
}

struct Sealed {
    report: Value,
    entries: Vec<Value>,
    seconds: f64,
    wall_seconds: f64,
    octets: u64,
    longest_write_lock_ms: Option<u64>,
}

struct SealRun {
    at: String,
    started: Instant,
    thread: std::thread::JoinHandle<SealStage>,
}

fn epoch_octets(entries: &[Value]) -> u64 {
    entries
        .iter()
        .map(|entry| {
            wist_core::jcs::canonicalize(entry)
                .map(|octets| octets.len() as u64)
                .unwrap_or(0)
                + 2
        })
        .sum()
}

fn governance_and_labels(log_entries: &Value) -> Value {
    Value::Object(
        log_entries
            .as_object()
            .into_iter()
            .flatten()
            .filter(|(key, _)| {
                !key.starts_with("publisher_") && !["all", "from", "to"].contains(&key.as_str())
            })
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    )
}

fn entry_host(entry: &Value) -> Option<&str> {
    match entry["type"].as_str()? {
        "publisher_catalog" => entry["body"]["catalog"]["publisher"].as_str(),
        "publisher_item" => entry["body"]["item"]["publisher"].as_str(),
        "label" => entry["body"]["label"]["labeler"].as_str(),
        _ => None,
    }
}

fn item_ids(entries: &[Value]) -> BTreeSet<String> {
    entries
        .iter()
        .filter(|entry| entry["type"] == "publisher_item")
        .filter_map(|entry| wist_core::item::item_id(&entry["body"]["item"]).ok())
        .collect()
}

struct Harness {
    bins: Arc<Bins>,
    proxy: String,
    requests: RequestLog,
    counters: BTreeMap<String, SiteCounters>,
    behaviors: Behaviors,
    aggregator: Aggregator,
    http: reqwest::blocking::Client,
    clock: Clock,
    sealed: u64,
    body_words: usize,
    round_bound: Duration,
    seal_during_pulls: bool,
    serve_stderr: AppendedText,
    longest_write_lock_ms: Option<u64>,
}

struct RoundStart {
    started: Instant,
    since: String,
    sampler: StatusSampler,
}

impl Harness {
    fn start(bins: &Arc<Bins>, root: &Path, sites: &[&Site], args: &Args) -> Self {
        let (proxy_addr, counters, requests, behaviors) = serve_sites_with_behaviors(
            sites
                .iter()
                .map(|site| (site.host.clone(), site.out.clone()))
                .collect(),
        );
        let proxy = format!("http://{proxy_addr}");
        let aggregator = start_aggregator(&bins.clave, root.join("clave-data"), None, Some(&proxy));
        let serve_stderr = AppendedText::new(&aggregator.stderr);
        Harness {
            bins: bins.clone(),
            proxy,
            requests,
            counters,
            behaviors,
            aggregator,
            http: reqwest::blocking::Client::new(),
            clock: Clock { last: None },
            sealed: 0,
            body_words: args.body_words(),
            round_bound: args.round_bound(),
            seal_during_pulls: args.seal_during_pulls,
            serve_stderr,
            longest_write_lock_ms: None,
        }
    }

    fn write_lock_window(&mut self, seal_stdout: Option<&str>) -> Option<u64> {
        let serve = self.serve_stderr.follow(&self.aggregator.stderr);
        let longest = [Some(serve.as_str()), seal_stdout]
            .into_iter()
            .flatten()
            .filter_map(|text| e2e::longest_reported_millis(text, WRITE_LOCK_HELD))
            .max();
        self.longest_write_lock_ms = self.longest_write_lock_ms.max(longest);
        longest
    }

    fn run_longest_write_lock_ms(&mut self) -> Option<u64> {
        self.write_lock_window(None);
        self.longest_write_lock_ms
    }

    fn base(&self) -> &str {
        &self.aggregator.base_url
    }

    fn pid(&self) -> u32 {
        self.aggregator.pid().expect("the aggregator is running")
    }

    fn begin(&self, status_host: &str) -> RoundStart {
        self.requests.clear();
        reset_peak_rss(self.pid());
        let since = after_this_second();
        RoundStart {
            started: Instant::now(),
            since,
            sampler: StatusSampler::start(self.base(), status_host),
        }
    }

    fn publish(&self, participants: &[Participant], revision: u64) -> (f64, Since) {
        let spake = &self.bins.spake;
        let body_words = self.body_words;
        let finished = Mutex::new(Since::new());
        let ((), seconds) = timed(|| {
            parallel(participants, |participant| {
                write_changed_pages(participant.site, &participant.changed, body_words, revision);
                participant.site.publish(spake);
                finished
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(participant.site.host.clone(), now_rfc3339());
            })
        });
        (
            seconds,
            finished.into_inner().unwrap_or_else(|e| e.into_inner()),
        )
    }

    fn ping_all(&self, hosts: &[String]) -> (u64, f64) {
        let mut refused = 0;
        let ((), seconds) = timed(|| {
            for host in hosts {
                refused += ping_until_admitted(&self.bins.spake, self.base(), host);
            }
        });
        (refused, seconds)
    }

    fn seal_start(&mut self) -> SealRun {
        let at = self.clock.next();
        let bins = self.bins.clone();
        let data = self.aggregator.data.clone();
        let seal_at = at.clone();
        let thread =
            std::thread::spawn(move || SealStage::run(&bins.clave, &data, &seal_at, false));
        SealRun {
            at,
            started: Instant::now(),
            thread,
        }
    }

    fn seal_finish(&mut self, run: SealRun) -> Sealed {
        let stage = run.thread.join().expect("the seal thread panicked");
        let at = run.at;
        let data = self.aggregator.data.clone();
        let longest_write_lock_ms = self.write_lock_window(Some(&stage.seal.stdout));
        let mut report = stage.report(&data);
        report["longest_write_lock_ms"] = json!(longest_write_lock_ms);
        let size = log_tree_size(&data);
        let entries: Vec<Value> = e2e::entry_leaves(&data, self.sealed, size)
            .iter()
            .map(|leaf| serde_json::from_slice(leaf).unwrap_or(Value::Null))
            .collect();
        let log_entries = log_entries_report(&data, self.sealed, size);
        report["at"] = json!(at);
        report["governance_and_label_entries"] = governance_and_labels(&log_entries);
        report["log_entries"] = log_entries;
        let octets = epoch_octets(&entries);
        report["epoch_octets"] = json!(octets);
        self.sealed = size;
        Sealed {
            report,
            entries,
            seconds: stage.seal_seconds().unwrap_or(stage.seal.seconds),
            wall_seconds: stage.seal.seconds,
            octets,
            longest_write_lock_ms,
        }
    }

    fn seal(&mut self) -> Sealed {
        let run = self.seal_start();
        self.seal_finish(run)
    }

    fn label(
        &self,
        labelers: &[Site],
        subjects: &[String],
        per_labeler: usize,
        seed: u64,
    ) -> (usize, Since) {
        let mut rng = Rng::new(seed);
        let mut issued = 0;
        let mut finished = Since::new();
        for labeler in labelers {
            issued += issue_labels(
                &self.bins.spake,
                labeler,
                subjects,
                per_labeler.min(subjects.len()),
                &mut rng,
            );
            finished.insert(labeler.host.clone(), now_rfc3339());
        }
        (issued, finished)
    }
}

fn issue_labels(
    spake: &Path,
    labeler: &Site,
    subjects: &[String],
    count: usize,
    rng: &mut Rng,
) -> usize {
    let mut issued = BTreeSet::new();
    while issued.len() < count && !subjects.is_empty() {
        let mut chosen = BTreeSet::new();
        while chosen.len() < (count - issued.len()).min(subjects.len()) {
            chosen.insert(rng.below(subjects.len()));
        }
        for subject in chosen {
            let value = loop {
                let value = rng.below(1_000_001);
                if issued.insert((subject, value)) {
                    break value;
                }
            };
            label_command(
                spake,
                labeler,
                &[
                    "--subject",
                    &subjects[subject],
                    "--name",
                    "wist:spam",
                    "--value",
                    &value.to_string(),
                ],
            );
        }
    }
    issued.len()
}

type Since = BTreeMap<String, String>;

fn settle(since: &Since) {
    if let Some(latest) = since.values().max() {
        wait_until_after(latest);
    }
}

struct Plan<'a> {
    participants: Vec<Participant<'a>>,
    classes: Vec<(&'static str, Vec<String>, usize)>,
    labelers: &'a [Site],
    subjects: &'a [String],
    labels_per_round: usize,
}

struct RoundOutcome {
    report: Value,
    sealed: Sealed,
    pulled: BTreeMap<String, f64>,
    expected: Vec<String>,
    seconds: f64,
    status_p99_ms: Option<f64>,
}

impl RoundOutcome {
    fn unpulled(&self) -> usize {
        self.expected
            .iter()
            .filter(|host| !self.pulled.contains_key(*host))
            .count()
    }

    fn pulled_seconds(&self) -> f64 {
        self.pulled.values().copied().fold(0.0, f64::max)
    }
}

fn run_round(
    h: &mut Harness,
    label: &str,
    plan: &Plan,
    revision: u64,
    status_host: &str,
    before_seal: impl FnOnce(&mut Harness) -> Value,
) -> RoundOutcome {
    let round = h.begin(status_host);
    let (publish_seconds, mut since) = h.publish(&plan.participants, revision);
    let (labels, labeled) = h.label(
        plan.labelers,
        plan.subjects,
        plan.labels_per_round,
        revision.wrapping_mul(7919),
    );
    let mut hosts: Vec<String> = plan
        .participants
        .iter()
        .map(|participant| participant.site.host.clone())
        .collect();
    if labels > 0 {
        hosts.extend(plan.labelers.iter().map(|labeler| labeler.host.clone()));
        since.extend(labeled);
    }
    settle(&since);
    let (refused, ping_seconds) = h.ping_all(&hosts);
    let pinged = Instant::now();
    let mut before_seal = Some(before_seal);
    let mut governance = Value::Null;
    let mut seal = None;
    if h.seal_during_pulls {
        governance = before_seal.take().expect("the governance step runs once")(h);
        seal = Some((StatusSampler::start(h.base(), status_host), h.seal_start()));
    }
    let pull_origin = pinged.elapsed().as_secs_f64();
    let pulled = pulled_each_since(&h.http, h.base(), &since, h.round_bound);
    let aggregator_peak = peak_rss_kb(h.pid());
    if let Some(before_seal) = before_seal.take() {
        governance = before_seal(h);
    }
    let (seal_sampler, seal_run) =
        seal.unwrap_or_else(|| (StatusSampler::start(h.base(), status_host), h.seal_start()));
    let seal_started = seal_run.started.duration_since(pinged).as_secs_f64();
    let sealed = h.seal_finish(seal_run);
    let seal_status = seal_sampler.finish();
    let pulls_during_seal = pulled
        .values()
        .map(|seconds| seconds + pull_origin)
        .filter(|&at| at >= seal_started && at <= seal_started + sealed.wall_seconds)
        .count();
    let seconds = round.started.elapsed().as_secs_f64();
    let status = round.sampler.finish();
    let rejected: Vec<Option<usize>> = hosts
        .iter()
        .map(|host| {
            fetch_status(&h.http, h.base(), host)
                .map(|status| rejections_after(&status, &round.since))
        })
        .collect();
    let requests = h.requests.requests();
    let changed: usize = plan.participants.iter().map(|p| p.items).sum();
    let mut by_class = serde_json::Map::new();
    for (class, class_hosts, items) in &plan.classes {
        by_class.insert(
            class.to_string(),
            round_report(&requests, class_hosts, *items, &pulled),
        );
    }
    if labels > 0 {
        let labeler_hosts: Vec<String> = plan.labelers.iter().map(|l| l.host.clone()).collect();
        by_class.insert(
            "labelers".into(),
            round_report(&requests, &labeler_hosts, labels, &pulled),
        );
    }
    let mut report = requests_report(&requests, &hosts, changed + labels);
    let outcome_report = json!({
        "round": label,
        "participating_domains": hosts.len(),
        "changed_items": changed,
        "labels": labels,
        "publish_seconds": publish_seconds,
        "ping_seconds": ping_seconds,
        "pings_refused": refused,
        "seconds_until_all_pulled": pulled.values().copied().fold(0.0, f64::max),
        "unpulled_domains": hosts.iter().filter(|host| !pulled.contains_key(*host)).count(),
        "by_class": by_class,
        "aggregator_peak_rss_kb": aggregator_peak,
        "status_latency": status,
        "seal_status_latency": seal_status,
        "governance": governance,
        "seal_started_after_last_ping_seconds": seal_started,
        "pulls_during_seal": pulls_during_seal,
        "rejected_pulls": rejected.iter().flatten().sum::<usize>(),
        "domains_rejected": rejected.iter().flatten().filter(|&&count| count > 0).count(),
        "rejection_status_unread": rejected.iter().filter(|count| count.is_none()).count(),
        "seal": sealed.report,
        "longest_write_lock_ms": sealed.longest_write_lock_ms,
        "seconds": seconds,
    });
    e2e::merge(&mut report, outcome_report);
    let status_p99_ms = report["status_latency"]["p99_ms"].as_f64();
    let sealed = Sealed {
        report: report["seal"].clone(),
        ..sealed
    };
    let outcome = RoundOutcome {
        report,
        sealed,
        pulled,
        expected: hosts,
        seconds,
        status_p99_ms,
    };
    println!("{}", summary(label, &outcome));
    outcome
}

fn summary(label: &str, outcome: &RoundOutcome) -> String {
    let report = &outcome.report;
    let entries = &report["seal"]["log_entries"]["all"];
    format!(
        "round {label}: {} items in {} domains, pulled in {:.1} s ({} unpulled), {} pings refused, seal {:.2} s at {} kB replanned {} with {} pulls during it, Epoch {} entries {} octets, aggregator {} kB, status p99 {} ms, {} rejected pulls in {} domains",
        report["changed_items"],
        report["participating_domains"],
        outcome.pulled_seconds(),
        outcome.unpulled(),
        report["pings_refused"],
        outcome.sealed.seconds,
        report["seal"]["seal_peak_rss_kb"],
        report["seal"]["replanned"],
        report["pulls_during_seal"],
        entries["entries"],
        entries["octets"],
        report["aggregator_peak_rss_kb"],
        outcome
            .status_p99_ms
            .map_or("n/a".to_string(), |ms| format!("{ms:.1}")),
        report["rejected_pulls"],
        report["domains_rejected"],
    )
}

fn over_rounds(outcomes: &[RoundOutcome]) -> (Value, u64) {
    let peaks: Vec<u64> = outcomes
        .iter()
        .filter_map(|outcome| outcome.report["aggregator_peak_rss_kb"].as_u64())
        .collect();
    let mean = (!peaks.is_empty()).then(|| peaks.iter().sum::<u64>() as f64 / peaks.len() as f64);
    let rejected = outcomes
        .iter()
        .filter_map(|outcome| outcome.report["rejected_pulls"].as_u64())
        .sum();
    (
        json!({
            "min": peaks.iter().min(),
            "max": peaks.iter().max(),
            "mean": mean,
        }),
        rejected,
    )
}

fn stage_over_rounds(scenario: &str, stage: &mut Value, outcomes: &[RoundOutcome]) {
    let (peaks, rejected) = over_rounds(outcomes);
    println!(
        "{scenario}: aggregator peak over rounds min {} kB, max {} kB, mean {} kB, {rejected} rejected pulls",
        peaks["min"],
        peaks["max"],
        peaks["mean"].as_f64().map_or("n/a".to_string(), |kb| format!("{kb:.0}")),
    );
    stage["aggregator_peak_rss_kb_over_rounds"] = peaks;
    stage["rejected_pulls_total"] = json!(rejected);
}

impl Harness {
    fn establish(
        &mut self,
        sites: &[&Site],
        labelers: &[Site],
        status_host: &str,
        report: &mut Value,
    ) {
        let spake = self.bins.spake.clone();
        let ((), publish_seconds) = timed(|| {
            parallel(sites, |site| {
                site.init(&spake);
                site.publish(&spake);
            });
            parallel(labelers, |labeler| {
                labeler.init(&spake);
                labeler.publish(&spake);
            });
        });
        report["stages"]["publish"] = json!({
            "seconds": publish_seconds,
            "domains": sites.len(),
            "labelers": labelers.len(),
        });
        self.requests.clear();
        reset_peak_rss(self.pid());
        let since = after_this_second();
        let started = Instant::now();
        let hosts: Vec<String> = std::iter::once(status_host.to_string())
            .chain(
                sites
                    .iter()
                    .map(|site| site.host.clone())
                    .filter(|host| host != status_host),
            )
            .chain(labelers.iter().map(|labeler| labeler.host.clone()))
            .collect();
        let (first_refused, first_seconds) = self.ping_all(&hosts[..1]);
        poll_until(
            Duration::from_secs(3600),
            Duration::from_millis(100),
            || fetch_status(&self.http, self.base(), status_host).map(|_| ()),
        );
        let round = RoundStart {
            started,
            since,
            sampler: StatusSampler::start(self.base(), status_host),
        };
        let (rest_refused, rest_seconds) = self.ping_all(&hosts[1..]);
        let (refused, ping_seconds) = (first_refused + rest_refused, first_seconds + rest_seconds);
        let pulled = pulled_within(
            &self.http,
            self.base(),
            &hosts,
            &round.since,
            Duration::from_secs(3600),
        );
        assert_eq!(
            pulled.len(),
            hosts.len(),
            "the first ingest left domains unpulled"
        );
        let aggregator_peak = peak_rss_kb(self.pid());
        let sealed = self.seal();
        let status = round.sampler.finish();
        let items = sites.iter().map(|site| site.served_list().len()).sum();
        let mut ingest = round_report(&self.requests.requests(), &hosts, items, &pulled);
        e2e::merge(
            &mut ingest,
            json!({
                "ping_seconds": ping_seconds,
                "pings_refused": refused,
                "aggregator_peak_rss_kb": aggregator_peak,
                "status_latency": status,
                "seal": sealed.report,
                "longest_write_lock_ms": sealed.longest_write_lock_ms,
                "seconds": round.started.elapsed().as_secs_f64(),
            }),
        );
        println!(
            "ingest: {} domains pulled in {:.1} s, seal {:.2} s",
            hosts.len(),
            pulled.values().copied().fold(0.0, f64::max),
            sealed.seconds
        );
        report["stages"]["ingest"] = ingest;
    }
}

impl Harness {
    fn label_and_seal(&mut self, labelers: &[Site], subjects: &[String], labels: usize) -> Value {
        let spake = self.bins.spake.clone();
        let work: Vec<(&Site, usize, u64)> = labelers
            .iter()
            .zip(spread(labels, labelers.len(), 0))
            .zip(1..)
            .map(|((labeler, count), seed)| (labeler, count, seed))
            .collect();
        let issued = AtomicUsize::new(0);
        let finished = Mutex::new(Since::new());
        let ((), label_seconds) = timed(|| {
            parallel(&work, |&(labeler, count, seed)| {
                let done = issue_labels(&spake, labeler, subjects, count, &mut Rng::new(seed));
                issued.fetch_add(done, Ordering::Relaxed);
                finished
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(labeler.host.clone(), now_rfc3339());
            })
        });
        let since = finished.into_inner().unwrap_or_else(|e| e.into_inner());
        settle(&since);
        let hosts: Vec<String> = labelers
            .iter()
            .map(|labeler| labeler.host.clone())
            .collect();
        let (refused, ping_seconds) = self.ping_all(&hosts);
        let pulled = pulled_each_since(&self.http, self.base(), &since, Duration::from_secs(3600));
        assert_eq!(
            pulled.len(),
            hosts.len(),
            "the labelers' pulls left domains unpulled or rejected"
        );
        let issued = issued.into_inner();
        let most_per_labeler = work.iter().map(|&(_, count, _)| count).max().unwrap_or(0);
        let epoch_bound = most_per_labeler.div_ceil(LABELER_EPOCH_ENTRIES_DEFAULT) + 1;
        let mut seals = Vec::new();
        let mut labels_sealed = 0;
        let mut longest_write_lock_ms = None;
        while (labels_sealed as usize) < issued && seals.len() < epoch_bound {
            let sealed = self.seal();
            labels_sealed += sealed.report["log_entries"]["label"]["entries"]
                .as_u64()
                .unwrap_or(0);
            longest_write_lock_ms = longest_write_lock_ms.max(sealed.longest_write_lock_ms);
            seals.push(sealed.report);
        }
        assert_eq!(
            labels_sealed as usize, issued,
            "the Labels did not seal within {epoch_bound} Epochs"
        );
        json!({
            "labels": issued,
            "label_seconds": label_seconds,
            "ping_seconds": ping_seconds,
            "pings_refused": refused,
            "seconds_until_all_pulled": pulled.values().copied().fold(0.0, f64::max),
            "labels_sealed": labels_sealed,
            "label_epochs": seals.len(),
            "seals": seals,
            "longest_write_lock_ms": longest_write_lock_ms,
        })
    }
}

fn make_sites(root: &Path, offset: usize, count: usize) -> Vec<Site> {
    (offset..offset + count)
        .map(|i| Site::new(root, &host_name(i), "default"))
        .collect()
}

fn hosts_of(sites: &[&Site]) -> Vec<String> {
    sites.iter().map(|site| site.host.clone()).collect()
}

fn page_urls(site: &Site, pages: usize) -> impl Iterator<Item = String> + '_ {
    (0..pages).map(move |j| site.url(&format!("p{j}.html")))
}

fn expected_item_ids(participants: &[Participant]) -> BTreeSet<String> {
    participants
        .iter()
        .flat_map(|participant| {
            participant.changed.iter().map(|j| {
                participant
                    .site
                    .item_id(&participant.site.url(&format!("p{j}.html")))
            })
        })
        .collect()
}

fn max_f64(values: impl IntoIterator<Item = f64>) -> Option<f64> {
    values.into_iter().reduce(f64::max)
}

fn seal_check(outcomes: &[&RoundOutcome]) -> Check {
    let longest = max_f64(outcomes.iter().map(|outcome| outcome.sealed.seconds));
    Check::new(
        "seals_complete_within_one_cadence",
        longest.is_some_and(|seconds| seconds <= CADENCE_SECONDS as f64),
        json!({ "max_seal_seconds": longest }),
        "every seal completes within one cadence, 3 600 s (meta ADR-0005, Targets, freshness: a pulled Delta seals in the next Epoch)",
    )
}

fn status_check(name: &str, p99s: &[Option<f64>], bound_ms: f64) -> Check {
    let worst = max_f64(p99s.iter().flatten().copied());
    let without = p99s.iter().filter(|p99| p99.is_none()).count();
    Check::new(
        name,
        without == 0 && worst.is_some_and(|ms| ms < bound_ms),
        json!({ "max_round_p99_ms": worst, "rounds_without_p99": without }),
        format!(
            "status endpoint p99 < {bound_ms} ms in every round, a failed or timed-out request counting as {} ms",
            STATUS_TIMEOUT.as_millis()
        ),
    )
}

fn pulled_check(name: &str, outcomes: &[&RoundOutcome], bound: Duration) -> Check {
    let unpulled: usize = outcomes.iter().map(|outcome| outcome.unpulled()).sum();
    let slowest = max_f64(outcomes.iter().map(|outcome| outcome.pulled_seconds()));
    Check::new(
        name,
        unpulled == 0 && slowest.is_some_and(|seconds| seconds <= bound.as_secs_f64()),
        json!({ "max_seconds_until_all_pulled": slowest, "unpulled_domains": unpulled }),
        format!(
            "every participating domain pulled within {} s of its round's last ping",
            bound.as_secs()
        ),
    )
}

struct SkewPlan {
    heavy: usize,
    heavy_pages: usize,
    counts: Vec<usize>,
}

fn spread(total: usize, slots: usize, round: usize) -> Vec<usize> {
    if slots == 0 {
        return Vec::new();
    }
    let (base, extra) = (total / slots, total % slots);
    (0..slots)
        .map(|i| base + usize::from((i + round * extra) % slots < extra))
        .collect()
}

fn skew_plan(domains: usize, pages: usize, percent: usize, round: usize) -> SkewPlan {
    let total = changed_count(domains * pages, percent);
    let heavy = (domains / 100).clamp(1, domains);
    let light = domains - heavy;
    let heavy_share = if light == 0 { total } else { total.div_ceil(2) };
    let heavy_pages = pages.max(heavy_share.div_ceil(heavy));
    let counts = spread(heavy_share, heavy, round)
        .into_iter()
        .chain(
            spread(total - heavy_share, light, round)
                .into_iter()
                .map(|count| count.min(pages)),
        )
        .collect();
    SkewPlan {
        heavy,
        heavy_pages,
        counts,
    }
}

fn skew(args: &Args, bins: &Arc<Bins>, root: &Path, report: &mut Value) -> Vec<Check> {
    let domains = args.size(args.domains, 200);
    let pages = args.size(args.pages, 50);
    let rounds = args.size(args.rounds, 5);
    let percent = args.changed_percent(10);
    let labeler_count = args.labelers.unwrap_or(2);
    assert!(
        rounds >= 2,
        "skew seals a Log key addition and its removal in two rounds"
    );
    report["parameters"] = json!({
        "domains": domains,
        "pages_per_domain": pages,
        "rounds": rounds,
        "changed_percent": percent,
        "labelers": labeler_count,
        "labels_per_round": args.labels_per_round(),
        "seal_during_pulls": args.seal_during_pulls,
        "round_bound_seconds": args.round_bound().as_secs(),
        "status_bound_ms": args.status_bound_ms(),
    });
    let layout = skew_plan(domains, pages, percent, 0);
    let page_counts: Vec<usize> = (0..domains)
        .map(|i| {
            if i < layout.heavy {
                layout.heavy_pages
            } else {
                pages
            }
        })
        .collect();
    let sites = make_sites(root, 0, domains);
    let labelers = make_sites(root, domains, labeler_count);
    for (site, &count) in sites.iter().zip(&page_counts) {
        write_pages(site, count, args.body_words(), 1);
    }
    for labeler in &labelers {
        write_pages(labeler, 1, args.body_words(), 1);
    }
    let site_refs: Vec<&Site> = sites.iter().collect();
    let served: Vec<&Site> = sites.iter().chain(&labelers).collect();
    let mut h = Harness::start(bins, root, &served, args);
    let status_host = sites[domains - 1].host.clone();
    h.establish(&site_refs, &labelers, &status_host, report);
    let subjects: Vec<String> = sites
        .iter()
        .zip(&page_counts)
        .flat_map(|(site, &count)| page_urls(site, count))
        .collect();
    let heavy_hosts = hosts_of(&site_refs[..layout.heavy]);
    let light_hosts = hosts_of(&site_refs[layout.heavy..]);
    let middle = (rounds - 1) / 2;
    let mut added_key: Option<String> = None;
    let mut outcomes = Vec::new();
    for r in 0..rounds {
        let plan = skew_plan(domains, pages, percent, r + 1);
        let participants: Vec<Participant> = sites
            .iter()
            .zip(&plan.counts)
            .zip(&page_counts)
            .filter(|((_, &count), _)| count > 0)
            .map(|((site, &count), &site_pages)| Participant {
                site,
                changed: changed_indices(count, site_pages, r + 1),
                items: count,
            })
            .collect();
        let heavy_items: usize = plan.counts[..layout.heavy].iter().sum();
        let light_items: usize = plan.counts[layout.heavy..].iter().sum();
        let round_plan = Plan {
            participants,
            classes: vec![
                ("heavy", heavy_hosts.clone(), heavy_items),
                ("light", light_hosts.clone(), light_items),
            ],
            labelers: &labelers,
            subjects: &subjects,
            labels_per_round: args.labels_per_round(),
        };
        let outcome = run_round(
            &mut h,
            &format!("{}", r + 1),
            &round_plan,
            r as u64 + 2,
            &status_host,
            |h| {
                if r == middle {
                    let effective_at = instant(
                        h.clock
                            .effective_after_grace(jiff::Timestamp::now().as_second()),
                    );
                    change_parameter(
                        &h.bins.clave,
                        &h.aggregator,
                        "quota_base",
                        2000,
                        &effective_at,
                    );
                    run(
                        &h.bins.clave,
                        &["log-key", "add", "--data", s(&h.aggregator.data)],
                    );
                    let key = log_keys(&h.bins.clave, &h.aggregator.data)
                        .into_iter()
                        .find(|key| key.added.is_none())
                        .expect("log-key add queued an unsealed key")
                        .key_id;
                    added_key = Some(key.clone());
                    json!({
                        "parameter_change": {
                            "parameter": "quota_base",
                            "value": 2000,
                            "effective_at": effective_at,
                        },
                        "log_key_added": key,
                    })
                } else if r == middle + 1 {
                    let key = added_key.clone().expect("a Log key was added");
                    run(
                        &h.bins.clave,
                        &[
                            "log-key",
                            "remove",
                            "--data",
                            s(&h.aggregator.data),
                            "--key-id",
                            &key,
                        ],
                    );
                    json!({ "log_key_removed": key })
                } else {
                    Value::Null
                }
            },
        );
        outcomes.push(outcome);
    }
    let refs: Vec<&RoundOutcome> = outcomes.iter().collect();
    let p99s: Vec<Option<f64>> = outcomes.iter().map(|o| o.status_p99_ms).collect();
    let checks = vec![
        pulled_check("rounds_pulled_within_bound", &refs, args.round_bound()),
        seal_check(&refs),
        status_check("status_p99_under_bound", &p99s, args.status_bound_ms()),
    ];
    report["stages"]["skew"] = json!({
        "heavy_domains": layout.heavy,
        "heavy_pages_per_domain": layout.heavy_pages,
        "rounds": outcomes.iter().map(|o| o.report.clone()).collect::<Vec<_>>(),
    });
    stage_over_rounds("skew", &mut report["stages"]["skew"], &outcomes);
    report["longest_write_lock_ms"] = json!(h.run_longest_write_lock_ms());
    checks
}

fn domain_entries(entries: &[Value], host: &str) -> usize {
    entries
        .iter()
        .filter(|entry| entry_host(entry) == Some(host))
        .count()
}

fn item_urls<'a>(entries: &'a [Value], host: &str) -> impl Iterator<Item = String> + 'a {
    let host = host.to_string();
    entries
        .iter()
        .filter(move |entry| {
            entry["type"] == "publisher_item" && entry["body"]["item"]["publisher"] == host.as_str()
        })
        .filter_map(|entry| entry["body"]["item"]["url"].as_str().map(str::to_string))
}

fn backfill(args: &Args, bins: &Arc<Bins>, root: &Path, report: &mut Value) -> Vec<Check> {
    let domains = args.size(args.domains, 100);
    let pages = args.size(args.pages, 10);
    let backfill_pages = args.size(args.backfill_pages, 20_000);
    let rounds = args.size(args.rounds, 3);
    let percent = args.changed_percent(10);
    let labeler_count = args.labelers.unwrap_or(0);
    let cap = DOMAIN_EPOCH_ENTRIES_DEFAULT;
    let expected_epochs = (backfill_pages + 1).div_ceil(cap);
    report["parameters"] = json!({
        "domains": domains,
        "pages_per_domain": pages,
        "backfill_pages": backfill_pages,
        "rounds": rounds,
        "changed_percent": percent,
        "labelers": labeler_count,
        "labels_per_round": args.labels_per_round(),
        "round_bound_seconds": args.round_bound().as_secs(),
        "status_bound_ms": args.status_bound_ms(),
    });
    let sites = make_sites(root, 0, domains);
    let labelers = make_sites(root, domains, labeler_count);
    let big = Site::new(root, &host_name(domains + labeler_count), "default");
    for site in &sites {
        write_pages(site, pages, args.body_words(), 1);
    }
    for labeler in &labelers {
        write_pages(labeler, 1, args.body_words(), 1);
    }
    write_pages(&big, backfill_pages, args.body_words(), 1);
    let site_refs: Vec<&Site> = sites.iter().collect();
    let served: Vec<&Site> = sites
        .iter()
        .chain(&labelers)
        .chain(std::iter::once(&big))
        .collect();
    let mut h = Harness::start(bins, root, &served, args);
    let status_host = sites[0].host.clone();
    h.establish(&site_refs, &labelers, &status_host, report);
    let subjects: Vec<String> = sites
        .iter()
        .flat_map(|site| page_urls(site, pages))
        .collect();
    let small_hosts = hosts_of(&site_refs);
    let changed = changed_count(pages, percent);
    let mut outcomes = Vec::new();
    let mut missing_by_round = Vec::new();
    let mut big_sealed: BTreeSet<String> = BTreeSet::new();
    let mut big_per_epoch = Vec::new();
    let mut drained_at = None;
    let mut r = 1;
    while r <= rounds || (drained_at.is_none() && r <= expected_epochs + rounds + 2) {
        if r == 1 {
            big.init(&bins.spake);
        }
        let mut participants: Vec<Participant> = sites
            .iter()
            .map(|site| Participant {
                site,
                changed: changed_indices(changed, pages, r),
                items: changed,
            })
            .collect();
        if r == 1 {
            participants.push(Participant {
                site: &big,
                changed: Vec::new(),
                items: backfill_pages,
            });
        }
        let classes = vec![
            ("small", small_hosts.clone(), changed * domains),
            (
                "backfill",
                vec![big.host.clone()],
                if r == 1 { backfill_pages } else { 0 },
            ),
        ];
        let plan = Plan {
            participants,
            classes,
            labelers: &labelers,
            subjects: &subjects,
            labels_per_round: args.labels_per_round(),
        };
        let mut outcome = run_round(
            &mut h,
            &r.to_string(),
            &plan,
            r as u64 + 1,
            &status_host,
            |_| Value::Null,
        );
        let small: Vec<Participant> = plan
            .participants
            .into_iter()
            .filter(|participant| participant.site.host != big.host)
            .collect();
        let sealed_ids = item_ids(&outcome.sealed.entries);
        let missing = expected_item_ids(&small).difference(&sealed_ids).count();
        missing_by_round.push(missing);
        let big_entries = domain_entries(&outcome.sealed.entries, &big.host);
        big_sealed.extend(item_urls(&outcome.sealed.entries, &big.host));
        big_per_epoch.push(big_entries);
        if drained_at.is_none() && big_sealed.len() >= backfill_pages {
            drained_at = Some(r);
        }
        outcome.report["small_changes_missing_from_epoch"] = json!(missing);
        outcome.report["backfill_domain_entries"] = json!(big_entries);
        outcome.report["backfill_items_sealed_so_far"] = json!(big_sealed.len());
        outcomes.push(outcome);
        r += 1;
    }
    let max_big = big_per_epoch.iter().copied().max().unwrap_or(0);
    let checks = vec![
        Check::new(
            "small_domains_seal_in_the_next_epoch",
            missing_by_round.iter().all(|&missing| missing == 0),
            json!({ "missing_items_by_round": missing_by_round }),
            "every small domain's changed Items sealed in the Epoch sealed right after their round while the backfill drains (meta ADR-0005, Targets: freshness)",
        ),
        Check::new(
            "backfill_drains_in_the_expected_epochs",
            drained_at == Some(expected_epochs),
            json!({
                "drained_after_epochs": drained_at,
                "items_sealed": big_sealed.len(),
                "domain_entries_per_epoch": big_per_epoch,
            }),
            format!(
                "all {backfill_pages} Items sealed after exactly ceil(({backfill_pages} Items + 1 Catalog) / {cap}) = {expected_epochs} Epochs (WIST-3 §3.2 counts the Catalog Entry with the Items)"
            ),
        ),
        Check::new(
            "backfill_epochs_within_the_domain_capacity",
            max_big <= cap,
            json!({ "max_domain_entries_in_an_epoch": max_big }),
            format!("<= {cap} Entries of the backfill domain per Epoch (WIST-3 §3.2 domain_epoch_entries_max, spec default)"),
        ),
    ];
    report["stages"]["backfill"] = json!({
        "domain_epoch_entries_max": cap,
        "domain_epoch_entries_max_source": "spec default (WIST-3 §3.2); the aggregator serves no parameter endpoint",
        "expected_epochs": expected_epochs,
        "rounds": outcomes.iter().map(|o| o.report.clone()).collect::<Vec<_>>(),
    });
    stage_over_rounds("backfill", &mut report["stages"]["backfill"], &outcomes);
    report["longest_write_lock_ms"] = json!(h.run_longest_write_lock_ms());
    checks
}

fn rejections_after(status: &Value, since: &str) -> usize {
    status["rejections"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|rejection| rejection["at"].as_str().is_some_and(|at| at > since))
        .count()
}

fn rejected_since(status: &Value, code: &str, since: &str) -> bool {
    status["rejections"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|rejection| {
            rejection["code"] == code && rejection["at"].as_str().is_some_and(|at| at > since)
        })
}

struct Failed {
    recorded: Option<f64>,
    retried_after: Option<f64>,
}

struct FailureWatch {
    http: reqwest::blocking::Client,
    base: String,
    since: Since,
    counters: BTreeMap<String, Arc<std::sync::atomic::AtomicU64>>,
    last_ping: Instant,
    record_bound: Duration,
    retry_wait: Duration,
}

impl FailureWatch {
    fn run(self) -> BTreeMap<String, Failed> {
        let mut observed: BTreeMap<String, (Instant, u64)> = BTreeMap::new();
        let mut outcome: BTreeMap<String, Failed> = self
            .since
            .keys()
            .map(|host| {
                (
                    host.clone(),
                    Failed {
                        recorded: None,
                        retried_after: None,
                    },
                )
            })
            .collect();
        loop {
            let mut open = false;
            for (host, failed) in outcome.iter_mut() {
                match observed.get(host) {
                    None if self.last_ping.elapsed() < self.record_bound => {
                        open = true;
                        if fetch_status(&self.http, &self.base, host).is_some_and(|status| {
                            rejected_since(&status, "WIST2-E01", &self.since[host])
                        }) {
                            failed.recorded = Some(self.last_ping.elapsed().as_secs_f64());
                            observed.insert(
                                host.clone(),
                                (Instant::now(), self.counters[host].load(Ordering::Relaxed)),
                            );
                        }
                    }
                    Some((at, count))
                        if failed.retried_after.is_none() && at.elapsed() < self.retry_wait =>
                    {
                        open = true;
                        if self.counters[host].load(Ordering::Relaxed) > *count {
                            failed.retried_after = Some(at.elapsed().as_secs_f64());
                        }
                    }
                    _ => {}
                }
            }
            if !open {
                return outcome;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }
}

fn hosts(args: &Args, bins: &Arc<Bins>, root: &Path, report: &mut Value) -> Vec<Check> {
    let domains = args.size(args.domains, 100);
    let pages = args.size(args.pages, 20);
    let slow = args.slow.unwrap_or(5);
    let failing = args.failing.unwrap_or(5);
    let hanging = args.hanging.unwrap_or(2);
    let delay = Duration::from_millis(args.delay_ms.unwrap_or(2000));
    let hang = Duration::from_secs(args.hang_seconds.unwrap_or(20));
    let healthy_bound = Duration::from_secs(args.healthy_bound_seconds.unwrap_or(60));
    let retry_wait = Duration::from_secs(args.retry_wait_seconds.unwrap_or(150));
    let percent = args.changed_percent(10);
    let degraded = slow + failing + hanging;
    assert!(
        degraded < domains,
        "hosts needs at least one healthy domain besides {degraded} degraded ones"
    );
    report["parameters"] = json!({
        "domains": domains,
        "pages_per_domain": pages,
        "changed_percent": percent,
        "slow": slow,
        "delay_ms": delay.as_millis() as u64,
        "failing": failing,
        "hanging": hanging,
        "hang_seconds": hang.as_secs(),
        "healthy_bound_seconds": healthy_bound.as_secs(),
        "retry_wait_seconds": retry_wait.as_secs(),
        "round_bound_seconds": args.round_bound().as_secs(),
        "status_bound_ms": args.status_bound_ms(),
    });
    let sites = make_sites(root, 0, domains);
    for site in &sites {
        write_pages(site, pages, args.body_words(), 1);
    }
    let site_refs: Vec<&Site> = sites.iter().collect();
    let mut h = Harness::start(bins, root, &site_refs, args);
    let status_host = sites[0].host.clone();
    h.establish(&site_refs, &[], &status_host, report);

    let healthy_count = domains - degraded;
    let healthy = hosts_of(&site_refs[..healthy_count]);
    let slowed = hosts_of(&site_refs[healthy_count..healthy_count + slow]);
    let unavailable = hosts_of(&site_refs[healthy_count + slow..domains - hanging]);
    let hung = hosts_of(&site_refs[domains - hanging..]);
    for host in &slowed {
        h.behaviors.set(
            host,
            HostBehavior {
                delay: Some(delay),
                failure: None,
            },
        );
    }
    for (group, failure) in [
        (&unavailable, Failure::Unavailable),
        (&hung, Failure::Hang(hang)),
    ] {
        for host in group {
            h.behaviors.set(
                host,
                HostBehavior {
                    delay: None,
                    failure: Some(failure),
                },
            );
        }
    }

    let changed = changed_count(pages, percent);
    let participants: Vec<Participant> = sites
        .iter()
        .map(|site| Participant {
            site,
            changed: changed_indices(changed, pages, 1),
            items: changed,
        })
        .collect();
    let round = h.begin(&status_host);
    let (publish_seconds, since) = h.publish(&participants, 2);
    let all = hosts_of(&site_refs);
    settle(&since);
    let (refused, ping_seconds) = h.ping_all(&all);
    let last_ping = Instant::now();
    let failed: Vec<String> = unavailable.iter().chain(&hung).cloned().collect();
    let only = |hosts: &[String]| -> Since {
        hosts
            .iter()
            .map(|host| (host.clone(), since[host].clone()))
            .collect()
    };
    let watched = FailureWatch {
        http: h.http.clone(),
        base: h.base().to_string(),
        since: only(&failed),
        counters: failed
            .iter()
            .map(|host| (host.clone(), h.counters[host].failures.clone()))
            .collect(),
        last_ping,
        record_bound: h.round_bound,
        retry_wait,
    };
    let watcher = std::thread::spawn(move || watched.run());
    let reachable: Vec<String> = healthy.iter().chain(&slowed).cloned().collect();
    let offset = last_ping.elapsed().as_secs_f64();
    let pulled: BTreeMap<String, f64> = pulled_each_since(
        &h.http,
        h.base(),
        &only(&reachable),
        healthy_bound.max(h.round_bound),
    )
    .into_iter()
    .map(|(host, seconds)| (host, seconds + offset))
    .collect();
    let split = |hosts: &[String]| -> BTreeMap<String, f64> {
        hosts
            .iter()
            .filter_map(|host| pulled.get(host).map(|seconds| (host.clone(), *seconds)))
            .collect()
    };
    let healthy_pulled = split(&healthy);
    let slow_pulled = split(&slowed);
    let failures = watcher.join().expect("failure watcher");
    let recorded: BTreeMap<&String, f64> = failures
        .iter()
        .filter_map(|(host, failure)| failure.recorded.map(|seconds| (host, seconds)))
        .collect();
    let retried: BTreeMap<&String, f64> = failures
        .iter()
        .filter_map(|(host, failure)| failure.retried_after.map(|seconds| (host, seconds)))
        .collect();
    let aggregator_peak = peak_rss_kb(h.pid());
    let sealed = h.seal();
    let status = round.sampler.finish();
    let p99 = status["p99_ms"].as_f64();
    let requests = h.requests.requests();
    let injected = |hosts: &[String]| -> Value {
        json!({
            "delays": hosts.iter().map(|host| h.counters[host].delays.load(Ordering::Relaxed)).sum::<u64>(),
            "failures": hosts.iter().map(|host| h.counters[host].failures.load(Ordering::Relaxed)).sum::<u64>(),
        })
    };
    let mut round_report_value = requests_report(&requests, &all, changed * domains);
    e2e::merge(
        &mut round_report_value,
        json!({
            "round": "1",
            "publish_seconds": publish_seconds,
            "ping_seconds": ping_seconds,
            "pings_refused": refused,
            "by_class": {
                "healthy": round_report(&requests, &healthy, changed * healthy.len(), &healthy_pulled),
                "slow": round_report(&requests, &slowed, changed * slowed.len(), &slow_pulled),
                "failing": requests_report(&requests, &unavailable, changed * unavailable.len()),
                "hanging": requests_report(&requests, &hung, changed * hung.len()),
            },
            "injected": {
                "slow": injected(&slowed),
                "failing": injected(&unavailable),
                "hanging": injected(&hung),
            },
            "healthy_unpulled": healthy.len() - healthy_pulled.len(),
            "slow_unpulled": slowed.len() - slow_pulled.len(),
            "failure_recorded_seconds_after_last_ping": recorded.iter().map(|(host, seconds)| (host.to_string(), json!(seconds))).collect::<serde_json::Map<_, _>>(),
            "requested_again_seconds_after_failure_recorded": retried.iter().map(|(host, seconds)| (host.to_string(), json!(seconds))).collect::<serde_json::Map<_, _>>(),
            "aggregator_peak_rss_kb": aggregator_peak,
            "status_latency": status,
            "seal": sealed.report,
            "longest_write_lock_ms": sealed.longest_write_lock_ms,
            "seconds": round.started.elapsed().as_secs_f64(),
        }),
    );
    println!(
        "round 1: {} healthy pulled in {:.1} s, {} slow pulled, {} of {} failing hosts recorded WIST2-E01, {} retried, aggregator {:?} kB, status p99 {:?} ms",
        healthy_pulled.len(),
        healthy_pulled.values().copied().fold(0.0, f64::max),
        slow_pulled.len(),
        recorded.len(),
        failed.len(),
        retried.len(),
        aggregator_peak,
        p99,
    );
    let slowest_healthy = max_f64(healthy_pulled.values().copied());
    let checks = vec![
        Check::new(
            "healthy_hosts_pulled_within_bound",
            healthy_pulled.len() == healthy.len()
                && slowest_healthy.is_some_and(|seconds| seconds <= healthy_bound.as_secs_f64()),
            json!({
                "max_seconds_until_pulled": slowest_healthy,
                "unpulled": healthy.len() - healthy_pulled.len(),
            }),
            format!(
                "every healthy host pulled within {} s of the last ping while {slow} hosts are slow, {failing} answer 503 and {hanging} hang",
                healthy_bound.as_secs()
            ),
        ),
        Check::new(
            "failing_hosts_have_a_retry_scheduled",
            recorded.len() == failed.len() && retried.len() == failed.len(),
            json!({
                "hosts": failed.len(),
                "failure_recorded": recorded.len(),
                "requested_again": retried.len(),
            }),
            format!(
                "each failing and hanging host shows a WIST2-E01 rejection dated after its republish (status rejections[].code and rejections[].at) within the round bound of the last ping, and its site is requested again without a new ping within {} s of that rejection's first observation (WIST-2 §7 WIST2-E01: first backoff 1 min)",
                retry_wait.as_secs()
            ),
        ),
        status_check("status_p99_under_bound", &[p99], args.status_bound_ms()),
        Check::new(
            "aggregator_peak_rss_reported",
            aggregator_peak.is_some(),
            json!({ "aggregator_peak_rss_kb": aggregator_peak }),
            "the aggregator's peak resident set size over the round is reported",
        ),
    ];
    report["stages"]["hosts"] = json!({ "rounds": [round_report_value] });
    report["longest_write_lock_ms"] = json!(h.run_longest_write_lock_ms());
    checks
}

enum Admission {
    Admitted,
    Refused(u64),
    Error(String),
}

// WIST-2 §4: a Ping is a POST of the one-field body {"host"} to /ingest.
fn post_ping(http: &reqwest::blocking::Client, base: &str, host: &str) -> Admission {
    match http
        .post(format!("{base}/ingest"))
        .json(&json!({ "host": host }))
        .send()
    {
        Ok(response) if response.status().as_u16() == 202 => Admission::Admitted,
        Ok(response) if response.status().as_u16() == 503 => Admission::Refused(
            response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok()?.parse().ok())
                .unwrap_or(1),
        ),
        Ok(response) => Admission::Error(format!("HTTP {}", response.status())),
        Err(error) => Admission::Error(error.to_string()),
    }
}

struct Flood {
    admitted: usize,
    refused: Vec<(String, Instant)>,
    errors: Vec<String>,
}

fn flood(base: &str, hosts: &[String], threads: usize) -> Flood {
    let next = AtomicUsize::new(0);
    let outcome = Mutex::new(Flood {
        admitted: 0,
        refused: Vec::new(),
        errors: Vec::new(),
    });
    std::thread::scope(|scope| {
        for _ in 0..threads.max(1) {
            scope.spawn(|| {
                let http = reqwest::blocking::Client::new();
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(host) = hosts.get(i) else { break };
                    let admission = post_ping(&http, base, host);
                    let mut outcome = outcome.lock().unwrap_or_else(|e| e.into_inner());
                    match admission {
                        Admission::Admitted => outcome.admitted += 1,
                        Admission::Refused(retry_after) => outcome.refused.push((
                            host.clone(),
                            Instant::now() + Duration::from_secs(retry_after),
                        )),
                        Admission::Error(error) => outcome.errors.push(format!("{host}: {error}")),
                    }
                }
            });
        }
    });
    outcome.into_inner().unwrap_or_else(|e| e.into_inner())
}

struct Reping {
    admitted: usize,
    refusals: usize,
    unadmitted: Vec<String>,
    errors: Vec<String>,
}

fn reping_after_retry_after(
    base: &str,
    refused: Vec<(String, Instant)>,
    deadline: Instant,
) -> Reping {
    let http = reqwest::blocking::Client::new();
    let mut pending = refused;
    let mut outcome = Reping {
        admitted: 0,
        refusals: 0,
        unadmitted: Vec::new(),
        errors: Vec::new(),
    };
    while !pending.is_empty() {
        pending.sort_by_key(|(_, due)| *due);
        let (host, due) = pending.remove(0);
        if due > deadline {
            outcome.unadmitted.push(host);
            continue;
        }
        if let Some(wait) = due.checked_duration_since(Instant::now()) {
            std::thread::sleep(wait);
        }
        match post_ping(&http, base, &host) {
            Admission::Admitted => outcome.admitted += 1,
            Admission::Refused(retry_after) => {
                outcome.refusals += 1;
                pending.push((host, Instant::now() + Duration::from_secs(retry_after)));
            }
            Admission::Error(error) => {
                outcome.errors.push(format!("{host}: {error}"));
                outcome.unadmitted.push(host);
            }
        }
    }
    outcome
}

struct FloodOutcome {
    report: Value,
    refused: usize,
    errors: usize,
    reping: Reping,
    unpulled: usize,
    max_pulled: Option<f64>,
}

fn flood_round(
    h: &mut Harness,
    label: &str,
    participants: &[Participant],
    threads: usize,
    status_host: &str,
    revision: u64,
) -> FloodOutcome {
    let round = h.begin(status_host);
    let (publish_seconds, since) = h.publish(participants, revision);
    settle(&since);
    let hosts: Vec<String> = participants
        .iter()
        .map(|participant| participant.site.host.clone())
        .collect();
    let (flooded, flood_seconds) = timed(|| flood(h.base(), &hosts, threads));
    let refused = flooded.refused.len();
    let deadline = Instant::now() + h.round_bound;
    let (reping, reping_seconds) =
        timed(|| reping_after_retry_after(h.base(), flooded.refused, deadline));
    let pulled = pulled_each_since(&h.http, h.base(), &since, h.round_bound);
    let aggregator_peak = peak_rss_kb(h.pid());
    let seconds = round.started.elapsed().as_secs_f64();
    let status = round.sampler.finish();
    let longest_write_lock_ms = h.write_lock_window(None);
    let items = participants
        .iter()
        .map(|participant| participant.items)
        .sum();
    let mut report = round_report(&h.requests.requests(), &hosts, items, &pulled);
    e2e::merge(
        &mut report,
        json!({
            "round": label,
            "publish_seconds": publish_seconds,
            "flood_seconds": flood_seconds,
            "pings_admitted_first": flooded.admitted,
            "pings_refused_first": refused,
            "ping_errors": flooded.errors,
            "repinged_admitted": reping.admitted,
            "repinged_refused_again": reping.refusals,
            "repinged_unadmitted": reping.unadmitted,
            "reping_errors": reping.errors,
            "reping_seconds": reping_seconds,
            "unpulled_domains": hosts.len() - pulled.len(),
            "aggregator_peak_rss_kb": aggregator_peak,
            "status_latency": status,
            "longest_write_lock_ms": longest_write_lock_ms,
            "seconds": seconds,
        }),
    );
    let max_pulled = max_f64(pulled.values().copied());
    println!(
        "{label} flood: {} admitted, {refused} refused then {} admitted after Retry-After, {} of {} pulled in {:.1} s, aggregator {aggregator_peak:?} kB",
        flooded.admitted,
        reping.admitted,
        pulled.len(),
        hosts.len(),
        max_pulled.unwrap_or(0.0),
    );
    FloodOutcome {
        report,
        refused,
        errors: flooded.errors.len(),
        reping,
        unpulled: hosts.len() - pulled.len(),
        max_pulled,
    }
}

fn saturation(args: &Args, bins: &Arc<Bins>, root: &Path, report: &mut Value) -> Vec<Check> {
    let domains = args.size(args.domains, 1000);
    let pages = args.size(args.pages, 5);
    let percent = args.changed_percent(100);
    let threads = args.ping_threads.unwrap_or(8);
    report["parameters"] = json!({
        "domains": domains,
        "pages_per_domain": pages,
        "changed_percent": percent,
        "ping_threads": threads,
        "round_bound_seconds": args.round_bound().as_secs(),
        "status_bound_ms": args.status_bound_ms(),
    });
    let sites = make_sites(root, 0, domains);
    let fresh = make_sites(root, domains, domains);
    for site in sites.iter().chain(&fresh) {
        write_pages(site, pages, args.body_words(), 1);
    }
    let site_refs: Vec<&Site> = sites.iter().collect();
    let served: Vec<&Site> = sites.iter().chain(&fresh).collect();
    let mut h = Harness::start(bins, root, &served, args);
    let status_host = sites[0].host.clone();
    h.establish(&site_refs, &[], &status_host, report);
    parallel(&fresh, |site| site.init(&bins.spake));

    let first_contact: Vec<Participant> = fresh
        .iter()
        .map(|site| Participant {
            site,
            changed: Vec::new(),
            items: pages,
        })
        .collect();
    let first = flood_round(
        &mut h,
        "first contact",
        &first_contact,
        threads,
        &status_host,
        1,
    );
    let changed = changed_count(pages, percent);
    let participants: Vec<Participant> = sites
        .iter()
        .map(|site| Participant {
            site,
            changed: changed_indices(changed, pages, 1),
            items: changed,
        })
        .collect();
    let update = flood_round(&mut h, "update", &participants, threads, &status_host, 2);
    let all = hosts_of(&served);

    let ingest_entries = report["stages"]["ingest"]["seal"]["log_entries"].clone();
    let sealed_octets = |kind: &str| {
        let row = &ingest_entries[kind];
        row["octets"].as_u64().unwrap_or(0) + 2 * row["entries"].as_u64().unwrap_or(0)
    };
    let first_contact_octets = ingest_entries["all"]["octets"].as_u64().unwrap_or(0)
        + 2 * ingest_entries["all"]["entries"].as_u64().unwrap_or(0);
    let estimate = first_contact_octets
        + sealed_octets("publisher_catalog")
        + sealed_octets("publisher_item") * changed as u64 / pages as u64;
    let bound = (estimate / 6).max(EPOCH_CAP_FLOOR);
    run(
        &bins.clave,
        &[
            "bound",
            "--data",
            s(&h.aggregator.data),
            "--parameter",
            "epoch_cap_bytes",
            "--value",
            &bound.to_string(),
        ],
    );
    let sampler = StatusSampler::start(h.base(), &status_host);
    let mut epochs = Vec::new();
    let mut sealed_entries = Vec::new();
    let limit = 10 + 4 * (estimate / bound) as usize;
    let mut drained = false;
    for _ in 0..limit {
        let sealed = h.seal();
        println!(
            "bounded seal: {} entries, {} octets, {:.2} s",
            sealed.entries.len(),
            sealed.octets,
            sealed.seconds
        );
        if sealed.entries.is_empty() {
            drained = true;
            epochs.push(sealed);
            break;
        }
        sealed_entries.extend(sealed.entries.iter().cloned());
        epochs.push(sealed);
    }
    let seal_status = sampler.finish();
    let filled: Vec<&Sealed> = epochs.iter().filter(|e| !e.entries.is_empty()).collect();
    let largest = filled.iter().map(|e| e.octets).max().unwrap_or(0);
    let mut item_counts: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut catalog_counts: BTreeMap<String, usize> = BTreeMap::new();
    for entry in &sealed_entries {
        match entry["type"].as_str() {
            Some("publisher_item") => {
                let item = &entry["body"]["item"];
                *item_counts
                    .entry((
                        item["publisher"].as_str().unwrap_or("").to_string(),
                        item["url"].as_str().unwrap_or("").to_string(),
                    ))
                    .or_default() += 1;
            }
            Some("publisher_catalog") => {
                *catalog_counts
                    .entry(
                        entry["body"]["catalog"]["publisher"]
                            .as_str()
                            .unwrap_or("")
                            .to_string(),
                    )
                    .or_default() += 1;
            }
            _ => {}
        }
    }
    let expected_items: BTreeSet<(String, String)> = participants
        .iter()
        .flat_map(|participant| {
            participant.changed.iter().map(|j| {
                (
                    participant.site.host.clone(),
                    participant.site.url(&format!("p{j}.html")),
                )
            })
        })
        .chain(
            fresh
                .iter()
                .flat_map(|site| page_urls(site, pages).map(|url| (site.host.clone(), url))),
        )
        .collect();
    let lost = expected_items
        .iter()
        .filter(|key| !item_counts.contains_key(*key))
        .count();
    let duplicated = item_counts.values().filter(|&&count| count > 1).count();
    let unexpected = item_counts
        .keys()
        .filter(|key| !expected_items.contains(*key))
        .count();
    let catalogs_off = all
        .iter()
        .filter(|host| catalog_counts.get(*host).copied().unwrap_or(0) != 1)
        .count();
    let seal_p99 = seal_status["p99_ms"].as_f64();
    let checks = vec![
        Check::new(
            "refused_pings_are_admitted_later",
            first.refused > 0
                && first.reping.unadmitted.is_empty()
                && first.reping.errors.is_empty()
                && first.errors == 0,
            json!({
                "refused_hosts": first.refused,
                "admitted_later": first.reping.admitted,
                "refused_again": first.reping.refusals,
                "never_admitted": first.reping.unadmitted.len(),
                "errors": first.errors + first.reping.errors.len(),
            }),
            format!(
                "a flood of first-contact Pings from {threads} threads is refused at least once, and every refused host is admitted on a ping sent after the refusal's Retry-After, within {} s",
                args.round_bound().as_secs()
            ),
        ),
        Check::new(
            "flooded_hosts_pulled_within_bound",
            first.unpulled == 0 && update.unpulled == 0,
            json!({
                "first_contact": { "max_seconds_until_all_pulled": first.max_pulled, "unpulled_domains": first.unpulled },
                "update": { "max_seconds_until_all_pulled": update.max_pulled, "unpulled_domains": update.unpulled },
            }),
            format!(
                "every domain of both floods pulled within {} s of the flood's last admitted ping",
                args.round_bound().as_secs()
            ),
        ),
        Check::new(
            "bound_spreads_the_round_over_five_epochs",
            filled.len() >= 5 && drained,
            json!({ "epochs_with_entries": filled.len(), "drained": drained }),
            format!("the local epoch_cap_bytes bound {bound} leaves at least 5 Epochs carrying the round's Entries before the pending queue is empty"),
        ),
        Check::new(
            "epochs_within_the_byte_bound",
            largest <= bound,
            json!({ "largest_epoch_octets": largest }),
            format!("every Epoch's octets, each Entry's JCS serialization plus two (WIST-3 §6), <= the local bound {bound}"),
        ),
        Check::new(
            "round_entries_sealed_exactly_once",
            lost == 0 && duplicated == 0 && unexpected == 0 && catalogs_off == 0,
            json!({
                "expected_items": expected_items.len(),
                "sealed_items": item_counts.values().sum::<usize>(),
                "lost": lost,
                "duplicated": duplicated,
                "unexpected": unexpected,
                "domains_without_exactly_one_catalog": catalogs_off,
            }),
            "the Epochs together seal each first-contact and changed Item and each domain's Catalog exactly once",
        ),
        status_check("status_p99_under_bound_during_seals", &[seal_p99], args.status_bound_ms()),
    ];
    report["stages"]["saturation"] = json!({
        "first_contact_flood": first.report,
        "update_flood": update.report,
        "sealing": {
            "estimated_round_octets": estimate,
            "epoch_cap_bytes_local_bound": bound,
            "epochs": epochs.iter().map(|e| e.report.clone()).collect::<Vec<_>>(),
            "status_latency": seal_status,
        },
    });
    report["longest_write_lock_ms"] = json!(h.run_longest_write_lock_ms());
    checks
}

fn uniform<'a>(
    sites: &'a [Site],
    changed: usize,
    pages: usize,
    round: usize,
) -> Vec<Participant<'a>> {
    sites
        .iter()
        .map(|site| Participant {
            site,
            changed: changed_indices(changed, pages, round),
            items: changed,
        })
        .collect()
}

fn drainage(args: &Args, bins: &Arc<Bins>, root: &Path, report: &mut Value) -> Vec<Check> {
    let domains = args.size(args.domains, 100);
    let pages = args.size(args.pages, 20);
    let steady = args.size(args.steady_rounds, 2).max(1);
    let outage = args.size(args.outage_rounds, 3);
    let recovery = args.size(args.recovery_rounds, 3);
    let percent = args.changed_percent(10);
    let labeler_count = args.labelers.unwrap_or(0);
    report["parameters"] = json!({
        "domains": domains,
        "pages_per_domain": pages,
        "changed_percent": percent,
        "steady_rounds": steady,
        "outage_rounds": outage,
        "recovery_rounds": recovery,
        "labelers": labeler_count,
        "labels_per_round": args.labels_per_round(),
        "round_bound_seconds": args.round_bound().as_secs(),
        "status_bound_ms": args.status_bound_ms(),
    });
    let sites = make_sites(root, 0, domains);
    let labelers = make_sites(root, domains, labeler_count);
    for site in &sites {
        write_pages(site, pages, args.body_words(), 1);
    }
    for labeler in &labelers {
        write_pages(labeler, 1, args.body_words(), 1);
    }
    let site_refs: Vec<&Site> = sites.iter().collect();
    let served: Vec<&Site> = sites.iter().chain(&labelers).collect();
    let mut h = Harness::start(bins, root, &served, args);
    let status_host = sites[0].host.clone();
    h.establish(&site_refs, &labelers, &status_host, report);
    let subjects: Vec<String> = sites
        .iter()
        .flat_map(|site| page_urls(site, pages))
        .collect();
    let all = hosts_of(&site_refs);
    let changed = changed_count(pages, percent);
    let plan = |round: usize| Plan {
        participants: uniform(&sites, changed, pages, round),
        classes: vec![("publishers", all.clone(), changed * domains)],
        labelers: &labelers,
        subjects: &subjects,
        labels_per_round: args.labels_per_round(),
    };
    let mut round = 1;
    let mut steady_outcomes = Vec::new();
    for _ in 0..steady {
        steady_outcomes.push(run_round(
            &mut h,
            &format!("steady {round}"),
            &plan(round),
            round as u64 + 1,
            &status_host,
            |_| Value::Null,
        ));
        round += 1;
    }
    let round_seconds =
        steady_outcomes.iter().map(|o| o.seconds).sum::<f64>() / steady_outcomes.len() as f64;

    h.aggregator.stop();
    let mut outage_reports = Vec::new();
    let mut outage_admitted = 0;
    for _ in 0..outage {
        let participants = uniform(&sites, changed, pages, round);
        let (publish_seconds, _) = h.publish(&participants, round as u64 + 1);
        let (mut failed, mut admitted) = (0, 0);
        for host in &all {
            match ping_once(&bins.spake, h.base(), host) {
                PingOutcome::Admitted => admitted += 1,
                PingOutcome::Refused(_) | PingOutcome::Failed(_) => failed += 1,
            }
        }
        outage_admitted += admitted;
        h.clock.skip(1);
        println!("outage round {round}: {failed} pings failed, {admitted} admitted");
        outage_reports.push(json!({
            "round": format!("outage {round}"),
            "changed_items": changed * domains,
            "publish_seconds": publish_seconds,
            "pings_failed": failed,
            "pings_admitted": admitted,
        }));
        round += 1;
    }

    let since_restart = after_this_second();
    let restarted = Instant::now();
    let proxy = h.proxy.clone();
    h.aggregator.start(&bins.clave, Some(&proxy));
    let drain_bound = outage as f64 * round_seconds;
    let watch_timeout =
        Duration::from_secs_f64((2.0 * drain_bound).max(args.round_bound().as_secs_f64()));
    let watcher = {
        let (http, base, hosts, since) = (
            h.http.clone(),
            h.base().to_string(),
            all.clone(),
            since_restart.clone(),
        );
        let offset = restarted.elapsed().as_secs_f64();
        std::thread::spawn(move || {
            pulled_within(&http, &base, &hosts, &since, watch_timeout)
                .into_iter()
                .map(|(host, seconds)| (host, seconds + offset))
                .collect::<BTreeMap<_, _>>()
        })
    };
    let (backlog_refused, backlog_ping_seconds) = h.ping_all(&all);
    let mut recovery_outcomes = Vec::new();
    let mut missing_by_round = Vec::new();
    let mut recovery_starts = Vec::new();
    for _ in 0..recovery {
        recovery_starts.push(restarted.elapsed().as_secs_f64());
        let round_plan = plan(round);
        let mut outcome = run_round(
            &mut h,
            &format!("recovery {round}"),
            &round_plan,
            round as u64 + 1,
            &status_host,
            |_| Value::Null,
        );
        let missing = expected_item_ids(&round_plan.participants)
            .difference(&item_ids(&outcome.sealed.entries))
            .count();
        outcome.report["changes_missing_from_epoch"] = json!(missing);
        missing_by_round.push(missing);
        recovery_outcomes.push(outcome);
        round += 1;
    }
    let drained = watcher.join().expect("drain watcher");
    let slowest = max_f64(drained.values().copied());
    if let (Some(first), Some(&start)) = (recovery_outcomes.first_mut(), recovery_starts.first()) {
        let end = recovery_starts.get(1).copied().unwrap_or(f64::INFINITY);
        first.report["backlog_overlap"] = json!({
            "note": "the backlog's first pulls after the restart run during this round, so its site requests, octets and per-Item figures include them",
            "backlog_domains_first_pulled_during_round": drained
                .values()
                .filter(|&&seconds| seconds >= start && seconds < end)
                .count(),
            "backlog_domains_first_pulled_before_round": drained
                .values()
                .filter(|&&seconds| seconds < start)
                .count(),
        });
    }
    println!(
        "backlog: {} of {} domains pulled after the restart, slowest {:?} s, bound {:.1} s",
        drained.len(),
        all.len(),
        slowest,
        drain_bound
    );
    let mut p99s: Vec<Option<f64>> = steady_outcomes.iter().map(|o| o.status_p99_ms).collect();
    p99s.extend(recovery_outcomes.iter().map(|o| o.status_p99_ms));
    let checks = vec![
        Check::new(
            "pings_fail_during_the_outage",
            outage_admitted == 0,
            json!({ "pings_admitted_during_outage": outage_admitted }),
            "no Ping is admitted while the aggregator is stopped",
        ),
        Check::new(
            "backlog_drains_within_the_outage_length",
            drained.len() == all.len() && slowest.is_some_and(|seconds| seconds <= drain_bound),
            json!({
                "max_seconds_after_restart": slowest,
                "unpulled_domains": all.len() - drained.len(),
                "mean_steady_round_seconds": round_seconds,
            }),
            format!(
                "every domain pulled within {outage} x {round_seconds:.1} s = {drain_bound:.1} s of the restart (meta ADR-0005, Targets: a backlog of h hours drains within h hours)"
            ),
        ),
        Check::new(
            "recovery_changes_seal_in_the_next_epoch",
            missing_by_round.iter().all(|&missing| missing == 0)
                && recovery_outcomes.iter().all(|o| o.unpulled() == 0),
            json!({
                "missing_items_by_round": missing_by_round,
                "unpulled_domains_by_round": recovery_outcomes.iter().map(RoundOutcome::unpulled).collect::<Vec<_>>(),
            }),
            "each recovery round's changed Items sealed in the Epoch sealed right after that round (meta ADR-0005, Targets: steady traffic keeps flowing during the drain)",
        ),
        status_check("status_p99_under_bound", &p99s, args.status_bound_ms()),
    ];
    report["stages"]["drainage"] = json!({
        "steady_rounds": steady_outcomes.iter().map(|o| o.report.clone()).collect::<Vec<_>>(),
        "mean_steady_round_seconds": round_seconds,
        "outage_rounds": outage_reports,
        "restart": {
            "backlog_pings_refused": backlog_refused,
            "backlog_ping_seconds": backlog_ping_seconds,
            "seconds_until_each_domain_pulled": drained,
            "drain_bound_seconds": drain_bound,
        },
        "recovery_rounds": recovery_outcomes.iter().map(|o| o.report.clone()).collect::<Vec<_>>(),
    });
    report["longest_write_lock_ms"] = json!(h.run_longest_write_lock_ms());
    checks
}

fn rss_kb(pid: u32) -> Option<u64> {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()?
        .lines()
        .find_map(|line| {
            line.strip_prefix("VmRSS:")?
                .trim()
                .strip_suffix("kB")?
                .trim()
                .parse()
                .ok()
        })
}

fn measure_probe_pull(
    h: &mut Harness,
    probe: &Site,
    changed: usize,
    round: usize,
) -> (Value, Option<u64>) {
    let changed = changed_indices(changed, PROBE_PAGES, round);
    let start = h.begin(&probe.host);
    let rss_before = rss_kb(h.pid());
    let participants = [Participant {
        site: probe,
        changed: changed.clone(),
        items: changed.len(),
    }];
    let (_, since) = h.publish(&participants, round as u64 + 1);
    settle(&since);
    let hosts = vec![probe.host.clone()];
    let (refused, _) = h.ping_all(&hosts);
    let pulled = pulled_each_since(&h.http, h.base(), &since, h.round_bound);
    let peak = peak_rss_kb(h.pid());
    let increase = peak
        .zip(rss_before)
        .map(|(peak, before)| peak.saturating_sub(before));
    let status = start.sampler.finish();
    let longest_write_lock_ms = h.write_lock_window(None);
    let mut report = round_report(&h.requests.requests(), &hosts, changed.len(), &pulled);
    e2e::merge(
        &mut report,
        json!({
            "pulled": pulled.len() == hosts.len(),
            "pings_refused": refused,
            "aggregator_rss_before_kb": rss_before,
            "aggregator_peak_rss_kb": peak,
            "aggregator_rss_increase_kb": increase,
            "status_latency": status,
            "longest_write_lock_ms": longest_write_lock_ms,
        }),
    );
    (report, increase)
}

fn memory(args: &Args, bins: &Arc<Bins>, root: &Path, report: &mut Value) -> Vec<Check> {
    let records = args.sizes(&args.records, &[1000, 10_000]);
    let epochs = args.sizes(&args.epochs, &[1, 20]);
    let labels = args.sizes(&args.labels, &[0, 10_000]);
    let labeler_count = args.labelers.unwrap_or(2);
    let domains = args.size(args.domains_per_cell, 100);
    let percent = args.changed_percent(10);
    assert!(
        epochs.iter().all(|&count| count >= 1),
        "--epochs counts the ingest Epoch, so each value is at least 1"
    );
    assert!(
        labeler_count > 0 || labels.iter().all(|&count| count == 0),
        "--labels above 0 needs at least one labeler"
    );
    report["parameters"] = json!({
        "records": records,
        "epochs": epochs,
        "labels": labels,
        "labelers": labeler_count,
        "domains_per_cell": domains,
        "probe_pages": PROBE_PAGES,
        "changed_percent": percent,
        "round_bound_seconds": args.round_bound().as_secs(),
    });
    let mut cells = Vec::new();
    let mut longest_write_lock_ms = None;
    let mut peaks: BTreeMap<MemoryCell, (Option<u64>, Option<u64>)> = BTreeMap::new();
    for (record_count, epoch_count, label_count) in memory_cells(&records, &epochs, &labels) {
        let cell_root = root.join(format!("cell-{record_count}-{epoch_count}-{label_count}"));
        std::fs::create_dir_all(&cell_root).expect("create the cell directory");
        let pages = record_count.div_ceil(domains);
        let sites = make_sites(&cell_root, 0, domains);
        let probe = Site::new(&cell_root, &host_name(domains), "default");
        let labelers = if label_count > 0 {
            make_sites(&cell_root, domains + 1, labeler_count)
        } else {
            Vec::new()
        };
        for site in &sites {
            write_pages(site, pages, args.body_words(), 1);
        }
        write_pages(&probe, PROBE_PAGES, args.body_words(), 1);
        for labeler in &labelers {
            write_pages(labeler, 1, args.body_words(), 1);
        }
        let served: Vec<&Site> = sites
            .iter()
            .chain(std::iter::once(&probe))
            .chain(&labelers)
            .collect();
        let mut h = Harness::start(bins, &cell_root, &served, args);
        let mut cell_report = json!({ "stages": {} });
        let subjects: Vec<String> = sites
            .iter()
            .flat_map(|site| page_urls(site, pages))
            .collect();
        let domain_sites: Vec<&Site> = sites.iter().chain(std::iter::once(&probe)).collect();
        h.establish(&domain_sites, &labelers, &probe.host, &mut cell_report);
        let labeling = if label_count > 0 {
            h.label_and_seal(&labelers, &subjects, label_count)
        } else {
            Value::Null
        };
        let labels_sealed = labeling["labels_sealed"].as_u64().unwrap_or(0);
        let label_epochs = labeling["label_epochs"].as_u64().unwrap_or(0) as usize;
        let data = h.aggregator.data.clone();
        let clave = &bins.clave;
        for _ in 1..epoch_count {
            let at = h.clock.next();
            let extra = run_measured(
                clave,
                &["seal", "--data", s(&data), "--at", &at, "--no-snapshot"],
            );
            h.write_lock_window(Some(&extra.stdout));
        }
        h.sealed = log_tree_size(&data);

        let changed = changed_count(PROBE_PAGES, percent);
        let (probe_pull, pull_increase) = measure_probe_pull(&mut h, &probe, changed, 1);
        let probe_seal = h.seal();
        let empty_seal = run_measured(
            clave,
            &[
                "seal",
                "--data",
                s(&data),
                "--at",
                &h.clock.next(),
                "--no-snapshot",
            ],
        );
        let empty_seal_write_lock_ms = h.write_lock_window(Some(&empty_seal.stdout));
        let snapshot = run_measured(clave, &["snapshot", "--data", s(&data)]);
        let store = cell_root.join("graven-store");
        let anchor = data.join("anchor.json");
        let consumer = run_measured(&bins.graven, &sync_args(&anchor, h.base(), &store, true));
        h.aggregator.stop();
        h.aggregator.start(clave, Some(&h.proxy));
        let (restarted_pull, _) = measure_probe_pull(&mut h, &probe, changed, 2);
        longest_write_lock_ms = longest_write_lock_ms.max(h.run_longest_write_lock_ms());
        println!(
                "memory cell {record_count} records x {epoch_count} Epochs x {label_count} Labels ({labels_sealed} sealed over {label_epochs} more Epochs): pull peak {} kB, increase {pull_increase:?} kB ({} kB after a restart), empty seal peak {:?} kB, snapshot peak {:?} kB, consumer cold start peak {:?} kB",
                probe_pull["aggregator_peak_rss_kb"], restarted_pull["aggregator_rss_increase_kb"], empty_seal.peak_rss_kb, snapshot.peak_rss_kb, consumer.peak_rss_kb
            );
        peaks.insert(
            (record_count, epoch_count, label_count),
            (pull_increase, empty_seal.peak_rss_kb),
        );
        cells.push(json!({
            "records": pages * domains,
            "epochs": epoch_count,
            "labels": label_count,
            "labels_sealed": labels_sealed,
            "labelers": labelers.len(),
            "epochs_before_probe": epoch_count + label_epochs,
            "labeling": labeling,
            "domains": domains,
            "pages_per_domain": pages,
            "publish": cell_report["stages"]["publish"],
            "ingest": cell_report["stages"]["ingest"],
            "probe_pull": probe_pull,
            "probe_pull_after_restart": restarted_pull,
            "probe_seal": probe_seal.report,
            "empty_seal": {
                "seconds": empty_seal.seconds,
                "seal_seconds": e2e::reported_seconds(&empty_seal.stdout, "seal took "),
                "peak_rss_kb": empty_seal.peak_rss_kb,
                "longest_write_lock_ms": empty_seal_write_lock_ms,
            },
            "unchanged_snapshot": snapshot_report(&snapshot),
            "consumer_cold_start": consumer_report(&consumer, &store),
        }));
    }
    let mut checks = Vec::new();
    let fewest_labels = labels.iter().min().copied().unwrap_or(0);
    let (fewest, most) = (records.iter().min(), records.iter().max());
    if let (Some(&fewest), Some(&most)) = (fewest, most) {
        if fewest != most {
            for &epoch_count in &epochs {
                let low = peaks[&(fewest, epoch_count, fewest_labels)].0;
                let high = peaks[&(most, epoch_count, fewest_labels)].0;
                checks.push(ratio_check(
                    &format!("one_domain_pull_increase_flat_in_records_at_{epoch_count}_epochs"),
                    low,
                    high,
                    1.5,
                    RATIO_FLOOR_KB,
                    &format!("the aggregator's resident size increase over the pull (peak minus the size before it) at {most} records against {fewest}, no full-state replication in a pull (meta ADR-0005, Per-worker resources: memory independent of U, B and R)"),
                ));
            }
        }
    }
    let (fewest, most) = (epochs.iter().min(), epochs.iter().max());
    if let (Some(&fewest), Some(&most)) = (fewest, most) {
        if fewest != most {
            for &record_count in &records {
                let low = peaks[&(record_count, fewest, fewest_labels)].1;
                let high = peaks[&(record_count, most, fewest_labels)].1;
                checks.push(ratio_check(
                    &format!("empty_seal_peak_flat_in_epochs_at_{record_count}_records"),
                    low,
                    high,
                    1.1,
                    0,
                    &format!(
                        "the empty seal's peak resident set size at {most} Epochs against {fewest}"
                    ),
                ));
            }
        }
    }
    let fewest_cell = records.iter().min().zip(epochs.iter().min());
    let most_labels = labels.iter().max().copied().unwrap_or(0);
    if let Some((&record_count, &epoch_count)) = fewest_cell {
        if most_labels != fewest_labels {
            let low = peaks[&(record_count, epoch_count, fewest_labels)];
            let high = peaks[&(record_count, epoch_count, most_labels)];
            checks.push(ratio_check(
                "one_domain_pull_increase_flat_in_labels",
                low.0,
                high.0,
                1.5,
                RATIO_FLOOR_KB,
                &format!("the aggregator's resident size increase over the probe pull (peak minus the size before it) at {most_labels} Labels against {fewest_labels}, at {record_count} records and {epoch_count} Epochs; a publisher's pull loads only its own publishers' sealed Label IDs (WIST-2 §3.3), not the Log's"),
            ));
            checks.push(per_label_check(
                "empty_seal_peak_per_label_bounded",
                low.1,
                high.1,
                most_labels - fewest_labels,
                10.0,
                &format!("the empty seal's peak resident set size growth from {fewest_labels} to {most_labels} Labels, at {record_count} records and {epoch_count} Epochs, per Label; the seal's judgment holds the Log's sealed Labels (ID set and subject map), about 2–3 kB per Label measured for an empty seal"),
            ));
        }
    }
    report["stages"]["memory"] = json!({ "cells": cells });
    report["longest_write_lock_ms"] = json!(longest_write_lock_ms);
    checks
}

type MemoryCell = (usize, usize, usize);

fn memory_cells(records: &[usize], epochs: &[usize], labels: &[usize]) -> Vec<MemoryCell> {
    let fewest_labels = labels.iter().min().copied().unwrap_or(0);
    let mut cells: Vec<MemoryCell> = records
        .iter()
        .flat_map(|&record_count| {
            epochs
                .iter()
                .map(move |&epoch_count| (record_count, epoch_count, fewest_labels))
        })
        .collect();
    if let (Some(&record_count), Some(&epoch_count)) = (records.iter().min(), epochs.iter().min()) {
        let further: BTreeSet<usize> = labels
            .iter()
            .copied()
            .filter(|&count| count != fewest_labels)
            .collect();
        cells.extend(
            further
                .into_iter()
                .map(|label_count| (record_count, epoch_count, label_count)),
        );
    }
    cells
}

fn per_label_check(
    name: &str,
    low: Option<u64>,
    high: Option<u64>,
    labels: usize,
    bound_kb: f64,
    compared: &str,
) -> Check {
    let per_label = low
        .zip(high)
        .filter(|_| labels > 0)
        .map(|(low, high)| (high as f64 - low as f64) / labels as f64);
    Check::new(
        name,
        per_label.is_some_and(|kb| kb <= bound_kb),
        json!({
            "smaller_kb": low,
            "larger_kb": high,
            "labels": labels,
            "kb_per_label": per_label,
        }),
        format!("{compared} <= {bound_kb} kB per Label"),
    )
}

fn ratio_check(
    name: &str,
    low: Option<u64>,
    high: Option<u64>,
    factor: f64,
    floor_kb: u64,
    compared: &str,
) -> Check {
    let ratio = match (low, high) {
        (Some(low), Some(high)) => Some(high as f64 / low.max(1) as f64),
        _ => None,
    };
    let within = low
        .zip(high)
        .is_some_and(|(low, high)| high as f64 <= factor * low as f64 + floor_kb as f64);
    let bound = if floor_kb > 0 {
        format!("{compared} <= {factor} x the smaller plus {floor_kb} kB")
    } else {
        format!("{compared} <= {factor} x the smaller")
    };
    Check::new(
        name,
        within,
        json!({ "smaller_kb": low, "larger_kb": high, "ratio": ratio }),
        bound,
    )
}

fn main() {
    let args = args();
    let scenario = args.scenario();
    assert!(
        !args.seal_during_pulls || matches!(scenario, Scenario::Skew),
        "--seal-during-pulls applies to skew only"
    );
    let bins = Arc::new(Bins {
        spake: resolve_sibling_bin("SPAKE_BIN", "spake"),
        clave: resolve_sibling_bin("CLAVE_BIN", "clave"),
        graven: graven_bin(),
    });
    let mut report = json!({
        "scenario": scenario.name(),
        "quick": args.quick,
        "arguments": std::env::args().skip(1).collect::<Vec<_>>(),
        "body_words": args.body_words(),
        "build_profile": e2e::build_profile(),
        "revisions": revisions(),
        "started_at": now_rfc3339(),
        "stages": {},
    });
    let tmp = match &args.work_dir {
        Some(dir) => tempfile::Builder::new().tempdir_in(dir),
        None => tempfile::tempdir(),
    }
    .expect("tempdir");
    let (_tmp_guard, root) = if args.keep {
        let root = tmp.keep();
        eprintln!("work directory: {}", root.display());
        (None, root)
    } else {
        let root = tmp.path().to_path_buf();
        (Some(tmp), root)
    };
    let (checks, seconds) = timed(|| match scenario {
        Scenario::Skew => skew(&args, &bins, &root, &mut report),
        Scenario::Backfill => backfill(&args, &bins, &root, &mut report),
        Scenario::Hosts => hosts(&args, &bins, &root, &mut report),
        Scenario::Saturation => saturation(&args, &bins, &root, &mut report),
        Scenario::Drainage => drainage(&args, &bins, &root, &mut report),
        Scenario::Memory => memory(&args, &bins, &root, &mut report),
    });
    report["seconds"] = json!(seconds);
    report["stages"][scenario.name()]["checks"] =
        Value::Array(checks.iter().map(Check::report).collect());
    for check in &checks {
        println!(
            "{} {}: observed {} (bound: {})",
            if check.pass { "PASS" } else { "FAIL" },
            check.name,
            check.observed,
            check.bound
        );
    }
    let text = serde_json::to_string_pretty(&report).expect("report");
    match &args.out {
        Some(out) => std::fs::write(out, text).expect("write report"),
        None => println!("{text}"),
    }
    let failed: Vec<&Check> = checks.iter().filter(|check| !check.pass).collect();
    if !failed.is_empty() {
        for check in failed {
            eprintln!(
                "check failed: {}: observed {} (bound: {})",
                check.name, check.observed, check.bound
            );
        }
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};

    fn parsed(flags: &[&str]) -> Args {
        parse_args(flags.iter().map(|flag| flag.to_string()))
    }

    #[test]
    fn scenario_parses_each_name() {
        for name in [
            "skew",
            "backfill",
            "hosts",
            "saturation",
            "drainage",
            "memory",
        ] {
            assert_eq!(Scenario::parse(name).name(), name);
        }
    }

    #[test]
    #[should_panic(expected = "--scenario takes skew")]
    fn scenario_refuses_another_name() {
        Scenario::parse("baseline");
    }

    #[test]
    fn quick_halves_the_defaults_but_not_a_given_size() {
        let quick = parsed(&["--scenario", "skew", "--quick", "--pages", "7"]);
        assert_eq!(quick.size(quick.domains, 200), 100);
        assert_eq!(quick.size(quick.pages, 50), 7);
        assert_eq!(quick.size(None, 5), 3);
        assert_eq!(quick.size(None, 1), 1);
        let full = parsed(&["--scenario", "skew"]);
        assert_eq!(full.size(full.domains, 200), 200);
    }

    #[test]
    fn quick_halves_a_default_list_but_not_a_given_one() {
        let quick = parsed(&["--scenario", "memory", "--quick", "--epochs", "1,3"]);
        assert_eq!(quick.sizes(&quick.records, &[1000, 10_000]), [500, 5000]);
        assert_eq!(quick.sizes(&quick.epochs, &[1, 20]), [1, 3]);
    }

    #[test]
    fn flags_parse_into_their_fields() {
        let args = parsed(&[
            "--scenario",
            "hosts",
            "--slow",
            "2",
            "--delay-ms",
            "150",
            "--status-bound-ms",
            "250.5",
            "--out",
            "report.json",
        ]);
        assert_eq!(args.scenario(), Scenario::Hosts);
        assert_eq!(args.slow, Some(2));
        assert_eq!(args.delay_ms, Some(150));
        assert_eq!(args.status_bound_ms(), 250.5);
        assert_eq!(args.out, Some(PathBuf::from("report.json")));
        assert_eq!(args.round_bound(), Duration::from_secs(300));
    }

    #[test]
    fn labels_parse_as_a_list_and_quick_halves_their_default() {
        let given = parsed(&["--scenario", "memory", "--labels", "0,300"]);
        assert_eq!(given.sizes(&given.labels, &[0, 10_000]), [0, 300]);
        let quick = parsed(&["--scenario", "memory", "--quick"]);
        assert_eq!(quick.sizes(&quick.labels, &[0, 10_000]), [0, 5000]);
    }

    #[test]
    fn memory_cells_cross_records_and_epochs_at_the_fewest_labels_and_add_one_cell_per_further_label_count(
    ) {
        assert_eq!(
            memory_cells(&[1000, 10_000], &[1, 20], &[0, 10_000]),
            [
                (1000, 1, 0),
                (1000, 20, 0),
                (10_000, 1, 0),
                (10_000, 20, 0),
                (1000, 1, 10_000),
            ]
        );
        assert_eq!(
            memory_cells(&[500], &[3, 1], &[200, 100, 200, 50]),
            [(500, 3, 50), (500, 1, 50), (500, 1, 100), (500, 1, 200)]
        );
        assert_eq!(memory_cells(&[500], &[1], &[0]), [(500, 1, 0)]);
    }

    #[test]
    fn per_label_check_bounds_the_growth_per_label_and_fails_without_a_peak() {
        let check = per_label_check("p", Some(1000), Some(101_000), 10_000, 10.0, "x");
        assert!(check.pass);
        assert_eq!(check.observed["kb_per_label"], 10.0);
        assert!(!per_label_check("p", Some(1000), Some(101_001), 10_000, 10.0, "x").pass);
        assert!(per_label_check("p", Some(2000), Some(1000), 10, 10.0, "x").pass);
        assert!(!per_label_check("p", None, Some(1000), 10, 10.0, "x").pass);
        assert!(!per_label_check("p", Some(1000), Some(1000), 0, 10.0, "x").pass);
    }

    #[test]
    fn rejections_after_counts_every_code_dated_after_the_instant() {
        let status = json!({"rejections": [
            {"code": "WIST2-E01", "at": "2026-10-14T10:00:00Z"},
            {"code": "WIST2-E08", "at": "2026-10-14T10:00:01Z"},
            {"code": "WIST2-E01", "at": "2026-10-14T12:00:00Z"},
        ]});
        assert_eq!(rejections_after(&status, "2026-10-14T10:00:00Z"), 2);
        assert_eq!(rejections_after(&status, "2026-10-14T12:00:00Z"), 0);
        assert_eq!(rejections_after(&json!({}), ""), 0);
    }

    fn outcome_with(peak: Option<u64>, rejected: u64) -> RoundOutcome {
        RoundOutcome {
            report: json!({ "aggregator_peak_rss_kb": peak, "rejected_pulls": rejected }),
            sealed: Sealed {
                report: Value::Null,
                entries: Vec::new(),
                seconds: 0.0,
                wall_seconds: 0.0,
                octets: 0,
                longest_write_lock_ms: None,
            },
            pulled: BTreeMap::new(),
            expected: Vec::new(),
            seconds: 0.0,
            status_p99_ms: None,
        }
    }

    #[test]
    fn over_rounds_states_the_peak_spread_and_totals_the_rejected_pulls() {
        let outcomes = [
            outcome_with(Some(100), 1),
            outcome_with(None, 0),
            outcome_with(Some(300), 2),
        ];
        let (peaks, rejected) = over_rounds(&outcomes);
        assert_eq!(peaks, json!({"min": 100, "max": 300, "mean": 200.0}));
        assert_eq!(rejected, 3);
        let (peaks, rejected) = over_rounds(&[]);
        assert_eq!(peaks, json!({"min": null, "max": null, "mean": null}));
        assert_eq!(rejected, 0);
    }

    #[test]
    #[should_panic(expected = "unknown flag --update-by")]
    fn an_unknown_flag_is_refused() {
        parsed(&["--update-by", "chain"]);
    }

    #[test]
    fn skew_plan_gives_the_top_percent_of_domains_half_the_changed_pages() {
        let plan = skew_plan(200, 50, 10, 3);
        assert_eq!(plan.heavy, 2);
        assert_eq!(plan.heavy_pages, 250);
        assert_eq!(plan.counts.len(), 200);
        assert_eq!(plan.counts[..2].iter().sum::<usize>(), 500);
        assert_eq!(plan.counts[2..].iter().sum::<usize>(), 500);
        assert!(plan.counts[2..].iter().all(|&count| count <= 50));
    }

    #[test]
    fn skew_plan_keeps_one_heavy_domain_below_a_hundred_domains() {
        let plan = skew_plan(10, 4, 50, 0);
        assert_eq!(plan.heavy, 1);
        assert_eq!(plan.counts.iter().sum::<usize>(), 20);
        assert_eq!(plan.counts[0], 10);
        assert_eq!(plan.heavy_pages, 10);
        let alone = skew_plan(1, 4, 50, 0);
        assert_eq!(alone.counts, [2]);
    }

    #[test]
    fn spread_keeps_the_total_and_rotates_the_remainder() {
        for round in 0..4 {
            let counts = spread(7, 3, round);
            assert_eq!(counts.iter().sum::<usize>(), 7);
            assert!(counts.iter().all(|&count| count == 2 || count == 3));
        }
        assert_ne!(spread(7, 3, 0), spread(7, 3, 1));
        assert!(spread(5, 0, 0).is_empty());
    }

    #[test]
    fn changed_indices_rotate_between_rounds_without_repeats() {
        assert_eq!(changed_indices(2, 5, 0), [0, 1]);
        assert_eq!(changed_indices(2, 5, 2), [4, 0]);
        assert_eq!(changed_indices(9, 3, 1), [0, 1, 2]);
        assert_eq!(changed_count(20, 10), 2);
        assert_eq!(changed_count(5, 10), 1);
    }

    #[test]
    fn clock_advances_one_cadence_per_seal_and_never_falls_behind_the_wall_clock() {
        let mut clock = Clock { last: None };
        let now = 1_800_000_100;
        let first = clock.next_at(now);
        assert_eq!(first, 1_800_003_600);
        assert_eq!(clock.next_at(now + 10), first + 3600);
        clock.skip(3);
        assert_eq!(clock.next_at(now + 20), first + 5 * 3600);
        let late = first + 9 * 3600 + 5;
        assert_eq!(clock.next_at(late), first + 10 * 3600);
        assert_eq!(instant(first), "2027-01-15T09:00:00Z");
        assert_eq!(
            clock.effective_after_grace(late),
            first + 12 * 3600 + 7 * 86_400
        );
    }

    #[test]
    fn percentile_takes_the_nearest_rank() {
        let samples: Vec<f64> = (1..=200).map(f64::from).collect();
        assert_eq!(percentile(&samples, 50.0), Some(100.0));
        assert_eq!(percentile(&samples, 99.0), Some(198.0));
        assert_eq!(percentile(&[4.0], 99.0), Some(4.0));
        assert_eq!(percentile(&[], 50.0), None);
    }

    #[test]
    fn latency_report_states_p50_p99_max_and_errors() {
        let report = latency_report(vec![3.0, 1.0, 2.0], 4);
        assert_eq!(
            report,
            json!({
                "samples": 3,
                "errors": 4,
                "p50_ms": 2.0,
                "p99_ms": 3.0,
                "max_ms": 3.0,
            })
        );
    }

    #[test]
    fn epoch_octets_counts_each_entry_serialization_plus_two() {
        let entries = [json!({"b": 1, "a": "x"}), json!({"type": "label"})];
        let jcs: u64 = entries
            .iter()
            .map(|e| wist_core::jcs::canonicalize(e).expect("jcs").len() as u64)
            .sum();
        assert_eq!(epoch_octets(&entries), jcs + 4);
    }

    #[test]
    fn governance_and_labels_keeps_the_entry_types_other_than_publications() {
        let log_entries = json!({
            "publisher_item": { "entries": 3 },
            "publisher_catalog": { "entries": 1 },
            "label": { "entries": 2 },
            "registry_update": { "entries": 1 },
            "all": { "entries": 7 },
            "from": 0,
            "to": 7,
        });
        assert_eq!(
            governance_and_labels(&log_entries),
            json!({
                "label": { "entries": 2 },
                "registry_update": { "entries": 1 },
            })
        );
    }

    #[test]
    fn entry_host_names_the_publisher_or_labeler_counted_toward_a_domain() {
        let item = json!({"type": "publisher_item", "body": {"item": {"publisher": "a"}}});
        let catalog = json!({"type": "publisher_catalog", "body": {"catalog": {"publisher": "b"}}});
        let label = json!({"type": "label", "body": {"label": {"labeler": "c"}}});
        let declaration = json!({"type": "publisher_declaration", "body": {}});
        assert_eq!(entry_host(&item), Some("a"));
        assert_eq!(entry_host(&catalog), Some("b"));
        assert_eq!(entry_host(&label), Some("c"));
        assert_eq!(entry_host(&declaration), None);
        let entries = [item.clone(), item, catalog, label];
        assert_eq!(domain_entries(&entries, "a"), 2);
    }

    #[test]
    fn rejected_since_finds_only_a_later_rejection_of_the_code() {
        let status = json!({"rejections": [
            {"code": "WIST2-E01", "at": "2026-10-14T10:00:00Z"},
            {"code": "WIST2-E08", "at": "2026-10-14T12:00:00Z"},
        ]});
        assert!(rejected_since(&status, "WIST2-E01", "2026-10-14T09:59:59Z"));
        assert!(!rejected_since(
            &status,
            "WIST2-E01",
            "2026-10-14T10:00:00Z"
        ));
        assert!(!rejected_since(&json!({}), "WIST2-E01", ""));
    }

    #[test]
    fn ratio_check_passes_within_the_factor_plus_the_floor_and_fails_without_a_peak() {
        assert!(ratio_check("r", Some(100_000), Some(158_192), 1.5, 8192, "x").pass);
        assert!(!ratio_check("r", Some(100_000), Some(158_193), 1.5, 8192, "x").pass);
        assert!(!ratio_check("r", None, Some(1), 1.5, 8192, "x").pass);
        assert!(!ratio_check("r", Some(1), None, 1.5, 8192, "x").pass);
        assert!(ratio_check("r", Some(0), Some(8192), 1.5, 8192, "x").pass);
        assert!(!ratio_check("r", Some(0), Some(8193), 1.5, 8192, "x").pass);
        assert!(!ratio_check("r", Some(100), Some(111), 1.1, 0, "x").pass);
        let report = ratio_check("r", Some(100), Some(110), 1.1, 0, "x").report();
        assert_eq!(report["name"], "r");
        assert_eq!(report["observed"]["smaller_kb"], 100);
        assert_eq!(report["observed"]["larger_kb"], 110);
        assert_eq!(report["observed"]["ratio"], 1.1);
        assert!(report["bound"]
            .as_str()
            .is_some_and(|bound| bound.ends_with("<= 1.1 x the smaller")));
        let floored = ratio_check("r", Some(0), Some(1), 1.5, 8192, "x").report();
        assert!(floored["bound"]
            .as_str()
            .is_some_and(|bound| bound.ends_with("<= 1.5 x the smaller plus 8192 kB")));
    }

    fn admission_server(refusals: usize) -> (String, Arc<AtomicUsize>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr").to_string();
        let seen = Arc::new(AtomicUsize::new(0));
        let counted = seen.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut reader = BufReader::new(stream.try_clone().expect("clone"));
                let mut length = 0;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line.trim().is_empty() {
                        break;
                    }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = value.trim().parse().unwrap_or(0);
                    }
                }
                let mut body = vec![0; length];
                let _ = reader.read_exact(&mut body);
                let answer: &[u8] = if counted.fetch_add(1, Ordering::Relaxed) < refusals {
                    b"HTTP/1.1 503 Service Unavailable\r\nRetry-After: 0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                } else {
                    b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                };
                let _ = stream.write_all(answer);
            }
        });
        (format!("http://{addr}"), seen)
    }

    #[test]
    fn flood_counts_admitted_and_refused_pings_and_reping_admits_the_refused_later() {
        let (base, seen) = admission_server(3);
        let hosts: Vec<String> = (0..8).map(host_name).collect();
        let flooded = flood(&base, &hosts, 4);
        assert_eq!(flooded.admitted, 5);
        assert_eq!(flooded.refused.len(), 3);
        assert!(flooded.errors.is_empty());
        let reping = reping_after_retry_after(
            &base,
            flooded.refused,
            Instant::now() + Duration::from_secs(10),
        );
        assert_eq!(reping.admitted, 3);
        assert_eq!(reping.refusals, 0);
        assert!(reping.unadmitted.is_empty());
        assert_eq!(seen.load(Ordering::Relaxed), 11);
    }

    #[test]
    fn reping_gives_up_on_a_host_due_after_the_deadline() {
        let (base, _) = admission_server(0);
        let late = Instant::now() + Duration::from_secs(60);
        let reping = reping_after_retry_after(
            &base,
            vec![("127.0.1.1".into(), late)],
            Instant::now() + Duration::from_secs(1),
        );
        assert_eq!(reping.admitted, 0);
        assert_eq!(reping.unadmitted, ["127.0.1.1"]);
    }

    fn json_server(body: Value) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr").to_string();
        let body = body.to_string();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut reader = BufReader::new(stream.try_clone().expect("clone"));
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line.trim().is_empty() {
                        break;
                    }
                }
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        format!("http://{addr}")
    }

    #[test]
    fn status_check_fails_a_round_without_a_p99() {
        assert!(status_check("s", &[Some(1.0), Some(2.0)], 500.0).pass);
        let missing = status_check("s", &[Some(1.0), None], 500.0);
        assert!(!missing.pass);
        assert_eq!(missing.observed["rounds_without_p99"], 1);
        assert!(!status_check("s", &[Some(600.0)], 500.0).pass);
    }

    #[test]
    fn a_failed_status_request_is_sampled_at_the_client_timeout() {
        let (base, _) = admission_server(usize::MAX);
        let sampler = StatusSampler::start(&base, "127.0.1.1");
        std::thread::sleep(Duration::from_millis(400));
        let report = sampler.finish();
        assert!(report["errors"].as_u64().is_some_and(|errors| errors > 0));
        assert_eq!(report["samples"], report["errors"]);
        assert_eq!(report["max_ms"], STATUS_TIMEOUT.as_secs_f64() * 1000.0);
    }

    #[test]
    fn failure_watch_times_the_rejection_from_the_last_ping_and_the_retry_from_the_rejection() {
        let base = json_server(json!({
            "rejections": [{ "code": "WIST2-E01", "at": "2026-10-14T10:00:01Z" }],
        }));
        let failures = Arc::new(std::sync::atomic::AtomicU64::new(1));
        let watch = FailureWatch {
            http: reqwest::blocking::Client::new(),
            base,
            since: BTreeMap::from([("h".to_string(), "2026-10-14T10:00:00Z".to_string())]),
            counters: BTreeMap::from([("h".to_string(), failures.clone())]),
            last_ping: Instant::now(),
            record_bound: Duration::from_secs(5),
            retry_wait: Duration::from_secs(5),
        };
        let watcher = std::thread::spawn(move || watch.run());
        std::thread::sleep(Duration::from_millis(800));
        failures.fetch_add(1, Ordering::Relaxed);
        let outcome = watcher.join().expect("watcher");
        let failed = &outcome["h"];
        assert!(failed.recorded.is_some_and(|seconds| seconds < 0.8));
        assert!(failed
            .retried_after
            .is_some_and(|seconds| seconds > 0.3 && seconds < 2.0));
    }

    #[test]
    fn failure_watch_gives_up_on_a_host_whose_rejection_never_appears() {
        let base = json_server(json!({ "rejections": [] }));
        let watch = FailureWatch {
            http: reqwest::blocking::Client::new(),
            base,
            since: BTreeMap::from([("h".to_string(), "2026-10-14T10:00:00Z".to_string())]),
            counters: BTreeMap::from([(
                "h".to_string(),
                Arc::new(std::sync::atomic::AtomicU64::new(0)),
            )]),
            last_ping: Instant::now(),
            record_bound: Duration::from_millis(500),
            retry_wait: Duration::from_secs(5),
        };
        let outcome = watch.run();
        assert!(outcome["h"].recorded.is_none());
        assert!(outcome["h"].retried_after.is_none());
    }

    #[test]
    fn parallel_visits_every_item_once() {
        let items: Vec<usize> = (0..50).collect();
        let seen = Mutex::new(Vec::new());
        parallel(&items, |item| seen.lock().expect("lock").push(*item));
        let mut seen = seen.into_inner().expect("seen");
        seen.sort();
        assert_eq!(seen, items);
    }
}
