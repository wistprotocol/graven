use e2e::{
    fetch_status, free_loopback_addr, graven_bin, grid_instant, now_rfc3339, resolve_sibling_bin,
    run, s, seal_epoch, serve_sites_counted, spawn_clave_serve_with, wait_until_after,
    LoggedRequest, RequestLog, Site,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpdateBy {
    Chain,
    Walk,
}

impl UpdateBy {
    fn parse(value: &str) -> Self {
        match value {
            "chain" => UpdateBy::Chain,
            "walk" => UpdateBy::Walk,
            other => panic!("--update-by takes chain or walk, not {other}"),
        }
    }

    fn name(self) -> &'static str {
        match self {
            UpdateBy::Chain => "chain",
            UpdateBy::Walk => "walk",
        }
    }
}

struct Args {
    domains: usize,
    pages: usize,
    large_domains: usize,
    large_pages: usize,
    changed_percent: usize,
    body_words: usize,
    tier1: bool,
    extra_empty_seals: usize,
    snapshot_shards: Option<i64>,
    skip_consumer: bool,
    compare_rebuild: bool,
    withdraw: bool,
    update_by: UpdateBy,
    tree_bound: bool,
    tree_bound_items: usize,
    work_dir: Option<PathBuf>,
    keep: bool,
    out: Option<PathBuf>,
}

fn args() -> Args {
    let mut args = Args {
        domains: 10,
        pages: 20,
        large_domains: 0,
        large_pages: 0,
        changed_percent: 10,
        body_words: 200,
        tier1: true,
        extra_empty_seals: 0,
        snapshot_shards: None,
        skip_consumer: false,
        compare_rebuild: false,
        withdraw: false,
        update_by: UpdateBy::Chain,
        tree_bound: false,
        tree_bound_items: 1024,
        work_dir: None,
        keep: false,
        out: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || it.next().unwrap_or_else(|| panic!("{flag} needs a value"));
        match flag.as_str() {
            "--domains" => args.domains = value().parse().expect("--domains"),
            "--pages" => args.pages = value().parse().expect("--pages"),
            "--large-domains" => args.large_domains = value().parse().expect("--large-domains"),
            "--large-pages" => args.large_pages = value().parse().expect("--large-pages"),
            "--changed-percent" => {
                args.changed_percent = value().parse().expect("--changed-percent")
            }
            "--body-words" => args.body_words = value().parse().expect("--body-words"),
            "--no-tier1" => args.tier1 = false,
            "--skip-consumer" => args.skip_consumer = true,
            "--extra-empty-seals" => {
                args.extra_empty_seals = value().parse().expect("--extra-empty-seals")
            }
            "--snapshot-shards" => {
                args.snapshot_shards = Some(value().parse().expect("--snapshot-shards"))
            }
            "--compare-rebuild" => args.compare_rebuild = true,
            "--withdraw" => args.withdraw = true,
            "--update-by" => args.update_by = UpdateBy::parse(&value()),
            "--tree-bound" => args.tree_bound = true,
            "--tree-bound-items" => {
                args.tree_bound_items = value().parse().expect("--tree-bound-items")
            }
            "--work-dir" => args.work_dir = Some(PathBuf::from(value())),
            "--keep" => args.keep = true,
            "--out" => args.out = Some(PathBuf::from(value())),
            other => panic!("unknown flag {other}"),
        }
    }
    args
}

fn words(seed: u64, count: usize) -> String {
    let mut x = seed
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    let mut out = String::new();
    for i in 0..count {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let len = 3 + (x % 8) as usize;
        for k in 0..len {
            out.push((b'a' + ((x >> (k * 5)) % 26) as u8) as char);
        }
        out.push(if i % 17 == 16 { '.' } else { ' ' });
    }
    out
}

fn page(host: &str, j: usize, body_words: usize, revision: u64) -> String {
    format!(
        "<html lang=\"en\"><head><title>Page {j} of {host}</title><meta name=\"wist\" content=\"publish\"></head><body><!--wist:content--><h1>Page {j}</h1><p>{}</p><!--/wist:content--></body></html>",
        words(revision * 1_000_003 + j as u64, body_words)
    )
}

fn write_pages(site: &Site, pages: usize, body_words: usize, revision: u64) {
    for j in 0..pages {
        site.write_page(
            &format!("p{j}.html"),
            &page(&site.host, j, body_words, revision),
        );
    }
}

fn dir_bytes(path: &Path) -> u64 {
    let Ok(meta) = std::fs::metadata(path) else {
        return 0;
    };
    if meta.is_file() {
        return meta.len();
    }
    std::fs::read_dir(path)
        .map(|entries| entries.flatten().map(|e| dir_bytes(&e.path())).sum())
        .unwrap_or(0)
}

fn git_revision(repo: &Path) -> String {
    Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(repo)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".into())
}

fn timed<T>(f: impl FnOnce() -> T) -> (T, f64) {
    let start = Instant::now();
    let value = f();
    (value, start.elapsed().as_secs_f64())
}

struct Measured {
    seconds: f64,
    peak_rss_kb: Option<u64>,
    stdout: String,
}

fn drain(pipe: Option<impl Read + Send + 'static>) -> std::thread::JoinHandle<String> {
    let mut pipe = pipe.expect("piped stream");
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = pipe.read_to_end(&mut buf);
        String::from_utf8_lossy(&buf).into_owned()
    })
}

#[cfg(unix)]
fn reap(child: &mut Child) -> (ExitStatus, Option<u64>) {
    use std::os::unix::process::ExitStatusExt;
    let pid = child.id() as libc::pid_t;
    let mut status = 0;
    // SAFETY: rusage is plain old data, so the all-zero value is valid.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    loop {
        // SAFETY: pid is this process's unreaped child and both out-pointers are live locals.
        let reaped = unsafe { libc::wait4(pid, &mut status, 0, &mut usage) };
        if reaped == pid {
            break;
        }
        let err = std::io::Error::last_os_error();
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::Interrupted,
            "wait4 {pid}: {err}"
        );
    }
    let max_rss = u64::try_from(usage.ru_maxrss).unwrap_or(0);
    // ru_maxrss is in bytes on Apple platforms and in kilobytes elsewhere.
    let kb = if cfg!(target_vendor = "apple") {
        max_rss / 1024
    } else {
        max_rss
    };
    (ExitStatus::from_raw(status), Some(kb))
}

#[cfg(not(unix))]
fn reap(child: &mut Child) -> (ExitStatus, Option<u64>) {
    (child.wait().expect("wait for child"), None)
}

fn run_measured(bin: &Path, args: &[&str]) -> Measured {
    let start = Instant::now();
    let mut child = Command::new(bin)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn {} {args:?}: {e}", bin.display()));
    let stdout = drain(child.stdout.take());
    let stderr = drain(child.stderr.take());
    let (status, peak_rss_kb) = reap(&mut child);
    let seconds = start.elapsed().as_secs_f64();
    let stdout = stdout.join().expect("stdout reader");
    let stderr = stderr.join().expect("stderr reader");
    assert!(
        status.success(),
        "{} {args:?} failed: status={status:?}\nstdout={stdout}\nstderr={stderr}",
        bin.display(),
    );
    Measured {
        seconds,
        peak_rss_kb,
        stdout,
    }
}

fn reported_seconds(stdout: &str, prefix: &str) -> Option<f64> {
    stdout.lines().find_map(|line| {
        line.trim()
            .strip_prefix(prefix)?
            .strip_suffix(" ms")?
            .parse::<f64>()
            .ok()
            .map(|ms| ms / 1000.0)
    })
}

fn reported_count(stdout: &str, prefix: &str) -> Option<u64> {
    stdout
        .lines()
        .find_map(|line| line.trim().strip_prefix(prefix)?.parse().ok())
}

fn shards_rebuilt(stdout: &str) -> Option<(u64, u64)> {
    stdout.lines().find_map(|line| {
        let (_, tail) = line
            .trim()
            .strip_prefix("snapshot built at epoch ")?
            .rsplit_once(", ")?;
        let (rebuilt, count) = tail.strip_suffix(" shards rebuilt")?.split_once(" of ")?;
        Some((rebuilt.parse().ok()?, count.parse().ok()?))
    })
}

fn snapshot_outcome(stdout: &str) -> Option<&'static str> {
    stdout.lines().find_map(|line| {
        let line = line.trim();
        [
            ("snapshot built at ", "built"),
            ("snapshot current at ", "current"),
            ("snapshot superseded ", "superseded"),
            ("snapshot not built", "unsealed"),
        ]
        .into_iter()
        .find_map(|(prefix, outcome)| line.starts_with(prefix).then_some(outcome))
    })
}

fn snapshot_report(run: &Measured) -> Value {
    let out = run.stdout.as_str();
    let shards = shards_rebuilt(out);
    json!({
        "outcome": snapshot_outcome(out),
        "seconds": run.seconds,
        "reported_seconds": reported_seconds(out, "snapshot took "),
        "peak_rss_kb": run.peak_rss_kb,
        "shards_rebuilt": shards.map(|(rebuilt, _)| rebuilt),
        "shard_count": shards.map(|(_, count)| count),
        "bytes_written": reported_count(out, "snapshot bytes written "),
        "bytes_reused": reported_count(out, "snapshot bytes reused "),
        "cache_bytes_written": reported_count(out, "snapshot cache bytes written "),
        "payloads_read": reported_count(out, "snapshot payloads read "),
        "payload_bytes_read": reported_count(out, "snapshot payload bytes read "),
    })
}

struct SealStage {
    seal: Measured,
    snapshot: Measured,
    rebuild: Option<Measured>,
}

impl SealStage {
    fn run(clave: &Path, data: &Path, at: &str, compare_rebuild: bool) -> Self {
        let data = s(data);
        let seal = run_measured(
            clave,
            &["seal", "--data", data, "--at", at, "--no-snapshot"],
        );
        let snapshot = run_measured(clave, &["snapshot", "--data", data]);
        let rebuild = compare_rebuild
            .then(|| run_measured(clave, &["snapshot", "--data", data, "--rebuild"]));
        SealStage {
            seal,
            snapshot,
            rebuild,
        }
    }

    fn seal_seconds(&self) -> Option<f64> {
        reported_seconds(&self.seal.stdout, "seal took ")
    }

    fn rebuild_report(&self) -> Value {
        self.rebuild.as_ref().map_or(Value::Null, snapshot_report)
    }

    fn report(&self, data: &Path) -> Value {
        let mut report = json!({
            "seconds": self.seal.seconds + self.snapshot.seconds,
            "seal_seconds": self.seal_seconds(),
            "seal_peak_rss_kb": self.seal.peak_rss_kb,
            "snapshot_seconds": reported_seconds(&self.snapshot.stdout, "snapshot took "),
            "snapshot": snapshot_report(&self.snapshot),
            "snapshot_rebuild": self.rebuild_report(),
            "entry_bundle_bytes": dir_bytes(&data.join("tile/entries")),
            "tile_bytes": dir_bytes(&data.join("tile")),
            "checkpoint_bytes": dir_bytes(&data.join("log/checkpoints")),
            "payloads_bytes": dir_bytes(&data.join("payloads")),
            "data_dir_bytes": dir_bytes(data),
        });
        merge(&mut report, storage_bytes(data));
        report
    }
}

fn storage_bytes(data: &Path) -> Value {
    json!({
        "sqlite_bytes": dir_bytes(&data.join("clave.sqlite")),
        "sqlite_wal_bytes": dir_bytes(&data.join("clave.sqlite-wal")),
        "snapshots_bytes": dir_bytes(&data.join("snapshots")),
        "snapshot_shards_bytes": dir_bytes(&data.join("snapshot-shards")),
        "snapshot_build_bytes": dir_bytes(&data.join("snapshot-build")),
    })
}

fn merge(into: &mut Value, from: Value) {
    let (Value::Object(into), Value::Object(from)) = (into, from) else {
        panic!("merge expects two JSON objects");
    };
    into.extend(from);
}

// WIST-2 §5.3: a chain the Aggregator discards or cannot read is reported and the list is walked.
const PULL_REPORTS_ALLOWED: &[&str] = &["WIST2-E08"];

fn wait_all_pulled(
    http: &reqwest::blocking::Client,
    base: &str,
    hosts: &[String],
    since: &str,
    timeout: Duration,
) -> BTreeMap<String, f64> {
    let start = Instant::now();
    let mut pulled = BTreeMap::new();
    let mut pending: Vec<&String> = hosts.iter().collect();
    while !pending.is_empty() {
        pending.retain(|host| {
            let done = fetch_status(http, base, host).is_some_and(|v| {
                v["rejections"].as_array().is_some_and(|r| {
                    r.iter().all(|rejection| {
                        PULL_REPORTS_ALLOWED.contains(&rejection["code"].as_str().unwrap_or(""))
                    })
                }) && v["last_pull_at"].as_str().is_some_and(|t| t > since)
            });
            if done {
                pulled.insert((*host).clone(), start.elapsed().as_secs_f64());
            }
            !done
        });
        assert!(
            start.elapsed() < timeout,
            "{} of {} domains were not pulled cleanly within {timeout:?}",
            pending.len(),
            hosts.len()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    pulled
}

fn reports_since(
    http: &reqwest::blocking::Client,
    base: &str,
    hosts: &[String],
    since: &str,
    code: &str,
) -> usize {
    hosts
        .iter()
        .filter_map(|host| fetch_status(http, base, host))
        .map(|status| {
            status["rejections"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|rejection| {
                    rejection["code"] == code
                        && rejection["at"].as_str().is_some_and(|at| at > since)
                })
                .count()
        })
        .sum()
}

fn request_kind(path: &str) -> &'static str {
    let Some(rest) = path.strip_prefix(".well-known/wist/") else {
        return "other";
    };
    if rest == "publisher.json" {
        return "declaration";
    }
    if rest == "label-feed.json" || rest.starts_with("label-feed/") {
        return "label_feed";
    }
    let Some((_, object)) = rest
        .strip_prefix("collections/")
        .and_then(|rest| rest.split_once('/'))
    else {
        return "other";
    };
    match object
        .split_once('/')
        .map_or(object, |(directory, _)| directory)
    {
        "catalog.json" => "catalog",
        "changes" => "change_list",
        "tree" => "tree_file",
        "payloads" => "payload",
        _ => "other",
    }
}

fn requests_report(requests: &[LoggedRequest], hosts: &[String], items: usize) -> Value {
    let hosts: BTreeSet<&str> = hosts.iter().map(String::as_str).collect();
    let mut by_kind: BTreeMap<&str, (u64, u64)> = BTreeMap::new();
    for request in requests
        .iter()
        .filter(|request| hosts.contains(request.host.as_str()))
    {
        let counted = by_kind.entry(request_kind(&request.path)).or_default();
        counted.0 += 1;
        counted.1 += request.octets;
    }
    let (count, octets) = by_kind
        .values()
        .fold((0, 0), |(count, octets), (c, o)| (count + c, octets + o));
    let per_item = |total: u64| (items > 0).then(|| total as f64 / items as f64);
    json!({
        "domains": hosts.len(),
        "items": items,
        "site_requests": count,
        "response_octets": octets,
        "requests_per_item": per_item(count),
        "octets_per_item": per_item(octets),
        "by_kind": by_kind
            .iter()
            .map(|(kind, (count, octets))| {
                (kind.to_string(), json!({ "requests": count, "octets": octets }))
            })
            .collect::<serde_json::Map<_, _>>(),
    })
}

fn round_report(
    requests: &[LoggedRequest],
    hosts: &[String],
    items: usize,
    pulled: &BTreeMap<String, f64>,
) -> Value {
    let mut report = requests_report(requests, hosts, items);
    report["seconds_until_all_pulled"] = json!(hosts
        .iter()
        .filter_map(|host| pulled.get(host))
        .copied()
        .fold(0.0, f64::max));
    report
}

struct Round<'a> {
    small: (&'a [String], usize),
    large: (&'a [String], usize),
}

impl Round<'_> {
    fn report(&self, log: &RequestLog, pulled: &BTreeMap<String, f64>) -> Value {
        let requests = log.requests();
        let all: Vec<String> = self.small.0.iter().chain(self.large.0).cloned().collect();
        let mut report = round_report(&requests, &all, self.small.1 + self.large.1, pulled);
        if !self.large.0.is_empty() {
            report["small_domains"] = round_report(&requests, self.small.0, self.small.1, pulled);
            report["large_domains"] = round_report(&requests, self.large.0, self.large.1, pulled);
        }
        report
    }
}

fn reset_peak_rss(pid: u32) {
    // Linux: writing 5 to clear_refs resets the process's peak resident set size (VmHWM).
    let _ = std::fs::write(format!("/proc/{pid}/clear_refs"), "5");
}

fn peak_rss_kb(pid: u32) -> Option<u64> {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()
        .and_then(|status| vm_hwm_kb(&status))
}

fn vm_hwm_kb(status: &str) -> Option<u64> {
    status.lines().find_map(|line| {
        line.strip_prefix("VmHWM:")?
            .trim()
            .strip_suffix("kB")?
            .trim()
            .parse()
            .ok()
    })
}

fn log_tree_size(data: &Path) -> u64 {
    let latest = std::fs::read_dir(data.join("log/checkpoints"))
        .expect("list the archived Checkpoints")
        .flatten()
        .map(|entry| entry.path())
        .max();
    latest.map_or(0, |path| {
        let note = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        wist_core::checkpoint::Checkpoint::parse(&note)
            .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
            .tree_size()
    })
}

fn log_entries_report(data: &Path, from: u64, to: u64) -> Value {
    let mut by_type: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for bundle in wist_core::tiles::entry_bundles_for_range(from, to, to) {
        let path = bundle.path();
        let file = data.join(path.trim_start_matches('/'));
        let octets =
            std::fs::read(&file).unwrap_or_else(|e| panic!("read {}: {e}", file.display()));
        let leaves = wist_core::tiles::decode_entry_bundle_at(&path, &octets)
            .unwrap_or_else(|e| panic!("decode the entry bundle {path}: {e}"));
        let (start, _) = bundle.leaf_range();
        for (offset, leaf) in leaves.iter().enumerate() {
            if !(from..to).contains(&(start + offset as u64)) {
                continue;
            }
            let entry_type = serde_json::from_slice::<Value>(leaf)
                .ok()
                .and_then(|entry| entry["type"].as_str().map(str::to_string))
                .unwrap_or_else(|| "unparsed".into());
            let counted = by_type.entry(entry_type).or_default();
            counted.0 += 1;
            counted.1 += leaf.len() as u64;
        }
    }
    let row = |(entries, octets): (u64, u64)| {
        json!({
            "entries": entries,
            "octets": octets,
            "octets_per_entry": (entries > 0).then(|| octets as f64 / entries as f64),
        })
    };
    let total = by_type.values().fold((0, 0), |(entries, octets), (e, o)| {
        (entries + e, octets + o)
    });
    let mut report: serde_json::Map<String, Value> = by_type
        .into_iter()
        .map(|(entry_type, counted)| (entry_type, row(counted)))
        .collect();
    report.insert("all".into(), row(total));
    report.insert("from".into(), json!(from));
    report.insert("to".into(), json!(to));
    Value::Object(report)
}

fn sealed_stage(
    clave: &Path,
    data: &Path,
    at: &str,
    compare_rebuild: bool,
    sealed: &mut u64,
) -> Value {
    let mut report = SealStage::run(clave, data, at, compare_rebuild).report(data);
    let size = log_tree_size(data);
    report["log_entries"] = log_entries_report(data, *sealed, size);
    *sealed = size;
    report
}

fn delete_change_lists(site: &Site) -> usize {
    let Ok(entries) = std::fs::read_dir(site.collection_dir().join("changes")) else {
        return 0;
    };
    let mut deleted = 0;
    for entry in entries.flatten() {
        std::fs::remove_file(entry.path()).expect("delete a change list");
        deleted += 1;
    }
    deleted
}

fn nibble(key: &[u8; 32], position: usize) -> u8 {
    let byte = key[position / 2];
    if position.is_multiple_of(2) {
        byte >> 4
    } else {
        byte & 0x0f
    }
}

const DEEP_FIRST_DIGITS: u8 = 8;

#[derive(Default)]
struct TreeFiles {
    files: BTreeMap<String, Vec<u8>>,
    inner: usize,
    buckets: usize,
    deepest: u64,
}

impl TreeFiles {
    fn store(&mut self, file: Value, level: u64) -> String {
        let octets = wist_core::jcs::canonicalize(&file).expect("canonicalize a tree file");
        let hex = wist_core::crypto::hex_encode(&Sha256::digest(&octets));
        self.deepest = self.deepest.max(level);
        self.files.insert(hex.clone(), octets);
        format!("sha256:{hex}")
    }

    fn bucket(&mut self, keyed: &[([u8; 32], Value)], level: u64) -> String {
        self.buckets += 1;
        let items: Vec<&Value> = keyed.iter().map(|(_, item)| item).collect();
        self.store(json!({ "items": items }), level)
    }

    fn chain(
        &mut self,
        keyed: &[([u8; 32], Value)],
        prefix: &str,
        level: u64,
        depth_max: u64,
    ) -> String {
        if level >= depth_max {
            return self.bucket(keyed, level);
        }
        let mut children = Vec::new();
        for group in keyed.chunk_by(|(left, _), (right, _)| {
            nibble(left, prefix.len()) == nibble(right, prefix.len())
        }) {
            let child = format!("{prefix}{:x}", nibble(&group[0].0, prefix.len()));
            let file = self.chain(group, &child, level + 1, depth_max);
            children.push(json!({ "prefix": child, "count": group.len(), "file": file }));
        }
        self.inner += 1;
        self.store(json!({ "children": children }), level)
    }
}

struct BoundTree {
    list: Vec<Value>,
    built: wist_core::tree::Built,
    shape: Value,
}

fn bound_tree(template: &Value, host: &str, deep_items: usize) -> BoundTree {
    let bounds = wist_core::tree::TreeBounds::suite();
    let cap = bounds.tree_file_cap_bytes() as usize;
    let depth_max = bounds.tree_depth_max();
    let deep_items = deep_items.max(1);
    let slots = usize::from(16 - DEEP_FIRST_DIGITS);
    let mut deep = Vec::new();
    let mut full: Vec<Vec<([u8; 32], Value)>> = vec![Vec::new(); slots];
    let mut full_octets = vec![r#"{"items":[]}"#.len(); slots];
    let mut closed = vec![false; slots];
    let candidates = std::iter::once(template.clone()).chain((0u64..).map(|n| {
        let mut item = template.clone();
        item["url"] = json!(format!("https://{host}/bound/{n}.html"));
        item
    }));
    for item in candidates {
        if deep.len() >= deep_items && closed.iter().all(|closed| *closed) {
            break;
        }
        let key = wist_core::item::key(item["url"].as_str().expect("an Item's url"));
        let first = nibble(&key, 0);
        if first < DEEP_FIRST_DIGITS {
            if deep.len() < deep_items {
                deep.push((key, item));
            }
            continue;
        }
        let slot = usize::from(first - DEEP_FIRST_DIGITS);
        if closed[slot] {
            continue;
        }
        let added = wist_core::jcs::canonicalize(&item)
            .expect("canonicalize an Item")
            .len()
            + usize::from(!full[slot].is_empty());
        if full_octets[slot] + added > cap {
            closed[slot] = true;
            continue;
        }
        full_octets[slot] += added;
        full[slot].push((key, item));
    }
    let deep_count = deep.len();
    let full_counts: Vec<usize> = full.iter().map(Vec::len).collect();
    let mut keyed: Vec<([u8; 32], Value)> =
        deep.into_iter().chain(full.into_iter().flatten()).collect();
    keyed.sort_by_key(|(key, _)| *key);
    let mut files = TreeFiles::default();
    let mut children = Vec::new();
    for group in keyed.chunk_by(|(left, _), (right, _)| nibble(left, 0) == nibble(right, 0)) {
        let digit = nibble(&group[0].0, 0);
        let prefix = format!("{digit:x}");
        let file = if digit < DEEP_FIRST_DIGITS {
            files.chain(group, &prefix, 2, depth_max)
        } else {
            files.bucket(group, 2)
        };
        children.push(json!({ "prefix": prefix, "count": group.len(), "file": file }));
    }
    files.inner += 1;
    let tree = files.store(json!({ "children": children }), 1);
    let sizes: Vec<usize> = files.files.values().map(Vec::len).collect();
    let shape = json!({
        "items": keyed.len(),
        "deep_items": deep_count,
        "full_bucket_items": full_counts,
        "full_bucket_octets": full_octets,
        "tree_files": files.files.len(),
        "inner_files": files.inner,
        "bucket_files": files.buckets,
        "levels": files.deepest,
        "tree_depth_max": depth_max,
        "largest_file_octets": sizes.iter().max(),
        "tree_file_cap_bytes": cap,
        "tree_octets": sizes.iter().sum::<usize>(),
    });
    BoundTree {
        list: keyed.into_iter().map(|(_, item)| item).collect(),
        built: wist_core::tree::Built {
            tree,
            files: files.files,
        },
        shape,
    }
}

fn after_this_second() -> String {
    let since = now_rfc3339();
    while now_rfc3339() == since {
        std::thread::sleep(Duration::from_millis(50));
    }
    since
}

// WIST-2 §4: the Publisher honors a 503 admission refusal.
fn ping_until_admitted(spake: &Path, clave_base: &str, host: &str) -> u64 {
    let deadline = Instant::now() + Duration::from_secs(600);
    let mut refused = 0;
    loop {
        let output = Command::new(spake)
            .args([
                "ping",
                "--log",
                clave_base,
                "--domain",
                host,
                "--allow-http",
                "--no-retry",
            ])
            .output()
            .unwrap_or_else(|e| panic!("failed to spawn {}: {e}", spake.display()));
        if output.status.success() {
            return refused;
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("503") && Instant::now() < deadline,
            "ping {host} failed: {stderr}"
        );
        refused += 1;
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn host_name(i: usize) -> String {
    format!("127.0.{}.{}", 1 + i / 250, 1 + i % 250)
}

fn sync_args<'a>(anchor: &'a Path, log: &'a str, dir: &'a Path, tier1: bool) -> Vec<&'a str> {
    let mut args = vec![
        "sync",
        "--anchor",
        s(anchor),
        "--log",
        log,
        "--dir",
        s(dir),
        "--allow-http",
    ];
    if tier1 {
        args.push("--tier1");
    }
    args
}

fn consumer_report(run: &Measured, dir: &Path) -> Value {
    json!({
        "seconds": run.seconds,
        "peak_rss_kb": run.peak_rss_kb,
        "store_bytes": dir_bytes(dir),
    })
}

fn main() {
    let args = args();
    let spake = resolve_sibling_bin("SPAKE_BIN", "spake");
    let clave = resolve_sibling_bin("CLAVE_BIN", "clave");
    let graven = graven_bin();
    let siblings = e2e::workspace_root()
        .parent()
        .expect("graven repo has a parent directory")
        .to_path_buf();
    let mut report = json!({
        "domains": args.domains,
        "pages_per_domain": args.pages,
        "large_domains": args.large_domains,
        "large_pages_per_domain": args.large_pages,
        "body_words": args.body_words,
        "changed_percent": args.changed_percent,
        "tier1": args.tier1,
        "snapshot_shards": args.snapshot_shards,
        "skip_consumer": args.skip_consumer,
        "update_by": args.update_by.name(),
        "tree_bound": args.tree_bound,
        "tree_bound_items": args.tree_bound.then_some(args.tree_bound_items),
        "build_profile": e2e::build_profile(),
        "revisions": {
            "spake": git_revision(&siblings.join("spake")),
            "clave": git_revision(&siblings.join("clave")),
            "graven": git_revision(&siblings.join("graven")),
            "core": git_revision(&siblings.join("core")),
            "spec": git_revision(&siblings.join("spec")),
        },
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
    let domain_count = args.domains + args.large_domains;
    let hosts: Vec<String> = (0..domain_count).map(host_name).collect();
    let (small_hosts, large_hosts) = hosts.split_at(args.domains);
    let page_counts: Vec<usize> = (0..domain_count)
        .map(|i| {
            if i < args.domains {
                args.pages
            } else {
                args.large_pages
            }
        })
        .collect();
    let small_items = args.domains * args.pages;
    let large_items = args.large_domains * args.large_pages;
    let sites: Vec<Site> = hosts
        .iter()
        .map(|host| Site::new(&root, host, "default"))
        .collect();
    for (site, pages) in sites.iter().zip(&page_counts) {
        write_pages(site, *pages, args.body_words, 1);
    }
    let tree_site = args
        .tree_bound
        .then(|| Site::new(&root, &host_name(domain_count), "default"));
    let (proxy_addr, _counters, requests) = serve_sites_counted(
        sites
            .iter()
            .chain(&tree_site)
            .map(|site| (site.host.clone(), site.out.clone()))
            .collect::<BTreeMap<_, _>>(),
    );

    let ((), publish_s) = timed(|| {
        for site in &sites {
            site.init(&spake);
            site.publish(&spake);
        }
    });
    let published_bytes: u64 = sites
        .iter()
        .map(|site| dir_bytes(&site.out.join(".well-known")))
        .sum();
    report["stages"]["publish"] = json!({
        "seconds": publish_s,
        "items": small_items + large_items,
        "well_known_bytes": published_bytes,
    });

    let clave_data = root.join("clave-data");
    let clave_host = free_loopback_addr();
    run(
        &clave,
        &["init", "--log-id", &clave_host, "--data", s(&clave_data)],
    );
    if let Some(shards) = args.snapshot_shards {
        rusqlite::Connection::open(clave_data.join("clave.sqlite"))
            .expect("open the aggregator store")
            .execute(
                "INSERT INTO params(name, value) VALUES ('snapshot_shard_count', ?1) ON CONFLICT(name) DO UPDATE SET value = excluded.value",
                [shards],
            )
            .expect("set snapshot_shard_count");
    }
    let (clave_child, _, _clave_stderr) = spawn_clave_serve_with(
        &clave,
        &clave_data,
        &clave_host,
        Some(&format!("http://{proxy_addr}")),
    );
    let clave_pid = clave_child.0.id();
    let clave_base = format!("http://{clave_host}");
    let http = reqwest::blocking::Client::new();

    requests.clear();
    reset_peak_rss(clave_pid);
    let since = after_this_second();
    let mut refused = 0u64;
    let ((), ping_s) = timed(|| {
        for host in &hosts {
            refused += ping_until_admitted(&spake, &clave_base, host);
        }
    });
    let pulled = wait_all_pulled(
        &http,
        &clave_base,
        &hosts,
        &since,
        Duration::from_secs(3600),
    );
    let ingest = Round {
        small: (small_hosts, small_items),
        large: (large_hosts, large_items),
    };
    let mut ingest_report = ingest.report(&requests, &pulled);
    merge(
        &mut ingest_report,
        json!({
            "ping_seconds": ping_s,
            "pings_refused": refused,
            "aggregator_peak_rss_kb": peak_rss_kb(clave_pid),
            "wist2_e08_reports": reports_since(&http, &clave_base, &hosts, &since, "WIST2-E08"),
        }),
    );
    report["stages"]["ingest"] = ingest_report;

    let mut sealed = 0u64;
    report["stages"]["seal_1"] = sealed_stage(
        &clave,
        &clave_data,
        &grid_instant(0),
        args.compare_rebuild,
        &mut sealed,
    );

    let gdir = root.join("graven-store");
    let anchor = clave_data.join("anchor.json");
    if !args.skip_consumer {
        let cold = run_measured(&graven, &sync_args(&anchor, &clave_base, &gdir, args.tier1));
        report["stages"]["consumer_cold_start"] = consumer_report(&cold, &gdir);
    }

    let changed: Vec<usize> = page_counts
        .iter()
        .map(|pages| (pages * args.changed_percent).div_ceil(100))
        .collect();
    for (site, changed) in sites.iter().zip(&changed) {
        for j in 0..*changed {
            site.write_page(
                &format!("p{j}.html"),
                &page(&site.host, j, args.body_words, 2),
            );
        }
    }
    let small_changed: usize = changed[..args.domains].iter().sum();
    let large_changed: usize = changed[args.domains..].iter().sum();
    requests.clear();
    reset_peak_rss(clave_pid);
    let since = after_this_second();
    let mut update_refused = 0u64;
    let mut change_lists_deleted = 0usize;
    let ((), republish_s) = timed(|| {
        for site in &sites {
            site.publish(&spake);
            if args.update_by == UpdateBy::Walk {
                change_lists_deleted += delete_change_lists(site);
            }
            update_refused += ping_until_admitted(&spake, &clave_base, &site.host);
        }
    });
    let pulled = wait_all_pulled(
        &http,
        &clave_base,
        &hosts,
        &since,
        Duration::from_secs(3600),
    );
    let update = Round {
        small: (small_hosts, small_changed),
        large: (large_hosts, large_changed),
    };
    let mut update_report = update.report(&requests, &pulled);
    merge(
        &mut update_report,
        json!({
            "update_by": args.update_by.name(),
            "changed_items": small_changed + large_changed,
            "change_lists_deleted": change_lists_deleted,
            "republish_and_ping_seconds": republish_s,
            "pings_refused": update_refused,
            "aggregator_peak_rss_kb": peak_rss_kb(clave_pid),
            "wist2_e08_reports": reports_since(&http, &clave_base, &hosts, &since, "WIST2-E08"),
        }),
    );
    report["stages"]["update"] = update_report;

    report["stages"]["seal_2"] = sealed_stage(
        &clave,
        &clave_data,
        &grid_instant(1),
        args.compare_rebuild,
        &mut sealed,
    );
    report["stages"]["seal_3_empty"] = sealed_stage(
        &clave,
        &clave_data,
        &grid_instant(2),
        args.compare_rebuild,
        &mut sealed,
    );

    let extra: Vec<SealStage> = (0..args.extra_empty_seals)
        .map(|k| {
            let at = grid_instant(3 + k as i64);
            SealStage::run(&clave, &clave_data, &at, args.compare_rebuild)
        })
        .collect();
    sealed = log_tree_size(&clave_data);
    let epochs = 3 + args.extra_empty_seals;
    let mut extra_report = json!({
        "count": args.extra_empty_seals,
        "seconds_each": extra.iter().map(|st| st.seal.seconds + st.snapshot.seconds).collect::<Vec<_>>(),
        "seal_seconds_each": extra.iter().map(SealStage::seal_seconds).collect::<Vec<_>>(),
        "seal_peak_rss_kb_each": extra.iter().map(|st| st.seal.peak_rss_kb).collect::<Vec<_>>(),
        "snapshot_seconds_each": extra.iter().map(|st| st.snapshot.seconds).collect::<Vec<_>>(),
        "snapshot_each": extra.iter().map(|st| snapshot_report(&st.snapshot)).collect::<Vec<_>>(),
        "snapshot_rebuild_each": extra.iter().map(SealStage::rebuild_report).collect::<Vec<_>>(),
        "log_bytes": dir_bytes(&clave_data.join("log")),
    });
    let mut last_storage = storage_bytes(&clave_data);
    last_storage
        .as_object_mut()
        .expect("storage bytes object")
        .remove("snapshot_build_bytes");
    merge(&mut extra_report, last_storage);
    report["stages"]["extra_empty_seals"] = extra_report;

    let ((), verify_s) = timed(|| {
        run(&clave, &["verify-history", "--data", s(&clave_data)]);
    });
    report["stages"]["verify_history"] = json!({ "seconds": verify_s, "epochs": epochs });

    if !args.skip_consumer {
        let catch_up = run_measured(&graven, &["sync", "--dir", s(&gdir), "--allow-http"]);
        report["stages"]["consumer_catch_up"] = consumer_report(&catch_up, &gdir);
    }
    let gdir2 = root.join("graven-store-2");
    if !args.skip_consumer {
        let cold = run_measured(
            &graven,
            &sync_args(&anchor, &clave_base, &gdir2, args.tier1),
        );
        let mut cold_report = consumer_report(&cold, &gdir2);
        cold_report["epochs"] = json!(epochs);
        report["stages"]["consumer_cold_start_after_all_seals"] = cold_report;
    }

    let mut next_seal = 3 + args.extra_empty_seals as i64;
    if args.withdraw {
        let site = &sites[0];
        let item_id = site.item_id(&site.url("p0.html"));
        let before = storage_bytes(&clave_data);
        run(
            &clave,
            &[
                "withdraw",
                "--data",
                s(&clave_data),
                "--domain",
                &site.host,
                "--item-id",
                &item_id,
                "--legal-basis",
                "test",
                "--jurisdiction",
                "test",
            ],
        );
        let mut withdrawal = sealed_stage(
            &clave,
            &clave_data,
            &grid_instant(next_seal),
            args.compare_rebuild,
            &mut sealed,
        );
        next_seal += 1;
        merge(
            &mut withdrawal,
            json!({ "items_withdrawn": 1, "before": before }),
        );
        report["stages"]["withdrawal"] = withdrawal;
    }

    if let Some(site) = &tree_site {
        write_pages(site, 1, args.body_words, 1);
        site.init(&spake);
        site.publish(&spake);
        let tree_hosts = [site.host.clone()];
        let since = after_this_second();
        ping_until_admitted(&spake, &clave_base, &site.host);
        wait_all_pulled(
            &http,
            &clave_base,
            &tree_hosts,
            &since,
            Duration::from_secs(600),
        );
        seal_epoch(&clave, &clave_data, &grid_instant(next_seal));
        next_seal += 1;
        sealed = log_tree_size(&clave_data);
        if !args.skip_consumer {
            run(&graven, &["sync", "--dir", s(&gdir), "--allow-http"]);
        }

        let template = site
            .served_list()
            .into_iter()
            .next()
            .expect("the served list holds the template page's Item");
        let (bound, build_s) = timed(|| bound_tree(&template, &site.host, args.tree_bound_items));
        for item in bound.list.iter().filter(|item| **item != template) {
            site.serve_payload_as(&template, item);
        }
        let served = site.catalog();
        let kid = served["sig"]["key_id"]
            .as_str()
            .expect("the served Catalog names its key")
            .to_string();
        wait_until_after(
            served["catalog"]["generated_at"]
                .as_str()
                .expect("the served Catalog's generated_at"),
        );
        site.serve_catalog_with_tree(
            &bound.list,
            &bound.built,
            &now_rfc3339(),
            &kid,
            &site.signing_key(&kid),
        );
        let deleted = delete_change_lists(site);
        assert_eq!(
            site.served_list().len(),
            bound.list.len(),
            "the bound tree does not walk to its list"
        );

        requests.clear();
        reset_peak_rss(clave_pid);
        let since = after_this_second();
        ping_until_admitted(&spake, &clave_base, &site.host);
        let pulled = wait_all_pulled(
            &http,
            &clave_base,
            &tree_hosts,
            &since,
            Duration::from_secs(3600),
        );
        let mut walk = round_report(&requests.requests(), &tree_hosts, bound.list.len(), &pulled);
        merge(
            &mut walk,
            json!({
                "aggregator_peak_rss_kb": peak_rss_kb(clave_pid),
                "change_lists_deleted": deleted,
                "wist2_e08_reports": reports_since(&http, &clave_base, &tree_hosts, &since, "WIST2-E08"),
            }),
        );
        let seal = sealed_stage(
            &clave,
            &clave_data,
            &grid_instant(next_seal),
            args.compare_rebuild,
            &mut sealed,
        );
        let mut tree_report = json!({
            "shape": bound.shape,
            "build_seconds": build_s,
            "walk": walk,
            "seal": seal,
        });
        if !args.skip_consumer {
            let catch_up = run_measured(&graven, &["sync", "--dir", s(&gdir), "--allow-http"]);
            tree_report["consumer_catch_up"] = consumer_report(&catch_up, &gdir);
        }
        report["stages"]["tree_bound"] = tree_report;
    }

    let text = serde_json::to_string_pretty(&report).expect("report");
    println!("{text}");
    if let Some(out) = args.out {
        std::fs::write(out, text).expect("write report");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUILT: &str =
        "snapshot built at epoch 7 for 2026-09-23 in 412 ms, 3 of 256 shards rebuilt
snapshot bytes written 1000
snapshot bytes reused 2000
snapshot cache bytes written 300
snapshot payloads read 40
snapshot payload bytes read 5000
snapshot took 450 ms
";

    fn measured(stdout: &str) -> Measured {
        Measured {
            seconds: 0.5,
            peak_rss_kb: Some(1234),
            stdout: stdout.into(),
        }
    }

    #[test]
    fn built_snapshot_output_parses_every_counter() {
        assert_eq!(
            snapshot_report(&measured(BUILT)),
            json!({
                "outcome": "built",
                "seconds": 0.5,
                "reported_seconds": 0.45,
                "peak_rss_kb": 1234,
                "shards_rebuilt": 3,
                "shard_count": 256,
                "bytes_written": 1000,
                "bytes_reused": 2000,
                "cache_bytes_written": 300,
                "payloads_read": 40,
                "payload_bytes_read": 5000,
            })
        );
    }

    #[test]
    fn current_snapshot_output_reports_missing_lines_as_null() {
        let report = snapshot_report(&measured(
            "snapshot current at epoch 7\nsnapshot took 2 ms\n",
        ));
        assert_eq!(report["outcome"], "current");
        assert_eq!(report["reported_seconds"], json!(0.002));
        for key in [
            "shards_rebuilt",
            "shard_count",
            "bytes_written",
            "bytes_reused",
            "cache_bytes_written",
            "payloads_read",
            "payload_bytes_read",
        ] {
            assert_eq!(report[key], Value::Null, "{key}");
        }
    }

    #[test]
    fn storage_bytes_counts_sqlite_wal_and_snapshot_directories() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("clave.sqlite"), [0u8; 10]).expect("sqlite");
        std::fs::write(dir.path().join("clave.sqlite-wal"), [0u8; 20]).expect("wal");
        for (name, len) in [
            ("snapshots", 30),
            ("snapshot-shards", 40),
            ("snapshot-build", 50),
        ] {
            std::fs::create_dir_all(dir.path().join(name).join("nested")).expect("dir");
            std::fs::write(dir.path().join(name).join("nested/f"), vec![0u8; len]).expect("file");
        }
        assert_eq!(
            storage_bytes(dir.path()),
            json!({
                "sqlite_bytes": 10,
                "sqlite_wal_bytes": 20,
                "snapshots_bytes": 30,
                "snapshot_shards_bytes": 40,
                "snapshot_build_bytes": 50,
            })
        );
    }

    #[test]
    fn a_page_carries_the_marker_and_one_whole_content_region() {
        let html = page("127.0.1.1", 3, 5, 1);
        assert!(
            html.contains("<meta name=\"wist\" content=\"publish\">"),
            "{html}"
        );
        assert_eq!(html.matches("<!--wist:content-->").count(), 1, "{html}");
        assert_eq!(html.matches("<!--/wist:content-->").count(), 1, "{html}");
        assert!(
            html.find("<!--wist:content-->") < html.find("<!--/wist:content-->"),
            "{html}"
        );
        assert_ne!(
            html,
            page("127.0.1.1", 3, 5, 2),
            "a revision changes the page"
        );
    }

    #[test]
    fn update_by_parses_chain_and_walk() {
        assert_eq!(UpdateBy::parse("chain"), UpdateBy::Chain);
        assert_eq!(UpdateBy::parse("walk"), UpdateBy::Walk);
        assert_eq!(UpdateBy::Walk.name(), "walk");
    }

    #[test]
    #[should_panic(expected = "--update-by takes chain or walk")]
    fn update_by_refuses_another_mode() {
        UpdateBy::parse("tree");
    }

    #[test]
    fn request_kind_names_each_published_object() {
        for (path, kind) in [
            (".well-known/wist/publisher.json", "declaration"),
            (
                ".well-known/wist/collections/default/catalog.json",
                "catalog",
            ),
            (
                ".well-known/wist/collections/default/changes/ab.json",
                "change_list",
            ),
            (".well-known/wist/collections/default/tree/ab", "tree_file"),
            (
                ".well-known/wist/collections/default/payloads/ab.json",
                "payload",
            ),
            (".well-known/wist/label-feed.json", "label_feed"),
            (".well-known/wist/label-feed/2.json", "label_feed"),
            ("p0.html", "other"),
            (".well-known/wist/collections/default", "other"),
        ] {
            assert_eq!(request_kind(path), kind, "{path}");
        }
    }

    fn logged(host: &str, path: &str, octets: u64) -> LoggedRequest {
        LoggedRequest {
            host: host.into(),
            path: path.into(),
            octets,
        }
    }

    #[test]
    fn requests_report_sums_requests_and_octets_by_kind_for_the_named_hosts() {
        let requests = [
            logged("a", ".well-known/wist/publisher.json", 100),
            logged("a", ".well-known/wist/collections/c/tree/ff", 30),
            logged("a", ".well-known/wist/collections/c/tree/ee", 10),
            logged("b", ".well-known/wist/collections/c/catalog.json", 500),
        ];
        let report = requests_report(&requests, &["a".to_string()], 4);
        assert_eq!(report["site_requests"], 3);
        assert_eq!(report["response_octets"], 140);
        assert_eq!(report["requests_per_item"], 0.75);
        assert_eq!(report["octets_per_item"], 35.0);
        assert_eq!(
            report["by_kind"],
            json!({
                "declaration": { "requests": 1, "octets": 100 },
                "tree_file": { "requests": 2, "octets": 40 },
            })
        );
    }

    #[test]
    fn round_report_takes_the_slowest_named_host() {
        let pulled = BTreeMap::from([
            ("a".to_string(), 1.5),
            ("b".to_string(), 9.0),
            ("c".to_string(), 3.0),
        ]);
        let report = round_report(&[], &["a".to_string(), "c".to_string()], 0, &pulled);
        assert_eq!(report["seconds_until_all_pulled"], 3.0);
        assert_eq!(report["requests_per_item"], Value::Null);
    }

    #[test]
    fn vm_hwm_line_reads_as_kilobytes() {
        let status = "Name:\tclave\nVmPeak:\t  900 kB\nVmHWM:\t   12345 kB\nVmRSS:\t  100 kB\n";
        assert_eq!(vm_hwm_kb(status), Some(12_345));
        assert_eq!(vm_hwm_kb("Name:\tclave\n"), None);
    }

    #[test]
    fn log_entries_report_counts_only_the_sealed_range_by_entry_type() {
        let dir = tempfile::tempdir().expect("tempdir");
        let leaves: Vec<Vec<u8>> = [
            "publisher_declaration",
            "publisher_catalog",
            "publisher_item",
            "publisher_item",
        ]
        .iter()
        .map(|entry_type| {
            json!({ "type": entry_type, "body": {} })
                .to_string()
                .into_bytes()
        })
        .collect();
        for bundle in wist_core::tiles::entry_bundles_for_range(0, 4, 4) {
            let file = dir.path().join(bundle.path().trim_start_matches('/'));
            std::fs::create_dir_all(file.parent().expect("bundle directory")).expect("dir");
            let (start, end) = bundle.leaf_range();
            std::fs::write(
                file,
                wist_core::tiles::encode_entry_bundle(&leaves[start as usize..end as usize])
                    .expect("encode"),
            )
            .expect("bundle");
        }
        let report = log_entries_report(dir.path(), 1, 4);
        let item_octets = leaves[2].len() as u64;
        assert_eq!(report["publisher_declaration"], Value::Null);
        assert_eq!(report["publisher_catalog"]["entries"], 1);
        assert_eq!(report["publisher_item"]["entries"], 2);
        assert_eq!(report["publisher_item"]["octets"], 2 * item_octets);
        assert_eq!(
            report["publisher_item"]["octets_per_entry"],
            item_octets as f64
        );
        assert_eq!(report["all"]["entries"], 3);
    }

    #[test]
    fn delete_change_lists_removes_every_served_change_list() {
        let root = tempfile::tempdir().expect("tempdir");
        let site = Site::new(root.path(), "127.0.9.9", "default");
        assert_eq!(delete_change_lists(&site), 0);
        let changes = site.collection_dir().join("changes");
        std::fs::create_dir_all(&changes).expect("changes directory");
        for name in ["aa.json", "bb.json"] {
            std::fs::write(changes.join(name), "{}").expect("change list");
        }
        assert_eq!(delete_change_lists(&site), 2);
        assert_eq!(std::fs::read_dir(&changes).expect("list").count(), 0);
    }

    #[test]
    fn bound_tree_walks_to_its_list_at_the_depth_bound_with_buckets_filled_to_the_cap() {
        let template = json!({
            "publisher": "127.0.9.9",
            "url": "https://127.0.9.9/p0.html",
            "observed_at": "2026-10-01T00:00:00Z",
            "payload": {
                "alg": "HMAC-SHA256",
                "bytes": 1584,
                "commitment": format!("hmac-sha256:{}", "0".repeat(64)),
            },
            "meta": { "lang": "en" },
        });
        let bound = bound_tree(&template, "127.0.9.9", 12);
        let bounds = wist_core::tree::TreeBounds::suite();
        assert!(bound.list.contains(&template));
        assert_eq!(bound.shape["deep_items"], 12);
        assert_eq!(bound.shape["levels"], bounds.tree_depth_max());
        let cap = bounds.tree_file_cap_bytes();
        let item_octets = wist_core::jcs::canonicalize(&bound.list[0])
            .expect("jcs")
            .len() as u64;
        for octets in bound.shape["full_bucket_octets"]
            .as_array()
            .expect("octets")
        {
            let octets = octets.as_u64().expect("octets");
            assert!(octets <= cap && octets + item_octets + 1 > cap, "{octets}");
        }
        let catalog: wist_core::objects::Catalog = serde_json::from_value(json!({
            "wist_version": "1.0.0",
            "publisher": "127.0.9.9",
            "collection": "default",
            "generated_at": "2026-10-01T00:00:00Z",
            "size": bound.list.len(),
            "root": format!(
                "sha256:{}",
                wist_core::crypto::hex_encode(&wist_core::item::root(&bound.list).expect("root"))
            ),
            "tree": bound.built.tree,
        }))
        .expect("Catalog form");
        let walked =
            wist_core::tree::walk(&catalog, &bounds, |hex| match bound.built.files.get(hex) {
                Some(octets) => wist_core::tree::TreeFetch::Octets(octets.clone()),
                None => wist_core::tree::TreeFetch::Failed,
            });
        let wist_core::tree::Walk::Listed(listed) = walked else {
            panic!("the bound tree does not walk: {walked:?}");
        };
        assert_eq!(listed.len(), bound.list.len());
    }

    #[cfg(unix)]
    #[test]
    fn measured_child_reports_stdout_wall_time_and_peak_rss() {
        let run = run_measured(Path::new("/bin/sh"), &["-c", "echo seal took 5 ms"]);
        assert_eq!(reported_seconds(&run.stdout, "seal took "), Some(0.005));
        assert!(run.seconds > 0.0);
        assert!(run.peak_rss_kb.is_some_and(|kb| kb > 0));
    }

    #[cfg(unix)]
    #[test]
    #[should_panic(expected = "stderr=boom")]
    fn failing_child_panics_with_its_stderr() {
        run_measured(Path::new("/bin/sh"), &["-c", "echo boom >&2; exit 3"]);
    }
}
