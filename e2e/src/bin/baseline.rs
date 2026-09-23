use e2e::{
    fetch_status, free_loopback_addr, graven_bin, grid_instant, now_rfc3339, resolve_sibling_bin,
    run, s, serve_sites, spawn_clave_serve_with,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

struct Args {
    domains: usize,
    pages: usize,
    changed_percent: usize,
    body_words: usize,
    tier1: bool,
    extra_empty_seals: usize,
    snapshot_shards: Option<i64>,
    compare_rebuild: bool,
    withdraw: bool,
    work_dir: Option<PathBuf>,
    keep: bool,
    out: Option<PathBuf>,
}

fn args() -> Args {
    let mut args = Args {
        domains: 10,
        pages: 20,
        changed_percent: 10,
        body_words: 200,
        tier1: true,
        extra_empty_seals: 0,
        snapshot_shards: None,
        compare_rebuild: false,
        withdraw: false,
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
            "--changed-percent" => {
                args.changed_percent = value().parse().expect("--changed-percent")
            }
            "--body-words" => args.body_words = value().parse().expect("--body-words"),
            "--no-tier1" => args.tier1 = false,
            "--extra-empty-seals" => {
                args.extra_empty_seals = value().parse().expect("--extra-empty-seals")
            }
            "--snapshot-shards" => {
                args.snapshot_shards = Some(value().parse().expect("--snapshot-shards"))
            }
            "--compare-rebuild" => args.compare_rebuild = true,
            "--withdraw" => args.withdraw = true,
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

fn write_site(dir: &Path, host: &str, pages: usize, body_words: usize, revision: u64) {
    std::fs::create_dir_all(dir).expect("site dir");
    let mut sitemap = String::from(
        r#"<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">"#,
    );
    for j in 0..pages {
        sitemap.push_str(&format!("<url><loc>https://{host}/p{j}.html</loc></url>"));
        std::fs::write(
            dir.join(format!("p{j}.html")),
            format!(
                "<html lang=\"en\"><head><title>Page {j} of {host}</title></head><body><h1>Page {j}</h1><p>{}</p></body></html>",
                words(revision * 1_000_003 + j as u64, body_words)
            ),
        )
        .expect("page");
    }
    sitemap.push_str("</urlset>");
    std::fs::write(dir.join("sitemap.xml"), sitemap).expect("sitemap");
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

fn snapshot_report(run: &Measured) -> Value {
    let out = run.stdout.as_str();
    let shards = shards_rebuilt(out);
    json!({
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

fn newest_delta_id(site: &Path) -> String {
    let feed_path = site.join(".well-known/wist/feed.json");
    let feed: Value = serde_json::from_slice(&std::fs::read(&feed_path).expect("read feed"))
        .expect("feed is JSON");
    feed["feed"]["deltas"]
        .as_array()
        .and_then(|ids| ids.last())
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{} lists no Delta", feed_path.display()))
        .to_string()
}

fn wait_all_pulled(
    http: &reqwest::blocking::Client,
    base: &str,
    hosts: &[String],
    since: &str,
    timeout: Duration,
) -> f64 {
    let start = Instant::now();
    let mut pending: Vec<&String> = hosts.iter().collect();
    while !pending.is_empty() {
        pending.retain(|host| {
            !fetch_status(http, base, host).is_some_and(|v| {
                v["rejections"].as_array().is_some_and(|r| r.is_empty())
                    && v["last_pull_at"].as_str().is_some_and(|t| t >= since)
            })
        });
        assert!(
            start.elapsed() < timeout,
            "{} of {} domains were not pulled cleanly within {timeout:?}",
            pending.len(),
            hosts.len()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    start.elapsed().as_secs_f64()
}

/// WIST-2 §4: the Publisher honors a 503 admission refusal.
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
        "body_words": args.body_words,
        "changed_percent": args.changed_percent,
        "tier1": args.tier1,
        "snapshot_shards": args.snapshot_shards,
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
        report["work_dir"] = json!(root);
        (None, root)
    } else {
        let root = tmp.path().to_path_buf();
        (Some(tmp), root)
    };
    let hosts: Vec<String> = (0..args.domains)
        .map(|i| format!("127.0.{}.{}", 1 + i / 250, 1 + i % 250))
        .collect();
    let sites: BTreeMap<String, PathBuf> = hosts
        .iter()
        .map(|host| (host.clone(), root.join("sites").join(host)))
        .collect();
    for (host, dir) in &sites {
        write_site(dir, host, args.pages, args.body_words, 1);
    }
    let (proxy_addr, counters) = serve_sites(sites.clone());

    let ((), build_s) = timed(|| {
        for (host, dir) in &sites {
            let state = root.join("state").join(host);
            run(
                &spake,
                &[
                    "init",
                    "--domain",
                    host,
                    "--out",
                    s(dir),
                    "--state",
                    s(&state),
                ],
            );
            run(
                &spake,
                &[
                    "build",
                    "--site",
                    s(dir),
                    "--domain",
                    host,
                    "--out",
                    s(dir),
                    "--state",
                    s(&state),
                    "--allow-http",
                ],
            );
        }
    });
    let published_bytes: u64 = sites
        .values()
        .map(|d| dir_bytes(&d.join(".well-known")))
        .sum();
    report["stages"]["publish"] = json!({
        "seconds": build_s,
        "deltas": args.domains * args.pages,
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
    let (_clave_child, _, clave_stderr) = spawn_clave_serve_with(
        &clave,
        &clave_data,
        &clave_host,
        Some(&format!("http://{proxy_addr}")),
    );
    let clave_base = format!("http://{clave_host}");
    let http = reqwest::blocking::Client::new();

    let since = now_rfc3339();
    let mut refused = 0u64;
    let ((), ping_s) = timed(|| {
        for host in &hosts {
            refused += ping_until_admitted(&spake, &clave_base, host);
        }
    });
    let ingest_s = wait_all_pulled(
        &http,
        &clave_base,
        &hosts,
        &since,
        Duration::from_secs(3600),
    );
    let requests_after_ingest: u64 = counters.values().map(|c| c.load(Ordering::Relaxed)).sum();
    report["stages"]["ingest"] = json!({
        "ping_seconds": ping_s,
        "pings_refused": refused,
        "seconds_until_all_pulled": ingest_s,
        "site_requests": requests_after_ingest,
        "requests_per_delta": requests_after_ingest as f64 / (args.domains * args.pages) as f64,
    });

    let first_seal = grid_instant(0);
    report["stages"]["seal_1"] =
        SealStage::run(&clave, &clave_data, &first_seal, args.compare_rebuild).report(&clave_data);

    let gdir = root.join("graven-store");
    let anchor = clave_data.join("anchor.json");
    let mut sync_args = vec![
        "sync",
        "--anchor",
        s(&anchor),
        "--log",
        &clave_base,
        "--dir",
        s(&gdir),
        "--allow-http",
    ];
    if args.tier1 {
        sync_args.push("--tier1");
    }
    let ((), cold_s) = timed(|| {
        run(&graven, &sync_args);
    });
    report["stages"]["consumer_cold_start"] = json!({
        "seconds": cold_s,
        "store_bytes": dir_bytes(&gdir),
    });

    let changed = (args.pages * args.changed_percent).div_ceil(100);
    for (host, dir) in &sites {
        for j in 0..changed {
            std::fs::write(
                dir.join(format!("p{j}.html")),
                format!(
                    "<html lang=\"en\"><head><title>Page {j} of {host}</title></head><body><h1>Page {j}</h1><p>{}</p></body></html>",
                    words(2 * 1_000_003 + j as u64, args.body_words)
                ),
            )
            .expect("page");
        }
    }
    let since = now_rfc3339();
    let requests_before = requests_after_ingest;
    let mut update_refused = 0u64;
    let ((), rebuild_s) = timed(|| {
        for (host, dir) in &sites {
            let state = root.join("state").join(host);
            run(
                &spake,
                &[
                    "build",
                    "--site",
                    s(dir),
                    "--domain",
                    host,
                    "--out",
                    s(dir),
                    "--state",
                    s(&state),
                    "--allow-http",
                ],
            );
            update_refused += ping_until_admitted(&spake, &clave_base, host);
        }
    });
    let update_ingest_s = wait_all_pulled(
        &http,
        &clave_base,
        &hosts,
        &since,
        Duration::from_secs(3600),
    );
    let requests_after_update: u64 = counters.values().map(|c| c.load(Ordering::Relaxed)).sum();
    report["stages"]["update"] = json!({
        "changed_deltas": args.domains * changed,
        "rebuild_and_ping_seconds": rebuild_s,
        "pings_refused": update_refused,
        "seconds_until_all_pulled": update_ingest_s,
        "site_requests": requests_after_update - requests_before,
    });

    let second_seal = grid_instant(1);
    report["stages"]["seal_2"] =
        SealStage::run(&clave, &clave_data, &second_seal, args.compare_rebuild).report(&clave_data);

    let third_seal = grid_instant(2);
    report["stages"]["seal_3_empty"] =
        SealStage::run(&clave, &clave_data, &third_seal, args.compare_rebuild).report(&clave_data);

    let extra: Vec<SealStage> = (0..args.extra_empty_seals)
        .map(|k| {
            let at = grid_instant(3 + k as i64);
            SealStage::run(&clave, &clave_data, &at, args.compare_rebuild)
        })
        .collect();
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

    let ((), catchup_s) = timed(|| {
        run(&graven, &["sync", "--dir", s(&gdir), "--allow-http"]);
    });
    report["stages"]["consumer_catch_up"] = json!({
        "seconds": catchup_s,
        "store_bytes": dir_bytes(&gdir),
    });
    let gdir2 = root.join("graven-store-2");
    let mut cold_args = vec![
        "sync",
        "--anchor",
        s(&anchor),
        "--log",
        &clave_base,
        "--dir",
        s(&gdir2),
        "--allow-http",
    ];
    if args.tier1 {
        cold_args.push("--tier1");
    }
    let ((), cold2_s) = timed(|| {
        run(&graven, &cold_args);
    });
    report["stages"]["consumer_cold_start_after_all_seals"] = json!({
        "epochs": epochs,
        "seconds": cold2_s,
        "store_bytes": dir_bytes(&gdir2),
    });

    if args.withdraw {
        let host = &hosts[0];
        let delta_id = newest_delta_id(&sites[host]);
        let before = storage_bytes(&clave_data);
        run(
            &clave,
            &[
                "withdraw",
                "--data",
                s(&clave_data),
                "--domain",
                host,
                "--delta-id",
                &delta_id,
                "--legal-basis",
                "test",
                "--jurisdiction",
                "test",
            ],
        );
        let at = grid_instant(3 + args.extra_empty_seals as i64);
        let mut withdrawal =
            SealStage::run(&clave, &clave_data, &at, args.compare_rebuild).report(&clave_data);
        merge(
            &mut withdrawal,
            json!({ "deltas_withdrawn": 1, "before": before }),
        );
        report["stages"]["withdrawal"] = withdrawal;
    }
    let _ = clave_stderr;

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
    fn newest_delta_id_is_the_last_feed_entry() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join(".well-known/wist")).expect("dir");
        std::fs::write(
            dir.path().join(".well-known/wist/feed.json"),
            r#"{"feed":{"deltas":["sha256:aa","sha256:bb"]}}"#,
        )
        .expect("feed");
        assert_eq!(newest_delta_id(dir.path()), "sha256:bb");
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
