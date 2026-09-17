//! Capacity baseline: publishes N loopback sites of M pages each through
//! the real publisher, aggregator and consumer executables and reports the
//! wall time, bytes and request counts of every stage, so the numbers a
//! capacity model extrapolates from are reproducible on any machine.
use e2e::{
    fetch_status, free_loopback_addr, graven_bin, grid_instant, now_rfc3339, resolve_sibling_bin,
    run, s, serve_sites, spawn_clave_serve_with,
};
use serde_json::json;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

struct Args {
    domains: usize,
    pages: usize,
    changed_percent: usize,
    body_words: usize,
    tier1: bool,
    extra_empty_seals: usize,
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

/// Pings `host` until the aggregator admits it, retrying a 503 the
/// admission gate answers when every pending slot is taken (WIST-2 §4
/// has the Publisher honor the refusal); returns the refusals.
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
    let tmp = tempfile::tempdir().expect("tempdir");
    let hosts: Vec<String> = (0..args.domains)
        .map(|i| format!("127.0.{}.{}", 1 + i / 250, 1 + i % 250))
        .collect();
    let sites: BTreeMap<String, PathBuf> = hosts
        .iter()
        .map(|host| (host.clone(), tmp.path().join("sites").join(host)))
        .collect();
    for (host, dir) in &sites {
        write_site(dir, host, args.pages, args.body_words, 1);
    }
    let (proxy_addr, counters) = serve_sites(sites.clone());

    let ((), build_s) = timed(|| {
        for (host, dir) in &sites {
            let state = tmp.path().join("state").join(host);
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

    let clave_data = tmp.path().join("clave-data");
    let clave_host = free_loopback_addr();
    run(
        &clave,
        &["init", "--log-id", &clave_host, "--data", s(&clave_data)],
    );
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
    let ((), seal_s) = timed(|| {
        run(
            &clave,
            &["seal", "--data", s(&clave_data), "--at", &first_seal],
        );
    });
    let block0 = clave_data.join("log/blocks/000000000.json.zst");
    report["stages"]["seal_1"] = json!({
        "seconds": seal_s,
        "block_compressed_bytes": dir_bytes(&block0),
        "block_decompressed_bytes": zstd::decode_all(std::fs::read(&block0).expect("block 0").as_slice()).map(|b| b.len()).unwrap_or(0),
        "payloads_bytes": dir_bytes(&clave_data.join("payloads")),
        "snapshots_bytes": dir_bytes(&clave_data.join("snapshots")),
        "sqlite_bytes": dir_bytes(&clave_data.join("clave.sqlite")),
        "data_dir_bytes": dir_bytes(&clave_data),
    });

    let gdir = tmp.path().join("graven-store");
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
            let state = tmp.path().join("state").join(host);
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
    let ((), seal2_s) = timed(|| {
        run(
            &clave,
            &["seal", "--data", s(&clave_data), "--at", &second_seal],
        );
    });
    let block1 = clave_data.join("log/blocks/000000001.json.zst");
    report["stages"]["seal_2"] = json!({
        "seconds": seal2_s,
        "block_compressed_bytes": dir_bytes(&block1),
        "snapshots_bytes": dir_bytes(&clave_data.join("snapshots")),
        "data_dir_bytes": dir_bytes(&clave_data),
    });

    let third_seal = grid_instant(2);
    let ((), seal3_s) = timed(|| {
        run(
            &clave,
            &["seal", "--data", s(&clave_data), "--at", &third_seal],
        );
    });
    report["stages"]["seal_3_empty"] = json!({ "seconds": seal3_s });

    let mut empty_seal_seconds = Vec::new();
    for k in 0..args.extra_empty_seals {
        let at = grid_instant(3 + k as i64);
        let ((), seal_s) = timed(|| {
            run(&clave, &["seal", "--data", s(&clave_data), "--at", &at]);
        });
        empty_seal_seconds.push(seal_s);
    }
    let blocks = 3 + args.extra_empty_seals;
    report["stages"]["extra_empty_seals"] = json!({
        "count": args.extra_empty_seals,
        "seconds_each": empty_seal_seconds,
        "log_bytes": dir_bytes(&clave_data.join("log")),
    });

    let ((), verify_s) = timed(|| {
        run(&clave, &["verify-history", "--data", s(&clave_data)]);
    });
    report["stages"]["verify_history"] = json!({ "seconds": verify_s, "blocks": blocks });

    let ((), catchup_s) = timed(|| {
        run(&graven, &["sync", "--dir", s(&gdir), "--allow-http"]);
    });
    report["stages"]["consumer_catch_up"] = json!({
        "seconds": catchup_s,
        "store_bytes": dir_bytes(&gdir),
    });
    let gdir2 = tmp.path().join("graven-store-2");
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
        "blocks": blocks,
        "seconds": cold2_s,
        "store_bytes": dir_bytes(&gdir2),
    });
    let _ = clave_stderr;

    let text = serde_json::to_string_pretty(&report).expect("report");
    println!("{text}");
    if let Some(out) = args.out {
        std::fs::write(out, text).expect("write report");
    }
}
