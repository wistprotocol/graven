use e2e::{
    graven_bin, grid_instant, now_rfc3339, resolve_sibling_bin, run, run_with_env, s, serve_sites,
    start_aggregator, wait_until_pulled_since, wait_until_status_active, workspace_root, McpClient,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

fn stage_fixture_site(tmp: &Path, name: &str) -> PathBuf {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/site");
    let dst = tmp.join(name);
    std::fs::create_dir_all(&dst).expect("create staged site dir");
    for entry in std::fs::read_dir(&src).expect("read fixtures/site") {
        let entry = entry.expect("fixture dir entry");
        std::fs::copy(entry.path(), dst.join(entry.file_name())).expect("copy fixture file");
    }
    dst
}

fn rewrite_sitemap_host(site: &Path, host: &str) {
    let path = site.join("sitemap.xml");
    let content = std::fs::read_to_string(&path).expect("read sitemap.xml");
    std::fs::write(&path, content.replace("__HOST__", host)).expect("write sitemap.xml");
}

/// Stages a one-page site for a host: a sitemap naming the page and the
/// page's HTML with the given title, body text and outbound links.
fn stage_page_site(
    tmp: &Path,
    host: &str,
    page: &str,
    title: &str,
    body: &str,
    links: &[String],
) -> PathBuf {
    let dir = tmp.join(format!("site-{host}"));
    std::fs::create_dir_all(&dir).expect("create page site dir");
    let anchors: String = links
        .iter()
        .map(|l| format!("<p><a href=\"{l}\">{l}</a></p>"))
        .collect();
    std::fs::write(
        dir.join(page),
        format!(
            "<!doctype html><html><head><title>{title}</title><meta name=\"description\" content=\"{title}\"></head><body><p>{body}</p>{anchors}</body></html>"
        ),
    )
    .expect("write page");
    std::fs::write(
        dir.join("sitemap.xml"),
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\"><url><loc>https://{host}/{page}</loc></url></urlset>"
        ),
    )
    .expect("write sitemap");
    dir
}

fn read_json(path: &Path) -> serde_json::Value {
    serde_json::from_slice(
        &std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display())),
    )
    .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

/// The tuples of the newest Snapshot the aggregator published.
fn snapshot_state_entries(clave_data: &Path) -> Vec<serde_json::Value> {
    let index = read_json(&clave_data.join("snapshots/index.json"));
    let manifest_url = index["index"]["snapshots"][0]["manifest_url"]
        .as_str()
        .unwrap_or_else(|| panic!("no snapshot in {index}"))
        .trim_start_matches('/')
        .to_string();
    let manifest_path = clave_data.join(&manifest_url);
    let manifest = read_json(&manifest_path);
    let state_path = manifest_path
        .parent()
        .expect("manifest has a directory")
        .join(
            manifest["manifest"]["state"]["path"]
                .as_str()
                .expect("state path"),
        );
    read_json(&state_path)["state"]["entries"]
        .as_array()
        .expect("state entries")
        .clone()
}

/// The tuple of the given kind keyed by `domain`, if the Snapshot carries one.
fn state_tuple(
    entries: &[serde_json::Value],
    kind: &str,
    domain: &str,
) -> Option<serde_json::Value> {
    entries
        .iter()
        .find(|entry| entry[0] == kind && entry[1] == domain)
        .cloned()
}

fn revise_fixture_page(site: &Path, from: &str, to: &str) {
    let path = site.join("b.html");
    let content = std::fs::read_to_string(&path).expect("read b.html");
    let revised = content.replacen(from, to, 1);
    assert_ne!(content, revised, "revision did not change b.html");
    std::fs::write(&path, revised).expect("write revised b.html");
}

fn mutate_fixture_page(site: &Path) {
    let path = site.join("a.html");
    let content = std::fs::read_to_string(&path).expect("read a.html");
    let mutated = content.replacen("Alpha Page", "Alpha Page changed", 1);
    assert_ne!(content, mutated, "mutation did not change a.html");
    std::fs::write(&path, mutated).expect("write mutated a.html");
}

fn validate_artifacts(site: &Path, clave_data: &Path) {
    let spec_dir = std::env::var("WIST_SPEC_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            workspace_root()
                .parent()
                .expect("graven repo has a parent directory")
                .join("spec")
        });
    let venv_python = spec_dir.join("tools/.venv/bin/python3");
    let python = if venv_python.exists() {
        venv_python
    } else {
        PathBuf::from("python3")
    };
    let importable = Command::new(&python)
        .args(["-c", "import jsonschema, rfc8785, cryptography"])
        .status();
    if !matches!(importable, Ok(status) if status.success()) {
        let message = format!(
            "{} lacks jsonschema/rfc8785/cryptography; set up {}/tools/.venv (or install them) to enable conformance validation",
            python.display(),
            spec_dir.display()
        );
        assert!(
            std::env::var("CI").is_err(),
            "validate_artifacts.py skipped under CI: {message}"
        );
        eprintln!("SKIP validate_artifacts.py: {message}");
        return;
    }
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("validate_artifacts.py");
    let status = Command::new(&python)
        .arg(&script)
        .arg(site)
        .arg(clave_data)
        .env("WIST_SPEC_DIR", &spec_dir)
        .status()
        .unwrap_or_else(|e| panic!("failed to spawn validate_artifacts.py: {e}"));
    assert!(status.success(), "validate_artifacts.py reported failures");
}

fn verify_with_external_tlog_client(base_url: &str, verifier_key: &str) {
    let go_available = Command::new("go").arg("version").output();
    if !matches!(go_available, Ok(output) if output.status.success()) {
        assert!(
            std::env::var("CI").is_err(),
            "the external tlog client was skipped under CI: no Go toolchain"
        );
        eprintln!("SKIP external tlog client: no Go toolchain on PATH");
        return;
    }
    let client = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tlog-client");
    let output = Command::new("go")
        .current_dir(&client)
        .args(["run", ".", "-log", base_url, "-key", verifier_key])
        .output()
        .unwrap_or_else(|e| panic!("failed to run the external tlog client: {e}"));
    assert!(
        output.status.success(),
        "the external tlog client rejected the served Log: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    eprint!("{stdout}");
    assert!(stdout.contains("checkpoint verified"), "{stdout}");
    assert!(stdout.contains("inclusion verified"), "{stdout}");
}

#[test]
fn end_to_end() {
    let harness_start = Instant::now();

    let spake = resolve_sibling_bin("SPAKE_BIN", "spake");
    let clave = resolve_sibling_bin("CLAVE_BIN", "clave");
    let graven = graven_bin();

    let tmp = tempfile::tempdir().expect("create tempdir");
    let site = stage_fixture_site(tmp.path(), "site");
    let site_host = "localhost".to_string();
    rewrite_sitemap_host(&site, &site_host);
    let labeler_site = stage_fixture_site(tmp.path(), "labeler-site");
    let labeler_host = "labeler.localhost".to_string();
    rewrite_sitemap_host(&labeler_site, &labeler_host);
    let cited_url = "https://cited.localhost/notes.html".to_string();
    let farmed_url = "https://farmed.localhost/farmed.html".to_string();
    let mut graph_sites: Vec<(String, PathBuf)> = vec![
        (
            "seed.localhost".into(),
            stage_page_site(
                tmp.path(),
                "seed.localhost",
                "home.html",
                "Seed home",
                "A curated page of trustworthy sources on orchards.",
                std::slice::from_ref(&cited_url),
            ),
        ),
        (
            "cited.localhost".into(),
            stage_page_site(
                tmp.path(),
                "cited.localhost",
                "notes.html",
                "Cited orchard notes",
                "The orchard is mentioned once among many other words about apples and pears.",
                &[],
            ),
        ),
        (
            "farmed.localhost".into(),
            stage_page_site(
                tmp.path(),
                "farmed.localhost",
                "farmed.html",
                "Orchard orchard orchard",
                "orchard orchard orchard orchard orchard orchard orchard orchard",
                &[],
            ),
        ),
    ];
    for n in 1..=3 {
        let host = format!("f{n}.localhost");
        let dir = stage_page_site(
            tmp.path(),
            &host,
            "x.html",
            &format!("Farm page {n}"),
            "boosting the farmed page",
            std::slice::from_ref(&farmed_url),
        );
        graph_sites.push((host, dir));
    }
    let mut sites: BTreeMap<String, PathBuf> = BTreeMap::from([
        (site_host.clone(), site.clone()),
        (labeler_host.clone(), labeler_site.clone()),
    ]);
    sites.extend(graph_sites.iter().cloned());
    let (proxy_addr, _) = serve_sites(sites);
    let site_proxy = format!("http://{proxy_addr}");

    let spake_state = tmp.path().join("spake-state");
    let labeler_state = tmp.path().join("labeler-state");
    let clave_data = tmp.path().join("clave-data");
    let gdir = tmp.path().join("graven-store");

    let suffix_list =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/public-suffix-list.dat");
    let aggregator = start_aggregator(
        &clave,
        clave_data.clone(),
        Some(&suffix_list),
        Some(&site_proxy),
    );
    let clave_host = aggregator.log_id.clone();
    let clave_base = aggregator.base_url.clone();
    let clave_stderr = aggregator.stderr.clone();
    assert!(
        aggregator
            .verifier_key
            .starts_with(&format!("{clave_host}+")),
        "the verifier key names the Log's origin: {}",
        aggregator.verifier_key
    );

    let clave2_data = tmp.path().join("clave-data-2");
    let aggregator2 = start_aggregator(
        &clave,
        clave2_data.clone(),
        Some(&suffix_list),
        Some(&site_proxy),
    );
    let clave2_host = aggregator2.log_id.clone();
    let clave2_base = aggregator2.base_url.clone();
    let clave2_stderr = aggregator2.stderr.clone();

    run(
        &spake,
        &[
            "init",
            "--domain",
            &site_host,
            "--out",
            s(&site),
            "--state",
            s(&spake_state),
        ],
    );
    run(
        &spake,
        &[
            "build",
            "--site",
            s(&site),
            "--domain",
            &site_host,
            "--out",
            s(&site),
            "--state",
            s(&spake_state),
        ],
    );

    let http = reqwest::blocking::Client::new();

    run(
        &spake,
        &[
            "ping",
            "--log",
            &clave_base,
            "--domain",
            &site_host,
            "--allow-http",
            "--no-retry",
        ],
    );
    wait_until_status_active(&http, &clave_base, &site_host);
    run(
        &spake,
        &[
            "ping",
            "--log",
            &clave2_base,
            "--domain",
            &site_host,
            "--allow-http",
            "--no-retry",
        ],
    );
    wait_until_status_active(&http, &clave2_base, &site_host);

    let first_seal = grid_instant(0);
    run(
        &clave,
        &["seal", "--data", s(&clave_data), "--at", &first_seal],
    );
    run(
        &clave,
        &["seal", "--data", s(&clave2_data), "--at", &first_seal],
    );

    let anchor_path = clave_data.join("anchor.json");
    let anchor2_path = clave2_data.join("anchor.json");
    run(
        &graven,
        &[
            "sync",
            "--anchor",
            s(&anchor_path),
            "--log",
            &clave_base,
            "--dir",
            s(&gdir),
            "--tier1",
            "--allow-http",
        ],
    );
    run(
        &graven,
        &[
            "sync",
            "--anchor",
            s(&anchor2_path),
            "--log",
            &clave2_base,
            "--dir",
            s(&gdir),
            "--allow-http",
        ],
    );

    run(
        &spake,
        &[
            "init",
            "--domain",
            &labeler_host,
            "--out",
            s(&labeler_site),
            "--state",
            s(&labeler_state),
        ],
    );
    run(
        &spake,
        &[
            "build",
            "--site",
            s(&labeler_site),
            "--domain",
            &labeler_host,
            "--out",
            s(&labeler_site),
            "--state",
            s(&labeler_state),
        ],
    );
    let labeled_url = format!("https://{site_host}/a.html");
    let label_output = run(
        &spake,
        &[
            "label",
            "--out",
            s(&labeler_site),
            "--state",
            s(&labeler_state),
            "--subject",
            &labeled_url,
            "--name",
            "wist:spam",
            "--value",
            "900000",
        ],
    );
    let label_id = String::from_utf8_lossy(&label_output.stdout)
        .trim()
        .to_string();
    assert!(label_id.starts_with("sha256:"), "{label_id}");
    run(
        &spake,
        &[
            "define",
            "--out",
            s(&labeler_site),
            "--state",
            s(&labeler_state),
            "--name",
            "wist:spam",
            "--description",
            &format!("https://{labeler_host}/labels/spam"),
            "--treatment",
            "warn",
        ],
    );
    run(
        &spake,
        &[
            "label",
            "--out",
            s(&labeler_site),
            "--state",
            s(&labeler_state),
            "--subject",
            "seed.localhost",
            "--name",
            "wist:trust-seed",
        ],
    );
    for base in [&clave_base, &clave2_base] {
        run(
            &spake,
            &[
                "ping",
                "--log",
                base,
                "--domain",
                &labeler_host,
                "--allow-http",
                "--no-retry",
            ],
        );
        wait_until_status_active(&http, base, &labeler_host);
    }
    for (host, dir) in &graph_sites {
        let state = tmp.path().join(format!("state-{host}"));
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
            ],
        );
        run(
            &spake,
            &[
                "ping",
                "--log",
                &clave_base,
                "--domain",
                host,
                "--allow-http",
                "--no-retry",
            ],
        );
        wait_until_status_active(&http, &clave_base, host);
    }

    mutate_fixture_page(&site);
    let since = now_rfc3339();
    run(
        &spake,
        &[
            "build",
            "--site",
            s(&site),
            "--domain",
            &site_host,
            "--out",
            s(&site),
            "--state",
            s(&spake_state),
        ],
    );
    run(
        &spake,
        &[
            "ping",
            "--log",
            &clave_base,
            "--domain",
            &site_host,
            "--allow-http",
            "--no-retry",
        ],
    );
    run(
        &spake,
        &[
            "ping",
            "--log",
            &clave2_base,
            "--domain",
            &site_host,
            "--allow-http",
            "--no-retry",
        ],
    );
    let final_status =
        wait_until_pulled_since(&http, &clave_base, &site_host, &since, &clave_stderr);
    wait_until_pulled_since(&http, &clave2_base, &site_host, &since, &clave2_stderr);
    std::fs::write(
        clave_data.join("status.json"),
        serde_json::to_vec(&final_status).expect("serialize status"),
    )
    .expect("write status.json");

    std::thread::sleep(Duration::from_secs(2));
    let second_seal = grid_instant(1);
    run(
        &clave,
        &["seal", "--data", s(&clave_data), "--at", &second_seal],
    );
    run(
        &clave,
        &["seal", "--data", s(&clave2_data), "--at", &second_seal],
    );

    let disputed_since = now_rfc3339();
    run(
        &spake,
        &[
            "dispute",
            "--out",
            s(&site),
            "--state",
            s(&spake_state),
            "--label",
            &label_id,
            "--subject",
            &labeled_url,
            "--log",
            "log.localhost",
            "--height",
            "0",
        ],
    );
    for base in [&clave_base, &clave2_base] {
        run(
            &spake,
            &[
                "ping",
                "--log",
                base,
                "--domain",
                &site_host,
                "--allow-http",
                "--no-retry",
            ],
        );
    }
    wait_until_pulled_since(
        &http,
        &clave_base,
        &site_host,
        &disputed_since,
        &clave_stderr,
    );
    wait_until_pulled_since(
        &http,
        &clave2_base,
        &site_host,
        &disputed_since,
        &clave2_stderr,
    );
    std::thread::sleep(Duration::from_secs(2));
    let third_seal = grid_instant(2);
    run(
        &clave,
        &["seal", "--data", s(&clave_data), "--at", &third_seal],
    );
    run(
        &clave,
        &["seal", "--data", s(&clave2_data), "--at", &third_seal],
    );
    run(
        &graven,
        &["subscribe", "--dir", s(&gdir), "--labeler", &labeler_host],
    );
    run_with_env(
        &graven,
        &["sync", "--dir", s(&gdir), "--allow-http"],
        &[
            ("HTTP_PROXY", &site_proxy),
            ("http_proxy", &site_proxy),
            ("NO_PROXY", "127.0.0.1"),
            ("no_proxy", "127.0.0.1"),
        ],
    );

    let mut mcp = McpClient::start(&graven, &gdir);
    let labels = mcp.tool_call("get_labels", serde_json::json!({"subject": labeled_url}));
    let labels = labels.as_array().expect("get_labels returns an array");
    assert_eq!(labels.len(), 1, "{labels:?}");
    let label = &labels[0];
    assert_eq!(label["labeler"], labeler_host);
    assert_eq!(label["name"], "wist:spam");
    assert_eq!(label["value"], 900000);
    assert_eq!(label["subscribed"], true);
    assert_eq!(label["treatment"], "warn", "{label}");
    assert_eq!(label["label_id"], label_id);
    let disputes = label["disputes"].as_array().expect("disputes array");
    assert_eq!(disputes.len(), 1, "{label}");
    assert_eq!(disputes[0]["disputant"], site_host);
    assert_eq!(
        label["provenance"].as_array().map(Vec::len),
        Some(2),
        "{label}"
    );
    let ranked = mcp.tool_call(
        "search",
        serde_json::json!({"query": "orchard", "profile": "default"}),
    );
    let ranked = ranked.as_array().expect("search returns an array");
    let order: Vec<&str> = ranked
        .iter()
        .map(|h| h["url"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(
        order,
        [cited_url.as_str(), farmed_url.as_str()],
        "{ranked:?}"
    );
    assert_eq!(ranked[0]["ranking"]["profile"], "default");
    assert!(
        ranked[0]["ranking"]["signals"]["trust"]
            .as_f64()
            .unwrap_or(0.0)
            > 0.0,
        "{ranked:?}"
    );
    assert!(ranked[0]["ranking"]["explanation"]
        .as_array()
        .is_some_and(|e| !e.is_empty()));
    let text_only = mcp.tool_call(
        "search",
        serde_json::json!({"query": "orchard", "profile": "text-only"}),
    );
    let text_only = text_only.as_array().expect("search returns an array");
    let order: Vec<&str> = text_only
        .iter()
        .map(|h| h["url"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(
        order,
        [farmed_url.as_str(), cited_url.as_str()],
        "{text_only:?}"
    );
    let profiles = mcp.tool_call("list_profiles", serde_json::json!({}));
    assert!(
        profiles.as_array().is_some_and(|p| p.len() >= 4),
        "{profiles}"
    );
    let labelers = mcp.tool_call("list_labelers", serde_json::json!({}));
    let labelers = labelers.as_array().expect("list_labelers returns an array");
    assert!(
        labelers
            .iter()
            .any(|l| l["labeler"] == labeler_host && l["label_count"] == 2),
        "{labelers:?}"
    );
    assert!(mcp
        .tool_call(
            "get_labels",
            serde_json::json!({"subject": "https://localhost/b.html"})
        )
        .as_array()
        .is_some_and(Vec::is_empty));
    // The subscribed Labeler marked the page as spam, so the default
    // profile drops it; the text-only profile ranks it by relevance alone.
    assert!(
        mcp.search("changed").is_empty(),
        "the default profile did not drop the spam-labeled page"
    );
    let hits = mcp.search_with_profile("changed", "text-only");
    assert!(!hits.is_empty(), "search(\"changed\") returned no hits");
    let hit = hits
        .iter()
        .find(|h| h["url"].as_str().unwrap_or_default().ends_with("/a.html"))
        .unwrap_or_else(|| panic!("no hit ending in /a.html among {hits:?}"));
    let provenance = hit["provenance"]
        .as_array()
        .unwrap_or_else(|| panic!("provenance is not an array: {hit}"));
    assert_eq!(
        provenance.len(),
        2,
        "expected dedup across 2 logs, got {hit}"
    );
    let log_ids: Vec<&str> = provenance
        .iter()
        .map(|p| p["log_id"].as_str().expect("log_id is a string"))
        .collect();
    assert_ne!(
        log_ids[0], log_ids[1],
        "expected distinct log_ids, got {hit}"
    );
    assert!(
        provenance
            .iter()
            .all(|p| p["synced_height"].as_u64().unwrap_or(0) >= 1),
        "expected synced_height >= 1 for both logs, got {hit}"
    );
    let url = hit["url"]
        .as_str()
        .expect("hit url is a string")
        .to_string();
    let delta_id = hit["delta_id"]
        .as_str()
        .expect("delta_id is a string")
        .to_string();
    let rec = mcp.get_record(&url);
    assert_eq!(
        rec["delta_id"], hit["delta_id"],
        "get_record delta_id mismatch"
    );

    let extract = mcp.get_extract(&url);
    let extract_text = extract["extract"].as_str().expect("extract is a string");
    assert!(!extract_text.is_empty(), "extract is empty");
    assert!(
        extract_text.contains("changed"),
        "extract does not contain \"changed\": {extract_text}"
    );
    drop(mcp);

    run(
        &clave,
        &[
            "withdraw",
            "--data",
            s(&clave_data),
            "--domain",
            &site_host,
            "--delta-id",
            &delta_id,
            "--legal-basis",
            "test",
            "--jurisdiction",
            "test",
        ],
    );
    std::thread::sleep(Duration::from_secs(2));
    let fourth_seal = grid_instant(3);
    run(
        &clave,
        &["seal", "--data", s(&clave_data), "--at", &fourth_seal],
    );
    run(&graven, &["sync", "--dir", s(&gdir), "--allow-http"]);

    let mut mcp2 = McpClient::start(&graven, &gdir);
    let hits2 = mcp2.search_with_profile("changed", "text-only");
    let hit2 = hits2
        .iter()
        .find(|h| h["url"].as_str().unwrap_or_default().ends_with("/a.html"))
        .unwrap_or_else(|| panic!("no hit ending in /a.html among {hits2:?}"));
    let provenance2 = hit2["provenance"]
        .as_array()
        .unwrap_or_else(|| panic!("provenance is not an array: {hit2}"));
    assert_eq!(
        provenance2.len(),
        1,
        "expected single surviving log after withdrawal, got {hit2}"
    );
    assert_eq!(
        provenance2[0]["log_id"], clave2_host,
        "expected surviving provenance to be log 2, got {hit2}"
    );
    drop(mcp2);

    // --- a signing key rotates while the outgoing key keeps an overlap ---
    run(
        &spake,
        &[
            "rotate",
            "--out",
            s(&site),
            "--state",
            s(&spake_state),
            "--overlap-seconds",
            "86400",
        ],
    );
    let rotated = read_json(&site.join(".well-known/wist/publisher.json"));
    let keys = rotated["publisher"]["keys"]
        .as_array()
        .unwrap_or_else(|| panic!("keys is not an array: {rotated}"));
    assert_eq!(keys.len(), 2, "the outgoing key stays listed: {rotated}");
    assert!(
        keys[0]["exp"].is_u64(),
        "the outgoing key expires at the end of the overlap: {rotated}"
    );
    assert!(
        keys[1].get("exp").is_none(),
        "the incoming key does not expire: {rotated}"
    );
    assert_eq!(
        rotated["sig"]["key_id"], keys[0]["kid"],
        "the rotation is signed by the key it replaces: {rotated}"
    );

    revise_fixture_page(
        &site,
        "beta page body content",
        "beta page body content rotated",
    );
    run(
        &spake,
        &[
            "build",
            "--site",
            s(&site),
            "--domain",
            &site_host,
            "--out",
            s(&site),
            "--state",
            s(&spake_state),
        ],
    );
    let rotated_since = now_rfc3339();
    for base in [&clave_base, &clave2_base] {
        run(
            &spake,
            &[
                "ping",
                "--log",
                base,
                "--domain",
                &site_host,
                "--allow-http",
                "--no-retry",
            ],
        );
    }
    wait_until_pulled_since(
        &http,
        &clave_base,
        &site_host,
        &rotated_since,
        &clave_stderr,
    );
    wait_until_pulled_since(
        &http,
        &clave2_base,
        &site_host,
        &rotated_since,
        &clave2_stderr,
    );
    std::thread::sleep(Duration::from_secs(2));
    let fifth_seal = grid_instant(4);
    for data in [&clave_data, &clave2_data] {
        run(&clave, &["seal", "--data", s(data), "--at", &fifth_seal]);
    }
    run(&graven, &["sync", "--dir", s(&gdir), "--allow-http"]);

    let mut mcp3 = McpClient::start(&graven, &gdir);
    let rotated_hits = mcp3.search_with_profile("rotated", "text-only");
    assert!(
        rotated_hits
            .iter()
            .any(|h| h["url"].as_str().unwrap_or_default().ends_with("/b.html")),
        "a Delta signed under the incoming key did not reach the index: {rotated_hits:?}"
    );
    drop(mcp3);

    // --- a Declaration published from the web host alone is reversed ---
    let owner = read_json(&site.join(".well-known/wist/publisher.json"));
    let owner_seq = owner["publisher"]["seq"].as_u64().expect("owner seq");
    let thief = wist_core::crypto::SigningKey::from_seed(&[42u8; 32]);
    let thief_entry = wist_core::objects::PublisherKey::new(
        &thief.public().to_b64u(),
        u64::try_from(jiff::Timestamp::now().as_second() - 3600).expect("unix second"),
        None,
    );
    let hijacked = wist_core::envelope::sign_envelope(
        &serde_json::json!({
            "wist_version": "1.0.0",
            "domain": site_host,
            "seq": owner_seq + 1,
            "prev_declaration": wist_core::declaration::inner_hash(&owner).expect("owner hash"),
            "keys": [thief_entry.clone()],
        }),
        "publisher",
        &thief_entry.kid,
        &thief,
    )
    .expect("sign the hijacked Declaration");
    std::fs::write(
        site.join(".well-known/wist/publisher.json"),
        serde_json::to_vec(&hijacked).expect("serialize the hijacked Declaration"),
    )
    .expect("serve the hijacked Declaration");

    let hijacked_since = now_rfc3339();
    for base in [&clave_base, &clave2_base] {
        run(
            &spake,
            &[
                "ping",
                "--log",
                base,
                "--domain",
                &site_host,
                "--allow-http",
                "--no-retry",
            ],
        );
    }
    wait_until_pulled_since(
        &http,
        &clave_base,
        &site_host,
        &hijacked_since,
        &clave_stderr,
    );
    std::thread::sleep(Duration::from_secs(2));
    let sixth_seal = grid_instant(5);
    run(
        &clave,
        &["seal", "--data", s(&clave_data), "--at", &sixth_seal],
    );

    let entries = snapshot_state_entries(&clave_data);
    let declaration_tuple = state_tuple(&entries, "declaration", &site_host)
        .unwrap_or_else(|| panic!("no declaration tuple for {site_host}: {entries:?}"));
    assert_eq!(
        declaration_tuple[2], owner,
        "the hijacked Declaration must not take the Declaration in force"
    );
    let pending_tuple = state_tuple(&entries, "pending_declaration", &site_host)
        .unwrap_or_else(|| panic!("no pending_declaration tuple: {entries:?}"));
    assert_eq!(
        pending_tuple[2], hijacked,
        "the hijack is sealed as pending"
    );
    assert!(
        pending_tuple[4].as_u64() > pending_tuple[3].as_u64(),
        "the activation height follows the sealing height: {pending_tuple}"
    );

    // The owner still holds a listed key and answers from the Declaration
    // its own state directory retained, above the floor the hijack raised.
    run(
        &spake,
        &[
            "rotate",
            "--out",
            s(&site),
            "--state",
            s(&spake_state),
            "--restore",
            "--seq",
            &(owner_seq + 2).to_string(),
            "--overlap-seconds",
            "86400",
        ],
    );
    run(
        &spake,
        &[
            "build",
            "--site",
            s(&site),
            "--domain",
            &site_host,
            "--out",
            s(&site),
            "--state",
            s(&spake_state),
        ],
    );
    let reversed = read_json(&site.join(".well-known/wist/publisher.json"));
    let reversed_since = now_rfc3339();
    run(
        &spake,
        &[
            "ping",
            "--log",
            &clave_base,
            "--domain",
            &site_host,
            "--allow-http",
            "--no-retry",
        ],
    );
    wait_until_pulled_since(
        &http,
        &clave_base,
        &site_host,
        &reversed_since,
        &clave_stderr,
    );
    std::thread::sleep(Duration::from_secs(2));
    let seventh_seal = grid_instant(6);
    run(
        &clave,
        &["seal", "--data", s(&clave_data), "--at", &seventh_seal],
    );

    let entries = snapshot_state_entries(&clave_data);
    assert_eq!(
        state_tuple(&entries, "declaration", &site_host).map(|t| t[2].clone()),
        Some(reversed),
        "the reversal takes the Declaration in force"
    );
    assert!(
        state_tuple(&entries, "pending_declaration", &site_host).is_none(),
        "the reversed Declaration is discarded: {entries:?}"
    );

    run(&graven, &["sync", "--dir", s(&gdir), "--allow-http"]);
    let mut mcp4 = McpClient::start(&graven, &gdir);
    let surviving = mcp4.search_with_profile("rotated", "text-only");
    assert!(
        surviving
            .iter()
            .any(|h| h["url"].as_str().unwrap_or_default().ends_with("/b.html")),
        "the domain's records did not survive the reversal: {surviving:?}"
    );
    drop(mcp4);

    // --- a one-Epoch mismatch Label is not counted yet ---
    run(
        &spake,
        &[
            "label",
            "--out",
            s(&labeler_site),
            "--state",
            s(&labeler_state),
            "--subject",
            &cited_url,
            "--name",
            "wist:mismatch",
        ],
    );
    let mismatch_since = now_rfc3339();
    for base in [&clave_base, &clave2_base] {
        run(
            &spake,
            &[
                "ping",
                "--log",
                base,
                "--domain",
                &labeler_host,
                "--allow-http",
                "--no-retry",
            ],
        );
    }
    wait_until_pulled_since(
        &http,
        &clave_base,
        &labeler_host,
        &mismatch_since,
        &clave_stderr,
    );
    wait_until_pulled_since(
        &http,
        &clave2_base,
        &labeler_host,
        &mismatch_since,
        &clave2_stderr,
    );
    std::thread::sleep(Duration::from_secs(2));
    let eighth_seal = grid_instant(7);
    for data in [&clave_data, &clave2_data] {
        run(&clave, &["seal", "--data", s(data), "--at", &eighth_seal]);
    }
    run(&graven, &["sync", "--dir", s(&gdir), "--allow-http"]);

    let mut mcp5 = McpClient::start(&graven, &gdir);
    let cited_mismatch = |hits: &[serde_json::Value]| -> bool {
        hits.iter()
            .find(|h| h["url"] == cited_url.as_str())
            .map(|h| h["ranking"]["signals"]["mismatch"] == true)
            .unwrap_or_else(|| panic!("no hit for {cited_url}: {hits:?}"))
    };
    let one_epoch = mcp5.tool_call(
        "search",
        serde_json::json!({"query": "orchard", "profile": "default"}),
    );
    assert!(
        !cited_mismatch(one_epoch.as_array().expect("search returns an array")),
        "a Label sealed one Epoch ago must not count yet: {one_epoch}"
    );
    drop(mcp5);

    // The same Label, still live an Epoch later, counts.
    let ninth_seal = grid_instant(8);
    for data in [&clave_data, &clave2_data] {
        run(&clave, &["seal", "--data", s(data), "--at", &ninth_seal]);
    }
    run(&graven, &["sync", "--dir", s(&gdir), "--allow-http"]);
    let mut mcp6 = McpClient::start(&graven, &gdir);
    let two_epochs = mcp6.tool_call(
        "search",
        serde_json::json!({"query": "orchard", "profile": "default"}),
    );
    assert!(
        cited_mismatch(two_epochs.as_array().expect("search returns an array")),
        "a Label live through two consecutive Epochs must count: {two_epochs}"
    );
    drop(mcp6);

    validate_artifacts(&site, &clave_data);
    verify_with_external_tlog_client(&aggregator.base_url, &aggregator.verifier_key);

    eprintln!("end_to_end completed in {:?}", harness_start.elapsed());
}
