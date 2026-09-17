use e2e::{
    free_loopback_addr, graven_bin, grid_instant, now_rfc3339, resolve_sibling_bin, run,
    run_with_env, s, serve_sites, spawn_clave_serve, wait_until_pulled_since,
    wait_until_status_active, workspace_root, McpClient,
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
    let (proxy_addr, _) = serve_sites(BTreeMap::from([
        (site_host.clone(), site.clone()),
        (labeler_host.clone(), labeler_site.clone()),
    ]));
    let site_proxy = format!("http://{proxy_addr}");

    let spake_state = tmp.path().join("spake-state");
    let labeler_state = tmp.path().join("labeler-state");
    let clave_data = tmp.path().join("clave-data");
    let gdir = tmp.path().join("graven-store");

    let suffix_list =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/public-suffix-list.dat");
    let clave_host = free_loopback_addr();
    run(
        &clave,
        &[
            "init",
            "--log-id",
            &clave_host,
            "--data",
            s(&clave_data),
            "--suffix-list",
            s(&suffix_list),
        ],
    );
    let (_clave_child, clave_bound_addr, clave_stderr) =
        spawn_clave_serve(&clave, &clave_data, &clave_host, &site_proxy);
    assert_eq!(
        clave_bound_addr, clave_host,
        "clave serve bound a different address than the pre-picked --log-id"
    );
    let clave_base = format!("http://{clave_host}");

    let clave2_data = tmp.path().join("clave-data-2");
    let clave2_host = free_loopback_addr();
    run(
        &clave,
        &[
            "init",
            "--log-id",
            &clave2_host,
            "--data",
            s(&clave2_data),
            "--suffix-list",
            s(&suffix_list),
        ],
    );
    let (_clave2_child, clave2_bound_addr, clave2_stderr) =
        spawn_clave_serve(&clave, &clave2_data, &clave2_host, &site_proxy);
    assert_eq!(
        clave2_bound_addr, clave2_host,
        "clave serve bound a different address than the pre-picked --log-id"
    );
    let clave2_base = format!("http://{clave2_host}");

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
    let labelers = mcp.tool_call("list_labelers", serde_json::json!({}));
    let labelers = labelers.as_array().expect("list_labelers returns an array");
    assert!(
        labelers
            .iter()
            .any(|l| l["labeler"] == labeler_host && l["label_count"] == 1),
        "{labelers:?}"
    );
    assert!(mcp
        .tool_call(
            "get_labels",
            serde_json::json!({"subject": "https://localhost/b.html"})
        )
        .as_array()
        .is_some_and(Vec::is_empty));
    let hits = mcp.search("changed");
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
    let hits2 = mcp2.search("changed");
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

    validate_artifacts(&site, &clave_data);

    eprintln!("end_to_end completed in {:?}", harness_start.elapsed());
}
