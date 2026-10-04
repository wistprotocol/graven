use e2e::{
    checkpoint_verifier_key, graven_bin, grid_instant, marked_page, read_json, resolve_sibling_bin,
    run, run_with_env, s, seal_epoch, serve_sites, start_aggregator, synced_heads,
    wait_until_status_active, wait_until_unreachable, workspace_root, Aggregator, McpClient, Site,
    SyncedHead,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

struct Binaries {
    spake: PathBuf,
    clave: PathBuf,
    graven: PathBuf,
}

fn binaries() -> Binaries {
    Binaries {
        spake: resolve_sibling_bin("SPAKE_BIN", "spake"),
        clave: resolve_sibling_bin("CLAVE_BIN", "clave"),
        graven: graven_bin(),
    }
}

fn suffix_list() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/public-suffix-list.dat")
}

fn log_store_dir(dir: &Path, log_id: &str) -> PathBuf {
    let sanitized: String = log_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    dir.join("logs").join(sanitized)
}

fn record_rows(dir: &Path, log_id: &str) -> Vec<graven::sync::RecordRow> {
    graven::sync::record_rows(&log_store_dir(dir, log_id)).expect("read the records rows")
}

fn assert_records_are_the_replays(dir: &Path, heads: &BTreeMap<String, SyncedHead>) {
    assert!(!heads.is_empty(), "the sync reported no Log");
    for log_id in heads.keys() {
        let replayed = graven::sync::replayed_records(&log_store_dir(dir, log_id))
            .expect("resume the stored Replay");
        assert_eq!(
            record_rows(dir, log_id),
            replayed,
            "the records rows of {log_id} are the records its resumed Replay materializes"
        );
    }
}

fn follow(
    graven: &Path,
    aggregator: &Aggregator,
    dir: &Path,
    tier1: bool,
) -> BTreeMap<String, SyncedHead> {
    let anchor = aggregator.data.join("anchor.json");
    let mut args = vec![
        "follow",
        "--anchor",
        s(&anchor),
        "--log",
        &aggregator.base_url,
        "--dir",
        s(dir),
        "--allow-http",
    ];
    if tier1 {
        args.push("--tier1");
    }
    let output = run(graven, &args);
    let heads = synced_heads(&String::from_utf8_lossy(&output.stdout));
    assert_records_are_the_replays(dir, &heads);
    heads
}

fn sync_with_env(graven: &Path, dir: &Path, env: &[(&str, &str)]) -> BTreeMap<String, SyncedHead> {
    let output = run_with_env(graven, &["sync", "--dir", s(dir), "--allow-http"], env);
    let heads = synced_heads(&String::from_utf8_lossy(&output.stdout));
    assert_records_are_the_replays(dir, &heads);
    heads
}

fn sync(graven: &Path, dir: &Path) -> BTreeMap<String, SyncedHead> {
    sync_with_env(graven, dir, &[])
}

fn seal_all(clave: &Path, aggregators: &[&Aggregator], at: &str) -> u64 {
    let epochs: Vec<u64> = aggregators
        .iter()
        .map(|aggregator| seal_epoch(clave, &aggregator.data, at))
        .collect();
    epochs[0]
}

fn ping_all(
    spake: &Path,
    http: &reqwest::blocking::Client,
    site: &Site,
    aggregators: &[&Aggregator],
    allowed: &[(&str, &str)],
) {
    for aggregator in aggregators {
        site.ping_and_wait_allowing(spake, http, aggregator, allowed);
    }
}

fn hits_for<'a>(hits: &'a [Value], url: &str) -> Option<&'a Value> {
    hits.iter().find(|hit| hit["url"] == url)
}

fn not_found(mcp: &mut McpClient, url: &str) {
    let absent = mcp.get_record_error(url);
    assert_eq!(
        absent["message"], "not found",
        "get_record answers for {url}: {absent}"
    );
}

struct RunRecord {
    name: String,
    scenarios: Vec<Value>,
}

fn repo_revision(dir: &Path) -> Value {
    let git = |args: &[&str]| {
        Command::new("git")
            .args(["-C", s(dir)])
            .args(args)
            .output()
            .ok()
            .filter(|output| output.status.success())
    };
    let head = git(&["rev-parse", "HEAD"])
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string());
    let dirty = git(&["status", "--porcelain"]).map(|output| !output.stdout.is_empty());
    json!({"head": head, "dirty": dirty})
}

fn spec_dir() -> PathBuf {
    std::env::var("WIST_SPEC_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            workspace_root()
                .parent()
                .expect("graven repo has a parent directory")
                .join("spec")
        })
}

impl RunRecord {
    fn new(name: &str) -> Self {
        RunRecord {
            name: name.to_string(),
            scenarios: Vec::new(),
        }
    }

    fn exercised(&mut self, scenario: &str, epoch: u64) {
        self.scenarios
            .push(json!({"scenario": scenario, "sealed_at_epoch": epoch}));
    }

    fn write(&self) {
        let siblings = workspace_root()
            .parent()
            .expect("graven repo has a parent directory")
            .to_path_buf();
        let record = json!({
            "repositories": {
                "core": repo_revision(&siblings.join("core")),
                "spake": repo_revision(&siblings.join("spake")),
                "clave": repo_revision(&siblings.join("clave")),
                "graven": repo_revision(&workspace_root()),
                "spec": repo_revision(&spec_dir()),
            },
            "scenarios": self.scenarios,
        });
        let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{}.json", self.name));
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(&record).expect("serialize the run record"),
        )
        .expect("write the run record");
        println!("run record: {}", path.display());
        let written = read_json(&path);
        for repo in ["core", "spake", "clave", "graven", "spec"] {
            assert!(
                written["repositories"][repo].is_object(),
                "the run record carries no revision for {repo}: {written}"
            );
        }
        assert_eq!(
            written["scenarios"].as_array().map(Vec::len),
            Some(self.scenarios.len()),
            "the run record lists every scenario the run exercised: {written}"
        );
    }
}

fn validate_artifacts(site: &Path, clave_data: &Path) {
    let spec_dir = spec_dir();
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

fn snapshot_state_entries(clave_data: &Path) -> Vec<Value> {
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

fn state_tuple(entries: &[Value], kind: &str, domain: &str) -> Option<Value> {
    entries
        .iter()
        .find(|entry| entry[0] == kind && entry[1] == domain)
        .cloned()
}

fn copy_tree(from: &Path, to: &Path) {
    let _ = std::fs::remove_dir_all(to);
    std::fs::create_dir_all(to).expect("create the copy's directory");
    for entry in std::fs::read_dir(from).expect("read the directory to copy") {
        let entry = entry.expect("directory entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).expect("copy a file");
        }
    }
}

fn fetch_text(http: &reqwest::blocking::Client, url: &str) -> String {
    let response = http
        .get(url)
        .send()
        .unwrap_or_else(|e| panic!("GET {url}: {e}"));
    let status = response.status();
    assert!(status.is_success(), "GET {url} answered {status}");
    response
        .text()
        .unwrap_or_else(|e| panic!("read the body of {url}: {e}"))
}

fn parse_note(note: &str) -> wist_core::checkpoint::Checkpoint {
    wist_core::checkpoint::Checkpoint::parse(note)
        .unwrap_or_else(|e| panic!("parse the Checkpoint note: {e}\n{note}"))
}

// WIST-3 §3.4: a `key_id` never appears in a note, so a rotation is read off the note key IDs.
fn log_signature_key_ids(note: &str, log_id: &str) -> Vec<String> {
    parse_note(note)
        .signatures()
        .iter()
        .filter(|line| line.name == log_id)
        .map(|line| wist_core::crypto::hex_encode(&line.key_id))
        .collect()
}

struct LogKey {
    key_id: String,
    note_key_id: String,
    added: Option<u64>,
    removed: Option<u64>,
}

fn log_keys(clave: &Path, data: &Path) -> Vec<LogKey> {
    let output = run(clave, &["log-key", "list", "--data", s(data)]);
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            assert!(
                fields.len() >= 6 && fields[2] == "added" && fields[4] == "removed",
                "unexpected log-key list line {line:?}"
            );
            LogKey {
                key_id: fields[0].to_string(),
                note_key_id: fields[1].to_string(),
                added: fields[3].parse().ok(),
                removed: fields[5].parse().ok(),
            }
        })
        .collect()
}

fn log_key<'a>(keys: &'a [LogKey], key_id: &str) -> &'a LogKey {
    keys.iter()
        .find(|key| key.key_id == key_id)
        .unwrap_or_else(|| panic!("no Aggregator key {key_id} in the Log's key list"))
}

struct Grid {
    hours_ahead: i64,
}

impl Grid {
    fn new() -> Self {
        Grid { hours_ahead: 0 }
    }

    fn next(&mut self) -> String {
        let at = grid_instant(self.hours_ahead);
        self.hours_ahead += 1;
        at
    }
}

fn served_generated_at(site: &Site) -> String {
    site.catalog()["catalog"]["generated_at"]
        .as_str()
        .expect("the served Catalog states its generated_at")
        .to_string()
}

#[test]
fn a_publication_reaches_the_consumer_through_two_logs_with_updates_removals_and_withdrawals() {
    let started = Instant::now();
    let mut record = RunRecord::new("e2e-publication");
    let Binaries {
        spake,
        clave,
        graven,
    } = binaries();
    let tmp = tempfile::tempdir().expect("create tempdir");
    let root = tmp.path();

    let site = Site::new(root, "localhost", "docs");
    site.write_page(
        "a.html",
        &marked_page("Alpha Page", "alpha page body content", &[]),
    );
    site.write_page(
        "b.html",
        &marked_page("Beta Page", "beta page body content", &[]),
    );
    site.write_page(
        "gone.html",
        &marked_page(
            "Gone Page",
            "vanishing notes the publisher later removes",
            &[],
        ),
    );
    let (proxy_addr, _) = serve_sites(BTreeMap::from([(site.host.clone(), site.out.clone())]));
    let proxy = format!("http://{proxy_addr}");

    let mut first_log = start_aggregator(
        &clave,
        root.join("clave-data"),
        Some(&suffix_list()),
        Some(&proxy),
    );
    assert!(
        first_log
            .verifier_key
            .starts_with(&format!("{}+", first_log.log_id)),
        "the verifier key names the Log's origin: {}",
        first_log.verifier_key
    );
    let second_log = start_aggregator(
        &clave,
        root.join("clave-data-2"),
        Some(&suffix_list()),
        Some(&proxy),
    );
    let http = reqwest::blocking::Client::new();
    let mut refused: Vec<(&str, &str)> = Vec::new();

    let mut grid = Grid::new();
    site.init(&spake);
    ping_all(&spake, &http, &site, &[&first_log, &second_log], &refused);
    let declared_epoch = seal_all(&clave, &[&first_log, &second_log], &grid.next());
    record.exercised("declaration", declared_epoch);
    site.add_collection(&spake);
    site.publish(&spake);
    ping_all(&spake, &http, &site, &[&first_log, &second_log], &refused);
    let first_epoch = seal_all(&clave, &[&first_log, &second_log], &grid.next());
    record.exercised("publication", first_epoch);

    let gdir = root.join("graven-store");
    let heads = follow(&graven, &first_log, &gdir, true);
    assert_eq!(
        heads[&first_log.log_id].epoch, first_epoch,
        "the cold start adopts the Snapshot at the sealed Epoch"
    );
    follow(&graven, &second_log, &gdir, false);
    for aggregator in [&first_log, &second_log] {
        let state = graven::store::synced_state(&log_store_dir(&gdir, &aggregator.log_id))
            .expect("read the sync state");
        assert_eq!(
            state.walk_floor,
            Some(first_epoch),
            "the Consumer was installed from the Snapshot at the sealed Epoch"
        );
    }

    let a_url = site.url("a.html");
    let b_url = site.url("b.html");
    let gone_url = site.url("gone.html");
    let published_at = served_generated_at(&site);
    let first_item = site.item_id(&a_url);
    let mut mcp = McpClient::start(&graven, &gdir);
    let a = mcp.get_record(&a_url);
    assert_eq!(a["item_id"], first_item, "{a}");
    assert_eq!(a["collection"], "docs", "{a}");
    assert_eq!(a["publisher"], "localhost", "{a}");
    assert_eq!(a["generated_at"], published_at.as_str(), "{a}");
    assert_eq!(a["attested_at"], published_at.as_str(), "{a}");
    assert_eq!(a["title"], "Alpha Page", "{a}");
    let provenance = a["provenance"].as_array().expect("provenance array");
    assert_eq!(provenance.len(), 2, "one record seen in both Logs: {a}");
    assert_ne!(provenance[0]["log_id"], provenance[1]["log_id"], "{a}");
    assert!(
        provenance.iter().all(|p| p["synced_height"] == first_epoch),
        "{a}"
    );
    let hit = mcp.search("alpha");
    let hit = hits_for(&hit, &a_url).unwrap_or_else(|| panic!("search(alpha) misses {a_url}"));
    for field in ["item_id", "collection", "attested_at", "generated_at"] {
        assert_eq!(
            hit[field], a[field],
            "search and get_record disagree on {field}"
        );
    }
    let extract = mcp.get_extract(&a_url);
    assert!(
        extract["extract"]
            .as_str()
            .is_some_and(|text| text.contains("alpha page body content")),
        "{extract}"
    );
    drop(mcp);

    site.write_page(
        "a.html",
        &marked_page("Alpha Page changed", "alpha page body content changed", &[]),
    );
    site.publish(&spake);
    ping_all(&spake, &http, &site, &[&first_log, &second_log], &refused);
    let update_epoch = seal_all(&clave, &[&first_log, &second_log], &grid.next());
    record.exercised("update", update_epoch);
    let heads = sync(&graven, &gdir);
    assert_eq!(heads[&first_log.log_id].epoch, update_epoch);
    assert_eq!(heads[&second_log.log_id].epoch, update_epoch);

    let updated_at = served_generated_at(&site);
    let updated_item = site.item_id(&a_url);
    assert_ne!(updated_item, first_item, "the changed page is a new Item");
    let mut mcp = McpClient::start(&graven, &gdir);
    let a = mcp.get_record(&a_url);
    assert_eq!(a["item_id"], updated_item, "{a}");
    assert_eq!(a["title"], "Alpha Page changed", "{a}");
    assert_eq!(a["generated_at"], updated_at.as_str(), "{a}");
    assert!(
        hits_for(&mcp.search("changed"), &a_url).is_some(),
        "the changed page is not searchable by its new text"
    );
    assert!(
        mcp.get_extract(&a_url)["extract"]
            .as_str()
            .is_some_and(|text| text.contains("changed")),
        "the extract is not the changed page's"
    );
    assert_eq!(
        mcp.get_record(&gone_url)["url"],
        gone_url,
        "the page to be removed is not indexed before its removal"
    );
    drop(mcp);

    site.remove_page("gone.html");
    site.publish(&spake);
    ping_all(&spake, &http, &site, &[&first_log, &second_log], &refused);
    let removal_epoch = seal_all(&clave, &[&first_log, &second_log], &grid.next());
    record.exercised("url_removal", removal_epoch);
    sync(&graven, &gdir);
    let mut mcp = McpClient::start(&graven, &gdir);
    not_found(&mut mcp, &gone_url);
    assert!(
        hits_for(&mcp.search("vanishing"), &gone_url).is_none(),
        "the removed URL is still searchable"
    );
    assert_eq!(
        mcp.get_record(&b_url)["url"],
        b_url,
        "the domain's other record left the index with the removed one"
    );
    drop(mcp);

    run(
        &clave,
        &[
            "withdraw",
            "--data",
            s(&first_log.data),
            "--domain",
            &site.host,
            "--item-id",
            &updated_item,
            "--legal-basis",
            "test",
            "--jurisdiction",
            "test",
        ],
    );
    let withdrawal_epoch = seal_epoch(&clave, &first_log.data, &grid.next());
    refused.push(("WIST2-E03", &updated_item));
    record.exercised("payload_withdrawal", withdrawal_epoch);
    sync(&graven, &gdir);
    let mut mcp = McpClient::start(&graven, &gdir);
    let a = mcp.get_record(&a_url);
    let provenance = a["provenance"].as_array().expect("provenance array");
    assert_eq!(
        provenance.len(),
        1,
        "the record withdrawn from one Log is seen in the other alone: {a}"
    );
    assert_eq!(provenance[0]["log_id"], second_log.log_id.as_str(), "{a}");
    drop(mcp);

    let b_item = site.item_id(&b_url);
    run(
        &spake,
        &[
            "withdraw",
            "--out",
            s(&site.out),
            "--state",
            s(&site.state),
            "--collection",
            &site.collection,
            "--item-id",
            &b_item,
            "--unpublish",
        ],
    );
    site.remove_page("b.html");
    site.sign_due(&spake);
    assert!(
        !site
            .out
            .join(".well-known/wist/collections/docs/payloads")
            .join(format!(
                "{}.json",
                b_item.strip_prefix("sha256:").expect("Item ID form")
            ))
            .exists(),
        "the Publisher still serves the withdrawn Payload"
    );
    ping_all(&spake, &http, &site, &[&first_log, &second_log], &refused);
    let unpublished_epoch = seal_all(&clave, &[&first_log, &second_log], &grid.next());
    record.exercised("publisher_withdrawal", unpublished_epoch);
    sync(&graven, &gdir);
    let mut mcp = McpClient::start(&graven, &gdir);
    not_found(&mut mcp, &b_url);
    drop(mcp);

    let resumed_url = site.url("resumed.html");
    site.write_page(
        "resumed.html",
        &marked_page(
            "Resumed Page",
            "resumed notes admitted before the aggregator stopped",
            &[],
        ),
    );
    site.publish(&spake);
    site.ping_and_wait_allowing(&spake, &http, &first_log, &refused);
    let heads_before = sync(&graven, &gdir);
    let anchor = first_log.data.join("anchor.json");
    let anchor_before = std::fs::read(&anchor).expect("read anchor.json");
    let mut mcp = McpClient::start(&graven, &gdir);
    not_found(&mut mcp, &resumed_url);
    drop(mcp);

    first_log.stop();
    wait_until_unreachable(&http, &first_log.base_url, &site.host);
    first_log.start(&clave, Some(&proxy));
    wait_until_status_active(&http, &first_log.base_url, &site.host);
    assert_eq!(
        std::fs::read(&anchor).expect("read anchor.json"),
        anchor_before,
        "the restarted Aggregator serves a different Log Anchor"
    );
    let restart_epoch = seal_epoch(&clave, &first_log.data, &grid.next());
    record.exercised("aggregator_restart", restart_epoch);
    run(&clave, &["verify-history", "--data", s(&first_log.data)]);
    let heads_after = sync(&graven, &gdir);
    for (log_id, before) in &heads_before {
        let after = &heads_after[log_id];
        assert!(
            after.epoch >= before.epoch && after.tree_size >= before.tree_size,
            "log {log_id} rolled back across the restart: {before:?} then {after:?}"
        );
        if after.epoch == before.epoch {
            assert_eq!(after.root, before.root, "log {log_id} changed its root");
        }
    }
    assert!(heads_after[&first_log.log_id].epoch > heads_before[&first_log.log_id].epoch);
    let mut mcp = McpClient::start(&graven, &gdir);
    assert_eq!(
        mcp.get_record(&resumed_url)["url"],
        resumed_url,
        "an Item admitted before the restart did not seal after it"
    );
    let resumed_item = mcp.get_record(&resumed_url)["item_id"].clone();
    drop(mcp);

    site.write_page(
        "resumed.html",
        &marked_page(
            "Resumed Page",
            "resumed notes restarted from the persisted state directory",
            &[],
        ),
    );
    site.publish_in_fresh_env(&spake);
    ping_all(&spake, &http, &site, &[&first_log, &second_log], &refused);
    let publisher_restart_epoch = seal_all(&clave, &[&first_log, &second_log], &grid.next());
    record.exercised("publisher_restart", publisher_restart_epoch);
    sync(&graven, &gdir);
    let mut mcp = McpClient::start(&graven, &gdir);
    let restarted = mcp.get_record(&resumed_url);
    assert_ne!(
        restarted["item_id"], resumed_item,
        "a run from the persisted state directory published nothing new"
    );
    assert_eq!(restarted["item_id"], site.item_id(&resumed_url));
    assert!(
        hits_for(&mcp.search("restarted"), &resumed_url).is_some(),
        "the Item published from the persisted state directory is not searchable"
    );
    drop(mcp);

    validate_artifacts(&site.out, &first_log.data);
    verify_with_external_tlog_client(&first_log.base_url, &first_log.verifier_key);
    record.write();
    eprintln!("completed in {:?}", started.elapsed());
}

fn label_command(spake: &Path, labeler: &Site, args: &[&str]) -> String {
    let mut full = vec![
        "label",
        "--out",
        s(&labeler.out),
        "--state",
        s(&labeler.state),
    ];
    full.extend_from_slice(args);
    let output = run(spake, &full);
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn urls(hits: &[Value]) -> Vec<&str> {
    hits.iter()
        .map(|hit| hit["url"].as_str().unwrap_or_default())
        .collect()
}

#[test]
fn labels_disputes_and_link_ranking_reach_the_consumer() {
    let started = Instant::now();
    let mut record = RunRecord::new("e2e-labels");
    let Binaries {
        spake,
        clave,
        graven,
    } = binaries();
    let tmp = tempfile::tempdir().expect("create tempdir");
    let root = tmp.path();

    let site = Site::new(root, "localhost", "default");
    site.write_page(
        "a.html",
        &marked_page("Alpha Page", "alpha page body content", &[]),
    );
    site.write_page(
        "b.html",
        &marked_page("Beta Page", "beta page body content", &[]),
    );
    let labeler = Site::new(root, "labeler.localhost", "default");
    let cited_url = "https://cited.localhost/notes.html".to_string();
    let farmed_url = "https://farmed.localhost/farmed.html".to_string();
    let mut graph = vec![
        (
            "seed.localhost",
            "home.html",
            "Seed home",
            "A curated page of trustworthy sources on orchards.",
            vec![cited_url.clone()],
        ),
        (
            "cited.localhost",
            "notes.html",
            "Cited orchard notes",
            "The orchard is mentioned once among many other words about apples and pears.",
            vec![],
        ),
        (
            "farmed.localhost",
            "farmed.html",
            "Orchard orchard orchard",
            "orchard orchard orchard orchard orchard orchard orchard orchard",
            vec![],
        ),
    ];
    for host in ["f1.localhost", "f2.localhost", "f3.localhost"] {
        graph.push((
            host,
            "x.html",
            "Farm page",
            "boosting the farmed page",
            vec![farmed_url.clone()],
        ));
    }
    let graph: Vec<Site> = graph
        .into_iter()
        .map(|(host, page, title, body, links)| {
            let graph_site = Site::new(root, host, "default");
            graph_site.write_page(page, &marked_page(title, body, &links));
            graph_site
        })
        .collect();
    let mut served: BTreeMap<String, PathBuf> = BTreeMap::from([
        (site.host.clone(), site.out.clone()),
        (labeler.host.clone(), labeler.out.clone()),
    ]);
    served.extend(graph.iter().map(|g| (g.host.clone(), g.out.clone())));
    let (proxy_addr, _) = serve_sites(served);
    let proxy = format!("http://{proxy_addr}");

    let first_log = start_aggregator(
        &clave,
        root.join("clave-data"),
        Some(&suffix_list()),
        Some(&proxy),
    );
    let second_log = start_aggregator(
        &clave,
        root.join("clave-data-2"),
        Some(&suffix_list()),
        Some(&proxy),
    );
    let both = [&first_log, &second_log];
    let http = reqwest::blocking::Client::new();
    let mut grid = Grid::new();

    for publisher in [&site, &labeler] {
        publisher.init(&spake);
        publisher.publish(&spake);
        ping_all(&spake, &http, publisher, &both, &[]);
    }
    for graph_site in &graph {
        graph_site.init(&spake);
        graph_site.publish(&spake);
        graph_site.ping_and_wait(&spake, &http, &first_log);
    }
    let published_epoch = seal_all(&clave, &both, &grid.next());
    record.exercised("publication", published_epoch);
    let gdir = root.join("graven-store");
    follow(&graven, &first_log, &gdir, true);
    follow(&graven, &second_log, &gdir, false);

    let a_url = site.url("a.html");
    let b_url = site.url("b.html");
    let label_id = label_command(
        &spake,
        &labeler,
        &[
            "--subject",
            &a_url,
            "--name",
            "wist:spam",
            "--value",
            "900000",
        ],
    );
    assert!(label_id.starts_with("sha256:"), "{label_id}");
    run(
        &spake,
        &[
            "define",
            "--out",
            s(&labeler.out),
            "--state",
            s(&labeler.state),
            "--name",
            "wist:spam",
            "--description",
            &format!("https://{}/labels/spam", labeler.host),
            "--treatment",
            "warn",
        ],
    );
    label_command(
        &spake,
        &labeler,
        &["--subject", "seed.localhost", "--name", "wist:trust-seed"],
    );
    ping_all(&spake, &http, &labeler, &both, &[]);
    let label_epoch = seal_all(&clave, &both, &grid.next());
    record.exercised("label", label_epoch);

    run(
        &spake,
        &[
            "dispute",
            "--out",
            s(&site.out),
            "--state",
            s(&site.state),
            "--label",
            &label_id,
            "--subject",
            &a_url,
            "--log",
            "log.localhost",
            "--height",
            &label_epoch.to_string(),
        ],
    );
    ping_all(&spake, &http, &site, &both, &[]);
    let dispute_epoch = seal_all(&clave, &both, &grid.next());
    record.exercised("label_dispute", dispute_epoch);
    run(
        &graven,
        &["subscribe", "--dir", s(&gdir), "--labeler", &labeler.host],
    );
    let proxied = [
        ("HTTP_PROXY", proxy.as_str()),
        ("http_proxy", proxy.as_str()),
        ("NO_PROXY", "127.0.0.1"),
        ("no_proxy", "127.0.0.1"),
    ];
    sync_with_env(&graven, &gdir, &proxied);

    let mut mcp = McpClient::start(&graven, &gdir);
    let labels = mcp.tool_call("get_labels", json!({"subject": a_url}));
    let labels = labels.as_array().expect("get_labels returns an array");
    assert_eq!(labels.len(), 1, "{labels:?}");
    let label = &labels[0];
    assert_eq!(label["labeler"], labeler.host.as_str(), "{label}");
    assert_eq!(label["name"], "wist:spam", "{label}");
    assert_eq!(label["value"], 900000, "{label}");
    assert_eq!(label["subscribed"], true, "{label}");
    assert_eq!(label["treatment"], "warn", "{label}");
    assert_eq!(label["label_id"], label_id.as_str(), "{label}");
    let disputes = label["disputes"].as_array().expect("disputes array");
    assert_eq!(disputes.len(), 1, "{label}");
    assert_eq!(disputes[0]["disputant"], site.host.as_str(), "{label}");
    assert_eq!(
        label["provenance"].as_array().map(Vec::len),
        Some(2),
        "{label}"
    );
    let ranked = mcp.tool_call("search", json!({"query": "orchard", "profile": "default"}));
    let ranked = ranked.as_array().expect("search returns an array");
    assert_eq!(
        urls(ranked),
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
        json!({"query": "orchard", "profile": "text-only"}),
    );
    let text_only = text_only.as_array().expect("search returns an array");
    assert_eq!(
        urls(text_only),
        [farmed_url.as_str(), cited_url.as_str()],
        "{text_only:?}"
    );
    let profiles = mcp.tool_call("list_profiles", json!({}));
    assert!(
        profiles.as_array().is_some_and(|p| p.len() >= 4),
        "{profiles}"
    );
    let labelers = mcp.tool_call("list_labelers", json!({}));
    let labelers = labelers.as_array().expect("list_labelers returns an array");
    assert!(
        labelers
            .iter()
            .any(|l| l["labeler"] == labeler.host.as_str() && l["label_count"] == 2),
        "{labelers:?}"
    );
    assert!(mcp
        .tool_call("get_labels", json!({"subject": b_url}))
        .as_array()
        .is_some_and(Vec::is_empty));
    assert!(
        hits_for(&mcp.search("alpha"), &a_url).is_none(),
        "the default profile did not drop the spam-labeled page"
    );
    let hits = mcp.search_with_profile("alpha", "text-only");
    let hit = hits_for(&hits, &a_url).unwrap_or_else(|| panic!("no hit for {a_url}: {hits:?}"));
    assert_eq!(
        hit["provenance"].as_array().map(Vec::len),
        Some(2),
        "the labeled record is seen in both Logs: {hit}"
    );
    drop(mcp);

    label_command(
        &spake,
        &labeler,
        &["--subject", &cited_url, "--name", "wist:mismatch"],
    );
    ping_all(&spake, &http, &labeler, &both, &[]);
    let one_epoch = seal_all(&clave, &both, &grid.next());
    record.exercised("label_one_epoch_old", one_epoch);
    sync_with_env(&graven, &gdir, &proxied);
    let cited_mismatch = |mcp: &mut McpClient| -> bool {
        let hits = mcp.tool_call("search", json!({"query": "orchard", "profile": "default"}));
        let hits = hits.as_array().expect("search returns an array");
        hits_for(hits, &cited_url)
            .map(|hit| hit["ranking"]["signals"]["mismatch"] == true)
            .unwrap_or_else(|| panic!("no hit for {cited_url}: {hits:?}"))
    };
    let mut mcp = McpClient::start(&graven, &gdir);
    assert!(
        !cited_mismatch(&mut mcp),
        "a Label sealed one Epoch ago must not count yet"
    );
    drop(mcp);
    let two_epochs = seal_all(&clave, &both, &grid.next());
    record.exercised("label_two_epochs_live", two_epochs);
    sync_with_env(&graven, &gdir, &proxied);
    let mut mcp = McpClient::start(&graven, &gdir);
    assert!(
        cited_mismatch(&mut mcp),
        "a Label live through two consecutive Epochs must count"
    );
    drop(mcp);

    run(
        &graven,
        &["profile", "use", "--dir", s(&gdir), "--name", "text-only"],
    );
    let mut mcp = McpClient::start(&graven, &gdir);
    let selected = mcp.search("alpha");
    let selected = hits_for(&selected, &a_url).unwrap_or_else(|| {
        panic!("a query naming no profile did not use the selected one: {selected:?}")
    });
    assert_eq!(selected["ranking"]["profile"], "text-only");
    drop(mcp);
    run(
        &graven,
        &["profile", "use", "--dir", s(&gdir), "--name", "default"],
    );
    let mut mcp = McpClient::start(&graven, &gdir);
    assert!(
        hits_for(&mcp.search("alpha"), &a_url).is_none(),
        "selecting the default profile again did not restore its treatment of the spam Label"
    );
    let defaulted = mcp.search("orchard");
    assert_eq!(
        defaulted
            .first()
            .unwrap_or_else(|| panic!("no hit for orchard under the default profile"))["ranking"]
            ["profile"],
        "default"
    );
    drop(mcp);
    record.exercised("default_profile_persistence", two_epochs);

    validate_artifacts(&labeler.out, &first_log.data);
    record.write();
    eprintln!("completed in {:?}", started.elapsed());
}

#[test]
fn publisher_key_rotation_and_a_reversed_hijack_keep_the_records() {
    let started = Instant::now();
    let mut record = RunRecord::new("e2e-publisher-keys");
    let Binaries {
        spake,
        clave,
        graven,
    } = binaries();
    let tmp = tempfile::tempdir().expect("create tempdir");
    let root = tmp.path();

    let site = Site::new(root, "localhost", "default");
    site.write_page(
        "a.html",
        &marked_page("Alpha Page", "alpha page body content", &[]),
    );
    site.write_page(
        "b.html",
        &marked_page("Beta Page", "beta page body content", &[]),
    );
    let (proxy_addr, _) = serve_sites(BTreeMap::from([(site.host.clone(), site.out.clone())]));
    let proxy = format!("http://{proxy_addr}");
    let aggregator = start_aggregator(
        &clave,
        root.join("clave-data"),
        Some(&suffix_list()),
        Some(&proxy),
    );
    let http = reqwest::blocking::Client::new();
    let mut grid = Grid::new();

    site.init(&spake);
    site.publish(&spake);
    site.ping_and_wait(&spake, &http, &aggregator);
    let published_epoch = seal_epoch(&clave, &aggregator.data, &grid.next());
    record.exercised("publication", published_epoch);
    let gdir = root.join("graven-store");
    follow(&graven, &aggregator, &gdir, true);

    run(
        &spake,
        &[
            "rotate",
            "--out",
            s(&site.out),
            "--state",
            s(&site.state),
            "--overlap-seconds",
            "86400",
        ],
    );
    let rotated = site.declaration();
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

    let b_url = site.url("b.html");
    site.write_page(
        "b.html",
        &marked_page("Beta Page", "beta page body content rotated", &[]),
    );
    site.publish(&spake);
    site.ping_and_wait(&spake, &http, &aggregator);
    let rotation_epoch = seal_epoch(&clave, &aggregator.data, &grid.next());
    record.exercised("publisher_key_rotation", rotation_epoch);
    sync(&graven, &gdir);
    let mut mcp = McpClient::start(&graven, &gdir);
    assert!(
        hits_for(&mcp.search("rotated"), &b_url).is_some(),
        "a Catalog signed after the rotation did not reach the index"
    );
    drop(mcp);

    let owner = site.declaration();
    let owner_seq = owner["publisher"]["seq"].as_u64().expect("owner seq");
    let thief = wist_core::crypto::SigningKey::from_seed(&[42u8; 32]);
    let thief_entry = wist_core::objects::PublisherKey::new(
        &thief.public().to_b64u(),
        u64::try_from(jiff::Timestamp::now().as_second() - 3600).expect("unix second"),
        None,
    );
    let mut hijacked_publisher = owner["publisher"].clone();
    hijacked_publisher["seq"] = json!(owner_seq + 1);
    hijacked_publisher["prev_declaration"] =
        json!(wist_core::declaration::inner_hash(&owner).expect("owner hash"));
    hijacked_publisher["keys"] = json!([thief_entry.clone()]);
    if let Some(publisher) = hijacked_publisher.as_object_mut() {
        publisher.remove("next_keys");
        publisher.remove("recovery_keys");
    }
    let hijacked = wist_core::envelope::sign_envelope(
        &hijacked_publisher,
        "publisher",
        &thief_entry.kid,
        &thief,
    )
    .expect("sign the hijacked Declaration");
    std::fs::write(
        site.out.join(".well-known/wist/publisher.json"),
        serde_json::to_vec(&hijacked).expect("serialize the hijacked Declaration"),
    )
    .expect("serve the hijacked Declaration");
    site.ping_and_wait(&spake, &http, &aggregator);
    let hijack_epoch = seal_epoch(&clave, &aggregator.data, &grid.next());
    record.exercised("hijacked_declaration", hijack_epoch);

    let entries = snapshot_state_entries(&aggregator.data);
    let declaration_tuple = state_tuple(&entries, "declaration", &site.host)
        .unwrap_or_else(|| panic!("no declaration tuple for {}: {entries:?}", site.host));
    assert_eq!(
        declaration_tuple[2], owner,
        "the hijacked Declaration must not take the Declaration in force"
    );
    let pending_tuple = state_tuple(&entries, "pending_declaration", &site.host)
        .unwrap_or_else(|| panic!("no pending_declaration tuple: {entries:?}"));
    assert_eq!(
        pending_tuple[2], hijacked,
        "the hijack is sealed as pending"
    );
    assert!(
        pending_tuple[4].as_u64() > pending_tuple[3].as_u64(),
        "the activation height follows the sealing height: {pending_tuple}"
    );
    sync(&graven, &gdir);

    run(
        &spake,
        &[
            "rotate",
            "--out",
            s(&site.out),
            "--state",
            s(&site.state),
            "--restore",
            "--seq",
            &(owner_seq + 2).to_string(),
            "--overlap-seconds",
            "86400",
        ],
    );
    site.sign_due(&spake);
    let reversed = site.declaration();
    site.ping_and_wait(&spake, &http, &aggregator);
    let reversal_epoch = seal_epoch(&clave, &aggregator.data, &grid.next());
    record.exercised("hijack_reversal", reversal_epoch);

    let entries = snapshot_state_entries(&aggregator.data);
    assert_eq!(
        state_tuple(&entries, "declaration", &site.host).map(|t| t[2].clone()),
        Some(reversed),
        "the reversal takes the Declaration in force"
    );
    assert!(
        state_tuple(&entries, "pending_declaration", &site.host).is_none(),
        "the reversed Declaration is discarded: {entries:?}"
    );
    sync(&graven, &gdir);
    let mut mcp = McpClient::start(&graven, &gdir);
    assert!(
        hits_for(&mcp.search("rotated"), &b_url).is_some(),
        "the domain's records did not survive the reversal"
    );
    assert_eq!(
        mcp.get_record(&site.url("a.html"))["url"],
        site.url("a.html")
    );
    drop(mcp);

    validate_artifacts(&site.out, &aggregator.data);
    record.write();
    eprintln!("completed in {:?}", started.elapsed());
}

#[test]
fn the_consumer_follows_aggregator_key_rotation_and_refuses_a_snapshot_under_a_retired_key() {
    let started = Instant::now();
    let mut record = RunRecord::new("e2e-aggregator-keys");
    let Binaries {
        spake,
        clave,
        graven,
    } = binaries();
    let tmp = tempfile::tempdir().expect("create tempdir");
    let root = tmp.path();

    let site = Site::new(root, "localhost", "default");
    site.write_page(
        "first.html",
        &marked_page(
            "First Page",
            "first notes sealed under the genesis key",
            &[],
        ),
    );
    let (proxy_addr, _) = serve_sites(BTreeMap::from([(site.host.clone(), site.out.clone())]));
    let proxy = format!("http://{proxy_addr}");
    let mut aggregator = start_aggregator(
        &clave,
        root.join("clave-data"),
        Some(&suffix_list()),
        Some(&proxy),
    );
    let log_id = aggregator.log_id.clone();
    let base = aggregator.base_url.clone();
    let data = aggregator.data.clone();
    let http = reqwest::blocking::Client::new();
    let mut grid = Grid::new();

    site.init(&spake);
    site.publish(&spake);
    site.ping_and_wait(&spake, &http, &aggregator);
    let published_epoch = seal_epoch(&clave, &data, &grid.next());
    record.exercised("publication", published_epoch);
    let gdir = root.join("graven-store");
    follow(&graven, &aggregator, &gdir, true);

    let anchor_path = data.join("anchor.json");
    let log_anchor = read_json(&anchor_path);
    let genesis_key_id = log_anchor["anchor"]["genesis_key"]["key_id"]
        .as_str()
        .unwrap_or_else(|| panic!("the Log Anchor declares no genesis key_id: {log_anchor}"))
        .to_string();
    assert_eq!(
        log_key(&log_keys(&clave, &data), &genesis_key_id).added,
        Some(0),
        "the Anchor's genesis key is not the key admitted at height 0"
    );
    let key_added = run(&clave, &["log-key", "add", "--data", s(&data)]);
    let admitted_verifier_key =
        checkpoint_verifier_key(&String::from_utf8_lossy(&key_added.stdout));
    let keys = log_keys(&clave, &data);
    let genesis_note_key_id = log_key(&keys, &genesis_key_id).note_key_id.clone();
    let admitted = keys
        .iter()
        .find(|key| key.added.is_none())
        .unwrap_or_else(|| panic!("log-key add queued no unsealed key"));
    let admitted_key_id = admitted.key_id.clone();
    let admitted_note_key_id = admitted.note_key_id.clone();
    assert_ne!(
        admitted_note_key_id, genesis_note_key_id,
        "the admitted key carries the genesis key's note key ID"
    );

    let addition_epoch = seal_epoch(&clave, &data, &grid.next());
    record.exercised("log_key_addition", addition_epoch);

    // WIST-3 §3.4: the Epoch that seals an addition is signed by the admitting key and the new one.
    let mut admitting_signers = vec![genesis_note_key_id.clone(), admitted_note_key_id.clone()];
    admitting_signers.sort();
    let head_note = fetch_text(&http, &format!("{base}/checkpoint"));
    let archived_note = fetch_text(
        &http,
        &format!(
            "{base}{}",
            wist_core::checkpoint::archive_path(addition_epoch)
        ),
    );
    assert_eq!(parse_note(&head_note).epoch_number(), addition_epoch);
    assert_eq!(
        parse_note(&head_note).note_text(),
        parse_note(&archived_note).note_text(),
        "the archived Checkpoint states another tree than the served head"
    );
    for (source, note) in [
        ("the served head", &head_note),
        ("the archive", &archived_note),
    ] {
        let mut signers = log_signature_key_ids(note, &log_id);
        signers.sort();
        assert_eq!(
            signers, admitting_signers,
            "{source} is not signed under the admitting key and the admitted one: {note}"
        );
    }
    let heads = sync(&graven, &gdir);
    assert_eq!(
        heads[&log_id].epoch, addition_epoch,
        "the Consumer did not advance to the Epoch that admitted the key"
    );

    let keystone_url = site.url("second-key.html");
    site.write_page(
        "second-key.html",
        &marked_page(
            "Second key",
            "keystone notes sealed while the Log held two Aggregator keys",
            &[],
        ),
    );
    site.publish(&spake);
    site.ping_and_wait(&spake, &http, &aggregator);
    let keystone_epoch = seal_epoch(&clave, &data, &grid.next());
    let heads = sync(&graven, &gdir);
    assert_eq!(heads[&log_id].epoch, keystone_epoch);
    let mut mcp = McpClient::start(&graven, &gdir);
    assert!(
        hits_for(&mcp.search("keystone"), &keystone_url).is_some(),
        "an Item sealed after the key addition is not searchable"
    );
    drop(mcp);

    let stale_snapshots = root.join("snapshots-before-the-removal");
    copy_tree(&data.join("snapshots"), &stale_snapshots);
    run(
        &clave,
        &[
            "log-key",
            "remove",
            "--data",
            s(&data),
            "--key-id",
            &genesis_key_id,
        ],
    );
    let removal_epoch = seal_epoch(&clave, &data, &grid.next());
    record.exercised("log_key_removal_of_the_genesis_key", removal_epoch);
    assert_eq!(
        log_key(&log_keys(&clave, &data), &genesis_key_id).removed,
        Some(removal_epoch),
        "the genesis key was not retired at the Epoch that sealed its removal"
    );

    // WIST-3 §3.4: a key removed at height N is invalid at N.
    let removal_note = fetch_text(
        &http,
        &format!(
            "{base}{}",
            wist_core::checkpoint::archive_path(removal_epoch)
        ),
    );
    assert_eq!(
        log_signature_key_ids(&removal_note, &log_id),
        std::slice::from_ref(&admitted_note_key_id),
        "the Checkpoint sealing the genesis key's removal is not signed by the remaining key alone"
    );

    let lodestar_url = site.url("retired-key.html");
    site.write_page(
        "retired-key.html",
        &marked_page(
            "Retired key",
            "lodestar notes sealed after the genesis key was retired",
            &[],
        ),
    );
    site.publish(&spake);
    site.ping_and_wait(&spake, &http, &aggregator);
    let lodestar_epoch = seal_epoch(&clave, &data, &grid.next());
    let later_note = fetch_text(&http, &format!("{base}/checkpoint"));
    assert_eq!(parse_note(&later_note).epoch_number(), lodestar_epoch);
    assert_eq!(
        log_signature_key_ids(&later_note, &log_id),
        std::slice::from_ref(&admitted_note_key_id),
        "a Checkpoint above the removal carries a key other than the remaining one"
    );
    let heads = sync(&graven, &gdir);
    assert_eq!(
        heads[&log_id].epoch, lodestar_epoch,
        "the replaying Consumer did not sync across the genesis key's removal"
    );
    let mut mcp = McpClient::start(&graven, &gdir);
    assert!(
        hits_for(&mcp.search("lodestar"), &lodestar_url).is_some(),
        "an Item sealed after the genesis key's removal is not searchable"
    );
    drop(mcp);
    run(&clave, &["verify-history", "--data", s(&data)]);

    aggregator.stop();
    wait_until_unreachable(&http, &base, &site.host);
    aggregator.start(&clave, Some(&proxy));
    wait_until_status_active(&http, &base, &site.host);
    let restarted_epoch = seal_epoch(&clave, &data, &grid.next());
    let restarted_note = fetch_text(&http, &format!("{base}/checkpoint"));
    assert_eq!(parse_note(&restarted_note).epoch_number(), restarted_epoch);
    assert_eq!(
        log_signature_key_ids(&restarted_note, &log_id),
        std::slice::from_ref(&admitted_note_key_id),
        "the restarted Aggregator signed under a key the removal retired"
    );
    let heads = sync(&graven, &gdir);
    assert_eq!(heads[&log_id].epoch, restarted_epoch);
    assert_eq!(
        log_key(&log_keys(&clave, &data), &admitted_key_id).removed,
        None,
        "the remaining key was retired with the genesis key"
    );

    // WIST-3 §3.4: the Aggregator re-signed every unsealed document the retired key signed.
    let fresh_snapshots = root.join("snapshots-after-the-removal");
    copy_tree(&data.join("snapshots"), &fresh_snapshots);
    let resumed_dir = root.join("graven-store-resumed");
    let resumed_heads = follow(&graven, &aggregator, &resumed_dir, true);
    record.exercised("cold_start_after_the_genesis_keys_removal", restarted_epoch);
    assert_eq!(resumed_heads[&log_id].epoch, restarted_epoch);
    let followed_cursor = read_json(&log_store_dir(&gdir, &log_id).join("sync.json"));
    let resumed_cursor = read_json(&log_store_dir(&resumed_dir, &log_id).join("sync.json"));
    for field in ["epoch_number", "tree_size", "root"] {
        assert_eq!(
            resumed_cursor[field], followed_cursor[field],
            "the cold-started Consumer's {field} differs from the one that followed throughout"
        );
    }
    assert_eq!(
        record_rows(&resumed_dir, &log_id),
        record_rows(&gdir, &log_id),
        "a Consumer installed from a Snapshot and one that replayed hold different records at one head"
    );
    let answered = |hits: &[Value]| -> Vec<Value> {
        hits.iter()
            .map(|hit| json!([&hit["url"], &hit["publisher"], &hit["item_id"]]))
            .collect()
    };
    let mut mcp = McpClient::start(&graven, &resumed_dir);
    let resumed_hits = answered(&mcp.search("lodestar"));
    drop(mcp);
    let mut mcp = McpClient::start(&graven, &gdir);
    let followed_hits = answered(&mcp.search("lodestar"));
    drop(mcp);
    assert!(
        !resumed_hits.is_empty() && resumed_hits == followed_hits,
        "the two Consumers answer the same query differently: {resumed_hits:?} vs {followed_hits:?}"
    );

    // WIST-3 §8 step 8: a Snapshot the retired key signed is rejected (`WIST3-E04`).
    copy_tree(&stale_snapshots, &data.join("snapshots"));
    let stale_dir = root.join("graven-store-stale-snapshot");
    let refused = Command::new(&graven)
        .args([
            "follow",
            "--anchor",
            s(&anchor_path),
            "--log",
            &base,
            "--dir",
            s(&stale_dir),
            "--allow-http",
        ])
        .output()
        .expect("run graven follow against the stale Snapshot");
    let refusal = String::from_utf8_lossy(&refused.stderr).to_string();
    record.exercised(
        "snapshot_signed_by_the_removed_genesis_key",
        restarted_epoch,
    );
    assert!(
        !refused.status.success(),
        "the Consumer accepted a Snapshot signed by the retired genesis key: {refusal}"
    );
    assert!(
        refusal.contains("WIST3-E04") && refusal.contains("the Snapshot index"),
        "the refusal names neither the code nor the document: {refusal}"
    );
    assert!(
        !stale_dir.join("logs.json").exists(),
        "a rejected Snapshot left the Log registered in {}",
        stale_dir.display()
    );
    copy_tree(&fresh_snapshots, &data.join("snapshots"));

    validate_artifacts(&site.out, &data);
    verify_with_external_tlog_client(&base, &admitted_verifier_key);
    record.write();
    eprintln!("completed in {:?}", started.elapsed());
}
