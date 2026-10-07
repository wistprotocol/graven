use e2e::{
    checkpoint_verifier_key, epoch_entries, fetch_status, graven_bin, grid_instant,
    head_snapshot_state, log_entries, marked_page, now_rfc3339, read_json, resolve_sibling_bin,
    run, run_with_env, s, seal_epoch, serve_sites, start_aggregator, synced_heads,
    wait_until_after, wait_until_status_active, wait_until_unreachable, workspace_root, Aggregator,
    McpClient, Site, SyncedHead,
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

fn entries_of<'a>(entries: &'a [Value], kind: &str) -> Vec<&'a Value> {
    entries
        .iter()
        .filter(|entry| entry["type"] == kind)
        .collect()
}

fn url_tuple(state: &[Value], kind: &str, domain: &str, url: &str) -> Option<Value> {
    state
        .iter()
        .find(|tuple| tuple[0] == kind && tuple[1] == domain && tuple[2] == url)
        .cloned()
}

fn collection_tuple(state: &[Value], domain: &str, name: &str) -> Value {
    url_tuple(state, "collection", domain, name)
        .unwrap_or_else(|| panic!("no collection tuple for {domain} {name}: {state:?}"))
}

fn catalog_id(envelope: &Value) -> String {
    wist_core::catalog::catalog_id(&envelope["catalog"]).expect("compute the Catalog ID")
}

fn item_id(item: &Value) -> String {
    wist_core::item::item_id(item).expect("compute the Item ID")
}

fn status_collection(status: &Value, name: &str) -> Value {
    status["collections"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|collection| collection["name"] == name)
        .cloned()
        .unwrap_or_else(|| panic!("the status lists no Collection {name}: {status}"))
}

fn status_rejection(status: &Value, code: &str, id: &str) -> Value {
    status["rejections"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|rejection| rejection["code"] == code && rejection["id"] == id)
        .cloned()
        .unwrap_or_else(|| panic!("the status reports no {code} for {id}: {status}"))
}

fn allowed(refused: &[(String, String)]) -> Vec<(&str, &str)> {
    refused
        .iter()
        .map(|(code, id)| (code.as_str(), id.as_str()))
        .collect()
}

fn consumer_records(dir: &Path, log_id: &str, domain: &str) -> Vec<graven::sync::RecordRow> {
    record_rows(dir, log_id)
        .into_iter()
        .filter(|row| row.publisher == domain)
        .collect()
}

fn generate_page(served_root: &Path, path: &str, html: &str) {
    let file = served_root.join(path);
    std::fs::create_dir_all(file.parent().expect("a page has a directory"))
        .expect("create the page's directory");
    std::fs::write(file, html).expect("write a generated page");
}

fn assert_collection_complete(state: &[Value], site: &Site) {
    let served = site.catalog();
    assert_eq!(
        collection_tuple(state, &site.host, &site.collection)[3],
        served,
        "the latest Catalog of {} is not the served one",
        site.collection
    );
    let list = site.served_list();
    let mut recorded: Vec<Value> = state
        .iter()
        .filter(|tuple| {
            tuple[0] == "record" && tuple[1] == site.host && tuple[4] == site.collection.as_str()
        })
        .map(|tuple| tuple[3].clone())
        .collect();
    let mut listed_pages: Vec<String> = list
        .iter()
        .filter(|item| item.get("removed").is_none())
        .map(item_id)
        .collect();
    let mut recorded_ids: Vec<String> = recorded.iter().map(item_id).collect();
    listed_pages.sort();
    recorded_ids.sort();
    assert_eq!(
        recorded_ids, listed_pages,
        "the records of {} are not the page Items of its latest Catalog",
        site.collection
    );
    for removed in list.iter().filter(|item| item.get("removed").is_some()) {
        let url = removed["url"].as_str().expect("a removed Item's url");
        let removal = url_tuple(state, "removal", &site.host, url)
            .unwrap_or_else(|| panic!("no removal state for {url}: {state:?}"));
        assert_eq!(removal[3], item_id(removed), "{removal}");
        recorded.push(removed.clone());
    }
    assert_eq!(
        format!(
            "sha256:{}",
            wist_core::crypto::hex_encode(&wist_core::item::root(&recorded).expect("root"))
        ),
        served["catalog"]["root"],
        "the records and removal states of {} do not recompute its latest Catalog's root",
        site.collection
    );
}

fn generated_page(n: usize) -> String {
    format!("docs/page-{n:03}.html")
}

#[test]
fn a_declared_collection_seals_its_emissions_and_refuses_an_item_outside_its_scope() {
    let started = Instant::now();
    let mut record = RunRecord::new("e2e-declared-collection");
    let Binaries {
        spake,
        clave,
        graven,
    } = binaries();
    let tmp = tempfile::tempdir().expect("create tempdir");
    let root = tmp.path();

    let site = Site::new(root, "localhost", "docs");
    let site_root = format!("https://{}/", site.host);
    let docs_prefix = format!("{site_root}docs/");
    let page_url = |n: usize| format!("{site_root}{}", generated_page(n));
    for n in 1..=100 {
        generate_page(
            &site.out,
            &generated_page(n),
            &marked_page(
                &format!("Generated page {n}"),
                &format!("static generator output number {n}"),
                &[],
            ),
        );
    }
    let (proxy_addr, _) = serve_sites(BTreeMap::from([(site.host.clone(), site.out.clone())]));
    let proxy = format!("http://{proxy_addr}");
    let aggregator = start_aggregator(
        &clave,
        root.join("clave-data"),
        Some(&suffix_list()),
        Some(&proxy),
    );
    let base = aggregator.base_url.clone();
    let http = reqwest::blocking::Client::new();
    let mut grid = Grid::new();
    let mut refused: Vec<(String, String)> = Vec::new();

    site.init(&spake);
    site.ping_and_wait(&spake, &http, &aggregator);
    let declared_epoch = seal_epoch(&clave, &aggregator.data, &grid.next());
    record.exercised("declaration", declared_epoch);

    site.collection_command(
        &spake,
        "add",
        &["--name", "docs", "--prefix", &docs_prefix, "--confirm"],
    );
    site.emit_from(&spake, &site.out, &site_root, true);
    site.apply_stream(&spake);
    let status = site.ping_and_wait(&spake, &http, &aggregator);
    assert_eq!(
        status_collection(&status, "docs")["accepted"],
        catalog_id(&site.catalog()),
        "{status}"
    );
    let first_epoch = seal_epoch(&clave, &aggregator.data, &grid.next());
    record.exercised("first_publication_of_a_generated_site", first_epoch);

    let first_catalog = site.catalog();
    let sealed = epoch_entries(&http, &base, first_epoch);
    let catalogs = entries_of(&sealed, "publisher_catalog");
    assert_eq!(catalogs.len(), 1, "{catalogs:?}");
    assert_eq!(catalogs[0]["body"], first_catalog);
    let items = entries_of(&sealed, "publisher_item");
    assert_eq!(items.len(), 100, "one Item per generated page");
    assert!(
        items
            .iter()
            .all(|entry| entry["body"]["collection"] == "docs"
                && entry["body"]["catalog"] == catalog_id(&first_catalog).as_str()
                && entry["body"]["item"].get("removed").is_none()),
        "{items:?}"
    );
    let status = fetch_status(&http, &base, &site.host).expect("the status of the domain");
    let docs = status_collection(&status, "docs");
    assert_eq!(docs["latest"], catalog_id(&first_catalog), "{status}");
    assert!(
        docs["waiting"].as_array().is_some_and(Vec::is_empty),
        "{status}"
    );
    let (snapshot_epoch, state) = head_snapshot_state(&aggregator.data);
    assert_eq!(snapshot_epoch, first_epoch);
    assert_collection_complete(&state, &site);

    let gdir = root.join("graven-store");
    follow(&graven, &aggregator, &gdir, true);
    let rows = consumer_records(&gdir, &aggregator.log_id, &site.host);
    assert_eq!(rows.len(), 100, "{rows:?}");
    assert!(
        rows.iter()
            .all(|row| row.collection.as_deref() == Some("docs")),
        "{rows:?}"
    );
    let mut mcp = McpClient::start(&graven, &gdir);
    let seventh = mcp.get_record(&page_url(7));
    assert_eq!(seventh["item_id"], site.item_id(&page_url(7)), "{seventh}");
    assert_eq!(seventh["collection"], "docs", "{seventh}");
    let hits = mcp.search("generator");
    assert!(
        !hits.is_empty()
            && hits.iter().all(|hit| hit["url"]
                .as_str()
                .is_some_and(|url| url.starts_with(&docs_prefix))),
        "{hits:?}"
    );
    drop(mcp);

    generate_page(
        &site.out,
        &generated_page(7),
        &marked_page(
            "Generated page 7 revised",
            "marmalade revision of page seven",
            &[],
        ),
    );
    std::fs::remove_file(site.out.join(generated_page(42))).expect("remove a generated page");
    site.emit_from(&spake, &site.out, &site_root, true);
    site.apply_stream(&spake);
    site.ping_and_wait(&spake, &http, &aggregator);
    let edit_epoch = seal_epoch(&clave, &aggregator.data, &grid.next());
    record.exercised("page_edited_and_page_removed", edit_epoch);

    let edited_catalog = site.catalog();
    let sealed = epoch_entries(&http, &base, edit_epoch);
    let catalogs = entries_of(&sealed, "publisher_catalog");
    assert_eq!(catalogs.len(), 1, "{catalogs:?}");
    assert_eq!(catalogs[0]["body"], edited_catalog);
    let items = entries_of(&sealed, "publisher_item");
    assert_eq!(items.len(), 2, "{items:?}");
    let edited = items
        .iter()
        .find(|entry| entry["body"]["item"]["url"] == page_url(7))
        .unwrap_or_else(|| panic!("no Item of the edited page: {items:?}"));
    assert!(edited["body"]["item"].get("removed").is_none(), "{edited}");
    assert_eq!(item_id(&edited["body"]["item"]), site.item_id(&page_url(7)));
    let removal = items
        .iter()
        .find(|entry| entry["body"]["item"]["url"] == page_url(42))
        .unwrap_or_else(|| panic!("no Item of the removed page: {items:?}"));
    assert_eq!(removal["body"]["item"]["removed"], true, "{removal}");
    let edited_inner: wist_core::objects::Catalog =
        serde_json::from_value(edited_catalog["catalog"].clone()).expect("the Catalog form");
    wist_core::proof::verify(
        &removal["body"]["item"],
        &removal["body"]["proof"],
        &edited_inner,
    )
    .unwrap_or_else(|code| panic!("the removal is not proved against its Catalog: {code}"));
    let status = fetch_status(&http, &base, &site.host).expect("the status of the domain");
    assert_eq!(
        status_collection(&status, "docs")["latest"],
        catalog_id(&edited_catalog),
        "{status}"
    );
    let (_, state) = head_snapshot_state(&aggregator.data);
    assert!(url_tuple(&state, "record", &site.host, &page_url(42)).is_none());
    assert_eq!(
        url_tuple(&state, "removal", &site.host, &page_url(42))
            .unwrap_or_else(|| panic!("no removal state for the removed page"))[4],
        catalog_id(&edited_catalog)
    );
    assert_collection_complete(&state, &site);

    sync(&graven, &gdir);
    assert_eq!(
        consumer_records(&gdir, &aggregator.log_id, &site.host).len(),
        99
    );
    let mut mcp = McpClient::start(&graven, &gdir);
    assert_eq!(
        mcp.get_record(&page_url(7))["item_id"],
        site.item_id(&page_url(7))
    );
    assert!(
        hits_for(&mcp.search("marmalade"), &page_url(7)).is_some(),
        "the edited page is not searchable by its new text"
    );
    not_found(&mut mcp, &page_url(42));
    drop(mcp);

    let order_url = format!("{docs_prefix}orders/1001");
    let order_text = "Order 1001 confirmed: two jars of quince preserve leave the warehouse today.";
    let order_links = [
        "https://example.org/track/1001",
        "https://example.net/preserves/quince",
    ];
    site.write_stream(
        "incremental",
        &[json!({
            "url": order_url,
            "lang": "en",
            "modified": now_rfc3339(),
            "title": "Order 1001",
            "text": order_text,
            "links": order_links,
        })],
    );
    site.apply_stream(&spake);
    site.ping_and_wait(&spake, &http, &aggregator);
    let text_epoch = seal_epoch(&clave, &aggregator.data, &grid.next());
    record.exercised("text_emission_of_a_client_rendered_page", text_epoch);

    let sealed = epoch_entries(&http, &base, text_epoch);
    assert_eq!(entries_of(&sealed, "publisher_catalog").len(), 1);
    let items = entries_of(&sealed, "publisher_item");
    assert_eq!(items.len(), 1, "{items:?}");
    assert_eq!(items[0]["body"]["item"]["url"], order_url.as_str());
    let order_item = site.served_item(&order_url);
    assert_eq!(items[0]["body"]["item"], order_item);
    let payload = read_json(&site.collection_dir().join("payloads").join(format!(
        "{}.json",
        wist_core::item::payload_name(&order_item).expect("Payload name")
    )));
    assert_eq!(payload["content"]["extract"], order_text, "{payload}");
    assert_eq!(
        payload["content"]["links"]["urls"],
        json!(order_links),
        "{payload}"
    );
    let (_, state) = head_snapshot_state(&aggregator.data);
    let order_record = url_tuple(&state, "record", &site.host, &order_url)
        .unwrap_or_else(|| panic!("no record of the text Emission"));
    assert_eq!(order_record[3], order_item);
    assert_eq!(order_record[4], "docs");

    sync(&graven, &gdir);
    let mut mcp = McpClient::start(&graven, &gdir);
    assert_eq!(mcp.get_record(&order_url)["item_id"], item_id(&order_item));
    assert_eq!(mcp.get_extract(&order_url)["extract"], order_text);
    let links = mcp.tool_call("get_links", json!({"url": order_url}));
    let links: Vec<(String, i64)> = links
        .as_array()
        .unwrap_or_else(|| panic!("get_links returns no array: {links}"))
        .iter()
        .map(|link| {
            (
                link["target_url"].as_str().unwrap_or_default().to_string(),
                link["position"].as_i64().unwrap_or(-1),
            )
        })
        .collect();
    assert_eq!(
        links,
        [
            (order_links[0].to_string(), 0),
            (order_links[1].to_string(), 1)
        ]
    );
    drop(mcp);

    let private_url = format!("{site_root}private/ledger.html");
    generate_page(
        &site.out,
        "private/ledger.html",
        &marked_page(
            "Ledger",
            "private ledger the generator emits by mistake",
            &[],
        ),
    );
    site.emit_from(&spake, &site.out, &site_root, false);
    assert!(
        !std::fs::read_to_string(&site.stream)
            .expect("read the emitted stream")
            .contains(&private_url),
        "emit wrote a URL its Collection's Scope does not cover"
    );
    std::fs::remove_file(site.out.join(generated_page(13))).expect("remove a generated page");
    site.write_stream(
        "incremental",
        &[json!({"url": page_url(13), "removed": true})],
    );
    site.apply_stream(&spake);
    let spake_catalog =
        std::fs::read(site.collection_dir().join("catalog.json")).expect("read the served Catalog");
    let mut faulty_list = site.served_list();
    let template = faulty_list
        .iter()
        .find(|item| item["url"] == page_url(21))
        .cloned()
        .expect("a page Item to copy");
    let mut outside = template.clone();
    outside["url"] = json!(private_url);
    site.serve_payload_as(&template, &outside);
    faulty_list.push(outside.clone());
    wait_until_after(&served_generated_at(&site));
    let faulty_generated_at = now_rfc3339();
    let docs_kid = site.collection_key_ids()[0].clone();
    let faulty = site.serve_catalog(
        &faulty_list,
        &faulty_generated_at,
        &docs_kid,
        &site.signing_key(&docs_kid),
    );
    let outside_id = item_id(&outside);
    refused.push(("WIST1-E03".into(), outside_id.clone()));
    let status = site.ping_and_wait_allowing(&spake, &http, &aggregator, &allowed(&refused));
    let rejection = status_rejection(&status, "WIST1-E03", &outside_id);
    assert_eq!(rejection["collection"], "docs", "{rejection}");
    assert_eq!(rejection["urls"], json!([private_url]), "{rejection}");
    assert_eq!(
        status_collection(&status, "docs")["accepted"],
        catalog_id(&faulty),
        "{status}"
    );
    let refusal_epoch = seal_epoch(&clave, &aggregator.data, &grid.next());
    record.exercised("item_outside_the_scope", refusal_epoch);
    record.exercised("removal_beside_a_refused_item", refusal_epoch);

    let sealed = epoch_entries(&http, &base, refusal_epoch);
    let catalogs = entries_of(&sealed, "publisher_catalog");
    assert_eq!(catalogs.len(), 1, "{catalogs:?}");
    assert_eq!(catalogs[0]["body"], faulty);
    let items = entries_of(&sealed, "publisher_item");
    assert_eq!(
        items.len(),
        1,
        "the removal beside the refused Item is sealed with its Catalog: {items:?}"
    );
    assert_eq!(items[0]["body"]["item"]["url"], page_url(13));
    assert_eq!(items[0]["body"]["item"]["removed"], true);
    let private_key = wist_core::crypto::hex_encode(&wist_core::item::key(&private_url));
    let leaked: Vec<Value> = log_entries(&http, &base, refusal_epoch)
        .into_iter()
        .filter(|entry| {
            let text = entry.to_string();
            text.contains(&private_url) || text.contains(&private_key)
        })
        .collect();
    assert!(
        leaked.is_empty(),
        "sealed Entries name the refused Item: {leaked:?}"
    );
    let (_, state) = head_snapshot_state(&aggregator.data);
    assert!(url_tuple(&state, "record", &site.host, &private_url).is_none());
    assert!(url_tuple(&state, "record", &site.host, &page_url(13)).is_none());
    assert_eq!(
        url_tuple(&state, "removal", &site.host, &page_url(13))
            .unwrap_or_else(|| panic!("no removal state beside the refused Item"))[4],
        catalog_id(&faulty)
    );
    let status = fetch_status(&http, &base, &site.host).expect("the status of the domain");
    assert_eq!(
        status_collection(&status, "docs")["latest"],
        catalog_id(&faulty),
        "{status}"
    );
    status_rejection(&status, "WIST1-E03", &outside_id);

    sync(&graven, &gdir);
    let mut mcp = McpClient::start(&graven, &gdir);
    not_found(&mut mcp, &private_url);
    not_found(&mut mcp, &page_url(13));
    drop(mcp);

    std::fs::write(site.collection_dir().join("catalog.json"), &spake_catalog)
        .expect("serve the Publisher's own Catalog again");
    wait_until_after(&faulty_generated_at);
    generate_page(
        &site.out,
        &generated_page(21),
        &marked_page(
            "Generated page 21 revised",
            "lantern revision of page twenty-one",
            &[],
        ),
    );
    site.emit_from(&spake, &site.out, &site_root, false);
    site.apply_stream(&spake);
    assert!(
        site.served_list()
            .iter()
            .all(|item| item["url"] != private_url.as_str()),
        "the Publisher's next Catalog lists the refused Item"
    );
    refused.push(("WIST2-E08".into(), catalog_id(&site.catalog())));
    site.ping_and_wait_allowing(&spake, &http, &aggregator, &allowed(&refused));
    let dropped_epoch = seal_epoch(&clave, &aggregator.data, &grid.next());
    assert_eq!(
        status_collection(
            &fetch_status(&http, &base, &site.host).expect("the status of the domain"),
            "docs"
        )["latest"],
        catalog_id(&site.catalog())
    );
    record.exercised("catalog_without_the_refused_item", dropped_epoch);
    let sealed = epoch_entries(&http, &base, dropped_epoch);
    assert_eq!(entries_of(&sealed, "publisher_catalog").len(), 1);
    let items = entries_of(&sealed, "publisher_item");
    assert_eq!(items.len(), 1, "{items:?}");
    assert_eq!(items[0]["body"]["item"]["url"], page_url(21));
    let (_, state) = head_snapshot_state(&aggregator.data);
    assert_collection_complete(&state, &site);

    sync(&graven, &gdir);
    assert_eq!(
        consumer_records(&gdir, &aggregator.log_id, &site.host).len(),
        99
    );
    let mut mcp = McpClient::start(&graven, &gdir);
    assert!(hits_for(&mcp.search("lantern"), &page_url(21)).is_some());
    not_found(&mut mcp, &page_url(13));
    not_found(&mut mcp, &private_url);
    drop(mcp);

    validate_artifacts(&site.out, &aggregator.data);
    record.write();
    eprintln!("completed in {:?}", started.elapsed());
}

#[test]
fn a_narrowed_scope_removes_records_at_its_epoch_and_a_reversed_pending_narrowing_removes_none() {
    let started = Instant::now();
    let mut record = RunRecord::new("e2e-scope-narrowing");
    let Binaries {
        spake,
        clave,
        graven,
    } = binaries();
    let tmp = tempfile::tempdir().expect("create tempdir");
    let root = tmp.path();

    let site = Site::new(root, "localhost", "docs");
    let prefix = |path: &str| format!("https://{}/{path}/", site.host);
    site.write_page(
        "docs/guide.html",
        &marked_page("Guide", "guide notes about saffron", &[]),
    );
    site.write_page(
        "drafts/plan.html",
        &marked_page("Plan", "draft plan about cardamom", &[]),
    );
    site.write_page(
        "notes/log.html",
        &marked_page("Log", "field notes about juniper", &[]),
    );
    let guide_url = site.url("docs/guide.html");
    let plan_url = site.url("drafts/plan.html");
    let log_url = site.url("notes/log.html");
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
    site.ping_and_wait(&spake, &http, &aggregator);
    let declared_epoch = seal_epoch(&clave, &aggregator.data, &grid.next());
    record.exercised("declaration", declared_epoch);
    site.collection_command(
        &spake,
        "add",
        &[
            "--name",
            "docs",
            "--prefix",
            &prefix("docs"),
            "--prefix",
            &prefix("drafts"),
            "--prefix",
            &prefix("notes"),
            "--confirm",
        ],
    );
    site.publish(&spake);
    site.ping_and_wait(&spake, &http, &aggregator);
    let published_epoch = seal_epoch(&clave, &aggregator.data, &grid.next());
    record.exercised("publication", published_epoch);
    let gdir = root.join("graven-store");
    follow(&graven, &aggregator, &gdir, true);
    let all_urls = [&guide_url, &plan_url, &log_url];
    let assert_recorded = |state: &[Value], urls: &[&String]| {
        for url in urls {
            assert!(
                url_tuple(state, "record", &site.host, url).is_some(),
                "no record of {url}: {state:?}"
            );
        }
    };
    let (_, state) = head_snapshot_state(&aggregator.data);
    assert_recorded(&state, &all_urls);

    let owner = site.declaration();
    let owner_seq = owner["publisher"]["seq"].as_u64().expect("owner seq");
    let thief = wist_core::crypto::SigningKey::from_seed(&[43u8; 32]);
    let thief_entry = wist_core::objects::PublisherKey::new(
        &thief.public().to_b64u(),
        u64::try_from(jiff::Timestamp::now().as_second() - 3600).expect("unix second"),
        None,
    );
    let mut pending_publisher = owner["publisher"].clone();
    pending_publisher["seq"] = json!(owner_seq + 1);
    pending_publisher["prev_declaration"] =
        json!(wist_core::declaration::inner_hash(&owner).expect("owner hash"));
    pending_publisher["keys"] = json!([thief_entry.clone()]);
    if let Some(publisher) = pending_publisher.as_object_mut() {
        publisher.remove("next_keys");
        publisher.remove("recovery_keys");
    }
    for collection in pending_publisher["collections"]
        .as_array_mut()
        .expect("the owner's Declaration names Collections")
    {
        if let Some(scope) = collection["scope"].as_array_mut() {
            scope.retain(|entry| entry["url"] != prefix("notes").as_str());
        }
    }
    let pending = wist_core::envelope::sign_envelope(
        &pending_publisher,
        "publisher",
        &thief_entry.kid,
        &thief,
    )
    .expect("sign the pending Declaration");
    std::fs::write(
        site.out.join(".well-known/wist/publisher.json"),
        serde_json::to_vec(&pending).expect("serialize the pending Declaration"),
    )
    .expect("serve the pending Declaration");
    site.ping_and_wait(&spake, &http, &aggregator);
    let pending_epoch = seal_epoch(&clave, &aggregator.data, &grid.next());
    record.exercised("pending_declaration_narrowing_the_scope", pending_epoch);
    let (_, state) = head_snapshot_state(&aggregator.data);
    assert_eq!(
        state_tuple(&state, "declaration", &site.host).map(|t| t[2].clone()),
        Some(owner.clone()),
        "the pending Declaration took the Declaration in force"
    );
    assert_eq!(
        state_tuple(&state, "pending_declaration", &site.host).map(|t| t[2].clone()),
        Some(pending.clone())
    );
    assert_recorded(&state, &all_urls);
    let still_pending_epoch = seal_epoch(&clave, &aggregator.data, &grid.next());
    record.exercised("pending_narrowing_before_activation", still_pending_epoch);
    let (_, state) = head_snapshot_state(&aggregator.data);
    assert!(state_tuple(&state, "pending_declaration", &site.host).is_some());
    assert_recorded(&state, &all_urls);
    sync(&graven, &gdir);
    let mut mcp = McpClient::start(&graven, &gdir);
    assert_eq!(mcp.get_record(&log_url)["url"], log_url);
    drop(mcp);

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
    record.exercised("reversal_of_a_pending_narrowing", reversal_epoch);
    let (_, state) = head_snapshot_state(&aggregator.data);
    assert_eq!(
        state_tuple(&state, "declaration", &site.host).map(|t| t[2].clone()),
        Some(reversed)
    );
    assert!(state_tuple(&state, "pending_declaration", &site.host).is_none());
    assert_recorded(&state, &all_urls);
    sync(&graven, &gdir);
    let mut mcp = McpClient::start(&graven, &gdir);
    for url in all_urls {
        assert_eq!(mcp.get_record(url)["url"], url.as_str());
    }
    drop(mcp);
    validate_artifacts(&site.out, &aggregator.data);

    site.collection_command(
        &spake,
        "scope-remove",
        &["--name", "docs", "--url", &prefix("drafts"), "--confirm"],
    );
    let narrowed = site.declaration();
    site.ping_and_wait(&spake, &http, &aggregator);
    let narrowing_epoch = seal_epoch(&clave, &aggregator.data, &grid.next());
    record.exercised("owner_narrows_the_scope", narrowing_epoch);
    let sealed = epoch_entries(&http, &aggregator.base_url, narrowing_epoch);
    let declarations = entries_of(&sealed, "publisher_declaration");
    assert_eq!(declarations.len(), 1, "{sealed:?}");
    assert_eq!(declarations[0]["body"], narrowed);
    assert!(
        entries_of(&sealed, "publisher_item").is_empty(),
        "{sealed:?}"
    );
    let (_, state) = head_snapshot_state(&aggregator.data);
    let declaration = state_tuple(&state, "declaration", &site.host).expect("declaration tuple");
    assert_eq!(declaration[2], narrowed);
    assert_eq!(declaration[3], narrowing_epoch);
    assert!(
        url_tuple(&state, "record", &site.host, &plan_url).is_none(),
        "the narrowing left the record under the removed prefix"
    );
    assert!(
        url_tuple(&state, "removal", &site.host, &plan_url).is_none(),
        "a record narrowing removed left a removal state"
    );
    assert_recorded(&state, &[&guide_url, &log_url]);
    sync(&graven, &gdir);
    let mut mcp = McpClient::start(&graven, &gdir);
    not_found(&mut mcp, &plan_url);
    assert!(hits_for(&mcp.search("cardamom"), &plan_url).is_none());
    assert_eq!(mcp.get_record(&guide_url)["url"], guide_url);
    assert_eq!(mcp.get_record(&log_url)["url"], log_url);
    drop(mcp);

    record.write();
    eprintln!("completed in {:?}", started.elapsed());
}

fn latest_catalog(state: &[Value], site: &Site) -> Value {
    collection_tuple(state, &site.host, &site.collection)[3].clone()
}

#[test]
fn collection_keys_sign_only_their_own_collection_and_a_removed_delegate_key_signs_nothing() {
    let started = Instant::now();
    let mut record = RunRecord::new("e2e-collection-keys");
    let Binaries {
        spake,
        clave,
        graven,
    } = binaries();
    let tmp = tempfile::tempdir().expect("create tempdir");
    let root = tmp.path();

    let docs = Site::new(root, "localhost", "docs");
    let blog = docs.with_collection("blog");
    let docs_prefix = format!("https://{}/docs/", docs.host);
    let blog_prefix = format!("https://{}/blog/", docs.host);
    docs.write_page(
        "docs/guide.html",
        &marked_page("Guide", "guide about tamarind", &[]),
    );
    docs.write_page(
        "blog/first.html",
        &marked_page("First post", "first post about sorrel", &[]),
    );
    docs.write_page(
        "blog/second.html",
        &marked_page("Second post", "second post about fennel", &[]),
    );
    let guide_url = docs.url("docs/guide.html");
    let first_url = docs.url("blog/first.html");
    let second_url = docs.url("blog/second.html");
    let (proxy_addr, _) = serve_sites(BTreeMap::from([(docs.host.clone(), docs.out.clone())]));
    let proxy = format!("http://{proxy_addr}");
    let aggregator = start_aggregator(
        &clave,
        root.join("clave-data"),
        Some(&suffix_list()),
        Some(&proxy),
    );
    let base = aggregator.base_url.clone();
    let http = reqwest::blocking::Client::new();
    let mut grid = Grid::new();
    let mut refused: Vec<(String, String)> = Vec::new();

    docs.init(&spake);
    docs.ping_and_wait(&spake, &http, &aggregator);
    let declared_epoch = seal_epoch(&clave, &aggregator.data, &grid.next());
    record.exercised("declaration", declared_epoch);
    docs.collection_command(
        &spake,
        "add",
        &["--name", "docs", "--prefix", &docs_prefix, "--confirm"],
    );
    docs.publish(&spake);
    docs.ping_and_wait(&spake, &http, &aggregator);
    let docs_epoch = seal_epoch(&clave, &aggregator.data, &grid.next());
    record.exercised("first_collection_with_its_own_key", docs_epoch);
    blog.collection_command(
        &spake,
        "add",
        &["--name", "blog", "--prefix", &blog_prefix, "--no-key"],
    );
    blog.sign_due(&spake);
    blog.ping_and_wait(&spake, &http, &aggregator);
    blog.collection_command(&spake, "key-add", &["--name", "blog"]);
    blog.publish(&spake);
    blog.ping_and_wait(&spake, &http, &aggregator);
    let keyed_epoch = seal_epoch(&clave, &aggregator.data, &grid.next());
    record.exercised("second_collection_keyed_by_key_add", keyed_epoch);

    let docs_kid = docs.collection_key_ids()[0].clone();
    let blog_kid = blog.collection_key_ids()[0].clone();
    let owner_kids = docs.owner_key_ids();
    assert_ne!(docs_kid, blog_kid);
    assert!(!owner_kids.contains(&docs_kid) && !owner_kids.contains(&blog_kid));
    let (_, state) = head_snapshot_state(&aggregator.data);
    for (site, kid, prefix, urls) in [
        (&docs, &docs_kid, &docs_prefix, vec![&guide_url]),
        (
            &blog,
            &blog_kid,
            &blog_prefix,
            vec![&first_url, &second_url],
        ),
    ] {
        let latest = latest_catalog(&state, site);
        assert_eq!(latest, site.catalog());
        assert_eq!(latest["sig"]["key_id"], kid.as_str(), "{latest}");
        assert!(
            site.served_list().iter().all(|item| item["url"]
                .as_str()
                .is_some_and(|url| url.starts_with(prefix.as_str()))),
            "the Catalog of {} lists a URL outside its Scope",
            site.collection
        );
        for url in urls {
            let tuple = url_tuple(&state, "record", &site.host, url)
                .unwrap_or_else(|| panic!("no record of {url}: {state:?}"));
            assert_eq!(tuple[4], site.collection.as_str(), "{tuple}");
        }
    }
    let gdir = root.join("graven-store");
    follow(&graven, &aggregator, &gdir, true);
    let mut mcp = McpClient::start(&graven, &gdir);
    assert_eq!(mcp.get_record(&guide_url)["collection"], "docs");
    assert_eq!(mcp.get_record(&first_url)["collection"], "blog");
    drop(mcp);

    let blog_catalog = std::fs::read(blog.collection_dir().join("catalog.json"))
        .expect("read the served blog Catalog");
    let blog_latest = blog.catalog();
    let crossed_url = docs.url("blog/crossed.html");
    let mut crossed_list = blog.served_list();
    let template = crossed_list
        .iter()
        .find(|item| item["url"] == first_url.as_str())
        .cloned()
        .expect("a blog page Item to copy");
    let mut crossed_item = template.clone();
    crossed_item["url"] = json!(crossed_url);
    blog.serve_payload_as(&template, &crossed_item);
    crossed_list.push(crossed_item);
    wait_until_after(&served_generated_at(&blog));
    let crossed = blog.serve_catalog(
        &crossed_list,
        &now_rfc3339(),
        &docs_kid,
        &docs.signing_key(&docs_kid),
    );
    refused.push(("WIST1-E02".into(), catalog_id(&crossed)));
    let status = blog.ping_and_wait_allowing(&spake, &http, &aggregator, &allowed(&refused));
    assert_eq!(
        status_rejection(&status, "WIST1-E02", &catalog_id(&crossed))["collection"],
        "blog",
        "{status}"
    );
    let crossed_epoch = seal_epoch(&clave, &aggregator.data, &grid.next());
    record.exercised("catalog_signed_by_another_collections_key", crossed_epoch);
    let sealed = epoch_entries(&http, &base, crossed_epoch);
    assert!(
        entries_of(&sealed, "publisher_catalog").is_empty(),
        "{sealed:?}"
    );
    assert!(
        entries_of(&sealed, "publisher_item").is_empty(),
        "{sealed:?}"
    );
    let (_, state) = head_snapshot_state(&aggregator.data);
    assert_eq!(latest_catalog(&state, &blog), blog_latest);
    assert!(url_tuple(&state, "record", &docs.host, &crossed_url).is_none());
    sync(&graven, &gdir);
    let mut mcp = McpClient::start(&graven, &gdir);
    not_found(&mut mcp, &crossed_url);
    drop(mcp);
    std::fs::write(blog.collection_dir().join("catalog.json"), &blog_catalog)
        .expect("serve the Publisher's own blog Catalog again");

    let docs_catalog = std::fs::read(docs.collection_dir().join("catalog.json"))
        .expect("read the served docs Catalog");
    wait_until_after(&served_generated_at(&docs));
    let reaching_generated_at = now_rfc3339();
    let reaching_removal = json!({
        "publisher": docs.host,
        "url": first_url,
        "observed_at": reaching_generated_at,
        "removed": true,
    });
    let mut reaching_list = docs.served_list();
    reaching_list.push(reaching_removal.clone());
    let reaching = docs.serve_catalog(
        &reaching_list,
        &reaching_generated_at,
        &docs_kid,
        &docs.signing_key(&docs_kid),
    );
    let reaching_id = item_id(&reaching_removal);
    refused.push(("WIST1-E03".into(), reaching_id.clone()));
    let status = docs.ping_and_wait_allowing(&spake, &http, &aggregator, &allowed(&refused));
    let rejection = status_rejection(&status, "WIST1-E03", &reaching_id);
    assert_eq!(rejection["collection"], "docs", "{rejection}");
    assert_eq!(rejection["urls"], json!([first_url]), "{rejection}");
    let reaching_epoch = seal_epoch(&clave, &aggregator.data, &grid.next());
    record.exercised("removal_naming_another_collections_url", reaching_epoch);
    let sealed = epoch_entries(&http, &base, reaching_epoch);
    assert!(
        entries_of(&sealed, "publisher_item")
            .iter()
            .all(|entry| entry["body"]["item"]["url"] != first_url.as_str()),
        "{sealed:?}"
    );
    let (_, state) = head_snapshot_state(&aggregator.data);
    assert_eq!(latest_catalog(&state, &docs), reaching);
    let first_record = url_tuple(&state, "record", &docs.host, &first_url)
        .unwrap_or_else(|| panic!("the other Collection's record left: {state:?}"));
    assert_eq!(first_record[4], "blog");
    assert!(url_tuple(&state, "removal", &docs.host, &first_url).is_none());
    sync(&graven, &gdir);
    let mut mcp = McpClient::start(&graven, &gdir);
    assert_eq!(mcp.get_record(&first_url)["collection"], "blog");
    drop(mcp);
    std::fs::write(docs.collection_dir().join("catalog.json"), &docs_catalog)
        .expect("serve the Publisher's own docs Catalog again");

    let delegate_key = blog.signing_key(&blog_kid);
    wait_until_after(&reaching_generated_at);
    docs.write_page(
        "docs/guide.html",
        &marked_page("Guide", "guide about tamarind and hibiscus", &[]),
    );
    blog.collection_command(
        &spake,
        "key-remove",
        &["--name", "blog", "--kid", &blog_kid, "--confirm"],
    );
    docs.publish(&spake);
    blog.sign_due(&spake);
    let key_removed = docs.declaration();
    let owner_signed = blog.catalog();
    assert!(
        owner_kids.contains(
            &owner_signed["sig"]["key_id"]
                .as_str()
                .unwrap_or_default()
                .to_string()
        ),
        "the Publisher did not sign the blog Catalog with an owner key: {owner_signed}"
    );
    refused.push(("WIST2-E08".into(), catalog_id(&docs.catalog())));
    docs.ping_and_wait_allowing(&spake, &http, &aggregator, &allowed(&refused));
    let key_removal_epoch = seal_epoch(&clave, &aggregator.data, &grid.next());
    record.exercised("delegate_key_removed_and_owner_catalog", key_removal_epoch);
    let sealed = epoch_entries(&http, &base, key_removal_epoch);
    assert_eq!(
        entries_of(&sealed, "publisher_declaration")
            .iter()
            .map(|entry| entry["body"].clone())
            .collect::<Vec<_>>(),
        [key_removed]
    );
    assert!(
        entries_of(&sealed, "publisher_catalog")
            .iter()
            .any(|entry| entry["body"] == owner_signed),
        "the owner's blog Catalog is not sealed with the Declaration that removed the delegate key: {sealed:?}"
    );
    let (_, state) = head_snapshot_state(&aggregator.data);
    assert_eq!(
        collection_tuple(&state, &blog.host, "blog")[4],
        key_removal_epoch
    );

    let mut delegate_list = blog.served_list();
    let mut delegate_item = template.clone();
    delegate_item["url"] = json!(docs.url("blog/delegated.html"));
    blog.serve_payload_as(&template, &delegate_item);
    delegate_list.push(delegate_item.clone());
    wait_until_after(&served_generated_at(&blog));
    let delegated = blog.serve_catalog(&delegate_list, &now_rfc3339(), &blog_kid, &delegate_key);
    refused.push(("WIST1-E02".into(), catalog_id(&delegated)));
    let status = blog.ping_and_wait_allowing(&spake, &http, &aggregator, &allowed(&refused));
    assert_eq!(
        status_rejection(&status, "WIST1-E02", &catalog_id(&delegated))["collection"],
        "blog",
        "{status}"
    );
    let delegated_epoch = seal_epoch(&clave, &aggregator.data, &grid.next());
    record.exercised("catalog_signed_by_a_removed_delegate_key", delegated_epoch);
    let sealed = epoch_entries(&http, &base, delegated_epoch);
    assert!(
        entries_of(&sealed, "publisher_catalog").is_empty(),
        "{sealed:?}"
    );
    let (_, state) = head_snapshot_state(&aggregator.data);
    assert_eq!(latest_catalog(&state, &blog), owner_signed);
    let delegated_url = docs.url("blog/delegated.html");
    assert!(url_tuple(&state, "record", &docs.host, &delegated_url).is_none());
    sync(&graven, &gdir);
    let mut mcp = McpClient::start(&graven, &gdir);
    not_found(&mut mcp, &delegated_url);
    assert_eq!(mcp.get_record(&first_url)["collection"], "blog");
    assert_eq!(mcp.get_record(&second_url)["collection"], "blog");
    assert!(hits_for(&mcp.search("hibiscus"), &guide_url).is_some());
    drop(mcp);
    std::fs::write(
        blog.collection_dir().join("catalog.json"),
        serde_json::to_vec(&owner_signed).expect("serialize the owner's Catalog"),
    )
    .expect("serve the owner's blog Catalog again");

    validate_artifacts(&docs.out, &aggregator.data);
    record.write();
    eprintln!("completed in {:?}", started.elapsed());
}
