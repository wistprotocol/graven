use e2e::{
    checkpoint_verifier_key, fetch_status, graven_bin, grid_instant, now_rfc3339,
    resolve_sibling_bin, run, run_in_fresh_env, run_with_env, s, seal_epoch, serve_sites,
    start_aggregator, synced_heads, wait_until_pull_recorded, wait_until_pulled_since,
    wait_until_status_active, wait_until_unreachable, workspace_root, McpClient,
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

fn add_page(dir: &Path, host: &str, page: &str, title: &str, body: &str) {
    std::fs::write(
        dir.join(page),
        format!(
            "<!doctype html><html><head><title>{title}</title><meta name=\"description\" content=\"{title}\"></head><body><p>{body}</p></body></html>"
        ),
    )
    .expect("write added page");
    let mut pages: Vec<String> = std::fs::read_dir(dir)
        .expect("read staged site dir")
        .filter_map(|entry| {
            let name = entry.expect("staged site entry").file_name();
            let name = name.to_str().expect("non-utf8 file name").to_string();
            name.ends_with(".html").then_some(name)
        })
        .collect();
    pages.sort();
    let urls: String = pages
        .iter()
        .map(|page| format!("<url><loc>https://{host}/{page}</loc></url>"))
        .collect();
    std::fs::write(
        dir.join("sitemap.xml"),
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">{urls}</urlset>"
        ),
    )
    .expect("write sitemap");
}

fn build_site(spake: &Path, host: &str, dir: &Path, state: &Path, extra: &[&str]) {
    let mut args = vec![
        "build",
        "--site",
        s(dir),
        "--domain",
        host,
        "--out",
        s(dir),
        "--state",
        s(state),
    ];
    args.extend_from_slice(extra);
    run(spake, &args);
}

fn ping(spake: &Path, log_base: &str, host: &str) {
    run(
        spake,
        &[
            "ping",
            "--log",
            log_base,
            "--domain",
            host,
            "--allow-http",
            "--no-retry",
        ],
    );
}

fn published_delta_id(out: &Path, url: &str) -> String {
    let mut newest: Option<(String, String)> = None;
    let dir = out.join(".well-known/wist/deltas");
    for entry in std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display())) {
        let path = entry.expect("delta directory entry").path();
        let doc = read_json(&path);
        if doc["delta"]["url"] != url {
            continue;
        }
        let observed_at = doc["delta"]["observed_at"]
            .as_str()
            .expect("observed_at is a string")
            .to_string();
        let id = format!(
            "sha256:{}",
            path.file_stem()
                .and_then(|stem| stem.to_str())
                .expect("delta file name")
        );
        if newest.as_ref().is_none_or(|(_, at)| *at <= observed_at) {
            newest = Some((id, observed_at));
        }
    }
    newest
        .unwrap_or_else(|| panic!("no published Delta for {url} under {}", dir.display()))
        .0
}

struct RunRecord {
    scenarios: Vec<serde_json::Value>,
}

fn repo_revision(dir: &Path) -> serde_json::Value {
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
    serde_json::json!({"head": head, "dirty": dirty})
}

impl RunRecord {
    fn new() -> Self {
        RunRecord {
            scenarios: Vec::new(),
        }
    }

    fn exercised(&mut self, scenario: &str, epoch: u64) {
        self.scenarios
            .push(serde_json::json!({"scenario": scenario, "sealed_at_epoch": epoch}));
    }

    fn write(&self, path: &Path) {
        let siblings = workspace_root()
            .parent()
            .expect("graven repo has a parent directory")
            .to_path_buf();
        let spec = std::env::var("WIST_SPEC_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| siblings.join("spec"));
        let record = serde_json::json!({
            "repositories": {
                "core": repo_revision(&siblings.join("core")),
                "spake": repo_revision(&siblings.join("spake")),
                "clave": repo_revision(&siblings.join("clave")),
                "graven": repo_revision(&workspace_root()),
                "spec": repo_revision(&spec),
            },
            "scenarios": self.scenarios,
        });
        std::fs::write(
            path,
            serde_json::to_vec_pretty(&record).expect("serialize the run record"),
        )
        .expect("write the run record");
    }
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

fn synced_cursor(dir: &Path, log_id: &str) -> serde_json::Value {
    read_json(&log_store_dir(dir, log_id).join("sync.json"))
}

/// WIST-3 §7's `content_digest`, recomputed over the Consumer's own index.
fn index_content_digest(dir: &Path, log_id: &str) -> String {
    let path = log_store_dir(dir, log_id).join("index.sqlite");
    let conn =
        rusqlite::Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap_or_else(|e| panic!("open {}: {e}", path.display()));
    let mut statement = conn
        .prepare("SELECT url, publisher, delta_id, observed_at FROM records")
        .expect("the index carries the records table");
    let records: Vec<serde_json::Value> = statement
        .query_map([], |row| {
            Ok(serde_json::json!({
                "url": row.get::<_, String>(0)?,
                "publisher": row.get::<_, String>(1)?,
                "delta_id": row.get::<_, String>(2)?,
                "observed_at": row.get::<_, String>(3)?,
            }))
        })
        .expect("read the records")
        .collect::<rusqlite::Result<Vec<_>>>()
        .expect("read the records");
    wist_core::snapshot::content_digest(&records).expect("digest the records")
}

fn read_json(path: &Path) -> serde_json::Value {
    serde_json::from_slice(
        &std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display())),
    )
    .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

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

/// WIST-3 §3.4: a `key_id` never appears in a note, so a rotation is read off the note key IDs.
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
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    stdout
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
    let mut record = RunRecord::new();

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
    let pruned_host = "pruned.localhost".to_string();
    let pruned_site = stage_page_site(
        tmp.path(),
        &pruned_host,
        "keep.html",
        "Pruned keep",
        "keepsake notes the publisher keeps serving",
        &[],
    );
    add_page(
        &pruned_site,
        &pruned_host,
        "gone.html",
        "Pruned gone",
        "vanishing notes the publisher later removes",
    );
    let kept_url = format!("https://{pruned_host}/keep.html");
    let removed_url = format!("https://{pruned_host}/gone.html");
    let recovered_host = "recovered.localhost".to_string();
    let recovered_site = stage_page_site(
        tmp.path(),
        &recovered_host,
        "first.html",
        "Recovered first",
        "custodian notes published before the key set was recovered",
        &[],
    );
    let mut sites: BTreeMap<String, PathBuf> = BTreeMap::from([
        (site_host.clone(), site.clone()),
        (labeler_host.clone(), labeler_site.clone()),
        (pruned_host.clone(), pruned_site.clone()),
        (recovered_host.clone(), recovered_site.clone()),
    ]);
    sites.extend(graph_sites.iter().cloned());
    let (proxy_addr, _) = serve_sites(sites);
    let site_proxy = format!("http://{proxy_addr}");

    let spake_state = tmp.path().join("spake-state");
    let labeler_state = tmp.path().join("labeler-state");
    let pruned_state = tmp.path().join("pruned-state");
    let recovered_state = tmp.path().join("recovered-state");
    let recovery_seed = tmp.path().join("offline/recovery.seed");
    let clave_data = tmp.path().join("clave-data");
    let gdir = tmp.path().join("graven-store");

    let suffix_list =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/public-suffix-list.dat");
    let mut aggregator = start_aggregator(
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
    let first_epoch = seal_epoch(&clave, &clave_data, &first_seal);
    seal_epoch(&clave, &clave2_data, &first_seal);
    record.exercised("publication", first_epoch);

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

    for (host, dir, state) in [
        (&pruned_host, &pruned_site, &pruned_state),
        (&recovered_host, &recovered_site, &recovered_state),
    ] {
        run(
            &spake,
            &[
                "init",
                "--domain",
                host,
                "--out",
                s(dir),
                "--state",
                s(state),
            ],
        );
        build_site(&spake, host, dir, state, &[]);
        ping(&spake, &clave_base, host);
        wait_until_status_active(&http, &clave_base, host);
    }

    // Only a Declaration already listing a recovery key can authorize a recovery.
    run(
        &spake,
        &[
            "recovery-init",
            "--out",
            s(&recovered_site),
            "--state",
            s(&recovered_state),
            "--seed-out",
            s(&recovery_seed),
        ],
    );
    let committed_since = now_rfc3339();
    ping(&spake, &clave_base, &recovered_host);
    wait_until_pulled_since(
        &http,
        &clave_base,
        &recovered_host,
        &committed_since,
        &clave_stderr,
    );
    let committed = read_json(&recovered_site.join(".well-known/wist/publisher.json"));
    assert_eq!(
        committed["publisher"]["recovery_keys"]
            .as_array()
            .map(Vec::len),
        Some(1),
        "recovery-init lists one recovery key: {committed}"
    );

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
    let second_epoch = seal_epoch(&clave, &clave_data, &second_seal);
    seal_epoch(&clave, &clave2_data, &second_seal);
    record.exercised("revision", second_epoch);

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
    let third_epoch = seal_epoch(&clave, &clave_data, &third_seal);
    seal_epoch(&clave, &clave2_data, &third_seal);
    record.exercised("label_dispute", third_epoch);
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
    let fourth_epoch = seal_epoch(&clave, &clave_data, &fourth_seal);
    record.exercised("payload_withdrawal", fourth_epoch);
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
    let fifth_epoch = seal_epoch(&clave, &clave_data, &fifth_seal);
    seal_epoch(&clave, &clave2_data, &fifth_seal);
    record.exercised("publisher_key_rotation", fifth_epoch);
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
    let sixth_epoch = seal_epoch(&clave, &clave_data, &sixth_seal);
    record.exercised("hijacked_declaration", sixth_epoch);

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
    let seventh_epoch = seal_epoch(&clave, &clave_data, &seventh_seal);
    record.exercised("hijack_reversal", seventh_epoch);

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
    let eighth_epoch = seal_epoch(&clave, &clave_data, &eighth_seal);
    seal_epoch(&clave, &clave2_data, &eighth_seal);
    record.exercised("label_one_epoch_old", eighth_epoch);
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

    let ninth_seal = grid_instant(8);
    let ninth_epoch = seal_epoch(&clave, &clave_data, &ninth_seal);
    seal_epoch(&clave, &clave2_data, &ninth_seal);
    record.exercised("label_two_epochs_live", ninth_epoch);
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

    let mut mcp7 = McpClient::start(&graven, &gdir);
    assert_eq!(
        mcp7.get_record(&removed_url)["url"],
        removed_url,
        "the page to be removed is not indexed before its removal"
    );
    assert!(
        mcp7.search("vanishing")
            .iter()
            .any(|h| h["url"] == removed_url.as_str()),
        "the page to be removed is not searchable before its removal"
    );
    drop(mcp7);

    let removed_since = now_rfc3339();
    build_site(
        &spake,
        &pruned_host,
        &pruned_site,
        &pruned_state,
        &["--remove", &removed_url],
    );
    ping(&spake, &clave_base, &pruned_host);
    wait_until_pulled_since(
        &http,
        &clave_base,
        &pruned_host,
        &removed_since,
        &clave_stderr,
    );
    std::thread::sleep(Duration::from_secs(2));
    let deletion_seal = grid_instant(9);
    let deletion_epoch = seal_epoch(&clave, &clave_data, &deletion_seal);
    record.exercised("url_deletion", deletion_epoch);
    run(&graven, &["sync", "--dir", s(&gdir), "--allow-http"]);

    let mut mcp8 = McpClient::start(&graven, &gdir);
    let absent = mcp8.get_record_error(&removed_url);
    assert_eq!(
        absent["message"], "not found",
        "get_record still answers for the removed URL: {absent}"
    );
    assert!(
        mcp8.search("vanishing").is_empty(),
        "the removed URL is still searchable"
    );
    assert_eq!(
        mcp8.get_record(&kept_url)["url"],
        kept_url,
        "the domain's other record left the index with the removed one"
    );
    assert!(
        mcp8.search("keepsake")
            .iter()
            .any(|h| h["url"] == kept_url.as_str()),
        "the domain's other record is no longer searchable"
    );
    drop(mcp8);

    let resumed_url = format!("https://{pruned_host}/resumed.html");
    add_page(
        &pruned_site,
        &pruned_host,
        "resumed.html",
        "Pruned resumed",
        "resumed notes admitted before the aggregator stopped",
    );
    let admitted_since = now_rfc3339();
    build_site(&spake, &pruned_host, &pruned_site, &pruned_state, &[]);
    ping(&spake, &clave_base, &pruned_host);
    wait_until_pulled_since(
        &http,
        &clave_base,
        &pruned_host,
        &admitted_since,
        &clave_stderr,
    );
    let synced = run(&graven, &["sync", "--dir", s(&gdir), "--allow-http"]);
    let heads_before = synced_heads(&String::from_utf8_lossy(&synced.stdout));
    assert_eq!(
        heads_before.len(),
        2,
        "the Consumer follows both Logs: {heads_before:?}"
    );
    let anchor_before = std::fs::read(&anchor_path).expect("read anchor.json");
    let mut mcp_pending = McpClient::start(&graven, &gdir);
    let unsealed = mcp_pending.get_record_error(&resumed_url);
    assert_eq!(
        unsealed["message"], "not found",
        "the admitted Delta sealed before the Aggregator was stopped: {unsealed}"
    );
    drop(mcp_pending);

    aggregator.stop();
    wait_until_unreachable(&http, &clave_base, &pruned_host);
    aggregator.start(&clave, Some(&site_proxy));
    let clave_stderr = aggregator.stderr.clone();
    wait_until_status_active(&http, &clave_base, &pruned_host);
    assert_eq!(
        std::fs::read(&anchor_path).expect("read anchor.json"),
        anchor_before,
        "the restarted Aggregator serves a different Log Anchor"
    );

    let restart_seal = grid_instant(10);
    let restart_epoch = seal_epoch(&clave, &clave_data, &restart_seal);
    record.exercised("aggregator_restart", restart_epoch);
    run(&clave, &["verify-history", "--data", s(&clave_data)]);
    let resynced = run(&graven, &["sync", "--dir", s(&gdir), "--allow-http"]);
    let heads_after = synced_heads(&String::from_utf8_lossy(&resynced.stdout));
    for (log_id, before) in &heads_before {
        let after = heads_after
            .get(log_id)
            .unwrap_or_else(|| panic!("log {log_id} missing after the restart: {heads_after:?}"));
        assert!(
            after.epoch >= before.epoch && after.tree_size >= before.tree_size,
            "log {log_id} rolled back across the restart: {before:?} then {after:?}"
        );
        if after.epoch == before.epoch {
            assert_eq!(
                after.root, before.root,
                "log {log_id} kept its head Epoch and changed its root: {before:?} then {after:?}"
            );
        }
    }
    assert!(
        heads_after[&clave_host].epoch > heads_before[&clave_host].epoch,
        "the restarted Aggregator sealed no Epoch: {heads_before:?} then {heads_after:?}"
    );

    let mut mcp9 = McpClient::start(&graven, &gdir);
    assert_eq!(
        mcp9.get_record(&resumed_url)["url"],
        resumed_url,
        "a Delta admitted before the restart did not seal after it"
    );
    drop(mcp9);

    let beta_url = format!("https://{site_host}/b.html");
    let mut mcp10 = McpClient::start(&graven, &gdir);
    let beta_tip = mcp10.get_record(&beta_url)["delta_id"]
        .as_str()
        .expect("delta_id is a string")
        .to_string();
    drop(mcp10);
    revise_fixture_page(
        &site,
        "beta page body content rotated",
        "beta page body content restarted",
    );
    run_in_fresh_env(
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
        &[],
    );
    let restarted_since = now_rfc3339();
    for base in [&clave_base, &clave2_base] {
        ping(&spake, base, &site_host);
    }
    wait_until_pulled_since(
        &http,
        &clave_base,
        &site_host,
        &restarted_since,
        &clave_stderr,
    );
    wait_until_pulled_since(
        &http,
        &clave2_base,
        &site_host,
        &restarted_since,
        &clave2_stderr,
    );
    std::thread::sleep(Duration::from_secs(2));
    let publisher_restart_seal = grid_instant(11);
    let publisher_restart_epoch = seal_epoch(&clave, &clave_data, &publisher_restart_seal);
    seal_epoch(&clave, &clave2_data, &publisher_restart_seal);
    record.exercised("publisher_restart", publisher_restart_epoch);
    run(&graven, &["sync", "--dir", s(&gdir), "--allow-http"]);

    let mut mcp11 = McpClient::start(&graven, &gdir);
    let restarted_record = mcp11.get_record(&beta_url);
    let restarted_tip = restarted_record["delta_id"]
        .as_str()
        .expect("delta_id is a string")
        .to_string();
    assert_ne!(
        restarted_tip, beta_tip,
        "the build from the persisted state directory published nothing new"
    );
    assert!(
        mcp11
            .search("restarted")
            .iter()
            .any(|h| h["url"] == beta_url.as_str()),
        "the Delta built from the persisted state directory is not searchable"
    );
    drop(mcp11);
    let restarted_delta = read_json(&site.join(format!(
        ".well-known/wist/deltas/{}.json",
        restarted_tip
            .strip_prefix("sha256:")
            .expect("delta id is prefixed")
    )));
    assert_eq!(
        restarted_delta["delta"]["prev"], beta_tip,
        "the Delta chain restarted instead of continuing from the sealed tip: {restarted_delta}"
    );

    run(
        &graven,
        &["profile", "use", "--dir", s(&gdir), "--name", "text-only"],
    );
    let mut mcp12 = McpClient::start(&graven, &gdir);
    let selected = mcp12.search("changed");
    let selected_hit = selected
        .iter()
        .find(|h| h["url"].as_str().unwrap_or_default().ends_with("/a.html"))
        .unwrap_or_else(|| {
            panic!("a query naming no profile did not use the selected one: {selected:?}")
        });
    assert_eq!(selected_hit["ranking"]["profile"], "text-only");
    drop(mcp12);
    run(
        &graven,
        &["profile", "use", "--dir", s(&gdir), "--name", "default"],
    );
    let mut mcp13 = McpClient::start(&graven, &gdir);
    assert!(
        mcp13.search("changed").is_empty(),
        "selecting the default profile again did not restore its treatment of the spam Label"
    );
    let defaulted = mcp13.search("orchard");
    assert_eq!(
        defaulted
            .first()
            .unwrap_or_else(|| panic!("no hit for orchard under the default profile"))["ranking"]
            ["profile"],
        "default"
    );
    drop(mcp13);
    record.exercised("default_profile_persistence", publisher_restart_epoch);

    let stale_url = format!("https://{recovered_host}/stale.html");
    let fresh_url = format!("https://{recovered_host}/fresh.html");
    let first_url = format!("https://{recovered_host}/first.html");
    add_page(
        &recovered_site,
        &recovered_host,
        "stale.html",
        "Recovered stale",
        "brittle notes signed under the key set the recovery replaces",
    );
    let stale_since = now_rfc3339();
    build_site(
        &spake,
        &recovered_host,
        &recovered_site,
        &recovered_state,
        &[],
    );
    ping(&spake, &clave_base, &recovered_host);
    wait_until_pulled_since(
        &http,
        &clave_base,
        &recovered_host,
        &stale_since,
        &clave_stderr,
    );
    let stale_delta = published_delta_id(&recovered_site, &stale_url);

    run(
        &spake,
        &[
            "recover",
            "--out",
            s(&recovered_site),
            "--state",
            s(&recovered_state),
            "--recovery-seed",
            s(&recovery_seed),
        ],
    );
    let recovered_declaration = read_json(&recovered_site.join(".well-known/wist/publisher.json"));
    assert_eq!(
        recovered_declaration["sig"]["key_id"], committed["publisher"]["recovery_keys"][0]["kid"],
        "the recovery is signed by the committed recovery key: {recovered_declaration}"
    );
    assert_eq!(
        recovered_declaration["publisher"]["keys"]
            .as_array()
            .map(Vec::len),
        Some(1),
        "the recovery installs one signing key: {recovered_declaration}"
    );
    add_page(
        &recovered_site,
        &recovered_host,
        "fresh.html",
        "Recovered fresh",
        "sturdy notes signed under the recovered key set",
    );
    let recovered_since = now_rfc3339();
    build_site(
        &spake,
        &recovered_host,
        &recovered_site,
        &recovered_state,
        &[],
    );
    ping(&spake, &clave_base, &recovered_host);
    wait_until_pulled_since(
        &http,
        &clave_base,
        &recovered_host,
        &recovered_since,
        &clave_stderr,
    );
    std::thread::sleep(Duration::from_secs(2));
    let window_seal = grid_instant(12);
    let window_epoch = seal_epoch(&clave, &clave_data, &window_seal);
    record.exercised("publisher_key_recovery_window", window_epoch);
    let entries = snapshot_state_entries(&clave_data);
    let window = state_tuple(&entries, "recovery_window", &recovered_host)
        .unwrap_or_else(|| panic!("no recovery_window tuple: {entries:?}"));
    assert_eq!(
        window[2], window_epoch,
        "the window opens at the Epoch sealing the recovery Declaration: {window}"
    );
    run(&graven, &["sync", "--dir", s(&gdir), "--allow-http"]);

    let mut mcp14 = McpClient::start(&graven, &gdir);
    assert_eq!(
        mcp14.get_record(&first_url)["url"],
        first_url,
        "a record sealed before the window opened must stay visible"
    );
    for queued in [&stale_url, &fresh_url] {
        let absent = mcp14.get_record_error(queued);
        assert_eq!(
            absent["message"], "not found",
            "a Delta queued by the open recovery window is visible: {absent}"
        );
    }
    drop(mcp14);

    let later_url = format!("https://{recovered_host}/later.html");
    add_page(
        &recovered_site,
        &recovered_host,
        "later.html",
        "Recovered later",
        "patient notes published while the recovery window stood open",
    );
    let later_since = now_rfc3339();
    build_site(
        &spake,
        &recovered_host,
        &recovered_site,
        &recovered_state,
        &[],
    );
    ping(&spake, &clave_base, &recovered_host);
    wait_until_pulled_since(
        &http,
        &clave_base,
        &recovered_host,
        &later_since,
        &clave_stderr,
    );
    std::thread::sleep(Duration::from_secs(2));
    let open_window_seal = grid_instant(13);
    let open_window_epoch = seal_epoch(&clave, &clave_data, &open_window_seal);
    record.exercised("delta_queued_inside_the_recovery_window", open_window_epoch);
    let entries = snapshot_state_entries(&clave_data);
    let window = state_tuple(&entries, "recovery_window", &recovered_host)
        .unwrap_or_else(|| panic!("the window closed before its end: {entries:?}"));
    assert_eq!(
        window[2], window_epoch,
        "a later Epoch moved the window's opening: {window}"
    );
    run(&graven, &["sync", "--dir", s(&gdir), "--allow-http"]);
    let mut mcp_queued = McpClient::start(&graven, &gdir);
    let absent = mcp_queued.get_record_error(&later_url);
    assert_eq!(
        absent["message"], "not found",
        "a Delta published inside the open window sealed instead of queueing: {absent}"
    );
    drop(mcp_queued);

    let settlement_seal = grid_instant(12 + 24 * 7 + 1);
    let settlement_epoch = seal_epoch(&clave, &clave_data, &settlement_seal);
    record.exercised("publisher_key_recovery_settlement", settlement_epoch);
    let entries = snapshot_state_entries(&clave_data);
    assert!(
        state_tuple(&entries, "recovery_window", &recovered_host).is_none(),
        "the recovery window did not settle: {entries:?}"
    );
    let settled_status = fetch_status(&http, &clave_base, &recovered_host)
        .unwrap_or_else(|| panic!("no status for {recovered_host} after settlement"));
    let rejections = settled_status["rejections"]
        .as_array()
        .expect("rejections array");
    assert!(
        rejections
            .iter()
            .any(|r| r["code"] == "WIST1-E13" && r["delta_id"] == stale_delta.as_str()),
        "settlement did not reject the Delta under the pre-recovery key: {rejections:?}"
    );
    run(&graven, &["sync", "--dir", s(&gdir), "--allow-http"]);

    let mut mcp15 = McpClient::start(&graven, &gdir);
    for materialized in [&fresh_url, &later_url] {
        assert_eq!(
            mcp15.get_record(materialized)["url"],
            materialized.as_str(),
            "a Delta under the recovered Key Set did not materialize at settlement"
        );
    }
    let absent = mcp15.get_record_error(&stale_url);
    assert_eq!(
        absent["message"], "not found",
        "the Delta under the pre-recovery key is visible after settlement: {absent}"
    );
    drop(mcp15);

    let rotated_seed = tmp.path().join("offline/recovery-next.seed");
    run(
        &spake,
        &[
            "recovery-rotate",
            "--out",
            s(&recovered_site),
            "--state",
            s(&recovered_state),
            "--recovery-seed",
            s(&recovery_seed),
            "--seed-out",
            s(&rotated_seed),
        ],
    );
    let rotated_since = now_rfc3339();
    ping(&spake, &clave_base, &recovered_host);
    wait_until_pull_recorded(&http, &clave_base, &recovered_host, &rotated_since);
    std::thread::sleep(Duration::from_secs(2));
    let recovery_rotation_seal = grid_instant(12 + 24 * 7 + 2);
    let recovery_rotation_epoch = seal_epoch(&clave, &clave_data, &recovery_rotation_seal);
    record.exercised("recovery_key_rotation", recovery_rotation_epoch);
    let entries = snapshot_state_entries(&clave_data);
    let rotated_window = state_tuple(&entries, "recovery_window", &recovered_host)
        .unwrap_or_else(|| panic!("the recovery-key rotation opened no window: {entries:?}"));
    assert_eq!(
        rotated_window[2], recovery_rotation_epoch,
        "the window opens at the Epoch sealing the rotation: {rotated_window}"
    );
    let rotated_declaration = read_json(&recovered_site.join(".well-known/wist/publisher.json"));
    assert_ne!(
        rotated_declaration["publisher"]["recovery_keys"][0]["kid"],
        committed["publisher"]["recovery_keys"][0]["kid"],
        "the rotation kept the replaced recovery key: {rotated_declaration}"
    );
    run(&graven, &["sync", "--dir", s(&gdir), "--allow-http"]);
    let mut mcp16 = McpClient::start(&graven, &gdir);
    assert_eq!(
        mcp16.get_record(&fresh_url)["url"],
        fresh_url,
        "the settled records did not survive the recovery-key rotation"
    );
    drop(mcp16);

    validate_artifacts(&site, &clave_data);
    // The external client reads the Log under one verifier key.
    verify_with_external_tlog_client(&aggregator.base_url, &aggregator.verifier_key);

    let log_anchor = read_json(&anchor_path);
    let genesis_key_id = log_anchor["anchor"]["genesis_key"]["key_id"]
        .as_str()
        .unwrap_or_else(|| panic!("the Log Anchor declares no genesis key_id: {log_anchor}"))
        .to_string();
    assert_eq!(
        log_key(&log_keys(&clave, &clave_data), &genesis_key_id).added,
        Some(0),
        "the Anchor's genesis key is not the key admitted at height 0"
    );
    let key_added = run(&clave, &["log-key", "add", "--data", s(&clave_data)]);
    let admitted_verifier_key =
        checkpoint_verifier_key(&String::from_utf8_lossy(&key_added.stdout));
    let keys = log_keys(&clave, &clave_data);
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

    let addition_seal = grid_instant(12 + 24 * 7 + 3);
    let addition_epoch = seal_epoch(&clave, &clave_data, &addition_seal);
    record.exercised("log_key_addition", addition_epoch);

    // WIST-3 §3.4: the Epoch that seals an addition is signed by the admitting key and the new one.
    let mut admitting_signers = vec![genesis_note_key_id.clone(), admitted_note_key_id.clone()];
    admitting_signers.sort();
    let head_note = fetch_text(&http, &format!("{clave_base}/checkpoint"));
    let archived_note = fetch_text(
        &http,
        &format!(
            "{clave_base}{}",
            wist_core::checkpoint::archive_path(addition_epoch)
        ),
    );
    assert_eq!(
        parse_note(&head_note).epoch_number(),
        addition_epoch,
        "the served head is not the Epoch that sealed the addition"
    );
    assert_eq!(
        parse_note(&head_note).note_text(),
        parse_note(&archived_note).note_text(),
        "the archived Checkpoint states another tree than the served head"
    );
    for (source, note) in [
        ("the served head", &head_note),
        ("the archive", &archived_note),
    ] {
        let mut signers = log_signature_key_ids(note, &clave_host);
        assert_eq!(
            signers.len(),
            2,
            "{source} carries {} Log signature lines, not the admitting key's and the new one's: {note}",
            signers.len()
        );
        signers.sort();
        assert_eq!(
            signers, admitting_signers,
            "{source} is not signed under the admitting key and the admitted one: {note}"
        );
    }
    let synced = run(&graven, &["sync", "--dir", s(&gdir), "--allow-http"]);
    let heads = synced_heads(&String::from_utf8_lossy(&synced.stdout));
    assert_eq!(
        heads[&clave_host].epoch, addition_epoch,
        "the Consumer did not advance to the Epoch that admitted the key: {heads:?}"
    );

    let keystone_url = format!("https://{pruned_host}/second-key.html");
    add_page(
        &pruned_site,
        &pruned_host,
        "second-key.html",
        "Pruned second key",
        "keystone notes sealed while the Log held two Aggregator keys",
    );
    let keystone_since = now_rfc3339();
    build_site(&spake, &pruned_host, &pruned_site, &pruned_state, &[]);
    ping(&spake, &clave_base, &pruned_host);
    wait_until_pulled_since(
        &http,
        &clave_base,
        &pruned_host,
        &keystone_since,
        &clave_stderr,
    );
    std::thread::sleep(Duration::from_secs(2));
    let keystone_epoch = seal_epoch(&clave, &clave_data, &grid_instant(12 + 24 * 7 + 4));
    let advanced = run(&graven, &["sync", "--dir", s(&gdir), "--allow-http"]);
    let heads = synced_heads(&String::from_utf8_lossy(&advanced.stdout));
    assert_eq!(
        heads[&clave_host].epoch, keystone_epoch,
        "the Consumer did not advance over the Epoch sealed above the addition: {heads:?}"
    );
    let mut mcp_admitted = McpClient::start(&graven, &gdir);
    assert_eq!(
        mcp_admitted.get_record(&keystone_url)["url"],
        keystone_url,
        "a Delta sealed after the key addition did not reach the index"
    );
    assert!(
        mcp_admitted
            .search("keystone")
            .iter()
            .any(|h| h["url"] == keystone_url.as_str()),
        "a Delta sealed after the key addition is not searchable"
    );
    drop(mcp_admitted);

    let stale_snapshots = tmp.path().join("snapshots-before-the-removal");
    copy_tree(&clave_data.join("snapshots"), &stale_snapshots);
    run(
        &clave,
        &[
            "log-key",
            "remove",
            "--data",
            s(&clave_data),
            "--key-id",
            &genesis_key_id,
        ],
    );
    let removal_epoch = seal_epoch(&clave, &clave_data, &grid_instant(12 + 24 * 7 + 5));
    record.exercised("log_key_removal_of_the_genesis_key", removal_epoch);
    assert_eq!(
        log_key(&log_keys(&clave, &clave_data), &genesis_key_id).removed,
        Some(removal_epoch),
        "the genesis key was not retired at the Epoch that sealed its removal"
    );

    // WIST-3 §3.4: a key removed at height N is invalid at N.
    let removal_note = fetch_text(
        &http,
        &format!(
            "{clave_base}{}",
            wist_core::checkpoint::archive_path(removal_epoch)
        ),
    );
    assert_eq!(
        log_signature_key_ids(&removal_note, &clave_host),
        std::slice::from_ref(&admitted_note_key_id),
        "the Checkpoint sealing the genesis key's removal is not signed by the remaining key alone: {removal_note}"
    );

    let lodestar_url = format!("https://{pruned_host}/retired-key.html");
    add_page(
        &pruned_site,
        &pruned_host,
        "retired-key.html",
        "Pruned retired key",
        "lodestar notes sealed after the genesis key was retired",
    );
    let lodestar_since = now_rfc3339();
    build_site(&spake, &pruned_host, &pruned_site, &pruned_state, &[]);
    ping(&spake, &clave_base, &pruned_host);
    wait_until_pulled_since(
        &http,
        &clave_base,
        &pruned_host,
        &lodestar_since,
        &clave_stderr,
    );
    std::thread::sleep(Duration::from_secs(2));
    let lodestar_epoch = seal_epoch(&clave, &clave_data, &grid_instant(12 + 24 * 7 + 6));
    let later_note = fetch_text(&http, &format!("{clave_base}/checkpoint"));
    assert_eq!(
        parse_note(&later_note).epoch_number(),
        lodestar_epoch,
        "the served head is not the Epoch sealed above the removal"
    );
    assert_eq!(
        log_signature_key_ids(&later_note, &clave_host),
        std::slice::from_ref(&admitted_note_key_id),
        "a Checkpoint above the removal carries a key other than the remaining one: {later_note}"
    );

    let resumed = run(&graven, &["sync", "--dir", s(&gdir), "--allow-http"]);
    let heads = synced_heads(&String::from_utf8_lossy(&resumed.stdout));
    assert_eq!(
        heads[&clave_host].epoch, lodestar_epoch,
        "the replaying Consumer did not sync across the genesis key's removal: {heads:?}"
    );
    let mut mcp_retired = McpClient::start(&graven, &gdir);
    assert_eq!(
        mcp_retired.get_record(&lodestar_url)["url"],
        lodestar_url,
        "a Delta sealed after the genesis key's removal did not reach the index"
    );
    assert!(
        mcp_retired
            .search("lodestar")
            .iter()
            .any(|h| h["url"] == lodestar_url.as_str()),
        "a Delta sealed after the genesis key's removal is not searchable"
    );
    drop(mcp_retired);
    run(&clave, &["verify-history", "--data", s(&clave_data)]);

    aggregator.stop();
    wait_until_unreachable(&http, &clave_base, &pruned_host);
    aggregator.start(&clave, Some(&site_proxy));
    wait_until_status_active(&http, &clave_base, &pruned_host);
    let restarted_epoch = seal_epoch(&clave, &clave_data, &grid_instant(12 + 24 * 7 + 7));
    let restarted_note = fetch_text(&http, &format!("{clave_base}/checkpoint"));
    assert_eq!(
        parse_note(&restarted_note).epoch_number(),
        restarted_epoch,
        "the restarted Aggregator serves another Epoch than the one it sealed"
    );
    assert_eq!(
        log_signature_key_ids(&restarted_note, &clave_host),
        std::slice::from_ref(&admitted_note_key_id),
        "the restarted Aggregator signed under a key the removal retired: {restarted_note}"
    );
    let restarted = run(&graven, &["sync", "--dir", s(&gdir), "--allow-http"]);
    let heads = synced_heads(&String::from_utf8_lossy(&restarted.stdout));
    assert_eq!(
        heads[&clave_host].epoch, restarted_epoch,
        "the Consumer did not advance over the Epoch the restarted Aggregator sealed: {heads:?}"
    );
    assert_eq!(
        log_key(&log_keys(&clave, &clave_data), &admitted_key_id).removed,
        None,
        "the remaining key was retired with the genesis key"
    );

    // WIST-3 §3.4: the Aggregator re-signed every unsealed document the retired key signed.
    let fresh_snapshots = tmp.path().join("snapshots-after-the-removal");
    copy_tree(&clave_data.join("snapshots"), &fresh_snapshots);

    let resumed_dir = tmp.path().join("graven-store-resumed");
    let resumed_start = run(
        &graven,
        &[
            "follow",
            "--anchor",
            s(&anchor_path),
            "--log",
            &clave_base,
            "--dir",
            s(&resumed_dir),
            "--tier1",
            "--allow-http",
        ],
    );
    let resumed_heads = synced_heads(&String::from_utf8_lossy(&resumed_start.stdout));
    record.exercised("cold_start_after_the_genesis_keys_removal", restarted_epoch);
    assert_eq!(
        resumed_heads[&clave_host].epoch, restarted_epoch,
        "the fresh Consumer did not cold-start to the head the followed one holds: {resumed_heads:?}"
    );
    let followed_cursor = synced_cursor(&gdir, &clave_host);
    let resumed_cursor = synced_cursor(&resumed_dir, &clave_host);
    for field in ["epoch_number", "tree_size", "root"] {
        assert_eq!(
            resumed_cursor[field], followed_cursor[field],
            "the cold-started Consumer's {field} differs from the one that followed throughout: {resumed_cursor} vs {followed_cursor}"
        );
    }
    assert_eq!(
        index_content_digest(&resumed_dir, &clave_host),
        index_content_digest(&gdir, &clave_host),
        "the two Consumers materialized different state at one head"
    );
    let mut mcp_resumed = McpClient::start(&graven, &resumed_dir);
    assert_eq!(
        mcp_resumed.get_record(&lodestar_url)["url"],
        lodestar_url,
        "the cold-started Consumer does not serve the record sealed after the removal"
    );
    // A resumed Consumer reads seal heights from the Snapshot's Epoch, which no WIST-3 §7 tuple
    // carries, so its ranking signals differ.
    let answered = |hits: &[serde_json::Value]| -> Vec<serde_json::Value> {
        hits.iter()
            .map(|hit| serde_json::json!([&hit["url"], &hit["publisher"], &hit["delta_id"]]))
            .collect()
    };
    let resumed_hits = answered(&mcp_resumed.search("lodestar"));
    drop(mcp_resumed);
    let mut mcp_followed = McpClient::start(&graven, &gdir);
    let followed_hits = answered(&mcp_followed.search("lodestar"));
    drop(mcp_followed);
    assert!(
        !resumed_hits.is_empty() && resumed_hits == followed_hits,
        "the two Consumers answer the same query differently: {resumed_hits:?} vs {followed_hits:?}"
    );

    // WIST-3 §8 step 8: a Snapshot the retired key signed is rejected (`WIST3-E04`).
    copy_tree(&stale_snapshots, &clave_data.join("snapshots"));
    let stale_dir = tmp.path().join("graven-store-stale-snapshot");
    let refused = Command::new(&graven)
        .args([
            "follow",
            "--anchor",
            s(&anchor_path),
            "--log",
            &clave_base,
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
    copy_tree(&fresh_snapshots, &clave_data.join("snapshots"));

    let run_record = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("e2e-run.json");
    record.write(&run_record);
    println!("run record: {}", run_record.display());
    let written = read_json(&run_record);
    for repo in ["core", "spake", "clave", "graven", "spec"] {
        assert!(
            written["repositories"][repo].is_object(),
            "the run record carries no revision for {repo}: {written}"
        );
    }
    assert_eq!(
        written["scenarios"]
            .as_array()
            .map(|scenarios| scenarios.len()),
        Some(record.scenarios.len()),
        "the run record lists every scenario the run exercised: {written}"
    );

    validate_artifacts(&site, &clave_data);
    verify_with_external_tlog_client(&aggregator.base_url, &admitted_verifier_key);

    eprintln!("end_to_end completed in {:?}", harness_start.elapsed());
}
