use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("e2e crate has a parent directory")
        .to_path_buf()
}

pub fn build_profile() -> &'static str {
    match std::env::var("WIST_BUILD_PROFILE").as_deref() {
        Ok("release") => "release",
        _ => "debug",
    }
}

pub fn cargo_build(repo_dir: &Path, package: &str) {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let mut args = vec!["build", "-p", package];
    if build_profile() == "release" {
        args.push("--release");
    }
    let status = Command::new(cargo)
        .args(&args)
        .current_dir(repo_dir)
        .status()
        .unwrap_or_else(|e| panic!("failed to spawn cargo build -p {package}: {e}"));
    assert!(
        status.success(),
        "cargo build -p {package} failed in {}",
        repo_dir.display()
    );
}

pub fn resolve_sibling_bin(env_var: &str, name: &str) -> PathBuf {
    if let Ok(p) = std::env::var(env_var) {
        return PathBuf::from(p);
    }
    let repo = workspace_root()
        .parent()
        .expect("graven repo has a parent directory")
        .join(name);
    let path = repo.join("target").join(build_profile()).join(name);
    cargo_build(&repo, name);
    assert!(
        path.exists(),
        "{} still missing after cargo build -p {name} in {}",
        path.display(),
        repo.display()
    );
    path
}

pub fn graven_bin() -> PathBuf {
    let repo = workspace_root();
    cargo_build(&repo, "graven");
    let path = repo.join("target").join(build_profile()).join("graven");
    assert!(path.exists(), "graven binary missing at {}", path.display());
    path
}

pub fn s(p: &Path) -> &str {
    p.to_str().expect("non-utf8 path")
}

pub fn run(bin: &Path, args: &[&str]) -> std::process::Output {
    run_with_env(bin, args, &[])
}

pub fn run_with_env(bin: &Path, args: &[&str], env: &[(&str, &str)]) -> std::process::Output {
    let output = Command::new(bin)
        .args(args)
        .envs(env.iter().copied())
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn {} {args:?}: {e}", bin.display()));
    assert!(
        output.status.success(),
        "{} {args:?} failed: status={:?}\nstdout={}\nstderr={}",
        bin.display(),
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

pub fn run_in_fresh_env(bin: &Path, args: &[&str], env: &[(&str, &str)]) -> std::process::Output {
    let mut command = Command::new(bin);
    command.args(args).env_clear();
    if let Ok(path) = std::env::var("PATH") {
        command.env("PATH", path);
    }
    let output = command
        .envs(env.iter().copied())
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn {} {args:?}: {e}", bin.display()));
    assert!(
        output.status.success(),
        "{} {args:?} failed in a fresh environment: status={:?}\nstdout={}\nstderr={}",
        bin.display(),
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

pub fn seal_epoch(bin: &Path, data: &Path, at: &str) -> u64 {
    let output = run(bin, &["seal", "--data", s(data), "--at", at]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("sealed epoch ")
                .and_then(|rest| rest.split_whitespace().next())
                .and_then(|n| n.parse::<u64>().ok())
        })
        .unwrap_or_else(|| panic!("clave seal printed no Epoch number:\n{stdout}"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncedHead {
    pub epoch: u64,
    pub tree_size: u64,
    pub root: String,
}

pub fn synced_heads(stdout: &str) -> std::collections::BTreeMap<String, SyncedHead> {
    let mut heads = std::collections::BTreeMap::new();
    for line in stdout.lines() {
        let Some(rest) = line.trim().strip_prefix('[') else {
            continue;
        };
        let Some((log_id, rest)) = rest.split_once("] ") else {
            continue;
        };
        let Some((_, rest)) = rest.split_once("to head epoch ") else {
            continue;
        };
        let Some((epoch, rest)) = rest.split_once(" (tree size ") else {
            continue;
        };
        let Some((tree_size, rest)) = rest.split_once(", root ") else {
            continue;
        };
        let root = rest.split(',').next().unwrap_or_default();
        let Ok(epoch) = epoch.trim().parse::<u64>() else {
            continue;
        };
        let Ok(tree_size) = tree_size.trim().parse::<u64>() else {
            continue;
        };
        heads.insert(
            log_id.to_string(),
            SyncedHead {
                epoch,
                tree_size,
                root: root.trim().to_string(),
            },
        );
    }
    heads
}

pub struct ChildGuard(pub Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub fn spawn_line_drain<R: Read + Send + 'static>(reader: R) -> Arc<Mutex<String>> {
    let buf = Arc::new(Mutex::new(String::new()));
    let sink = buf.clone();
    std::thread::spawn(move || {
        let mut r = BufReader::new(reader);
        let mut line = String::new();
        loop {
            line.clear();
            match r.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => sink
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push_str(&line),
            }
        }
    });
    buf
}

pub fn poll_until<T>(timeout: Duration, interval: Duration, mut f: impl FnMut() -> Option<T>) -> T {
    let start = Instant::now();
    loop {
        if let Some(v) = f() {
            return v;
        }
        assert!(
            start.elapsed() < timeout,
            "poll_until timed out after {timeout:?}"
        );
        std::thread::sleep(interval);
    }
}

pub fn spawn_clave_serve(
    bin: &Path,
    data: &Path,
    bind_addr: &str,
    proxy: &str,
) -> (ChildGuard, String, Arc<Mutex<String>>) {
    spawn_clave_serve_with(bin, data, bind_addr, Some(proxy))
}

pub fn spawn_clave_serve_with(
    bin: &Path,
    data: &Path,
    bind_addr: &str,
    proxy: Option<&str>,
) -> (ChildGuard, String, Arc<Mutex<String>>) {
    let data_str = data.to_str().expect("non-utf8 path").to_string();
    let mut command = Command::new(bin);
    command.args([
        "serve",
        "--data",
        &data_str,
        "--bind",
        bind_addr,
        "--allow-http",
        "--no-seal",
    ]);
    if let Some(proxy) = proxy {
        command
            .env("HTTP_PROXY", proxy)
            .env("http_proxy", proxy)
            .env("NO_PROXY", "")
            .env("no_proxy", "");
    }
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn clave serve: {e}"));
    let stdout = child.stdout.take().expect("clave serve stdout piped");
    let stderr = child.stderr.take().expect("clave serve stderr piped");
    let stdout_buf = spawn_line_drain(stdout);
    let stderr_buf = spawn_line_drain(stderr);

    let start = Instant::now();
    let addr = loop {
        if let Some(addr) = stdout_buf
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .lines()
            .find_map(|l| l.trim().strip_prefix("listening on http://"))
        {
            break addr.to_string();
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "clave serve did not print a listening line within 10s\nstdout={}\nstderr={}",
            stdout_buf.lock().unwrap_or_else(|e| e.into_inner()),
            stderr_buf.lock().unwrap_or_else(|e| e.into_inner())
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    (ChildGuard(child), addr, stderr_buf)
}

pub fn checkpoint_verifier_key(stdout: &str) -> String {
    stdout
        .lines()
        .find_map(|line| line.trim().strip_prefix("checkpoint verifier key: "))
        .unwrap_or_else(|| panic!("no checkpoint verifier key printed:\n{stdout}"))
        .to_string()
}

pub struct Aggregator {
    pub data: PathBuf,
    pub log_id: String,
    pub base_url: String,
    pub verifier_key: String,
    pub stderr: Arc<Mutex<String>>,
    child: Option<ChildGuard>,
}

impl Aggregator {
    pub fn stop(&mut self) {
        self.child = None;
    }

    pub fn start(&mut self, bin: &Path, proxy: Option<&str>) {
        assert!(
            self.child.is_none(),
            "clave serve is already running for {}",
            self.log_id
        );
        let (child, bound, stderr) = spawn_clave_serve_with(bin, &self.data, &self.log_id, proxy);
        assert_eq!(
            bound, self.log_id,
            "the restarted clave serve bound a different address"
        );
        self.stderr = stderr;
        self.child = Some(child);
    }
}

pub fn start_aggregator(
    bin: &Path,
    data: PathBuf,
    suffix_list: Option<&Path>,
    proxy: Option<&str>,
) -> Aggregator {
    let log_id = free_loopback_addr();
    let data_str = data.to_str().expect("non-utf8 path").to_string();
    let mut args = vec![
        "init".to_string(),
        "--log-id".to_string(),
        log_id.clone(),
        "--data".to_string(),
        data_str,
    ];
    if let Some(suffix_list) = suffix_list {
        args.push("--suffix-list".to_string());
        args.push(s(suffix_list).to_string());
    }
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = run(bin, &borrowed);
    let verifier_key = checkpoint_verifier_key(&String::from_utf8_lossy(&output.stdout));
    let (child, bound, stderr) = spawn_clave_serve_with(bin, &data, &log_id, proxy);
    assert_eq!(
        bound, log_id,
        "clave serve bound a different address than the pre-picked --log-id"
    );
    Aggregator {
        data,
        base_url: format!("http://{log_id}"),
        log_id,
        verifier_key,
        stderr,
        child: Some(child),
    }
}

pub fn free_loopback_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local_addr").to_string()
}

pub fn serve_static(dir: PathBuf) -> String {
    serve_static_counted(dir).0
}

pub fn serve_static_counted(dir: PathBuf) -> (String, Arc<AtomicU64>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind static fixture server");
    let addr = listener.local_addr().expect("local_addr").to_string();
    let requests = Arc::new(AtomicU64::new(0));
    let counter = requests.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let dir = dir.clone();
            counter.fetch_add(1, Ordering::Relaxed);
            std::thread::spawn(move || serve_one_request(stream, &dir));
        }
    });
    (addr, requests)
}

pub fn serve_sites(
    sites: std::collections::BTreeMap<String, PathBuf>,
) -> (String, std::collections::BTreeMap<String, Arc<AtomicU64>>) {
    let (addr, counters, _) = serve_sites_logged(sites);
    (addr, counters)
}

#[derive(Debug, Clone, Default)]
pub struct RequestLog(Arc<Mutex<Vec<LoggedRequest>>>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoggedRequest {
    pub host: String,
    pub path: String,
    pub octets: u64,
}

impl RequestLog {
    fn push(&self, host: &str, path: &str, octets: u64) {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(LoggedRequest {
                host: host.to_string(),
                path: path.to_string(),
                octets,
            });
    }

    pub fn clear(&self) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    pub fn paths(&self, host: &str) -> Vec<String> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|logged| logged.host == host)
            .map(|logged| logged.path.clone())
            .collect()
    }

    pub fn requests(&self) -> Vec<LoggedRequest> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

#[derive(Debug, Clone, Default)]
pub struct SiteCounters {
    pub requests: Arc<AtomicU64>,
    pub octets: Arc<AtomicU64>,
}

pub fn serve_sites_logged(
    sites: std::collections::BTreeMap<String, PathBuf>,
) -> (
    String,
    std::collections::BTreeMap<String, Arc<AtomicU64>>,
    RequestLog,
) {
    let (addr, counters, log) = serve_sites_counted(sites);
    let requests = counters
        .into_iter()
        .map(|(host, counters)| (host, counters.requests))
        .collect();
    (addr, requests, log)
}

pub fn serve_sites_counted(
    sites: std::collections::BTreeMap<String, PathBuf>,
) -> (
    String,
    std::collections::BTreeMap<String, SiteCounters>,
    RequestLog,
) {
    let log = RequestLog::default();
    let recorder = log.clone();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind site proxy");
    let addr = listener.local_addr().expect("local_addr").to_string();
    let counters: std::collections::BTreeMap<String, SiteCounters> = sites
        .keys()
        .map(|host| (host.clone(), SiteCounters::default()))
        .collect();
    let routes = Arc::new((sites, counters.clone()));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let routes = routes.clone();
            let recorder = recorder.clone();
            std::thread::spawn(move || {
                let Ok(clone) = stream.try_clone() else {
                    return;
                };
                let mut reader = BufReader::new(clone);
                let mut request_line = String::new();
                if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
                    return;
                }
                loop {
                    let mut header_line = String::new();
                    if reader.read_line(&mut header_line).unwrap_or(0) == 0
                        || header_line.trim().is_empty()
                    {
                        break;
                    }
                }
                let target = request_line.split_whitespace().nth(1).unwrap_or("/");
                let without_scheme = target.strip_prefix("http://").unwrap_or(target);
                let (host, path) = without_scheme
                    .split_once('/')
                    .map_or((without_scheme, ""), |(h, p)| (h, p));
                let rel = path.split('?').next().unwrap_or("");
                let (dirs, counters) = &*routes;
                match dirs.get(host) {
                    Some(dir) => {
                        let body = std::fs::read(dir.join(rel)).ok();
                        let octets = body.as_ref().map_or(0, |body| body.len() as u64);
                        counters[host].requests.fetch_add(1, Ordering::Relaxed);
                        counters[host].octets.fetch_add(octets, Ordering::Relaxed);
                        recorder.push(host, rel, octets);
                        respond_body(stream, body);
                    }
                    None => {
                        let _ = (&stream).write_all(
                            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        );
                    }
                }
            });
        }
    });
    (addr, counters, log)
}

fn respond_body(mut stream: TcpStream, body: Option<Vec<u8>>) {
    match body {
        Some(bytes) => {
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                bytes.len()
            );
            let _ = stream.write_all(header.as_bytes());
            let _ = stream.write_all(&bytes);
        }
        None => {
            let _ = stream.write_all(
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
        }
    }
}

pub fn serve_one_request(mut stream: TcpStream, dir: &Path) {
    let Ok(clone) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(clone);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
        return;
    }
    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .to_string();
    loop {
        let mut header_line = String::new();
        if reader.read_line(&mut header_line).unwrap_or(0) == 0 || header_line.trim().is_empty() {
            break;
        }
    }
    let path = path.strip_prefix("http://localhost").unwrap_or(&path);
    let rel = path
        .split('?')
        .next()
        .unwrap_or("/")
        .trim_start_matches('/');
    match std::fs::read(dir.join(rel)) {
        Ok(bytes) => {
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                bytes.len()
            );
            let _ = stream.write_all(header.as_bytes());
            let _ = stream.write_all(&bytes);
        }
        Err(_) => {
            let _ = stream.write_all(
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
        }
    }
}

/// [tlog-witness] and [tlog-cosignature] v1 (WIST-3 §5).
pub struct TestWitness {
    pub name: String,
    pub verifier_key: String,
    pub base_url: String,
}

pub fn spawn_witness(name: &str, seed: [u8; 32]) -> TestWitness {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    let key = wist_core::crypto::SigningKey::from_seed(&seed);
    let mut encoded = vec![wist_core::checkpoint::WITNESS_KEY_TYPE];
    encoded.extend_from_slice(&key.public().to_bytes());
    let verifier_key = format!(
        "{name}+{}+{}",
        wist_core::crypto::hex_encode(&wist_core::checkpoint::witness_key_id(name, &key.public())),
        STANDARD.encode(&encoded)
    );
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind witness");
    let addr = listener.local_addr().expect("local_addr").to_string();
    let owned = name.to_string();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let Ok(clone) = stream.try_clone() else {
                continue;
            };
            let mut reader = BufReader::new(clone);
            let mut request = String::new();
            if reader.read_line(&mut request).unwrap_or(0) == 0 {
                continue;
            }
            let mut length = 0usize;
            loop {
                let mut header = String::new();
                if reader.read_line(&mut header).unwrap_or(0) == 0 || header.trim().is_empty() {
                    break;
                }
                if let Some(value) = header.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0u8; length];
            if reader.read_exact(&mut body).is_err() {
                continue;
            }
            let body = String::from_utf8_lossy(&body).to_string();
            let Some((_, note)) = body.split_once("\n\n") else {
                let _ = stream.write_all(
                    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
                continue;
            };
            let Ok(checkpoint) = wist_core::checkpoint::Checkpoint::parse(note) else {
                let _ = stream.write_all(
                    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
                continue;
            };
            let line = wist_core::checkpoint::cosignature_line(
                &owned,
                &key,
                &checkpoint.note_text(),
                jiff::Timestamp::now().as_second().max(0) as u64,
            );
            let answer = format!("{}\n", line.encode());
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                answer.len()
            );
            let _ = stream.write_all(header.as_bytes());
            let _ = stream.write_all(answer.as_bytes());
        }
    });
    TestWitness {
        name: name.to_string(),
        verifier_key,
        base_url: format!("http://{addr}"),
    }
}

pub fn now_rfc3339() -> String {
    jiff::Timestamp::from_second(jiff::Timestamp::now().as_second())
        .expect("current second is in range")
        .to_string()
}

pub fn fetch_status(http: &reqwest::blocking::Client, base: &str, domain: &str) -> Option<Value> {
    let resp = http.get(format!("{base}/status/{domain}")).send().ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.json::<Value>().ok()
}

pub fn wait_until_unreachable(http: &reqwest::blocking::Client, base: &str, domain: &str) {
    poll_until(Duration::from_secs(10), Duration::from_millis(50), || {
        fetch_status(http, base, domain).is_none().then_some(())
    });
}

pub fn wait_until_status_active(
    http: &reqwest::blocking::Client,
    base: &str,
    domain: &str,
) -> Value {
    poll_until(Duration::from_secs(30), Duration::from_millis(100), || {
        fetch_status(http, base, domain).filter(|v| v["state"] == "active")
    })
}

/// A rejection the status endpoint keeps from an earlier Epoch never clears.
pub fn wait_until_pull_recorded(
    http: &reqwest::blocking::Client,
    base: &str,
    domain: &str,
    since: &str,
) -> Value {
    poll_until(Duration::from_secs(30), Duration::from_millis(100), || {
        fetch_status(http, base, domain)
            .filter(|v| v["last_pull_at"].as_str().is_some_and(|t| t >= since))
    })
}

pub fn wait_until_pulled_since(
    http: &reqwest::blocking::Client,
    base: &str,
    domain: &str,
    since: &str,
    child_stderr: &Arc<Mutex<String>>,
) -> Value {
    let mut last_status = None;
    let start = Instant::now();
    loop {
        let status = fetch_status(http, base, domain);
        if let Some(status) = status.as_ref().filter(|v| {
            v["rejections"]
                .as_array()
                .is_some_and(|rejections| rejections.is_empty())
                && v["last_pull_at"].as_str().is_some_and(|t| t >= since)
        }) {
            return status.clone();
        }
        last_status = status.or(last_status);
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "no clean pull of {domain} at {base} since {since} within 30s\nlast status={}\nclave serve stderr={}",
            last_status
                .as_ref()
                .map(|v| v.to_string())
                .unwrap_or_else(|| "none".into()),
            child_stderr.lock().unwrap_or_else(|e| e.into_inner())
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// WIST-3 §3.2: the accepted cadence grid, hourly by default.
pub fn grid_instant(hours_ahead: i64) -> String {
    let now = jiff::Timestamp::now().as_second();
    let next_hour = now.div_euclid(3600) * 3600 + 3600;
    jiff::Timestamp::from_second(next_hour + hours_ahead * 3600)
        .expect("grid instant is in range")
        .to_string()
}

pub struct McpClient {
    _child: ChildGuard,
    stdin: ChildStdin,
    reader: BufReader<ChildStdout>,
    stderr_buf: Arc<Mutex<String>>,
    next_id: u64,
}

impl McpClient {
    pub fn start(graven_bin: &Path, dir: &Path) -> Self {
        let dir_str = dir.to_str().expect("non-utf8 path").to_string();
        let mut child = Command::new(graven_bin)
            .args(["serve", "--dir", &dir_str])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("failed to spawn graven serve: {e}"));
        let stdin = child.stdin.take().expect("graven serve stdin piped");
        let stdout: ChildStdout = child.stdout.take().expect("graven serve stdout piped");
        let stderr: ChildStderr = child.stderr.take().expect("graven serve stderr piped");
        let stderr_buf = spawn_line_drain(stderr);
        let mut client = McpClient {
            _child: ChildGuard(child),
            stdin,
            reader: BufReader::new(stdout),
            stderr_buf,
            next_id: 1,
        };
        client.initialize();
        client
    }

    pub fn send(&mut self, value: &Value) {
        let mut line = serde_json::to_string(value).expect("serialize JSON-RPC message");
        line.push('\n');
        self.stdin
            .write_all(line.as_bytes())
            .expect("write to graven serve stdin");
        self.stdin.flush().expect("flush graven serve stdin");
    }

    pub fn recv_line(&mut self) -> Value {
        loop {
            let mut line = String::new();
            let n = self
                .reader
                .read_line(&mut line)
                .expect("read graven serve stdout");
            if n == 0 {
                panic!(
                    "graven serve closed stdout unexpectedly; stderr={}",
                    self.stderr_buf.lock().unwrap_or_else(|e| e.into_inner())
                );
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            return serde_json::from_str(trimmed)
                .unwrap_or_else(|e| panic!("bad JSON-RPC line {trimmed:?}: {e}"));
        }
    }

    pub fn call(&mut self, method: &str, params: Value) -> Value {
        self.try_call(method, params)
            .unwrap_or_else(|err| panic!("{method} returned JSON-RPC error: {err}"))
    }

    pub fn try_call(&mut self, method: &str, params: Value) -> Result<Value, Value> {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        loop {
            let resp = self.recv_line();
            if resp.get("id").and_then(Value::as_u64) != Some(id) {
                continue;
            }
            if let Some(err) = resp.get("error") {
                return Err(err.clone());
            }
            return Ok(resp["result"].clone());
        }
    }

    pub fn initialize(&mut self) {
        self.call(
            "initialize",
            json!({
                "protocolVersion": "2026-07-28",
                "capabilities": {},
                "clientInfo": {"name": "wist-e2e", "version": "0.1.0"},
            }),
        );
        self.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
    }

    pub fn tool_call(&mut self, name: &str, arguments: Value) -> Value {
        let result = self.call("tools/call", json!({"name": name, "arguments": arguments}));
        if let Some(structured) = result.get("structuredContent") {
            return structured.clone();
        }
        let text = result["content"][0]["text"].as_str().unwrap_or_else(|| {
            panic!("tool {name} result has neither structuredContent nor content[0].text: {result}")
        });
        serde_json::from_str(text).unwrap_or_else(|e| panic!("tool {name} content not JSON: {e}"))
    }

    pub fn search(&mut self, query: &str) -> Vec<Value> {
        self.tool_call("search", json!({"query": query}))
            .as_array()
            .cloned()
            .unwrap_or_default()
    }

    pub fn search_with_profile(&mut self, query: &str, profile: &str) -> Vec<Value> {
        self.tool_call("search", json!({"query": query, "profile": profile}))
            .as_array()
            .cloned()
            .unwrap_or_default()
    }

    pub fn get_record(&mut self, url: &str) -> Value {
        self.tool_call("get_record", json!({"url": url}))
    }

    pub fn get_record_error(&mut self, url: &str) -> Value {
        match self.try_call(
            "tools/call",
            json!({"name": "get_record", "arguments": {"url": url}}),
        ) {
            Err(err) => err,
            Ok(result) => panic!("get_record({url}) returned a record: {result}"),
        }
    }

    pub fn get_extract(&mut self, url: &str) -> Value {
        self.tool_call("get_extract", json!({"url": url}))
    }
}

pub fn marked_page(title: &str, body: &str, links: &[String]) -> String {
    let anchors: String = links
        .iter()
        .map(|link| format!("<p><a href=\"{link}\">{link}</a></p>"))
        .collect();
    format!(
        "<!doctype html><html lang=\"en\"><head><title>{title}</title><meta name=\"description\" content=\"{title}\"><meta name=\"wist\" content=\"publish\"></head><body><!--wist:content--><p>{body}</p>{anchors}<!--/wist:content--></body></html>"
    )
}

pub struct Site {
    pub host: String,
    pub collection: String,
    pub pages: PathBuf,
    pub out: PathBuf,
    pub state: PathBuf,
    pub stream: PathBuf,
}

impl Site {
    pub fn new(root: &Path, host: &str, collection: &str) -> Self {
        let site = Site {
            host: host.to_string(),
            collection: collection.to_string(),
            pages: root.join("pages").join(host),
            out: root.join("sites").join(host),
            state: root.join("state").join(host),
            stream: root.join("streams").join(format!("{host}.jsonl")),
        };
        std::fs::create_dir_all(&site.pages).expect("create the pages directory");
        std::fs::create_dir_all(root.join("streams")).expect("create the streams directory");
        std::fs::create_dir_all(&site.out).expect("create the output directory");
        site
    }

    pub fn url(&self, page: &str) -> String {
        format!("https://{}/{page}", self.host)
    }

    pub fn with_collection(&self, collection: &str) -> Site {
        Site {
            host: self.host.clone(),
            collection: collection.to_string(),
            pages: self.pages.clone(),
            out: self.out.clone(),
            state: self.state.clone(),
            stream: self.stream.clone(),
        }
    }

    pub fn write_page(&self, page: &str, html: &str) {
        let path = self.pages.join(page);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create the page's directory");
        }
        std::fs::write(path, html).expect("write a page");
    }

    pub fn remove_page(&self, page: &str) {
        std::fs::remove_file(self.pages.join(page)).expect("remove a page");
    }

    pub fn declaration(&self) -> Value {
        read_json(&self.out.join(".well-known/wist/publisher.json"))
    }

    pub fn init(&self, spake: &Path) {
        run(
            spake,
            &[
                "init",
                "--domain",
                &self.host,
                "--out",
                s(&self.out),
                "--state",
                s(&self.state),
            ],
        );
        self.sign_due(spake);
    }

    pub fn add_collection(&self, spake: &Path) {
        run(
            spake,
            &[
                "collection",
                "add",
                "--out",
                s(&self.out),
                "--state",
                s(&self.state),
                "--name",
                &self.collection,
                "--prefix",
                &format!("https://{}/", self.host),
                "--confirm",
            ],
        );
    }

    pub fn publish(&self, spake: &Path) -> std::process::Output {
        self.publish_with(spake, run)
    }

    pub fn publish_in_fresh_env(&self, spake: &Path) -> std::process::Output {
        self.publish_with(spake, |bin, args| run_in_fresh_env(bin, args, &[]))
    }

    fn publish_with(
        &self,
        spake: &Path,
        runner: impl Fn(&Path, &[&str]) -> std::process::Output,
    ) -> std::process::Output {
        let base_url = format!("https://{}/", self.host);
        runner(
            spake,
            &[
                "emit",
                "--out",
                s(&self.out),
                "--state",
                s(&self.state),
                "--collection",
                &self.collection,
                "--dir",
                s(&self.pages),
                "--base-url",
                &base_url,
                "--complete",
                "--output",
                s(&self.stream),
            ],
        );
        runner(
            spake,
            &[
                "publish",
                "--out",
                s(&self.out),
                "--state",
                s(&self.state),
                "--collection",
                &self.collection,
                "--stream",
                s(&self.stream),
                "--allow-added",
            ],
        )
    }

    pub fn sign_due(&self, spake: &Path) -> std::process::Output {
        run(
            spake,
            &["publish", "--out", s(&self.out), "--state", s(&self.state)],
        )
    }

    pub fn catalog(&self) -> Value {
        read_json(
            &self
                .out
                .join(".well-known/wist/collections")
                .join(&self.collection)
                .join("catalog.json"),
        )
    }

    pub fn served_item(&self, url: &str) -> Value {
        let catalog = self.catalog();
        let tree = catalog["catalog"]["tree"]
            .as_str()
            .and_then(|tree| tree.strip_prefix("sha256:"))
            .unwrap_or_else(|| panic!("the served Catalog names no tree file: {catalog}"))
            .to_string();
        self.find_item(&tree, url).unwrap_or_else(|| {
            panic!(
                "the served tree of {} lists no Item for {url}",
                self.collection
            )
        })
    }

    fn find_item(&self, tree: &str, url: &str) -> Option<Value> {
        let file = read_json(
            &self
                .out
                .join(".well-known/wist/collections")
                .join(&self.collection)
                .join("tree")
                .join(tree),
        );
        if let Some(items) = file["items"].as_array() {
            return items.iter().find(|item| item["url"] == url).cloned();
        }
        file["children"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|child| child["file"].as_str())
            .filter_map(|file| file.strip_prefix("sha256:"))
            .find_map(|child| self.find_item(child, url))
    }

    pub fn item_id(&self, url: &str) -> String {
        wist_core::item::item_id(&self.served_item(url)).expect("compute the Item ID")
    }

    pub fn ping_and_wait(
        &self,
        spake: &Path,
        http: &reqwest::blocking::Client,
        aggregator: &Aggregator,
    ) -> Value {
        self.ping_and_wait_allowing(spake, http, aggregator, &[])
    }

    pub fn ping_and_wait_allowing(
        &self,
        spake: &Path,
        http: &reqwest::blocking::Client,
        aggregator: &Aggregator,
        allowed: &[(&str, &str)],
    ) -> Value {
        let previous = fetch_status(http, &aggregator.base_url, &self.host)
            .and_then(|status| status["last_pull_at"].as_str().map(str::to_string));
        let since = poll_until(Duration::from_secs(5), Duration::from_millis(50), || {
            let now = now_rfc3339();
            previous
                .as_ref()
                .is_none_or(|previous| now > *previous)
                .then_some(now)
        });
        self.ping(spake, &aggregator.base_url);
        let status = wait_until_pull_recorded(http, &aggregator.base_url, &self.host, &since);
        let unexpected: Vec<&Value> = status["rejections"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|rejection| {
                !allowed
                    .iter()
                    .any(|(code, id)| rejection["code"] == *code && rejection["id"] == *id)
            })
            .collect();
        assert!(
            unexpected.is_empty(),
            "the pull of {} at {} since {since} left rejections {unexpected:?}\nstatus={status}\nclave serve stderr={}",
            self.host,
            aggregator.base_url,
            aggregator.stderr.lock().unwrap_or_else(|e| e.into_inner())
        );
        status
    }

    pub fn collection_command(&self, spake: &Path, command: &str, args: &[&str]) -> String {
        let mut full = vec![
            "collection",
            command,
            "--out",
            s(&self.out),
            "--state",
            s(&self.state),
        ];
        full.extend_from_slice(args);
        String::from_utf8_lossy(&run(spake, &full).stdout).to_string()
    }

    pub fn emit_from(&self, spake: &Path, dir: &Path, base_url: &str, complete: bool) {
        let mut args = vec![
            "emit",
            "--out",
            s(&self.out),
            "--state",
            s(&self.state),
            "--collection",
            &self.collection,
            "--dir",
            s(dir),
            "--base-url",
            base_url,
            "--output",
            s(&self.stream),
        ];
        if complete {
            args.push("--complete");
        }
        run(spake, &args);
    }

    pub fn write_stream(&self, mode: &str, lines: &[Value]) {
        let mut stream = json!({
            "wist_emission": "1",
            "publisher": self.host,
            "collection": self.collection,
            "mode": mode,
        })
        .to_string();
        for line in lines {
            stream.push('\n');
            stream.push_str(&line.to_string());
        }
        stream.push('\n');
        stream.push_str(&json!({"end": true, "count": lines.len()}).to_string());
        stream.push('\n');
        std::fs::write(&self.stream, stream).expect("write the Emission stream");
    }

    pub fn apply_stream(&self, spake: &Path) -> String {
        let output = run(
            spake,
            &[
                "publish",
                "--out",
                s(&self.out),
                "--state",
                s(&self.state),
                "--collection",
                &self.collection,
                "--stream",
                s(&self.stream),
            ],
        );
        String::from_utf8_lossy(&output.stdout).to_string()
    }

    pub fn collection_dir(&self) -> PathBuf {
        self.out
            .join(".well-known/wist/collections")
            .join(&self.collection)
    }

    pub fn declared_collection(&self) -> Value {
        let declaration = self.declaration();
        declaration["publisher"]["collections"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|collection| collection["name"] == self.collection.as_str())
            .cloned()
            .unwrap_or_else(|| {
                panic!(
                    "the served Declaration names no Collection {}: {declaration}",
                    self.collection
                )
            })
    }

    pub fn collection_key_ids(&self) -> Vec<String> {
        self.declared_collection()["keys"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|key| key["kid"].as_str().map(str::to_string))
            .collect()
    }

    pub fn owner_key_ids(&self) -> Vec<String> {
        self.declaration()["publisher"]["keys"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|key| key["kid"].as_str().map(str::to_string))
            .collect()
    }

    pub fn signing_key(&self, kid: &str) -> wist_core::crypto::SigningKey {
        let path = self.state.join(format!("seed-{kid}"));
        let seed: [u8; 32] = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
            .try_into()
            .unwrap_or_else(|_| panic!("{} is not a 32-octet seed", path.display()));
        wist_core::crypto::SigningKey::from_seed(&seed)
    }

    pub fn served_list(&self) -> Vec<Value> {
        let catalog: wist_core::objects::Catalog =
            serde_json::from_value(self.catalog()["catalog"].clone())
                .expect("the served Catalog has the Catalog form");
        let tree = self.collection_dir().join("tree");
        match wist_core::tree::walk(&catalog, &wist_core::tree::TreeBounds::suite(), |hex| {
            match std::fs::read(tree.join(hex)) {
                Ok(octets) => wist_core::tree::TreeFetch::Octets(octets),
                Err(_) => wist_core::tree::TreeFetch::Failed,
            }
        }) {
            wist_core::tree::Walk::Listed(list) => list,
            other => panic!(
                "the served tree of {} does not walk: {other:?}",
                self.collection
            ),
        }
    }

    pub fn serve_payload_as(&self, served: &Value, item: &Value) {
        let payloads = self.collection_dir().join("payloads");
        let name = |item: &Value| {
            format!(
                "{}.json",
                wist_core::item::payload_name(item).expect("an Item has a Payload name")
            )
        };
        std::fs::copy(payloads.join(name(served)), payloads.join(name(item)))
            .expect("serve the Payload under the new Item");
    }

    pub fn serve_catalog(
        &self,
        list: &[Value],
        generated_at: &str,
        key_id: &str,
        key: &wist_core::crypto::SigningKey,
    ) -> Value {
        let built = wist_core::tree::build(list, &wist_core::tree::TreeBounds::suite())
            .expect("build the tree files");
        self.serve_catalog_with_tree(list, &built, generated_at, key_id, key)
    }

    pub fn serve_catalog_with_tree(
        &self,
        list: &[Value],
        built: &wist_core::tree::Built,
        generated_at: &str,
        key_id: &str,
        key: &wist_core::crypto::SigningKey,
    ) -> Value {
        let served = self.catalog();
        let served_list = self.served_list();
        let dir = self.collection_dir();
        std::fs::create_dir_all(dir.join("tree")).expect("create the tree directory");
        for (hex, octets) in &built.files {
            std::fs::write(dir.join("tree").join(hex), octets).expect("write a tree file");
        }
        let root = wist_core::item::root(list).expect("compute the root");
        let inner = json!({
            "wist_version": served["catalog"]["wist_version"],
            "publisher": self.host,
            "collection": self.collection,
            "generated_at": generated_at,
            "size": list.len(),
            "root": format!("sha256:{}", wist_core::crypto::hex_encode(&root)),
            "tree": built.tree,
        });
        let envelope = wist_core::envelope::sign_envelope(&inner, "catalog", key_id, key)
            .expect("sign the Catalog");
        let served_catalog: wist_core::objects::Catalog =
            serde_json::from_value(served["catalog"].clone()).expect("the served Catalog form");
        let new_catalog: wist_core::objects::Catalog =
            serde_json::from_value(inner).expect("the built Catalog form");
        if let Some(written) = wist_core::change_list::write(
            Some(wist_core::change_list::Listed {
                catalog: &served_catalog,
                list: &served_list,
            }),
            wist_core::change_list::Listed {
                catalog: &new_catalog,
                list,
            },
        )
        .expect("write the change list")
        {
            std::fs::create_dir_all(dir.join("changes")).expect("create the changes directory");
            std::fs::write(
                dir.join("changes").join(format!("{}.json", written.name)),
                written.octets,
            )
            .expect("write the change list");
        }
        std::fs::write(
            dir.join("catalog.json"),
            serde_json::to_vec(&envelope).expect("serialize the Catalog"),
        )
        .expect("serve the Catalog");
        envelope
    }

    pub fn ping(&self, spake: &Path, log_base: &str) {
        run(
            spake,
            &[
                "ping",
                "--log",
                log_base,
                "--domain",
                &self.host,
                "--allow-http",
                "--no-retry",
            ],
        );
    }
}

pub fn wait_until_after(instant: &str) {
    poll_until(Duration::from_secs(5), Duration::from_millis(50), || {
        (now_rfc3339().as_str() > instant).then_some(())
    });
}

fn fetch_ok(http: &reqwest::blocking::Client, url: &str) -> Vec<u8> {
    let response = http
        .get(url)
        .send()
        .unwrap_or_else(|e| panic!("GET {url}: {e}"));
    assert!(
        response.status().is_success(),
        "GET {url} answered {}",
        response.status()
    );
    response
        .bytes()
        .unwrap_or_else(|e| panic!("read the body of {url}: {e}"))
        .to_vec()
}

pub fn epoch_tree_size(http: &reqwest::blocking::Client, base: &str, epoch: u64) -> u64 {
    let note = fetch_ok(
        http,
        &format!("{base}{}", wist_core::checkpoint::archive_path(epoch)),
    );
    wist_core::checkpoint::Checkpoint::parse(&String::from_utf8_lossy(&note))
        .unwrap_or_else(|e| panic!("parse the Checkpoint of Epoch {epoch}: {e}"))
        .tree_size()
}

pub fn sealed_entries(
    http: &reqwest::blocking::Client,
    base: &str,
    from: u64,
    to: u64,
) -> Vec<Value> {
    let mut entries = Vec::new();
    for bundle in wist_core::tiles::entry_bundles_for_range(from, to, to) {
        let path = bundle.path();
        let leaves = wist_core::tiles::decode_entry_bundle_at(
            &path,
            &fetch_ok(http, &format!("{base}{path}")),
        )
        .unwrap_or_else(|e| panic!("decode the entry bundle {path}: {e}"));
        let (start, _) = bundle.leaf_range();
        for (offset, leaf) in leaves.iter().enumerate() {
            let index = start + offset as u64;
            if (from..to).contains(&index) {
                entries.push(
                    serde_json::from_slice(leaf)
                        .unwrap_or_else(|e| panic!("parse the Entry at leaf {index}: {e}")),
                );
            }
        }
    }
    entries
}

pub fn epoch_entries(http: &reqwest::blocking::Client, base: &str, epoch: u64) -> Vec<Value> {
    let from = match epoch.checked_sub(1) {
        Some(previous) => epoch_tree_size(http, base, previous),
        None => 0,
    };
    sealed_entries(http, base, from, epoch_tree_size(http, base, epoch))
}

pub fn log_entries(http: &reqwest::blocking::Client, base: &str, epoch: u64) -> Vec<Value> {
    sealed_entries(http, base, 0, epoch_tree_size(http, base, epoch))
}

pub fn head_snapshot_state(clave_data: &Path) -> (u64, Vec<Value>) {
    let index = read_json(&clave_data.join("snapshots/index.json"));
    let head = index["index"]["snapshots"]
        .as_array()
        .into_iter()
        .flatten()
        .max_by_key(|snapshot| snapshot["tree_size"].as_u64())
        .unwrap_or_else(|| panic!("no Snapshot in {index}"));
    let manifest_path = clave_data.join(
        head["manifest_url"]
            .as_str()
            .expect("manifest_url")
            .trim_start_matches('/'),
    );
    let manifest = read_json(&manifest_path);
    let state = read_json(
        &manifest_path
            .parent()
            .expect("the manifest has a directory")
            .join(
                manifest["manifest"]["state"]["path"]
                    .as_str()
                    .expect("state path"),
            ),
    );
    let epoch = manifest["manifest"]["epoch_number"]
        .as_u64()
        .unwrap_or_else(|| panic!("the Snapshot manifest states no epoch_number: {manifest}"));
    (
        epoch,
        state["state"]["entries"]
            .as_array()
            .expect("state entries")
            .clone(),
    )
}

pub fn read_json(path: &Path) -> Value {
    serde_json::from_slice(
        &std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display())),
    )
    .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_served_item_is_found_through_inner_tree_nodes() {
        let root = tempfile::tempdir().expect("tempdir");
        let site = Site::new(root.path(), "example.localhost", "docs");
        let tree = site.out.join(".well-known/wist/collections/docs/tree");
        std::fs::create_dir_all(&tree).expect("tree directory");
        let wanted = json!({"url": "https://example.localhost/b.html", "observed_at": "2026-01-01T00:00:00Z"});
        let bucket = json!({"items": [{"url": "https://example.localhost/a.html"}, wanted]});
        let other = json!({"items": [{"url": "https://example.localhost/c.html"}]});
        std::fs::write(tree.join("bb"), bucket.to_string()).expect("bucket");
        std::fs::write(tree.join("cc"), other.to_string()).expect("bucket");
        let node = json!({"children": [
            {"prefix": "0", "count": 1, "file": "sha256:cc"},
            {"prefix": "1", "count": 2, "file": "sha256:bb"},
        ]});
        std::fs::write(tree.join("aa"), node.to_string()).expect("node");
        std::fs::write(
            tree.parent()
                .expect("collection directory")
                .join("catalog.json"),
            json!({"catalog": {"tree": "sha256:aa"}}).to_string(),
        )
        .expect("catalog");
        assert_eq!(site.served_item("https://example.localhost/b.html"), wanted);
        assert_eq!(
            site.item_id("https://example.localhost/b.html"),
            wist_core::item::item_id(&wanted).expect("Item ID")
        );
    }
}
