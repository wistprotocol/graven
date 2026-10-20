use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
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

    pub fn pid(&self) -> Option<u32> {
        self.child.as_ref().map(|child| child.0.id())
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
    pub delays: Arc<AtomicU64>,
    pub failures: Arc<AtomicU64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    Unavailable,
    Hang(Duration),
    Close,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HostBehavior {
    pub delay: Option<Duration>,
    pub failure: Option<Failure>,
}

#[derive(Debug, Clone, Default)]
pub struct Behaviors(Arc<Mutex<BTreeMap<String, HostBehavior>>>);

impl Behaviors {
    pub fn set(&self, host: &str, behavior: HostBehavior) {
        let mut map = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if behavior == HostBehavior::default() {
            map.remove(host);
        } else {
            map.insert(host.to_string(), behavior);
        }
    }

    pub fn clear(&self) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    pub fn get(&self, host: &str) -> HostBehavior {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(host)
            .copied()
            .unwrap_or_default()
    }
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
    let (addr, counters, log, _) = serve_sites_with_behaviors(sites);
    (addr, counters, log)
}

pub fn serve_sites_with_behaviors(
    sites: std::collections::BTreeMap<String, PathBuf>,
) -> (
    String,
    std::collections::BTreeMap<String, SiteCounters>,
    RequestLog,
    Behaviors,
) {
    let behaviors = Behaviors::default();
    let injected = behaviors.clone();
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
            let injected = injected.clone();
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
                        let behavior = injected.get(host);
                        if let Some(delay) = behavior.delay {
                            counters[host].delays.fetch_add(1, Ordering::Relaxed);
                            std::thread::sleep(delay);
                        }
                        if let Some(failure) = behavior.failure {
                            counters[host].failures.fetch_add(1, Ordering::Relaxed);
                            counters[host].requests.fetch_add(1, Ordering::Relaxed);
                            recorder.push(host, rel, 0);
                            inject(stream, failure);
                            return;
                        }
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
    (addr, counters, log, behaviors)
}

fn inject(mut stream: TcpStream, failure: Failure) {
    match failure {
        Failure::Unavailable => {
            let _ = stream.write_all(
                b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
        }
        Failure::Hang(duration) => std::thread::sleep(duration),
        Failure::Close => {}
    }
    let _ = stream.shutdown(std::net::Shutdown::Both);
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

pub fn words(seed: u64, count: usize) -> String {
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

pub fn page(host: &str, j: usize, body_words: usize, revision: u64) -> String {
    format!(
        "<html lang=\"en\"><head><title>Page {j} of {host}</title><meta name=\"wist\" content=\"publish\"></head><body><!--wist:content--><h1>Page {j}</h1><p>{}</p><!--/wist:content--></body></html>",
        words(revision * 1_000_003 + j as u64, body_words)
    )
}

pub fn write_pages(site: &Site, pages: usize, body_words: usize, revision: u64) {
    for j in 0..pages {
        site.write_page(
            &format!("p{j}.html"),
            &page(&site.host, j, body_words, revision),
        );
    }
}

pub fn dir_bytes(path: &Path) -> u64 {
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

pub fn git_revision(repo: &Path) -> String {
    Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(repo)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".into())
}

pub fn revisions() -> Value {
    let siblings = workspace_root()
        .parent()
        .expect("graven repo has a parent directory")
        .to_path_buf();
    json!({
        "spake": git_revision(&siblings.join("spake")),
        "clave": git_revision(&siblings.join("clave")),
        "graven": git_revision(&siblings.join("graven")),
        "core": git_revision(&siblings.join("core")),
        "spec": git_revision(&siblings.join("spec")),
    })
}

pub fn timed<T>(f: impl FnOnce() -> T) -> (T, f64) {
    let start = Instant::now();
    let value = f();
    (value, start.elapsed().as_secs_f64())
}

pub struct Measured {
    pub seconds: f64,
    pub peak_rss_kb: Option<u64>,
    pub stdout: String,
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

pub fn run_measured(bin: &Path, args: &[&str]) -> Measured {
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

pub fn reported_seconds(stdout: &str, prefix: &str) -> Option<f64> {
    stdout.lines().find_map(|line| {
        line.trim()
            .strip_prefix(prefix)?
            .strip_suffix(" ms")?
            .parse::<f64>()
            .ok()
            .map(|ms| ms / 1000.0)
    })
}

pub const WRITE_LOCK_HELD: &str = "write lock held ";

pub const WRITE_LOCK_WAITED: &str = "write lock waited ";

pub fn seal_phases(stdout: &str) -> Option<Value> {
    stdout.lines().find_map(|line| {
        let phases: Value = serde_json::from_str(line.trim().strip_prefix("seal phases ")?).ok()?;
        phases.is_object().then_some(phases)
    })
}

pub fn fold_seal_phases_max(max: &mut Value, phases: &Value) {
    let Some(phases) = phases.as_object() else {
        return;
    };
    if !max.is_object() {
        *max = json!({});
    }
    let max = max.as_object_mut().expect("the maximum is an object");
    for (name, phase) in phases {
        let entry = max.entry(name.clone()).or_insert_with(|| json!({}));
        for field in ["ms", "sqlite_ms", "hwm_kb"] {
            if let Some(ms) = phase[field].as_u64() {
                let largest = entry[field].as_u64().map_or(ms, |seen| seen.max(ms));
                entry[field] = json!(largest);
            }
        }
    }
}

pub fn reported_replans(stdout: &str) -> u64 {
    stdout
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("replanned ")?
                .strip_suffix(" times")?
                .parse()
                .ok()
        })
        .unwrap_or(0)
}

pub fn reported_conflicts(stdout: &str) -> Vec<Vec<String>> {
    stdout
        .lines()
        .filter_map(|line| line.trim().strip_prefix("plan conflict: "))
        .map(|changed| changed.split(", ").map(str::to_owned).collect())
        .collect()
}

pub fn reported_merged(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .filter_map(|line| line.trim().strip_prefix("plan merged: "))
        .flat_map(|merged| merged.split(", ").map(str::to_owned))
        .collect()
}

pub fn longest_reported_millis(text: &str, prefix: &str) -> Option<u64> {
    text.lines()
        .filter_map(|line| {
            line.trim()
                .strip_prefix(prefix)?
                .strip_suffix(" ms")?
                .parse()
                .ok()
        })
        .max()
}

pub struct AppendedText {
    buffer: Arc<Mutex<String>>,
    read: usize,
}

impl AppendedText {
    pub fn new(buffer: &Arc<Mutex<String>>) -> Self {
        AppendedText {
            buffer: buffer.clone(),
            read: 0,
        }
    }

    pub fn follow(&mut self, buffer: &Arc<Mutex<String>>) -> String {
        let mut appended = self.take();
        if !Arc::ptr_eq(&self.buffer, buffer) {
            *self = AppendedText::new(buffer);
            appended.push_str(&self.take());
        }
        appended
    }

    fn take(&mut self) -> String {
        let text = self.buffer.lock().unwrap_or_else(|e| e.into_inner());
        let appended = text[self.read..].to_string();
        self.read = text.len();
        appended
    }
}

pub fn reported_count(stdout: &str, prefix: &str) -> Option<u64> {
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

pub fn snapshot_report(run: &Measured) -> Value {
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

pub struct SealStage {
    pub seal: Measured,
    pub snapshot: Measured,
    pub rebuild: Option<Measured>,
}

impl SealStage {
    pub fn run(clave: &Path, data: &Path, at: &str, compare_rebuild: bool) -> Self {
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

    pub fn seal_seconds(&self) -> Option<f64> {
        reported_seconds(&self.seal.stdout, "seal took ")
    }

    pub fn rebuild_report(&self) -> Value {
        self.rebuild.as_ref().map_or(Value::Null, snapshot_report)
    }

    pub fn report(&self, data: &Path) -> Value {
        let mut report = json!({
            "seconds": self.seal.seconds + self.snapshot.seconds,
            "seal_seconds": self.seal_seconds(),
            "seal_peak_rss_kb": self.seal.peak_rss_kb,
            "replanned": reported_replans(&self.seal.stdout),
            "replan_conflicts": reported_conflicts(&self.seal.stdout),
            "merged_publishers": reported_merged(&self.seal.stdout).len(),
            "seal_phases": seal_phases(&self.seal.stdout),
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

pub fn storage_bytes(data: &Path) -> Value {
    json!({
        "sqlite_bytes": dir_bytes(&data.join("clave.sqlite")),
        "sqlite_wal_bytes": dir_bytes(&data.join("clave.sqlite-wal")),
        "snapshots_bytes": dir_bytes(&data.join("snapshots")),
        "snapshot_shards_bytes": dir_bytes(&data.join("snapshot-shards")),
        "snapshot_build_bytes": dir_bytes(&data.join("snapshot-build")),
    })
}

pub fn merge(into: &mut Value, from: Value) {
    let (Value::Object(into), Value::Object(from)) = (into, from) else {
        panic!("merge expects two JSON objects");
    };
    into.extend(from);
}

// WIST-2 §5.3: a chain the Aggregator discards or cannot read is reported and the list is walked.
pub const PULL_REPORTS_ALLOWED: &[&str] = &["WIST2-E08"];

pub fn pulled_within(
    http: &reqwest::blocking::Client,
    base: &str,
    hosts: &[String],
    since: &str,
    timeout: Duration,
) -> BTreeMap<String, f64> {
    let since: BTreeMap<String, String> = hosts
        .iter()
        .map(|host| (host.clone(), since.to_string()))
        .collect();
    pulled_each_since(http, base, &since, timeout)
}

pub fn pulled_each_since(
    http: &reqwest::blocking::Client,
    base: &str,
    since: &BTreeMap<String, String>,
    timeout: Duration,
) -> BTreeMap<String, f64> {
    let start = Instant::now();
    let mut pulled = BTreeMap::new();
    let mut pending: Vec<(&String, &String)> = since.iter().collect();
    loop {
        pending.retain(|(host, since)| {
            let done = fetch_status(http, base, host).is_some_and(|v| {
                v["rejections"].as_array().is_some_and(|r| {
                    r.iter().all(|rejection| {
                        PULL_REPORTS_ALLOWED.contains(&rejection["code"].as_str().unwrap_or(""))
                    })
                }) && v["last_pull_at"]
                    .as_str()
                    .is_some_and(|t| t > since.as_str())
            });
            if done {
                pulled.insert((*host).clone(), start.elapsed().as_secs_f64());
            }
            !done
        });
        if pending.is_empty() || start.elapsed() >= timeout {
            return pulled;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

pub fn wait_all_pulled(
    http: &reqwest::blocking::Client,
    base: &str,
    hosts: &[String],
    since: &str,
    timeout: Duration,
) -> BTreeMap<String, f64> {
    let pulled = pulled_within(http, base, hosts, since, timeout);
    assert!(
        pulled.len() == hosts.len(),
        "{} of {} domains were not pulled cleanly within {timeout:?}",
        hosts.len() - pulled.len(),
        hosts.len()
    );
    pulled
}

pub fn reports_since(
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

pub fn request_kind(path: &str) -> &'static str {
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

pub fn requests_report(requests: &[LoggedRequest], hosts: &[String], items: usize) -> Value {
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

pub fn round_report(
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

pub fn reset_peak_rss(pid: u32) {
    // Linux: writing 5 to clear_refs resets the process's peak resident set size (VmHWM).
    std::fs::write(format!("/proc/{pid}/clear_refs"), "5")
        .unwrap_or_else(|e| panic!("reset the peak resident set size of {pid}: {e}"));
}

pub fn peak_rss_kb(pid: u32) -> Option<u64> {
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

pub fn log_tree_size(data: &Path) -> u64 {
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

pub fn entry_leaves(data: &Path, from: u64, to: u64) -> Vec<Vec<u8>> {
    let mut leaves = Vec::new();
    for bundle in wist_core::tiles::entry_bundles_for_range(from, to, to) {
        let path = bundle.path();
        let file = data.join(path.trim_start_matches('/'));
        let octets =
            std::fs::read(&file).unwrap_or_else(|e| panic!("read {}: {e}", file.display()));
        let decoded = wist_core::tiles::decode_entry_bundle_at(&path, &octets)
            .unwrap_or_else(|e| panic!("decode the entry bundle {path}: {e}"));
        let (start, _) = bundle.leaf_range();
        leaves.extend(
            decoded
                .into_iter()
                .enumerate()
                .filter(|(offset, _)| (from..to).contains(&(start + *offset as u64)))
                .map(|(_, leaf)| leaf),
        );
    }
    leaves
}

pub fn log_entries_report(data: &Path, from: u64, to: u64) -> Value {
    let mut by_type: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for leaf in entry_leaves(data, from, to) {
        let entry_type = serde_json::from_slice::<Value>(&leaf)
            .ok()
            .and_then(|entry| entry["type"].as_str().map(str::to_string))
            .unwrap_or_else(|| "unparsed".into());
        let counted = by_type.entry(entry_type).or_default();
        counted.0 += 1;
        counted.1 += leaf.len() as u64;
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

pub fn sealed_stage(
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

pub fn after_this_second() -> String {
    let since = now_rfc3339();
    while now_rfc3339() == since {
        std::thread::sleep(Duration::from_millis(50));
    }
    since
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PingOutcome {
    Admitted,
    Refused(String),
    Failed(String),
}

pub fn ping_once(spake: &Path, clave_base: &str, host: &str) -> PingOutcome {
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
        return PingOutcome::Admitted;
    }
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if stderr.contains("503") {
        PingOutcome::Refused(stderr)
    } else {
        PingOutcome::Failed(stderr)
    }
}

pub fn retry_after_seconds(message: &str) -> Option<u64> {
    let lower = message.to_ascii_lowercase();
    let (_, rest) = lower.split_once("retry-after")?;
    let digits: String = rest
        .trim_start_matches(|c: char| !c.is_ascii_digit())
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

// WIST-2 §4: a refused Ping is retried after its Retry-After.
pub fn ping_until_admitted(spake: &Path, clave_base: &str, host: &str) -> u64 {
    let deadline = Instant::now() + Duration::from_secs(600);
    let mut refused = 0;
    loop {
        let stderr = match ping_once(spake, clave_base, host) {
            PingOutcome::Admitted => return refused,
            PingOutcome::Refused(stderr) => stderr,
            PingOutcome::Failed(stderr) => panic!("ping {host} failed: {stderr}"),
        };
        assert!(Instant::now() < deadline, "ping {host} failed: {stderr}");
        refused += 1;
        std::thread::sleep(
            retry_after_seconds(&stderr).map_or(Duration::from_millis(250), Duration::from_secs),
        );
    }
}

pub fn write_changed_pages(site: &Site, changed: &[usize], body_words: usize, revision: u64) {
    for &j in changed {
        site.write_page(
            &format!("p{j}.html"),
            &page(&site.host, j, body_words, revision),
        );
    }
}

pub fn host_name(i: usize) -> String {
    format!("127.0.{}.{}", 1 + i / 250, 1 + i % 250)
}

pub fn sync_args<'a>(anchor: &'a Path, log: &'a str, dir: &'a Path, tier1: bool) -> Vec<&'a str> {
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
    args.extend(payload_fetches_args());
    args
}

pub fn registered_sync_args(dir: &Path) -> Vec<&str> {
    let mut args = vec!["sync", "--dir", s(dir), "--allow-http"];
    args.extend(payload_fetches_args());
    args
}

pub fn payload_fetches_args() -> Vec<&'static str> {
    static FETCHES: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    fetches_flag(
        FETCHES
            .get_or_init(|| std::env::var("WIST_PAYLOAD_FETCHES").ok())
            .as_deref(),
    )
}

fn fetches_flag(fetches: Option<&str>) -> Vec<&str> {
    match fetches {
        Some(fetches) => vec!["--payload-fetches", fetches],
        None => Vec::new(),
    }
}

pub fn consumer_report(run: &Measured, dir: &Path) -> Value {
    json!({
        "seconds": run.seconds,
        "peak_rss_kb": run.peak_rss_kb,
        "store_bytes": dir_bytes(dir),
    })
}

pub fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap_or_else(|e| panic!("create {}: {e}", to.display()));
    for entry in std::fs::read_dir(from).unwrap_or_else(|e| panic!("read {}: {e}", from.display()))
    {
        let entry = entry.expect("directory entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target)
                .unwrap_or_else(|e| panic!("copy {}: {e}", entry.path().display()));
        }
    }
}

pub fn consumer_state(dir: &Path) -> graven::sync::SyncState {
    let logs: Vec<PathBuf> = std::fs::read_dir(dir.join("logs"))
        .expect("the consumer's store holds a logs directory")
        .map(|entry| entry.expect("directory entry").path().join("index.sqlite"))
        .filter(|index| index.is_file())
        .collect();
    let [index] = logs.as_slice() else {
        panic!("the consumer's store follows {} logs, not one", logs.len());
    };
    let conn =
        rusqlite::Connection::open_with_flags(index, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open the consumer's index");
    graven::sync::load_sync_state(&conn)
        .expect("read the consumer's sync state")
        .expect("the consumer's index holds a sync state")
}

pub struct LogKey {
    pub key_id: String,
    pub note_key_id: String,
    pub added: Option<u64>,
    pub removed: Option<u64>,
}

pub fn log_keys(clave: &Path, data: &Path) -> Vec<LogKey> {
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

pub fn label_command(spake: &Path, labeler: &Site, args: &[&str]) -> String {
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

pub fn change_parameter(
    clave: &Path,
    aggregator: &Aggregator,
    parameter: &str,
    value: i64,
    at: &str,
) {
    run(
        clave,
        &[
            "param-change",
            "--data",
            s(&aggregator.data),
            "--parameter",
            parameter,
            "--value",
            &value.to_string(),
            "--effective-at",
            at,
        ],
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn longest_reported_millis_reads_the_seal_stdout_figure() {
        let stdout =
            "sealed epoch 3 at 2026-01-01T01:00:00Z\nseal took 12 ms\nwrite lock held 7 ms\n";
        assert_eq!(longest_reported_millis(stdout, WRITE_LOCK_HELD), Some(7));
    }

    #[test]
    fn longest_reported_millis_takes_the_largest_serve_line() {
        let stderr =
            "write lock held 3 ms\npull of a.localhost failed: timeout\nwrite lock held 41 ms\n";
        assert_eq!(longest_reported_millis(stderr, WRITE_LOCK_HELD), Some(41));
    }

    #[test]
    fn longest_reported_millis_is_absent_without_a_figure() {
        let text = "pull of a.localhost failed: timeout\nwrite lock held soon ms\n";
        assert_eq!(longest_reported_millis(text, WRITE_LOCK_HELD), None);
        assert_eq!(longest_reported_millis("", WRITE_LOCK_HELD), None);
    }

    #[test]
    fn longest_reported_millis_reads_write_lock_waits_apart_from_holds() {
        let stderr = "write lock waited 9 ms\nwrite lock held 41 ms\nwrite lock waited 13 ms\n";
        assert_eq!(longest_reported_millis(stderr, WRITE_LOCK_WAITED), Some(13));
        assert_eq!(longest_reported_millis(stderr, WRITE_LOCK_HELD), Some(41));
        assert_eq!(
            longest_reported_millis("write lock held 41 ms\n", WRITE_LOCK_WAITED),
            None
        );
    }

    #[test]
    fn seal_phases_reads_the_phase_object_of_any_names() {
        let stdout = "sealed epoch 3 at 2026-01-01T01:00:00Z\nseal phases {\"catch_up\":{\"ms\":4,\"sqlite_ms\":3},\"novel\":{\"ms\":1,\"sqlite_ms\":0}}\nseal took 12 ms\n";
        assert_eq!(
            seal_phases(stdout),
            Some(json!({
                "catch_up": {"ms": 4, "sqlite_ms": 3},
                "novel": {"ms": 1, "sqlite_ms": 0},
            }))
        );
    }

    #[test]
    fn seal_phases_is_absent_without_a_line_or_an_object() {
        assert_eq!(seal_phases("seal took 12 ms\n"), None);
        assert_eq!(seal_phases("seal phases soon\n"), None);
        assert_eq!(seal_phases("seal phases [1]\n"), None);
        assert_eq!(seal_phases(""), None);
    }

    #[test]
    fn fold_seal_phases_max_takes_each_field_maximum_per_phase() {
        let mut max = Value::Null;
        fold_seal_phases_max(&mut max, &Value::Null);
        assert_eq!(max, Value::Null);
        fold_seal_phases_max(
            &mut max,
            &json!({"merge": {"ms": 5, "sqlite_ms": 1}, "commit": {"ms": 2, "sqlite_ms": 2}}),
        );
        fold_seal_phases_max(
            &mut max,
            &json!({"merge": {"ms": 3, "sqlite_ms": 4}, "witness": {"ms": 7, "sqlite_ms": 0}}),
        );
        assert_eq!(
            max,
            json!({
                "merge": {"ms": 5, "sqlite_ms": 4},
                "commit": {"ms": 2, "sqlite_ms": 2},
                "witness": {"ms": 7, "sqlite_ms": 0},
            })
        );
    }

    #[test]
    fn reported_replans_reads_the_seal_line_and_is_zero_without_one() {
        let stdout = "replanned 2 times\nsealed epoch 3 at 2026-01-01T01:00:00Z\nseal took 12 ms\n";
        assert_eq!(reported_replans(stdout), 2);
        assert_eq!(reported_replans("seal took 12 ms\n"), 0);
    }

    #[test]
    fn reported_conflicts_reads_one_publisher_list_per_discarded_plan() {
        let stdout = "replanned 2 times\nplan conflict: a.example, b.example\nplan conflict: <epoch>\nseal took 12 ms\n";
        assert_eq!(
            reported_conflicts(stdout),
            vec![
                vec!["a.example".to_owned(), "b.example".to_owned()],
                vec!["<epoch>".to_owned()]
            ]
        );
        assert!(reported_conflicts("seal took 12 ms\n").is_empty());
    }

    #[test]
    fn reported_merged_reads_the_publishers_merged_at_commit() {
        let stdout = "plan merged: a.example, b.example\nseal took 12 ms\n";
        assert_eq!(
            reported_merged(stdout),
            vec!["a.example".to_owned(), "b.example".to_owned()]
        );
        assert!(reported_merged("seal took 12 ms\n").is_empty());
    }

    #[test]
    fn appended_text_returns_only_what_was_appended_since_the_last_read() {
        let buffer = Arc::new(Mutex::new("write lock held 9 ms\n".to_string()));
        let mut appended = AppendedText::new(&buffer);
        assert_eq!(appended.follow(&buffer), "write lock held 9 ms\n");
        assert_eq!(appended.follow(&buffer), "");
        buffer.lock().unwrap().push_str("write lock held 12 ms\n");
        assert_eq!(appended.follow(&buffer), "write lock held 12 ms\n");
    }

    #[test]
    fn appended_text_finishes_a_replaced_buffer_before_the_new_one() {
        let first = Arc::new(Mutex::new("write lock held 4 ms\n".to_string()));
        let mut appended = AppendedText::new(&first);
        appended.follow(&first);
        first.lock().unwrap().push_str("write lock held 30 ms\n");
        let second = Arc::new(Mutex::new("write lock held 2 ms\n".to_string()));
        assert_eq!(
            appended.follow(&second),
            "write lock held 30 ms\nwrite lock held 2 ms\n"
        );
        first.lock().unwrap().push_str("write lock held 99 ms\n");
        assert_eq!(appended.follow(&second), "");
    }

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
    fn copy_dir_copies_nested_files() {
        let root = tempfile::tempdir().expect("tempdir");
        let from = root.path().join("from");
        std::fs::create_dir_all(from.join("logs/a")).expect("nested directory");
        std::fs::write(from.join("registry.json"), "{}").expect("file");
        std::fs::write(from.join("logs/a/index.sqlite"), "db").expect("nested file");
        let to = root.path().join("to");
        copy_dir(&from, &to);
        assert_eq!(
            std::fs::read(to.join("registry.json")).expect("copy"),
            b"{}"
        );
        assert_eq!(
            std::fs::read(to.join("logs/a/index.sqlite")).expect("nested copy"),
            b"db"
        );
    }

    #[test]
    fn consumer_state_reads_the_sync_state_of_the_one_followed_log() {
        let root = tempfile::tempdir().expect("tempdir");
        let log = root.path().join("logs").join("log-a");
        std::fs::create_dir_all(&log).expect("log directory");
        let state = graven::sync::SyncState {
            format: graven::sync::SYNC_STATE_FORMAT,
            tree_size: 12,
            epoch_number: 3,
            root: "sha256:ab".into(),
            unwitnessed: false,
            content_digest: None,
            snapshot_tree_size: None,
            schedule_first_s: None,
            prior_sealed_at_s: None,
            largest_epoch_bytes: 0,
            walk_floor: Some(2),
            rejected_epochs: Vec::new(),
        };
        let conn = rusqlite::Connection::open(log.join("index.sqlite")).expect("index");
        graven::sync::save_sync_state(&conn, &state).expect("save");
        drop(conn);
        let read = consumer_state(root.path());
        assert_eq!(
            (
                read.epoch_number,
                read.tree_size,
                read.root,
                read.walk_floor
            ),
            (3, 12, "sha256:ab".to_string(), Some(2))
        );
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

    fn proxied_get(addr: &str, host: &str, path: &str) -> std::io::Result<String> {
        let mut stream = TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        write!(
            stream,
            "GET http://{host}/{path} HTTP/1.1\r\nHost: {host}\r\n\r\n"
        )?;
        let mut answer = String::new();
        stream.read_to_string(&mut answer)?;
        Ok(answer)
    }

    fn behaving_proxy() -> (
        tempfile::TempDir,
        String,
        BTreeMap<String, SiteCounters>,
        Behaviors,
    ) {
        let (dir, addr, counters, _, behaviors) = recorded_proxy();
        (dir, addr, counters, behaviors)
    }

    fn recorded_proxy() -> (
        tempfile::TempDir,
        String,
        BTreeMap<String, SiteCounters>,
        RequestLog,
        Behaviors,
    ) {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("page.html"), "hello").expect("page");
        let (addr, counters, log, behaviors) = serve_sites_with_behaviors(BTreeMap::from([(
            "site.test".to_string(),
            dir.path().to_path_buf(),
        )]));
        (dir, addr, counters, log, behaviors)
    }

    #[test]
    fn proxy_records_every_injected_failure_as_a_request_without_octets() {
        let (_dir, addr, counters, log, behaviors) = recorded_proxy();
        for failure in [
            Failure::Unavailable,
            Failure::Close,
            Failure::Hang(Duration::from_millis(50)),
        ] {
            behaviors.set(
                "site.test",
                HostBehavior {
                    delay: None,
                    failure: Some(failure),
                },
            );
            let _ = proxied_get(&addr, "site.test", "page.html");
        }
        assert_eq!(counters["site.test"].requests.load(Ordering::Relaxed), 3);
        assert_eq!(counters["site.test"].failures.load(Ordering::Relaxed), 3);
        assert_eq!(counters["site.test"].octets.load(Ordering::Relaxed), 0);
        let expected = LoggedRequest {
            host: "site.test".into(),
            path: "page.html".into(),
            octets: 0,
        };
        assert_eq!(log.requests(), vec![expected; 3]);
    }

    #[test]
    fn retry_after_is_read_from_a_refusal_message_that_carries_it() {
        assert_eq!(
            retry_after_seconds("HTTP 503 Service Unavailable, Retry-After: 30"),
            Some(30)
        );
        assert_eq!(retry_after_seconds("retry-after=7 seconds"), Some(7));
        assert_eq!(
            retry_after_seconds("ping failed after retries: HTTP 503"),
            None
        );
    }

    #[test]
    fn proxy_serves_a_host_without_a_behavior_unchanged() {
        let (_dir, addr, counters, _) = behaving_proxy();
        let answer = proxied_get(&addr, "site.test", "page.html").expect("answer");
        assert!(answer.starts_with("HTTP/1.1 200 OK"), "{answer}");
        assert!(answer.ends_with("hello"), "{answer}");
        assert_eq!(counters["site.test"].requests.load(Ordering::Relaxed), 1);
        assert_eq!(counters["site.test"].delays.load(Ordering::Relaxed), 0);
        assert_eq!(counters["site.test"].failures.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn proxy_delays_every_request_of_a_delayed_host_and_counts_each_delay() {
        let (_dir, addr, counters, behaviors) = behaving_proxy();
        behaviors.set(
            "site.test",
            HostBehavior {
                delay: Some(Duration::from_millis(300)),
                failure: None,
            },
        );
        for _ in 0..2 {
            let start = Instant::now();
            let answer = proxied_get(&addr, "site.test", "page.html").expect("answer");
            assert!(start.elapsed() >= Duration::from_millis(300));
            assert!(answer.starts_with("HTTP/1.1 200 OK"), "{answer}");
        }
        assert_eq!(counters["site.test"].delays.load(Ordering::Relaxed), 2);
        assert_eq!(counters["site.test"].requests.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn proxy_answers_503_for_an_unavailable_host_and_counts_the_failure() {
        let (_dir, addr, counters, behaviors) = behaving_proxy();
        behaviors.set(
            "site.test",
            HostBehavior {
                delay: None,
                failure: Some(Failure::Unavailable),
            },
        );
        let answer = proxied_get(&addr, "site.test", "page.html").expect("answer");
        assert!(
            answer.starts_with("HTTP/1.1 503 Service Unavailable"),
            "{answer}"
        );
        assert_eq!(counters["site.test"].failures.load(Ordering::Relaxed), 1);
        assert_eq!(counters["site.test"].requests.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn proxy_closes_a_closing_host_without_answering() {
        let (_dir, addr, counters, behaviors) = behaving_proxy();
        behaviors.set(
            "site.test",
            HostBehavior {
                delay: None,
                failure: Some(Failure::Close),
            },
        );
        let answer = proxied_get(&addr, "site.test", "page.html").unwrap_or_default();
        assert_eq!(answer, "");
        assert_eq!(counters["site.test"].failures.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn proxy_holds_a_hanging_host_for_its_duration_then_closes_without_answering() {
        let (_dir, addr, _counters, behaviors) = behaving_proxy();
        behaviors.set(
            "site.test",
            HostBehavior {
                delay: None,
                failure: Some(Failure::Hang(Duration::from_millis(500))),
            },
        );
        let start = Instant::now();
        let answer = proxied_get(&addr, "site.test", "page.html").unwrap_or_default();
        assert!(start.elapsed() >= Duration::from_millis(500));
        assert_eq!(answer, "");
    }

    #[test]
    fn proxy_serves_normally_again_once_a_behavior_is_reset() {
        let (_dir, addr, _counters, behaviors) = behaving_proxy();
        behaviors.set(
            "site.test",
            HostBehavior {
                delay: None,
                failure: Some(Failure::Unavailable),
            },
        );
        behaviors.set("site.test", HostBehavior::default());
        let answer = proxied_get(&addr, "site.test", "page.html").expect("answer");
        assert!(answer.starts_with("HTTP/1.1 200 OK"), "{answer}");
        behaviors.set(
            "site.test",
            HostBehavior {
                delay: None,
                failure: Some(Failure::Unavailable),
            },
        );
        behaviors.clear();
        let answer = proxied_get(&addr, "site.test", "page.html").expect("answer");
        assert!(answer.starts_with("HTTP/1.1 200 OK"), "{answer}");
    }

    #[test]
    fn write_changed_pages_rewrites_only_the_named_pages() {
        let root = tempfile::tempdir().expect("tempdir");
        let site = Site::new(root.path(), "127.0.9.9", "default");
        write_pages(&site, 3, 5, 1);
        write_changed_pages(&site, &[1], 5, 2);
        let read = |j: usize| {
            std::fs::read_to_string(site.pages.join(format!("p{j}.html"))).expect("page")
        };
        assert_eq!(read(0), page("127.0.9.9", 0, 5, 1));
        assert_eq!(read(1), page("127.0.9.9", 1, 5, 2));
        assert_eq!(read(2), page("127.0.9.9", 2, 5, 1));
    }

    #[test]
    fn entry_leaves_returns_only_the_leaves_from_the_given_index_to_the_tree_size() {
        let dir = tempfile::tempdir().expect("tempdir");
        let leaves: Vec<Vec<u8>> = (0..5)
            .map(|n| format!("{{\"n\":{n}}}").into_bytes())
            .collect();
        for bundle in wist_core::tiles::entry_bundles_for_range(0, 5, 5) {
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
        assert_eq!(entry_leaves(dir.path(), 2, 5), leaves[2..5].to_vec());
    }

    #[test]
    fn payload_fetches_flag_is_passed_only_when_set() {
        assert_eq!(fetches_flag(None), Vec::<&str>::new());
        assert_eq!(fetches_flag(Some("1")), vec!["--payload-fetches", "1"]);
    }
}
