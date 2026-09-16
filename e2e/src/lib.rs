//! Drives the real publisher, aggregator and consumer executables: shared
//! by the end-to-end test and the capacity baseline.
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

/// `WIST_BUILD_PROFILE=release` builds and runs the executables in release
/// mode; the default is the debug profile.
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
    let output = Command::new(bin)
        .args(args)
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

/// Starts `clave serve`; with a proxy every fetch the aggregator makes is
/// routed through it, which is how loopback sites stand in for domains.
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

pub fn free_loopback_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local_addr").to_string()
}

pub fn serve_static(dir: PathBuf) -> String {
    serve_static_counted(dir).0
}

/// Serves a directory over loopback and counts the requests it answers.
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

/// A forward proxy serving several loopback hosts from directories: the
/// request line of a proxied request names the host, and each host's
/// requests are counted.
pub fn serve_sites(
    sites: std::collections::BTreeMap<String, PathBuf>,
) -> (String, std::collections::BTreeMap<String, Arc<AtomicU64>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind site proxy");
    let addr = listener.local_addr().expect("local_addr").to_string();
    let counters: std::collections::BTreeMap<String, Arc<AtomicU64>> = sites
        .keys()
        .map(|host| (host.clone(), Arc::new(AtomicU64::new(0))))
        .collect();
    let routes = Arc::new((sites, counters.clone()));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let routes = routes.clone();
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
                        counters[host].fetch_add(1, Ordering::Relaxed);
                        respond_file(stream, &dir.join(rel));
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
    (addr, counters)
}

fn respond_file(mut stream: TcpStream, path: &Path) {
    match std::fs::read(path) {
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

pub fn wait_until_status_active(
    http: &reqwest::blocking::Client,
    base: &str,
    domain: &str,
) -> Value {
    poll_until(Duration::from_secs(30), Duration::from_millis(100), || {
        fetch_status(http, base, domain).filter(|v| v["state"] == "active")
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

/// WIST-3 §3.2 seals on the accepted cadence grid, hourly by default and
/// amendable only with a seven-day grace, so the harness advances Log time
/// by whole hours: the first Block seals at the next hour boundary and each
/// later one an hour after it, while Deltas keep wall-clock `observed_at`
/// values that stay inside every Block's clock allowance.
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
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        loop {
            let resp = self.recv_line();
            if resp.get("id").and_then(Value::as_u64) != Some(id) {
                continue;
            }
            if let Some(err) = resp.get("error") {
                panic!("{method} returned JSON-RPC error: {err}");
            }
            return resp["result"].clone();
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

    pub fn get_record(&mut self, url: &str) -> Value {
        self.tool_call("get_record", json!({"url": url}))
    }

    pub fn get_extract(&mut self, url: &str) -> Value {
        self.tool_call("get_extract", json!({"url": url}))
    }
}
