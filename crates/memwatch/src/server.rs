//! On-demand local report: a short-lived, token-protected server on 127.0.0.1.

use std::collections::HashSet;
use std::io::Read;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use rusqlite::Connection;
use serde_json::{json, Value};
use tiny_http::{Header, Method, Request, Response, Server};

use crate::config::Config;
use crate::grouping;
use crate::models::{ActionResult, AppGroup, StartupEntry};
use crate::probe;
use crate::selfid::{is_memwatch_proc, own_pids_in};
use crate::suggest::{build_report_live, startup_by_app};

const REPORT_HTML: &str = include_str!("../../../src/memwatch/static/report.html");
const REPORT_JS: &str = include_str!("../../../src/memwatch/static/report.js");
const REPORT_CSS: &str = include_str!("../../../src/memwatch/static/report.css");

const MAX_BODY: usize = 65536;
/// Oversized bodies are read (and dropped) up to this, then answered with 413.
const DRAIN_LIMIT: usize = 1 << 20;
const SELF_MSG: &str = "memwatch will not stop itself";
const WORKERS: usize = 4;

/// The things the page can ask for. The real implementation lives in `actions`.
pub trait Actions: Send + Sync {
    fn stop_now(&self, group: &AppGroup, cfg: &Config) -> ActionResult;
    fn force_kill(&self, group: &AppGroup, cfg: &Config) -> ActionResult;
    fn disable_startup(
        &self,
        conn: &Connection,
        app_key: &str,
        entries: &[StartupEntry],
        mode: Option<&str>,
        cfg: &Config,
    ) -> ActionResult;
    fn undo(&self, conn: &Connection, action_id: i64, cfg: &Config) -> ActionResult;
}

/// Stand-in until the actions are ported: every request is refused politely.
pub struct NoActions;

fn unavailable() -> ActionResult {
    ActionResult {
        status: "failed".into(),
        message: "Actions are not available in this build yet.".into(),
        remaining_pids: vec![],
    }
}

impl Actions for NoActions {
    fn stop_now(&self, _: &AppGroup, _: &Config) -> ActionResult {
        unavailable()
    }
    fn force_kill(&self, _: &AppGroup, _: &Config) -> ActionResult {
        unavailable()
    }
    fn disable_startup(&self, _: &Connection, _: &str, _: &[StartupEntry], _: Option<&str>, _: &Config) -> ActionResult {
        unavailable()
    }
    fn undo(&self, _: &Connection, _: i64, _: &Config) -> ActionResult {
        unavailable()
    }
}

pub type ConnFactory = Box<dyn Fn() -> rusqlite::Result<Connection> + Send + Sync>;
pub type Resolver = Box<dyn Fn(&str, &Config) -> Option<AppGroup> + Send + Sync>;
pub type Excluder = Box<dyn Fn(&Config) -> HashSet<String> + Send + Sync>;

/// The live group for an app key, or None when it is not running.
pub fn group_for_key(key: &str, cfg: &Config) -> Option<AppGroup> {
    let procs = probe::snapshot_processes();
    grouping::group_processes(&procs, &probe::services_by_pid(), cfg).remove(key)
}

/// Groups holding this server, its launching tree, or any memwatch process.
pub fn exclude_keys_from(procs: &[crate::models::ProcInfo], mine: &HashSet<u32>, cfg: &Config) -> HashSet<String> {
    let groups = grouping::group_processes(procs, &probe::services_by_pid(), cfg);
    let by_pid: std::collections::HashMap<u32, &crate::models::ProcInfo> =
        procs.iter().map(|p| (p.pid, p)).collect();
    groups
        .into_iter()
        .filter(|(_, g)| {
            g.pids.iter().any(|(pid, _)| {
                mine.contains(pid) || by_pid.get(pid).is_some_and(|p| is_memwatch_proc(p))
            })
        })
        .map(|(k, _)| k)
        .collect()
}

pub fn exclude_keys(cfg: &Config) -> HashSet<String> {
    let procs = probe::snapshot_processes();
    let mine = own_pids_in(&procs, std::process::id());
    exclude_keys_from(&procs, &mine, cfg)
}

pub struct ReportServer {
    http: Server,
    port: u16,
    cfg: Config,
    conn_factory: ConnFactory,
    token: String,
    actions: Box<dyn Actions>,
    resolve: Resolver,
    exclude: Excluder,
    last_request: Mutex<Instant>,
    last_heartbeat: Mutex<Option<Instant>>,
    inflight: AtomicI64,
    done: AtomicBool,
}

/// What a request reduces to once read; routing never touches the socket.
struct Parsed {
    method: Method,
    path: String,
    query: String,
    host: Option<String>,
    origin: Option<String>,
    token: Option<String>,
    body: Option<Vec<u8>>, // None: over the cap
}

struct Reply {
    code: u16,
    body: Vec<u8>,
    ctype: &'static str,
}

impl Reply {
    fn new(code: u16, body: impl Into<Vec<u8>>, ctype: &'static str) -> Reply {
        Reply { code, body: body.into(), ctype }
    }
    fn json(code: u16, v: &Value) -> Reply {
        Reply::new(code, serde_json::to_vec(v).unwrap_or_default(), "application/json")
    }
    fn deny() -> Reply {
        Reply::new(403, "Forbidden", "text/plain; charset=utf-8")
    }
    fn not_found() -> Reply {
        Reply::new(404, "Not found", "text/plain; charset=utf-8")
    }
    fn too_large() -> Reply {
        Reply::new(413, "Payload too large", "text/plain; charset=utf-8")
    }
    fn internal() -> Reply {
        Reply::json(500, &json!({"error": "internal error"}))
    }
}

fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).expect("static header")
}

fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let hex = b
                    .get(i + 1..i + 3)
                    .and_then(|h| std::str::from_utf8(h).ok())
                    .and_then(|h| u8::from_str_radix(h, 16).ok());
                match hex {
                    Some(v) => {
                        out.push(v);
                        i += 3;
                    }
                    None => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn query_param(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        (percent_decode(k) == name).then(|| percent_decode(v))
    })
}

fn url_safe_token() -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut raw = [0u8; 32];
    getrandom::getrandom(&mut raw).expect("os random");
    // 32 bytes -> 43 url-safe characters, no padding (like secrets.token_urlsafe(32))
    let mut out = String::with_capacity(43);
    for chunk in raw.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |acc, (i, &b)| acc | (b as u32) << (16 - 8 * i));
        let chars = chunk.len() + 1;
        for i in 0..chars {
            out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

impl ReportServer {
    pub fn port(&self) -> u16 {
        self.port
    }

    fn gate(&self, rq: &Parsed, api: bool) -> bool {
        *self.last_request.lock().unwrap() = Instant::now();
        if rq.host.as_deref() != Some(&format!("127.0.0.1:{}", self.port)) {
            return false;
        }
        if api {
            if let Some(origin) = &rq.origin {
                if *origin != format!("http://127.0.0.1:{}", self.port) {
                    return false;
                }
            }
            if !ct_eq(rq.token.as_deref().unwrap_or(""), &self.token) {
                return false;
            }
        }
        true
    }

    fn route(&self, rq: &Parsed) -> Reply {
        match rq.method {
            Method::Get => self.route_get(rq),
            Method::Post => self.route_post(rq),
            _ => Reply::new(501, "Unsupported method", "text/plain; charset=utf-8"),
        }
    }

    fn route_get(&self, rq: &Parsed) -> Reply {
        if rq.path.starts_with("/api/") {
            if !self.gate(rq, true) {
                return Reply::deny();
            }
            return if rq.path == "/api/report" { self.report() } else { Reply::not_found() };
        }
        if !self.gate(rq, false) {
            return Reply::deny();
        }
        if rq.path == "/" {
            let t = query_param(&rq.query, "t").unwrap_or_default();
            if !ct_eq(&t, &self.token) {
                return Reply::deny();
            }
            return static_file("report.html");
        }
        match rq.path.strip_prefix("/static/") {
            Some(name) => static_file(name),
            None => Reply::not_found(),
        }
    }

    fn report(&self) -> Reply {
        let built = (|| -> Result<Value, String> {
            let conn = (self.conn_factory)().map_err(|e| e.to_string())?;
            let exclude = (self.exclude)(&self.cfg);
            let r = build_report_live(&conn, &self.cfg, probe::now_unix(), &exclude).map_err(|e| e.to_string())?;
            let mut v = serde_json::to_value(&r).map_err(|e| e.to_string())?;
            v["logger_cap_mb"] = json!(self.cfg.logger_cap_mb); // for the page only
            Ok(v)
        })();
        match built {
            Ok(v) => Reply::json(200, &v),
            Err(e) => {
                log::error!("report failed: {e}");
                Reply::internal()
            }
        }
    }

    fn route_post(&self, rq: &Parsed) -> Reply {
        // The whole body was read before any reply, denials included: closing a socket
        // with unread data makes Windows send RST, and the client sees a reset, not a status.
        let Some(body) = &rq.body else { return Reply::too_large() };
        if !self.gate(rq, true) {
            return Reply::deny();
        }
        if rq.path == "/api/heartbeat" {
            *self.last_heartbeat.lock().unwrap() = Some(Instant::now());
            return Reply::json(200, &json!({"ok": true}));
        }
        if rq.path != "/api/action" {
            return Reply::not_found();
        }
        let bad = |m: &str| Reply::json(400, &json!({"error": m}));
        let Ok(req) = serde_json::from_slice::<Value>(body) else { return bad("malformed JSON") };
        let Some(obj) = req.as_object() else { return bad("unknown action") };
        let action = obj.get("action").and_then(Value::as_str).unwrap_or("");
        if !["stop", "force", "disable_startup", "undo"].contains(&action) {
            return bad("unknown action");
        }
        for k in ["app_key", "mode"] {
            if obj.get(k).is_some_and(|v| !v.is_null() && !v.is_string()) {
                return bad(&format!("bad {k}"));
            }
        }
        let app_key = obj.get("app_key").and_then(Value::as_str).unwrap_or("");
        let mode = obj.get("mode").and_then(Value::as_str);
        let mut action_id = 0;
        if action == "undo" {
            match obj.get("action_id").and_then(Value::as_i64) {
                Some(id) => action_id = id,
                None => return bad("bad action_id"),
            }
        } else if app_key.is_empty() {
            return bad("app_key required");
        }
        if !matches!(mode, None | Some("manual") | Some("disabled")) {
            return bad("bad mode");
        }

        self.inflight.fetch_add(1, Ordering::SeqCst);
        let out = catch_unwind(AssertUnwindSafe(|| self.act(action, app_key, mode, action_id)));
        self.inflight.fetch_sub(1, Ordering::SeqCst);
        if let Some(hb) = self.last_heartbeat.lock().unwrap().as_mut() {
            *hb = Instant::now(); // the page cannot beat while we worked
        }
        match out {
            Ok(Ok(res)) => Reply::json(200, &serde_json::to_value(res).unwrap_or(Value::Null)),
            Ok(Err(e)) => {
                log::error!("action failed: {e}");
                Reply::internal()
            }
            Err(_) => {
                log::error!("action panicked");
                Reply::internal()
            }
        }
    }

    fn act(&self, action: &str, key: &str, mode: Option<&str>, action_id: i64) -> Result<ActionResult, String> {
        let fail = |m: &str| ActionResult { status: "failed".into(), message: m.into(), remaining_pids: vec![] };
        let conn = (self.conn_factory)().map_err(|e| e.to_string())?;
        let (cfg, imp) = (&self.cfg, &*self.actions);
        if action == "undo" {
            return Ok(imp.undo(&conn, action_id, cfg));
        }
        let exclude = (self.exclude)(cfg);
        if exclude.contains(key) {
            return Ok(fail(SELF_MSG));
        }
        if action == "disable_startup" {
            if mode == Some("disabled") {
                let r = build_report_live(&conn, cfg, probe::now_unix(), &exclude).map_err(|e| e.to_string())?;
                let offered = r
                    .suggestions
                    .iter()
                    .find(|s| s.app_key == key)
                    .is_some_and(|s| s.service_modes.iter().any(|m| m == "disabled"));
                if !offered {
                    return Ok(fail("Disabling is not offered for this app; use Manual instead."));
                }
            }
            let mut by_app = startup_by_app(&conn, None, None).map_err(|e| e.to_string())?;
            let entries = by_app.remove(key).unwrap_or_default();
            return Ok(imp.disable_startup(&conn, key, &entries, mode, cfg));
        }
        let Some(group) = (self.resolve)(key, cfg) else {
            return Ok(ActionResult {
                status: "already_stopped".into(),
                message: "It is no longer running.".into(),
                remaining_pids: vec![],
            });
        };
        Ok(if action == "stop" { imp.stop_now(&group, cfg) } else { imp.force_kill(&group, cfg) })
    }

    fn serve_one(&self, mut req: Request) {
        let find = |name: &str| {
            req.headers().iter().find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name)).map(|h| h.value.as_str().to_string())
        };
        let (host, origin, token) = (find("Host"), find("Origin"), find("X-Memwatch-Token"));
        let url = req.url().to_string();
        let (path, query) = match url.split_once('?') {
            Some((p, q)) => (p.to_string(), q.to_string()),
            None => (url.clone(), String::new()),
        };
        let method = req.method().clone();
        let body = (method == Method::Post).then(|| {
            let n = req.body_length().unwrap_or(0);
            let take = n.min(DRAIN_LIMIT) as u64;
            let mut buf = Vec::new();
            let _ = req.as_reader().take(take).read_to_end(&mut buf);
            (n <= MAX_BODY).then_some(buf)
        });
        let parsed = Parsed { method, path, query, host, origin, token, body: body.flatten() };
        let reply = catch_unwind(AssertUnwindSafe(|| self.route(&parsed))).unwrap_or_else(|_| {
            log::error!("request panicked");
            Reply::internal()
        });
        let resp = Response::from_data(reply.body)
            .with_status_code(reply.code)
            .with_header(header("Content-Type", reply.ctype))
            .with_header(header("Cache-Control", "no-store"))
            .with_header(header("X-Content-Type-Options", "nosniff"))
            .with_header(header("Referrer-Policy", "no-referrer"));
        let _ = req.respond(resp);
    }

    fn serve_loop(&self) {
        while !self.done.load(Ordering::SeqCst) {
            match self.http.recv_timeout(Duration::from_millis(100)) {
                Ok(Some(req)) => self.serve_one(req),
                Ok(None) => {}
                Err(_) => break,
            }
        }
    }

    pub fn start_workers(self: &Arc<Self>, n: usize) -> Vec<JoinHandle<()>> {
        (0..n)
            .map(|_| {
                let s = Arc::clone(self);
                thread::spawn(move || s.serve_loop())
            })
            .collect()
    }

    pub fn stop(&self) {
        self.done.store(true, Ordering::SeqCst);
    }
}

fn static_file(name: &str) -> Reply {
    match name {
        "report.html" => Reply::new(200, REPORT_HTML, "text/html; charset=utf-8"),
        "report.js" => Reply::new(200, REPORT_JS, "text/javascript; charset=utf-8"),
        "report.css" => Reply::new(200, REPORT_CSS, "text/css; charset=utf-8"),
        _ => Reply::not_found(),
    }
}

pub fn make_server(
    cfg: Config,
    conn_factory: ConnFactory,
    token: String,
    actions: Box<dyn Actions>,
    resolve: Resolver,
    exclude: Excluder,
) -> std::io::Result<Arc<ReportServer>> {
    let http = Server::http("127.0.0.1:0").map_err(|e| std::io::Error::other(e.to_string()))?;
    let port = http.server_addr().to_ip().map(|a| a.port()).ok_or_else(|| std::io::Error::other("no ip"))?;
    Ok(Arc::new(ReportServer {
        http,
        port,
        cfg,
        conn_factory,
        token,
        actions,
        resolve,
        exclude,
        last_request: Mutex::new(Instant::now()),
        last_heartbeat: Mutex::new(None),
        inflight: AtomicI64::new(0),
        done: AtomicBool::new(false),
    }))
}

/// Serve until a heartbeat lapses or the server sits idle too long.
pub fn run(srv: &Arc<ReportServer>, poll: Duration) {
    let workers = srv.start_workers(WORKERS);
    loop {
        thread::sleep(poll);
        if srv.done.load(Ordering::SeqCst) {
            break;
        }
        if srv.inflight.load(Ordering::SeqCst) > 0 {
            continue;
        }
        let hb = *srv.last_heartbeat.lock().unwrap();
        let lapsed = match hb {
            Some(t) => t.elapsed().as_secs_f64() > srv.cfg.heartbeat_timeout_s as f64,
            None => srv.last_request.lock().unwrap().elapsed().as_secs_f64() > srv.cfg.server_idle_timeout_s as f64,
        };
        if lapsed {
            srv.stop();
            break;
        }
    }
    for w in workers {
        let _ = w.join(); // a half-finished change completes (and is recorded) first
    }
}

fn open_in_browser(url: &str) {
    use windows::core::{w, HSTRING};
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    unsafe {
        ShellExecuteW(None, w!("open"), &HSTRING::from(url), None, None, SW_SHOWNORMAL);
    }
}

pub fn serve_report(cfg: Config, open_browser: bool) -> std::io::Result<()> {
    let token = url_safe_token();
    let path: PathBuf = cfg.data_dir.join("memwatch.db");
    let srv = make_server(
        cfg,
        Box::new(move || crate::db::connect(&path)),
        token.clone(),
        Box::new(crate::actions::RealActions::new()),
        Box::new(group_for_key),
        Box::new(exclude_keys),
    )?;
    let url = format!("http://127.0.0.1:{}/?t={token}", srv.port());
    if open_browser {
        open_in_browser(&url);
    } else {
        println!("{url}");
    }
    run(&srv, Duration::from_millis(250));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::*;
    use std::io::Write;
    use std::net::TcpStream;

    const TOKEN: &str = "tok-123";

    struct Resp {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }
    impl Resp {
        fn json(&self) -> Value {
            serde_json::from_slice(&self.body).unwrap()
        }
        fn header(&self, name: &str) -> Option<&str> {
            self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
        }
    }

    /// One request on a fresh socket; `headers` may override Host.
    fn raw(port: u16, method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Resp {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let has = |n: &str| headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(n));
        let mut head = format!("{method} {path} HTTP/1.1\r\n");
        if !has("Host") {
            head += &format!("Host: 127.0.0.1:{port}\r\n");
        }
        if method == "POST" && !has("Content-Length") {
            head += &format!("Content-Length: {}\r\n", body.len());
        }
        for (k, v) in headers {
            head += &format!("{k}: {v}\r\n");
        }
        head += "Connection: close\r\n\r\n";
        s.write_all(head.as_bytes()).unwrap();
        s.write_all(body).unwrap();
        let mut buf = Vec::new();
        let _ = s.read_to_end(&mut buf);
        let split = buf.windows(4).position(|w| w == b"\r\n\r\n").expect("response head") + 4;
        let head = String::from_utf8_lossy(&buf[..split]).into_owned();
        let mut lines = head.lines();
        let status = lines.next().unwrap().split(' ').nth(1).unwrap().parse().unwrap();
        let headers = lines
            .filter_map(|l| l.split_once(':'))
            .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
            .collect();
        Resp { status, headers, body: buf[split..].to_vec() }
    }

    const AUTH: [(&str, &str); 1] = [("X-Memwatch-Token", TOKEN)];

    #[derive(Default)]
    struct Fake {
        calls: Mutex<Vec<String>>,
        stop: Mutex<Option<Arc<dyn Fn() -> ActionResult + Send + Sync>>>,
    }
    fn done(msg: &str) -> ActionResult {
        ActionResult { status: "done".into(), message: msg.into(), remaining_pids: vec![] }
    }
    impl Actions for Arc<Fake> {
        fn stop_now(&self, g: &AppGroup, _: &Config) -> ActionResult {
            self.calls.lock().unwrap().push(format!("stop_now {}", g.app_key));
            let hook = self.stop.lock().unwrap().clone();
            hook.map_or_else(|| done("stopped"), |h| h())
        }
        fn force_kill(&self, g: &AppGroup, _: &Config) -> ActionResult {
            self.calls.lock().unwrap().push(format!("force_kill {}", g.app_key));
            done("killed")
        }
        fn disable_startup(&self, _: &Connection, key: &str, entries: &[StartupEntry], mode: Option<&str>, _: &Config) -> ActionResult {
            let names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
            self.calls.lock().unwrap().push(format!("disable_startup {key} {} {names:?}", mode.unwrap_or("-")));
            done("disabled")
        }
        fn undo(&self, _: &Connection, id: i64, _: &Config) -> ActionResult {
            self.calls.lock().unwrap().push(format!("undo {id}"));
            done("undone")
        }
    }

    struct Rig {
        srv: Arc<ReportServer>,
        fake: Arc<Fake>,
        port: u16,
        workers: Vec<JoinHandle<()>>,
        _dir: tempfile::TempDir,
    }
    impl Drop for Rig {
        fn drop(&mut self) {
            self.srv.stop();
            for w in self.workers.drain(..) {
                let _ = w.join();
            }
        }
    }

    fn rig_with(cfg: Config, seed_db: impl FnOnce(&Connection), start: bool) -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.db");
        let c = crate::db::connect(&path).unwrap();
        c.execute_batch("PRAGMA synchronous=OFF").unwrap();
        seed_db(&c);
        drop(c);
        let fake = Arc::new(Fake::default());
        let srv = make_server(
            cfg,
            Box::new(move || crate::db::connect(&path)),
            TOKEN.into(),
            Box::new(fake.clone()),
            Box::new(|key, _| (key != "suite:gone").then(|| mk_group(key, 1))),
            Box::new(|_| HashSet::from(["suite:self".to_string()])),
        )
        .unwrap();
        let workers = if start { srv.start_workers(WORKERS) } else { vec![] };
        Rig { port: srv.port(), srv, fake, workers, _dir: dir }
    }

    fn rig() -> Rig {
        rig_with(mk_cfg(), |c| seed(c, "suite:steam", 30, 600 << 20), true)
    }

    fn post_json(rig: &Rig, path: &str, body: &Value) -> Resp {
        raw(rig.port, "POST", path, &AUTH, body.to_string().as_bytes())
    }
    fn act(rig: &Rig, body: Value) -> Value {
        let r = post_json(rig, "/api/action", &body);
        assert_eq!(r.status, 200);
        r.json()
    }
    fn calls(rig: &Rig) -> Vec<String> {
        rig.fake.calls.lock().unwrap().clone()
    }

    #[test]
    fn page_requires_token() {
        let r = rig();
        assert_eq!(raw(r.port, "GET", "/?t=wrong", &[], b"").status, 403);
        assert_eq!(raw(r.port, "GET", "/", &[], b"").status, 403);
        let ok = raw(r.port, "GET", &format!("/?t={TOKEN}"), &[], b"");
        assert_eq!(ok.status, 200);
        assert!(String::from_utf8_lossy(&ok.body).contains("<html"));
        assert_eq!(ok.header("Cache-Control"), Some("no-store"));
        assert_eq!(ok.header("X-Content-Type-Options"), Some("nosniff"));
    }

    #[test]
    fn api_requires_header_and_rejects_foreign_origin() {
        let r = rig();
        let body = json!({"action": "stop", "app_key": "suite:x"}).to_string();
        assert_eq!(raw(r.port, "POST", "/api/action", &[], body.as_bytes()).status, 403);
        let evil = [("X-Memwatch-Token", TOKEN), ("Origin", "https://evil.example")];
        assert_eq!(raw(r.port, "POST", "/api/action", &evil, body.as_bytes()).status, 403);
        assert!(calls(&r).is_empty());
        assert_eq!(raw(r.port, "GET", "/api/report", &[], b"").status, 403);
        let bad = [("X-Memwatch-Token", "nope")];
        assert_eq!(raw(r.port, "POST", "/api/action", &bad, body.as_bytes()).status, 403);
    }

    #[test]
    fn same_origin_allowed_and_no_cors_headers() {
        let r = rig();
        let origin = format!("http://127.0.0.1:{}", r.port);
        let h = [("X-Memwatch-Token", TOKEN), ("Origin", origin.as_str())];
        let resp = raw(r.port, "GET", "/api/report", &h, b"");
        assert_eq!(resp.status, 200);
        assert!(!resp.headers.iter().any(|(k, _)| k.to_lowercase().starts_with("access-control")));
    }

    #[test]
    fn wrong_host_header_rejected() {
        let r = rig();
        let h = [("Host", "attacker.example:80")];
        assert_eq!(raw(r.port, "GET", &format!("/?t={TOKEN}"), &h, b"").status, 403);
        assert_eq!(raw(r.port, "GET", "/static/report.js", &h, b"").status, 403);
    }

    #[test]
    fn static_whitelist() {
        let r = rig();
        for n in ["report.html", "report.js", "report.css"] {
            assert_eq!(raw(r.port, "GET", &format!("/static/{n}"), &[], b"").status, 200);
        }
        assert_eq!(raw(r.port, "GET", "/static/../server.py", &[], b"").status, 404);
        assert_eq!(raw(r.port, "GET", "/static/%2e%2e/server.py", &[], b"").status, 404);
        assert_eq!(raw(r.port, "GET", "/static/.gitkeep", &[], b"").status, 404);
    }

    #[test]
    fn report_json_and_action_dispatch() {
        let r = rig();
        let rep = raw(r.port, "GET", "/api/report", &AUTH, b"").json();
        for k in ["suggestions", "system", "apps", "undo"] {
            assert!(rep.get(k).is_some(), "{k}");
        }
        assert_eq!(rep["logger_cap_mb"], 50);
        let out = act(&r, json!({"action": "stop", "app_key": "suite:steam"}));
        assert_eq!(calls(&r), ["stop_now suite:steam"]);
        assert_eq!(out["status"], "done");
        act(&r, json!({"action": "force", "app_key": "suite:steam"}));
        act(&r, json!({"action": "undo", "action_id": 7}));
        assert_eq!(calls(&r)[1..], ["force_kill suite:steam", "undo 7"]);
    }

    #[test]
    fn missing_group_is_already_stopped() {
        let r = rig();
        let out = act(&r, json!({"action": "stop", "app_key": "suite:gone"}));
        assert_eq!(out["status"], "already_stopped");
        assert!(calls(&r).is_empty());
    }

    #[test]
    fn self_keys_are_refused() {
        let r = rig();
        let out = act(&r, json!({"action": "force", "app_key": "suite:self"}));
        assert_eq!((out["status"].as_str(), out["message"].as_str()), (Some("failed"), Some(SELF_MSG)));
        let out = act(&r, json!({"action": "disable_startup", "app_key": "suite:self"}));
        assert_eq!(out["status"], "failed");
        assert!(calls(&r).is_empty());
    }

    #[test]
    fn bad_requests_are_400() {
        let r = rig();
        let status = |b: &[u8]| raw(r.port, "POST", "/api/action", &AUTH, b).status;
        assert_eq!(status(br#"{"action":"format_c","app_key":"a"}"#), 400);
        assert_eq!(status(b"{not json"), 400);
        assert_eq!(status(b"[1, 2]"), 400);
        assert_eq!(status(br#"{"action":"stop"}"#), 400);
        assert_eq!(status(br#"{"action":"undo","action_id":"x"}"#), 400);
        assert_eq!(status(br#"{"action":"undo","action_id":true}"#), 400);
        assert_eq!(status(br#"{"action":"undo","action_id":7.5}"#), 400);
        assert_eq!(status(br#"{"action":"stop","app_key":5}"#), 400);
        assert_eq!(status(br#"{"action":"disable_startup","app_key":"a","mode":"rm -rf"}"#), 400);
        assert!(calls(&r).is_empty());
    }

    #[test]
    fn disabled_mode_rejected_unless_offered() {
        let r = rig();
        let out = act(&r, json!({"action": "disable_startup", "app_key": "suite:steam", "mode": "disabled"}));
        assert_eq!(out["status"], "failed");
        assert!(calls(&r).is_empty());
        let out = act(&r, json!({"action": "disable_startup", "app_key": "suite:steam", "mode": "manual"}));
        assert_eq!(out["status"], "done");
        assert_eq!(calls(&r), ["disable_startup suite:steam manual []"]);
    }

    #[test]
    fn heartbeat_ok() {
        let r = rig();
        assert_eq!(post_json(&r, "/api/heartbeat", &json!({})).status, 200);
        assert_eq!(raw(r.port, "POST", "/api/heartbeat", &[], b"{}").status, 403);
    }

    fn run_in_thread(r: &Rig, poll_ms: u64) -> JoinHandle<()> {
        let srv = r.srv.clone();
        thread::spawn(move || run(&srv, Duration::from_millis(poll_ms)))
    }

    fn join_within(h: JoinHandle<()>, secs: u64) -> bool {
        let end = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < end {
            if h.is_finished() {
                return true;
            }
            thread::sleep(Duration::from_millis(20));
        }
        false
    }

    #[test]
    fn shuts_down_after_heartbeat_timeout() {
        let mut cfg = mk_cfg();
        cfg.heartbeat_timeout_s = 1;
        let r = rig_with(cfg, |_| {}, false);
        let t = run_in_thread(&r, 100);
        assert_eq!(post_json(&r, "/api/heartbeat", &json!({})).status, 200);
        assert!(join_within(t, 4));
    }

    #[test]
    fn shuts_down_when_idle() {
        let mut cfg = mk_cfg();
        cfg.server_idle_timeout_s = 1;
        let r = rig_with(cfg, |_| {}, false);
        assert!(join_within(run_in_thread(&r, 100), 4));
    }

    #[test]
    fn slow_action_outlives_heartbeat_timeout() {
        let mut cfg = mk_cfg();
        cfg.heartbeat_timeout_s = 1;
        let r = rig_with(cfg, |_| {}, false);
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let release_rx = Mutex::new(release_rx);
        *r.fake.stop.lock().unwrap() = Some(Arc::new(move || {
            started_tx.send(()).ok();
            let _ = release_rx.lock().unwrap().recv_timeout(Duration::from_secs(10));
            done("slow done")
        }));
        let t = run_in_thread(&r, 100);
        assert_eq!(post_json(&r, "/api/heartbeat", &json!({})).status, 200);
        let port = r.port;
        let client = thread::spawn(move || {
            raw(port, "POST", "/api/action", &AUTH, br#"{"action":"stop","app_key":"suite:a"}"#)
        });
        started_rx.recv_timeout(Duration::from_secs(3)).expect("action started");
        thread::sleep(Duration::from_secs(2)); // well past the heartbeat timeout
        assert!(!t.is_finished());
        release_tx.send(()).unwrap();
        let resp = client.join().unwrap();
        assert_eq!((resp.status, resp.json()["message"].clone()), (200, json!("slow done")));
        assert!(join_within(t, 5)); // now the lapsed heartbeat may end it
    }

    #[test]
    fn real_exclude_keys_from_processes() {
        use crate::selfid::own_pids_in;
        let cfg = mk_cfg();
        let mut procs = vec![
            mkproc(10, 1, "me.exe", Some(r"C:\Program Files\Mine\me.exe")),
            mkproc(20, 1, "launcher.exe", Some(r"C:\Program Files\Launch\launcher.exe")),
            mkproc(30, 1, "python.exe", Some(r"C:\Program Files\Py\python.exe")),
            mkproc(40, 1, "other.exe", Some(r"C:\Program Files\Other\other.exe")),
        ];
        procs[2].cmdline = Some(["python.exe", "-m", "memwatch", "log"].map(String::from).to_vec());
        let mine = HashSet::from([10, 20]);
        let keys = exclude_keys_from(&procs, &mine, &cfg);
        let groups = grouping::group_processes(&procs, &Default::default(), &cfg);
        let key_of = |pid: u32| groups.iter().find(|(_, g)| g.pids.iter().any(|(p, _)| *p == pid)).unwrap().0.clone();
        assert_eq!(keys, HashSet::from([key_of(10), key_of(20), key_of(30)]));
        assert!(!keys.contains(&key_of(40)));
        let _ = own_pids_in; // exercised in selfid
    }

    #[test]
    fn internal_errors_are_json_500() {
        let r = rig();
        *r.fake.stop.lock().unwrap() = Some(Arc::new(|| panic!("secret detail")));
        let resp = raw(r.port, "POST", "/api/action", &AUTH, br#"{"action":"stop","app_key":"suite:a"}"#);
        assert_eq!(resp.status, 500);
        assert_eq!(resp.json(), json!({"error": "internal error"}));
        assert!(!String::from_utf8_lossy(&resp.body).contains("secret"));

        // a database that cannot be opened
        let srv = make_server(
            mk_cfg(),
            Box::new(|| Err(rusqlite::Error::InvalidQuery)),
            TOKEN.into(),
            Box::new(NoActions),
            Box::new(|_, _| None),
            Box::new(|_| HashSet::new()),
        )
        .unwrap();
        let workers = srv.start_workers(1);
        assert_eq!(raw(srv.port(), "GET", "/api/report", &AUTH, b"").status, 500);
        srv.stop();
        workers.into_iter().for_each(|w| w.join().unwrap());
    }

    #[test]
    fn body_cap_and_bad_content_length() {
        let r = rig();
        let big = format!(r#"{{"action":"stop","app_key":"suite:steam","pad":"{}"}}"#, "x".repeat(70000));
        assert_eq!(raw(r.port, "POST", "/api/action", &AUTH, big.as_bytes()).status, 413);
        for cl in ["abc", "-5"] {
            let h = [("X-Memwatch-Token", TOKEN), ("Content-Length", cl)];
            assert_eq!(raw(r.port, "POST", "/api/action", &h, b"").status, 400, "{cl}");
        }
        assert!(calls(&r).is_empty());
    }

    #[test]
    fn disable_startup_finds_entries_of_shared_service_group() {
        use crate::db::replace_startup;
        let r = rig_with(
            mk_cfg(),
            |c| {
                seed_with(c, "service:bits+wuauserv", 10, 50 << 20, &|g| {
                    g.kind = "windows".into();
                    g.services = vec!["BITS".into(), "wuauserv".into()];
                });
                let e = StartupEntry {
                    source: "service".into(),
                    name: "BITS".into(),
                    location: "BITS".into(),
                    command: "svchost.exe -k x".into(),
                    enabled: true,
                    needs_admin: true,
                    can_disable: true,
                    note: None,
                    app_key: Some("service:bits".into()),
                };
                replace_startup(c, &[e]).unwrap();
            },
            true,
        );
        let out = act(&r, json!({"action": "disable_startup", "app_key": "service:bits+wuauserv", "mode": "manual"}));
        assert_eq!(out["status"], "done");
        assert_eq!(calls(&r), [r#"disable_startup service:bits+wuauserv manual ["BITS"]"#]);
    }

    #[test]
    fn report_carries_data_ts_and_stale() {
        let r = rig();
        let rep = raw(r.port, "GET", "/api/report", &AUTH, b"").json();
        assert_eq!(rep["data_ts"], 29 * 60); // seeded at epoch 0..29 min
        assert_eq!(rep["stale"], true);
    }

    #[test]
    fn denied_and_oversized_posts_never_reset() {
        let r = rig();
        let (big, small) = (vec![b'x'; 200_000], vec![b'y'; 60_000]);
        let evil = [("Origin", "https://evil.example"), ("X-Memwatch-Token", TOKEN)];
        for _ in 0..40 {
            assert_eq!(raw(r.port, "POST", "/api/action", &[], &small).status, 403);
            assert_eq!(raw(r.port, "POST", "/api/action", &AUTH, &big).status, 413);
            assert_eq!(raw(r.port, "POST", "/api/heartbeat", &evil, &small).status, 403);
        }
        assert!(calls(&r).is_empty());
    }

    #[test]
    fn tokens_are_43_url_safe_chars_and_differ() {
        let (a, b) = (url_safe_token(), url_safe_token());
        assert_eq!(a.len(), 43);
        assert!(a.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'));
        assert_ne!(a, b);
    }

    #[test]
    fn query_params_decode() {
        assert_eq!(query_param("a=1&t=x%2Dy", "t").as_deref(), Some("x-y"));
        assert_eq!(query_param("a=1", "t"), None);
    }
}
