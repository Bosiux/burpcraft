//! Performance baseline: `cargo test --release perf -- --ignored --nocapture` prints the numbers the
//! plan tracks (proxy overhead, passive scan cost, project save/load at scale). Measure before optimising.
// ponytail: wall-clock on the current machine, not a CI gate; instruction-count benches if one is needed
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

const BODY: &[u8] = b"<html><head><title>t</title></head><body><form action=/l method=post><input name=u><input type=password name=p></form><a href='/a?x=1'>a</a> mail me at dev@example.test</body></html>";

/// Origin answering every connection with one HTML page, like a typical proxied site.
fn origin() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for c in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut r = BufReader::new(c.try_clone().unwrap());
                let mut line = String::new();
                while r.read_line(&mut line).is_ok_and(|n| n > 2) {
                    line.clear();
                }
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: Apache/2.4.1\r\nSet-Cookie: sid=1; Path=/\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    BODY.len()
                );
                let mut c = c;
                let _ = c.write_all(&[head.as_bytes(), BODY].concat());
            });
        }
    });
    port
}

fn get(via: u16, target: u16, path: &str) {
    let mut s = TcpStream::connect(("127.0.0.1", via)).unwrap();
    let uri = if via == target {
        path.to_string()
    } else {
        format!("http://127.0.0.1:{target}{path}")
    };
    write!(
        s,
        "GET {uri} HTTP/1.1\r\nHost: 127.0.0.1:{target}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut out = vec![];
    s.read_to_end(&mut out).unwrap();
    assert!(
        out.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&out)
    );
}

/// Mean per request over `n`, from `threads` clients in parallel; returns (per-request, requests/s).
fn load(n: usize, threads: usize, f: impl Fn(usize) + Sync) -> (Duration, f64) {
    let t = Instant::now();
    std::thread::scope(|s| {
        for k in 0..threads {
            let f = &f;
            s.spawn(move || (k..n).step_by(threads).for_each(f));
        }
    });
    let e = t.elapsed();
    (e * threads as u32 / n as u32, n as f64 / e.as_secs_f64())
}

#[test]
#[ignore = "benchmark: cargo test --release perf -- --ignored --nocapture"]
fn baseline() {
    let state = crate::proxy::Shared::new();
    let ca = std::sync::Arc::new(crate::http::net::Ca::load_or_create().unwrap());
    crate::proxy::start(state.clone(), ca, 0);
    let proxy = crate::proxy::listen_port().unwrap();
    let target = origin();
    let n = 2000;
    let mut rows = vec![];
    for threads in [1, 8] {
        let (direct, _) = load(n, threads, |i| get(target, target, &format!("/d{i}")));
        let (proxied, rps) = load(n, threads, |i| get(proxy, target, &format!("/p{i}?q={i}")));
        rows.push(format!(
            "proxy, {threads} client(s): {:>7.0} µs/request direct, {:>7.0} µs proxied (+{:.0} µs), {rps:.0} req/s",
            direct.as_secs_f64() * 1e6,
            proxied.as_secs_f64() * 1e6,
            (proxied.as_secs_f64() - direct.as_secs_f64()) * 1e6
        ));
    }

    let entries: Vec<_> = state.lock().unwrap().history.clone();
    assert!(entries.len() >= 2 * n, "history has {}", entries.len());
    let t = Instant::now();
    let issues: usize = entries
        .iter()
        .map(|e| crate::security::scanner::passive(e).len())
        .sum();
    rows.push(format!(
        "passive scan: {:.1} µs/entry ({issues} issues over {} entries)",
        t.elapsed().as_secs_f64() * 1e6 / entries.len() as f64,
        entries.len()
    ));

    let mut app = crate::App::blank(crate::proxy::Shared::new());
    app.state.lock().unwrap().history = entries.iter().cycle().take(100_000).cloned().collect();
    let t = Instant::now();
    let file = crate::project::project::encode(&app);
    let enc = t.elapsed();
    let t = Instant::now();
    crate::project::project::decode(&mut crate::App::blank(crate::proxy::Shared::new()), &file)
        .unwrap();
    rows.push(format!(
        "project, 100k entries: encode {:.0} ms, decode {:.0} ms, {:.1} MB before gzip",
        enc.as_secs_f64() * 1e3,
        t.elapsed().as_secs_f64() * 1e3,
        file.len() as f64 / 1e6
    ));
    println!("\n{}", rows.join("\n"));
}
