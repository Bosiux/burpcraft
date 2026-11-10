//! Panic fuzzing of every parser that reads bytes a target server, a web page or a shared file controls.
//! Deterministic (fixed seed, so a failure reproduces) and fast enough for `cargo test`; set
//! `BURPCRAFT_FUZZ_ITERS` for a longer run. A panic prints the offending input.
// ponytail: mutation fuzzing in a unit test; cargo-fuzz (coverage-guided) needs a lib target first
use std::io::Write;
use std::panic::{AssertUnwindSafe, catch_unwind};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

/// Byte sequences that steer parsers into their edge cases.
const TOKENS: &[&[u8]] = &[
    b"\r\n",
    b"\r\n\r\n",
    b"\n",
    b":",
    b";",
    b"=",
    b"&",
    b"%",
    b"%%",
    b"%zz",
    b"&#",
    b"&#x;",
    b"\0",
    b"Transfer-Encoding: chunked\r\n",
    b"Content-Length: ",
    b"Content-Encoding: gzip\r\n",
    b"ffffffffffffffff",
    b"99999999999999999999",
    b"-1",
    b"0\r\n\r\n",
    b"{",
    b"}",
    b"[",
    b"]",
    b"\"",
    b"\\u",
    b"\xff\xfe",
    b"\xc3",
    b"\xe2\x82",
    b"\x7f\xff\xff\xff",
    b"\x81\xff",
    b"<",
    b">",
    b"/*",
    b"*/",
    b"  ",
    b"\t",
    b"#",
    b"..",
    b"\xf0\x9f\x92",
];

fn mutate(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    let mut v = seed.to_vec();
    for _ in 0..1 + rng.below(8) {
        let at = rng.below(v.len() + 1);
        match rng.below(6) {
            0 if !v.is_empty() => {
                let i = rng.below(v.len());
                v[i] ^= 1 << rng.below(8);
            }
            1 if !v.is_empty() => {
                let end = (at + rng.below(16)).min(v.len());
                v.drain(at.min(end)..end);
            }
            2 => v
                .splice(at..at, TOKENS[rng.below(TOKENS.len())].iter().copied())
                .for_each(drop),
            3 => v.truncate(at),
            4 if !v.is_empty() => {
                // duplicate a slice: repeated headers, nested structures
                let s = rng.below(v.len());
                let e = (s + rng.below(32)).min(v.len());
                let chunk = v[s..e].to_vec();
                v.splice(at..at, chunk).for_each(drop);
            }
            _ => v.insert(at, rng.next() as u8),
        }
    }
    v
}

fn iters() -> usize {
    std::env::var("BURPCRAFT_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1500)
}

/// Runs `f` on mutations of every seed; a panic fails the test with the input that caused it.
fn fuzz(name: &str, seeds: &[&[u8]], f: impl Fn(&[u8])) {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ name.len() as u64);
    for i in 0..iters() {
        let input = mutate(&mut rng, seeds[i % seeds.len()]);
        if catch_unwind(AssertUnwindSafe(|| f(&input))).is_err() {
            panic!(
                "{name}: panic on input {:?}",
                String::from_utf8_lossy(&input)
            );
        }
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

const REQ: &[u8] = b"POST /a/b.php?x=1&y=%41 HTTP/1.1\r\nHost: t.test\r\nCookie: a=1; b=2\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 7\r\n\r\nq=1&r=2";
const JSON_REQ: &[u8] = b"POST /api HTTP/1.1\r\nHost: t.test\r\nContent-Type: application/json\r\nContent-Length: 27\r\n\r\n{\"a\":[1,{\"b\":\"c\"}],\"d\":null}";
const MULTIPART: &[u8] = b"POST /up HTTP/1.1\r\nHost: t.test\r\nContent-Type: multipart/form-data; boundary=XX\r\n\r\n--XX\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\n\r\nhi\r\n--XX--\r\n";
const CHUNKED: &[u8] = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nSet-Cookie: s=1; Path=/\r\nContent-Type: text/html\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
const HTML: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 98\r\n\r\n<html><form action=/l method=post><input type=password name=p></form><a href='mailto:a@b.c'>x</a></html>";

#[test]
fn http_messages() {
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(b"compressed body").unwrap();
    let gzipped = [
        &b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 35\r\n\r\n"[..],
        &gz.finish().unwrap(),
    ]
    .concat();
    fuzz("http", &[REQ, JSON_REQ, CHUNKED, HTML, &gzipped], |b| {
        for resp in [false, true] {
            let _ = crate::http::net::read_message(&mut std::io::BufReader::new(b), resp, false);
        }
        let _ = (
            crate::proxy::body_bytes(b),
            crate::proxy::display(b),
            crate::proxy::head(b),
        );
        let _ = crate::http::h2up::parse(b);
    });
}

#[test]
fn websocket_frames() {
    fuzz(
        "ws",
        &[
            b"\x81\x05hello",
            b"\x81\x85abcd\x09\x07\x0f\x08\x0e",
            b"\x82\x7e\x00\x02hi",
            b"\x88\x00",
        ],
        |b| {
            let _ = crate::proxy::ws_frames(&mut b.to_vec());
        },
    );
}

#[test]
fn scanner_inputs() {
    fuzz(
        "scan",
        &[
            REQ,
            JSON_REQ,
            MULTIPART,
            b"GET /x/1/y HTTP/1.1\r\nHost: t\r\nX-A: 1\r\n\r\n",
        ],
        |b| {
            let req = text(b);
            for p in crate::scan::points(&req).iter().take(8) {
                let _ = crate::scan::inject(&req, p, "'\"<x>");
            }
            let _ = crate::scan::parse_url(&req);
        },
    );
    fuzz("passive", &[CHUNKED, HTML], |b| {
        let e = crate::proxy::Entry {
            id: 1,
            host: "t.test".into(),
            port: 80,
            tls: false,
            method: "GET".into(),
            url: "/".into(),
            status: 200,
            req: REQ.to_vec(),
            resp: b.to_vec(),
            edited: false,
            time: String::new(),
            ip: String::new(),
            listener: 8080,
            comment: String::new(),
            highlight: None,
            tool: "Proxy",
        };
        let _ = crate::security::scanner::passive(&e);
    });
}

#[test]
fn text_formats() {
    let bcheck: &[u8] = b"metadata:\n    language: v2-beta\n    name: \"x\"\n\ngiven response then\n    if {latest.response.body} matches \"a.+b\" then\n        report issue:\n            severity: low\n            confidence: firm\n    end if\n";
    fuzz("bcheck", &[bcheck], |b| {
        let _ = crate::security::bcheck::parse(&text(b));
    });
    let openapi: &[u8] = b"{\"openapi\":\"3.0.0\",\"servers\":[{\"url\":\"http://t\"}],\"paths\":{\"/p/{id}\":{\"get\":{\"parameters\":[{\"name\":\"id\",\"in\":\"path\"}]}}}}";
    let yaml: &[u8] = b"swagger: \"2.0\"\nhost: t\npaths:\n  /a:\n    post:\n      parameters:\n        - name: q\n          in: query\n        - {name: b, in: body}\n";
    fuzz("openapi", &[openapi, yaml], |b| {
        let _ = crate::automation::openapi::parse_any(&text(b));
    });
    fuzz(
        "css",
        &[b"a.b > c:hover, #d { color: #fff; margin: 1px 2px } p{color:rgb(1,2,3)}"],
        |b| {
            let css = text(b);
            let _ = crate::render::css::parse_css(&css);
            let _ = crate::render::css::parse_color(&css);
        },
    );
    fuzz(
        "codec",
        &[b"aGVsbG8=", b"%41%zz&#65;&#x41;&lt;", b"0a1B"],
        |b| {
            let t = text(b);
            let _ = crate::http::codec::base64_decode(&t);
            let _ = crate::http::codec::url_decode(&t);
            let _ = crate::http::codec::html_decode(&t);
            let _ = crate::http::codec::hex_decode(&t);
        },
    );
    fuzz(
        "responses",
        &[
            b"{\"content\":[{\"type\":\"text\",\"text\":\"x\"}],\"stop_reason\":\"end_turn\"}",
            b"[{\"sink\":\"innerHTML\",\"url\":\"http://t/\"}]",
        ],
        |b| {
            let _ = crate::project::ai::parse_response(200, &text(b));
            let _ = crate::security::domi::parse_findings(&text(b));
        },
    );
}

#[test]
fn project_files() {
    let app = crate::App::blank(crate::proxy::Shared::new());
    {
        let mut s = app.state.lock().unwrap();
        s.event("Proxy", "seed");
    }
    let file = crate::project::project::encode(&app);
    fuzz("project", &[&file], |b| {
        let _ =
            crate::project::project::decode(&mut crate::App::blank(crate::proxy::Shared::new()), b);
    });
}

/// Inputs the fuzzer found, kept so the fixes stay fixed whatever the iteration count.
#[test]
fn found_crashes() {
    // non-ASCII in hex / HTML-entity input (Decoder, MCP decode)
    assert_eq!(crate::http::codec::hex_decode("\u{fffd}\u{fffd}"), None);
    assert_eq!(crate::http::codec::hex_decode("4 1"), Some(vec![0x41]));
    let _ = crate::http::codec::html_decode("&lt;&\u{fffd}6&#x41\u{fffd};");
    // truncated / huge chunk sizes from a server (passive scanner, viewers)
    assert_eq!(crate::proxy::dechunk(b"5\r\nhello\r\n3\r\nab"), b"hello");
    assert_eq!(crate::proxy::dechunk(b"ffffffffffffffff\r\nx\r\n"), b"");
    // a WebSocket frame claiming a 2^64-1 byte payload
    let mut f = b"\x81\x7f\xff\xff\xff\xff\xff\xff\xff\xffab".to_vec();
    assert!(crate::proxy::ws_frames(&mut f).is_empty());
    // multipart part without the CRLF before the next boundary
    let req = "POST / HTTP/1.1\r\nContent-Type: multipart/form-data; boundary=X\r\n\r\n--X\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv\u{fffd}--X--";
    for p in crate::scan::points(req) {
        let _ = crate::scan::inject(req, &p, "x");
    }
}
