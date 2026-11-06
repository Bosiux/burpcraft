//! MCP server: lets AI agents drive the running app (traffic, send, intercept/MITM, rules, scope, scans,
//! Collaborator). JSON-RPC 2.0 over Streamable HTTP, plain JSON replies (no SSE), on 127.0.0.1 only.
//!
//!   BURPCRAFT_MCP=1338[:token] burpcraft
//!   claude mcp add --transport http burpcraft http://127.0.0.1:1338/mcp [--header "Authorization: Bearer <token>"]
//!
//! The tool descriptions in `TOOLS` are the documentation agents read: keep them short and exact.
use crate::openapi::{self, J};
use crate::proxy::State;
use crate::rest::Tasks;
use crate::target::Scope;

mod attack;
mod handlers;
mod helpers;
mod server;
#[cfg(test)]
mod tests;

use handlers::call;
use helpers::{n, obj, s, str_arg};
pub use server::start;

/// Everything the tools can reach.
#[derive(Clone)]
pub struct Ctx {
    pub state: State,
    pub tasks: Tasks,
    pub scope: Scope,
}

const INSTRUCTIONS: &str = "BurpCraft MCP: full control of the running BurpCraft proxy.
Messages are raw HTTP text; line endings may be \\n (sent as CRLF, Content-Length fixed for you).
`target` = scheme://host[:port] (default: https + the Host header). Request line `... HTTP/2` sends HTTP/2.
Typical loop: history_list -> history_get -> send (edit and replay) -> intruder / scan_start.
MITM: intercept {enabled:true} -> intercept_queue -> intercept_forward (optionally edited) / intercept_drop.
Bodies are decoded (chunked/gzip) and cut at max_bytes (default 20000). All calls return JSON.";

/// (name, description, JSON schema of the arguments).
const TOOLS: &[(&str, &str, &str)] = &[
    (
        "status",
        "Proxy listener, intercept state, counts (history, logger, websockets, issues, queue), CA cert path, Collaborator.",
        r#"{"type":"object","properties":{}}"#,
    ),
    (
        "history_list",
        "List captured requests (oldest first). source: proxy (default) or logger (all tools). Filters combine. Returns id, method, url, status, length, mime, tool.",
        r#"{"type":"object","properties":{"source":{"enum":["proxy","logger"]},"host":{"type":"string","description":"substring of host"},"method":{"type":"string"},"status":{"type":"integer"},"grep":{"type":"string","description":"regex over request+response"},"after_id":{"type":"integer","description":"only ids greater than this (poll for new traffic)"},"limit":{"type":"integer","description":"default 50, newest kept"}}}"#,
    ),
    (
        "history_get",
        "Full request and response of one history/logger item.",
        r#"{"type":"object","properties":{"id":{"type":"integer"},"source":{"enum":["proxy","logger"]},"max_bytes":{"type":"integer"}},"required":["id"]}"#,
    ),
    (
        "ws_list",
        "WebSocket messages seen by the proxy. direction: to_server true/false.",
        r#"{"type":"object","properties":{"grep":{"type":"string"},"after_id":{"type":"integer"},"limit":{"type":"integer"},"max_bytes":{"type":"integer"}}}"#,
    ),
    (
        "send",
        "Send one raw HTTP request (Repeater) and return the response. Logged in Logger as tool MCP.",
        r#"{"type":"object","properties":{"request":{"type":"string","description":"raw HTTP request"},"target":{"type":"string","description":"scheme://host[:port]"},"max_bytes":{"type":"integer"}},"required":["request"]}"#,
    ),
    (
        "intruder",
        "Run an attack synchronously. Mark positions with §value§. attack: sniper (default), battering_ram, pitchfork, cluster_bomb. payloads: one list per position (sniper/battering_ram use the first). Max 1000 requests. Returns status/length/ms per request and grep match. anomalies=true returns only the odd rows (error, status or length unlike the commonest response, ms > 3x median and >= 100 ms over it, grep match), each with `reasons`, plus total and baseline.",
        r#"{"type":"object","properties":{"request":{"type":"string"},"target":{"type":"string"},"attack":{"enum":["sniper","battering_ram","pitchfork","cluster_bomb"]},"payloads":{"type":"array","items":{"type":"array","items":{"type":"string"}}},"threads":{"type":"integer","description":"default 8"},"grep":{"type":"string","description":"regex; first match per response"},"anomalies":{"type":"boolean","description":"only anomalous rows, default false"}},"required":["request","payloads"]}"#,
    ),
    (
        "intercept",
        "Read or change intercept settings (only given fields change). Turning it off forwards everything queued. Returns settings and queue size.",
        r#"{"type":"object","properties":{"enabled":{"type":"boolean"},"responses":{"type":"boolean","description":"also hold responses"},"host":{"type":"string","description":"only hosts containing this ('' = all)"},"skip_ext":{"type":"string","description":"regex of file extensions not intercepted"}}}"#,
    ),
    (
        "intercept_queue",
        "Messages held by intercept, waiting for intercept_forward/intercept_drop. response=true means a held response.",
        r#"{"type":"object","properties":{"max_bytes":{"type":"integer"}}}"#,
    ),
    (
        "intercept_forward",
        "Release a held message by id, optionally replaced with an edited raw message.",
        r#"{"type":"object","properties":{"id":{"type":"integer"},"message":{"type":"string"}},"required":["id"]}"#,
    ),
    (
        "intercept_drop",
        "Drop a held message by id (the client gets an error).",
        r#"{"type":"object","properties":{"id":{"type":"integer"}},"required":["id"]}"#,
    ),
    (
        "rules",
        "Proxy match-and-replace rules. Without `set` returns them; `set` replaces the whole list. kind: request_header, request_body, response_header, response_body, request_first_line. Regex pattern; empty pattern on a header rule adds `replace` as a header.",
        r#"{"type":"object","properties":{"set":{"type":"array","items":{"type":"object","properties":{"enabled":{"type":"boolean"},"kind":{"type":"string"},"pattern":{"type":"string"},"replace":{"type":"string"},"comment":{"type":"string"}},"required":["kind","pattern","replace"]}}}}"#,
    ),
    (
        "scope",
        "Target scope (URL prefixes). Without `set` returns it; `set` replaces it. include=false excludes.",
        r#"{"type":"object","properties":{"set":{"type":"array","items":{"type":"object","properties":{"prefix":{"type":"string"},"include":{"type":"boolean"},"enabled":{"type":"boolean"}},"required":["prefix"]}}}}"#,
    ),
    (
        "scan_start",
        "Start an active scan in the background. Either urls (crawl + audit), one raw request + target (audit its parameters), or openapi (audit every operation; urls[0] overrides its server). headers/login authenticate every request. Returns task_id for scan_status.",
        r#"{"type":"object","properties":{"urls":{"type":"array","items":{"type":"string"}},"request":{"type":"string"},"target":{"type":"string"},"openapi":{"type":"string","description":"OpenAPI 3 / Swagger 2 definition, JSON or YAML text"},"headers":{"type":"string","description":"extra `Name: value` lines on every request"},"login":{"type":"string","description":"raw login request sent first; its cookies join every request"},"thorough":{"type":"boolean"},"crawl":{"type":"boolean","description":"default true"}}}"#,
    ),
    (
        "scan_status",
        "Scan progress and the issues it found. stop=true stops it.",
        r#"{"type":"object","properties":{"task_id":{"type":"integer"},"stop":{"type":"boolean"}},"required":["task_id"]}"#,
    ),
    (
        "issues",
        "All issues found so far (passive and active).",
        r#"{"type":"object","properties":{}}"#,
    ),
    (
        "codec",
        "Encode, decode or hash text. op: base64_encode, base64_decode, url_encode, url_decode, html_encode, html_decode, hex_encode, hex_decode, md5, sha1, sha256, sha384, sha512.",
        r#"{"type":"object","properties":{"op":{"type":"string"},"data":{"type":"string"}},"required":["op","data"]}"#,
    ),
    (
        "collaborator",
        "Out-of-band testing. builtin=true starts a local server; or configure server/domain/secret. payloads=n mints n payloads. Always polls and returns interactions.",
        r#"{"type":"object","properties":{"builtin":{"type":"boolean"},"server":{"type":"string"},"domain":{"type":"string"},"secret":{"type":"string"},"payloads":{"type":"integer"}}}"#,
    ),
    (
        "open_in",
        "Show a history/logger item in a UI tool for the human: repeater, intruder, organizer, sequencer, decoder, comparer.",
        r#"{"type":"object","properties":{"id":{"type":"integer"},"tool":{"type":"string"},"source":{"enum":["proxy","logger"]}},"required":["id","tool"]}"#,
    ),
    (
        "events",
        "App event log (proxy errors, extension output, ...), newest last.",
        r#"{"type":"object","properties":{"limit":{"type":"integer"}}}"#,
    ),
];

/// One JSON-RPC message in, the reply out (None for notifications).
pub fn handle(body: &str, ctx: &Ctx) -> Option<String> {
    let req = match openapi::parse(body) {
        Ok(j) => j,
        Err(e) => return Some(rpc_err(J::Null, -32700, &format!("parse error: {e}"))),
    };
    let id = req.get("id").cloned()?; // no id: notification, nothing to answer
    let params = req.get("params").cloned().unwrap_or(J::Obj(vec![]));
    let result = match req.get("method") {
        Some(J::Str(m)) if m == "initialize" => {
            let v = match params.get("protocolVersion") {
                Some(J::Str(v))
                    if ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"]
                        .contains(&v.as_str()) =>
                {
                    v.clone()
                }
                _ => "2025-06-18".into(),
            };
            obj(vec![
                ("protocolVersion", s(v)),
                ("capabilities", obj(vec![("tools", obj(vec![]))])),
                (
                    "serverInfo",
                    obj(vec![
                        ("name", s("burpcraft")),
                        ("version", s(env!("CARGO_PKG_VERSION"))),
                    ]),
                ),
                ("instructions", s(INSTRUCTIONS)),
            ])
        }
        Some(J::Str(m)) if m == "ping" => obj(vec![]),
        Some(J::Str(m)) if m == "tools/list" => obj(vec![(
            "tools",
            J::Arr(
                TOOLS
                    .iter()
                    .map(|(name, desc, schema)| {
                        obj(vec![
                            ("name", s(*name)),
                            ("description", s(*desc)),
                            ("inputSchema", openapi::parse(schema).expect("tool schema")),
                        ])
                    })
                    .collect(),
            ),
        )]),
        Some(J::Str(m)) if m == "tools/call" => {
            let name = str_arg(&params, "name").unwrap_or("");
            let args = params.get("arguments").cloned().unwrap_or(J::Obj(vec![]));
            let (text, err) = match call(name, &args, ctx) {
                Ok(j) => (j.to_json(), false),
                Err(e) => (e, true),
            };
            obj(vec![
                (
                    "content",
                    J::Arr(vec![obj(vec![("type", s("text")), ("text", s(text))])]),
                ),
                ("isError", J::Bool(err)),
            ])
        }
        _ => return Some(rpc_err(id, -32601, "method not found")),
    };
    Some(obj(vec![("jsonrpc", s("2.0")), ("id", id), ("result", result)]).to_json())
}

fn rpc_err(id: J, code: i32, msg: &str) -> String {
    obj(vec![
        ("jsonrpc", s("2.0")),
        ("id", id),
        ("error", obj(vec![("code", n(code)), ("message", s(msg))])),
    ])
    .to_json()
}
