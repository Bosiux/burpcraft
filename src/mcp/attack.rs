//! The intruder attack runner (threaded request fan-out) and the anomaly filter
//! that flags odd response rows against a computed baseline.
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use crate::openapi::J;
use crate::{intruder, http::net, proxy, tools};

use super::Ctx;
use super::helpers::{bool_arg, n, num_arg, obj, raw, s, str_arg, strs, target};

pub(crate) fn intruder_attack(a: &J, ctx: &Ctx, grep: Option<regex::Regex>) -> Result<J, String> {
    let template = raw(str_arg(a, "request").ok_or("`request` required")?);
    let t = target(a, &template.replace('§', ""))?;
    let attack = match str_arg(a, "attack").unwrap_or("sniper") {
        "sniper" => 0,
        "battering_ram" => 1,
        "pitchfork" => 2,
        "cluster_bomb" => 3,
        x => return Err(format!("bad attack {x:?}")),
    };
    let sets: Vec<Vec<String>> = match a.get("payloads") {
        Some(J::Arr(v)) => v.iter().map(strs).collect(),
        _ => return Err("`payloads` must be a list of string lists".into()),
    };
    let reqs = intruder::generate(&template, attack, &sets);
    if reqs.is_empty() {
        return Err("no requests: mark positions with §value§ and give payloads".into());
    }
    // ponytail: hard cap keeps one call fast; split bigger attacks into several calls
    if reqs.len() > 1000 {
        return Err(format!("{} requests: max 1000 per call", reqs.len()));
    }
    let threads = num_arg(a, "threads").unwrap_or(8).clamp(1, 32) as usize;
    let next = AtomicUsize::new(0);
    let rows: Mutex<Vec<(usize, J)>> = Mutex::new(vec![]);
    std::thread::scope(|sc| {
        for _ in 0..threads {
            sc.spawn(|| {
                loop {
                    let k = next.fetch_add(1, Ordering::SeqCst);
                    let Some((payloads, req)) = reqs.get(k) else {
                        break;
                    };
                    let req = tools::fix_content_length(req);
                    let t0 = Instant::now();
                    let res = net::send(&t.host, t.port, t.tls, req.as_bytes());
                    let ms = t0.elapsed().as_millis();
                    let row = match &res {
                        Ok(resp) => {
                            ctx.state.lock().unwrap().log_tool(
                                "MCP",
                                &t.host,
                                t.port,
                                t.tls,
                                req.as_bytes(),
                                resp,
                            );
                            let body = proxy::display(resp);
                            let m = grep
                                .as_ref()
                                .and_then(|g| g.find(&body))
                                .map(|m| s(m.as_str()));
                            obj(vec![
                                (
                                    "payloads",
                                    J::Arr(payloads.iter().cloned().map(s).collect()),
                                ),
                                ("status", n(proxy::status_of(resp))),
                                ("length", n(resp.len())),
                                ("ms", n(ms)),
                                ("match", m.unwrap_or(J::Null)),
                            ])
                        }
                        Err(e) => obj(vec![
                            (
                                "payloads",
                                J::Arr(payloads.iter().cloned().map(s).collect()),
                            ),
                            ("error", s(e.to_string())),
                        ]),
                    };
                    rows.lock().unwrap().push((k, row));
                }
            });
        }
    });
    let mut rows = rows.into_inner().unwrap();
    rows.sort_by_key(|r| r.0);
    let rows: Vec<J> = rows.into_iter().map(|r| r.1).collect();
    Ok(if bool_arg(a, "anomalies") == Some(true) {
        anomalies(rows)
    } else {
        J::Arr(rows)
    })
}

/// Only the odd intruder rows. Baseline = the commonest (status, length) among rows without `error`;
/// length matches within the `soft_404` tolerance (exact, or 2% above 200 bytes). A row is anomalous
/// for `error`, `status`, `length`, `time` (ms > 3x median and >= 100 ms over it) or `grep` (match set).
pub(crate) fn anomalies(rows: Vec<J>) -> J {
    fn nu(r: &J, k: &str) -> i64 {
        num_arg(r, k).unwrap_or(0)
    }
    let compat = |a: i64, b: i64| b == a || (a > 200 && a.abs_diff(b) <= (a / 50) as u64);
    let ok: Vec<&J> = rows.iter().filter(|r| r.get("error").is_none()).collect();
    // ponytail: O(n^2) baseline search, fine for the 1000-request cap; bucket by status if the cap grows
    let mut base: Option<(i64, i64, usize)> = None;
    for r in &ok {
        let (st, len) = (nu(r, "status"), nu(r, "length"));
        let c = ok
            .iter()
            .filter(|o| nu(o, "status") == st && compat(len, nu(o, "length")))
            .count();
        if base.is_none_or(|(_, _, bc)| c > bc) {
            base = Some((st, len, c));
        }
    }
    let mut ms: Vec<i64> = ok.iter().map(|r| nu(r, "ms")).collect();
    ms.sort_unstable();
    let med = ms.get(ms.len() / 2).copied().unwrap_or(0);
    let mut out = vec![];
    for r in &rows {
        let mut why = vec![];
        if r.get("error").is_some() {
            why.push("error");
        } else if let Some((bs, bl, _)) = base {
            if nu(r, "status") != bs {
                why.push("status");
            }
            if !compat(bl, nu(r, "length")) {
                why.push("length");
            }
            let t = nu(r, "ms");
            if t > 3 * med && t - med >= 100 {
                why.push("time");
            }
            if !matches!(r.get("match"), None | Some(J::Null)) {
                why.push("grep");
            }
        }
        if let (false, J::Obj(mut v)) = (why.is_empty(), r.clone()) {
            v.push(("reasons".into(), J::Arr(why.into_iter().map(s).collect())));
            out.push(J::Obj(v));
        }
    }
    obj(vec![
        ("total", n(rows.len())),
        (
            "baseline",
            base.map_or(J::Null, |(st, len, c)| {
                obj(vec![
                    ("status", n(st)),
                    ("length", n(len)),
                    ("count", n(c)),
                    ("median_ms", n(med)),
                ])
            }),
        ),
        ("anomalies", J::Arr(out)),
    ])
}
