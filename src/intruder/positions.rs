//! § positions, the four attack types, and request generation.

pub const MARK: char = '§';
pub(crate) const ATTACKS: [&str; 4] = [
    "Sniper attack",
    "Battering ram attack",
    "Pitchfork attack",
    "Cluster bomb attack",
];

/// Splits a template on § markers: returns literal chunks (positions.len() + 1) and the default value of each position.
pub fn split_positions(t: &str) -> (Vec<String>, Vec<String>) {
    let parts: Vec<&str> = t.split(MARK).collect();
    if parts.len().is_multiple_of(2) {
        return (vec![t.to_string()], vec![]); // unbalanced markers: treat as no positions
    }
    let lits = parts.iter().step_by(2).map(|s| s.to_string()).collect();
    let defs = parts
        .iter()
        .skip(1)
        .step_by(2)
        .map(|s| s.to_string())
        .collect();
    (lits, defs)
}

fn build(lits: &[String], vals: &[String]) -> String {
    let mut s = lits[0].clone();
    for (v, l) in vals.iter().zip(&lits[1..]) {
        s.push_str(v);
        s.push_str(l);
    }
    s
}

/// Generates (payloads shown in the results table, request) for every attack request.
pub fn generate(template: &str, attack: usize, sets: &[Vec<String>]) -> Vec<(Vec<String>, String)> {
    let (lits, defs) = split_positions(template);
    let n = defs.len();
    let mut out = vec![];
    if n == 0 {
        return out;
    }
    let set = |i: usize| sets.get(i).cloned().unwrap_or_default();
    match attack {
        0 => {
            for p in 0..n {
                for v in set(0) {
                    let mut vals = defs.clone();
                    vals[p] = v.clone();
                    out.push((vec![v], build(&lits, &vals)));
                }
            }
        }
        1 => {
            for v in set(0) {
                out.push((vec![v.clone()], build(&lits, &vec![v; n])));
            }
        }
        2 => {
            let len = (0..n).map(|i| set(i).len()).min().unwrap_or(0);
            for k in 0..len {
                let vals: Vec<String> = (0..n).map(|i| set(i)[k].clone()).collect();
                out.push((vals.clone(), build(&lits, &vals)));
            }
        }
        _ => {
            let lists: Vec<Vec<String>> = (0..n).map(set).collect();
            if lists.iter().any(|l| l.is_empty()) {
                return out;
            }
            let mut idx = vec![0usize; n];
            loop {
                let vals: Vec<String> = (0..n).map(|i| lists[i][idx[i]].clone()).collect();
                out.push((vals.clone(), build(&lits, &vals)));
                // first position iterates fastest, like the original
                let mut i = 0;
                loop {
                    if i == n {
                        return out;
                    }
                    idx[i] += 1;
                    if idx[i] < lists[i].len() {
                        break;
                    }
                    idx[i] = 0;
                    i += 1;
                }
            }
        }
    }
    out
}

/// "Auto §": marks every query/body/cookie parameter value.
pub fn auto_positions(req: &str) -> String {
    let mark = |s: &str, sep: char| -> String {
        s.split(sep)
            .map(|kv| match kv.split_once('=') {
                Some((k, v)) => format!("{k}={MARK}{v}{MARK}"),
                None => kv.to_string(),
            })
            .collect::<Vec<_>>()
            .join(&sep.to_string())
    };
    let (head, body) = match req.split_once("\r\n\r\n") {
        Some((h, b)) => (h.to_string(), Some(b.to_string())),
        None => (req.to_string(), None),
    };
    let mut lines: Vec<String> = head.split("\r\n").map(String::from).collect();
    if let Some(first) = lines.first_mut()
        && let Some(q) = first.find('?')
    {
        let end = first[q..].find(' ').map(|e| q + e).unwrap_or(first.len());
        let marked = mark(&first[q + 1..end], '&');
        *first = format!("{}{}{}", &first[..=q], marked, &first[end..]);
    }
    for l in lines.iter_mut().skip(1) {
        if let Some(v) = l.strip_prefix("Cookie: ") {
            *l = format!("Cookie: {}", mark(v, ';'));
        }
    }
    let mut out = lines.join("\r\n");
    if let Some(b) = body {
        out.push_str("\r\n\r\n");
        let form = !b.trim_start().starts_with(['{', '[', '<']) && b.contains('=');
        out.push_str(&if form { mark(&b, '&') } else { b });
    }
    out
}
