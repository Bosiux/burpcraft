//! Issue reports: a standalone HTML page (summary by severity, then each issue with its evidence) and an XML export.
use crate::codec::html_encode;
use crate::proxy::Entry;
use crate::scanner::{Issue, Severity};

fn esc(s: &str) -> String {
    html_encode(s.as_bytes(), false)
}

/// Evidence text for an issue: request and response, cut so a report of binary/large bodies stays readable.
fn evidence(e: Option<&Entry>) -> (String, String) {
    let cut = |b: &[u8]| {
        let t = crate::proxy::display(b);
        if t.len() > 20_000 {
            format!(
                "{}\n[... {} more bytes]",
                &t[..t.floor_char_boundary(20_000)],
                t.len() - 20_000
            )
        } else {
            t
        }
    };
    e.map(|e| (cut(&e.req), cut(&e.resp))).unwrap_or_default()
}

fn sorted(issues: &[Issue]) -> Vec<&Issue> {
    let mut v: Vec<&Issue> = issues.iter().collect();
    v.sort_by(|a, b| a.severity.cmp(&b.severity).then(a.id.cmp(&b.id)));
    v
}

pub fn html(issues: &[Issue], history: &[Entry], title: &str) -> String {
    let count = |s: Severity| issues.iter().filter(|i| i.severity == s).count();
    let mut out = format!(
        "<!doctype html><html><head><meta charset=utf-8><title>{t}</title><style>\
body{{font-family:-apple-system,Segoe UI,sans-serif;max-width:1000px;margin:24px auto;padding:0 16px;color:#222}}\
h1{{color:#e8590c}} table{{border-collapse:collapse}} td,th{{border:1px solid #ccc;padding:4px 10px;text-align:left}}\
.High{{color:#c00}} .Medium{{color:#e8590c}} .Low{{color:#b8860b}} .Information{{color:#2266aa}}\
pre{{background:#f6f6f6;padding:8px;overflow:auto;white-space:pre-wrap;word-break:break-all;font-size:12px}}\
.issue{{border-top:2px solid #eee;margin-top:24px}}</style></head><body><h1>{t}</h1><p>Generated {now}</p>\
<h2>Summary</h2><table><tr><th>Severity</th><th>Issues</th></tr>",
        t = esc(title),
        now = esc(&crate::proxy::now())
    );
    for s in [
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        out += &format!(
            "<tr><td class={l}>{l}</td><td>{}</td></tr>",
            count(s),
            l = s.label()
        );
    }
    out += "</table><h2>Contents</h2><ol>";
    let list = sorted(issues);
    for (n, i) in list.iter().enumerate() {
        out += &format!(
            "<li><a href=#i{n}>{}</a> &ndash; {}{}</li>",
            esc(i.name),
            esc(&i.origin),
            esc(&i.path)
        );
    }
    out += "</ol>";
    for (n, i) in list.iter().enumerate() {
        let (req, resp) = evidence(history.iter().find(|e| e.id == i.entry_id));
        out += &format!(
            "<div class=issue id=i{n}><h2>{n1}. {name}</h2><table><tr><th>Severity</th><td class={sev}>{sev}</td></tr>\
<tr><th>Confidence</th><td>{conf}</td></tr><tr><th>Host</th><td>{host}</td></tr><tr><th>Path</th><td>{path}</td></tr></table>\
<h3>Issue detail</h3><p>{detail}</p><h3>Issue background</h3><p>{bg}</p><h3>Issue remediation</h3><p>{rem}</p>\
<h3>Request</h3><pre>{req}</pre><h3>Response</h3><pre>{resp}</pre></div>",
            n1 = n + 1,
            name = esc(i.name),
            sev = i.severity.label(),
            conf = esc(i.confidence),
            host = esc(&i.origin),
            path = esc(&i.path),
            detail = esc(&i.detail),
            bg = esc(i.background),
            rem = esc(i.remediation),
            req = esc(&req),
            resp = esc(&resp),
        );
    }
    out + "</body></html>"
}

fn xml_esc(s: &str) -> String {
    // XML 1.0 forbids most control characters even when escaped
    s.chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
        .collect::<String>()
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub fn xml(issues: &[Issue], history: &[Entry]) -> String {
    use crate::codec::base64_encode as encode;
    let mut out = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<issues burpcraftVersion=\"{}\" exportTime=\"{}\">\n",
        env!("CARGO_PKG_VERSION"),
        xml_esc(&crate::proxy::now())
    );
    for i in sorted(issues) {
        let e = history.iter().find(|e| e.id == i.entry_id);
        out += &format!(
            "  <issue>\n    <name>{}</name>\n    <host>{}</host>\n    <path>{}</path>\n    <severity>{}</severity>\n    <confidence>{}</confidence>\n    <issueDetail>{}</issueDetail>\n    <issueBackground>{}</issueBackground>\n    <remediationBackground>{}</remediationBackground>\n",
            xml_esc(i.name),
            xml_esc(&i.origin),
            xml_esc(&i.path),
            i.severity.label(),
            xml_esc(i.confidence),
            xml_esc(&i.detail),
            xml_esc(i.background),
            xml_esc(i.remediation)
        );
        if let Some(e) = e {
            // raw bytes as base64, like the original's export option, so binary bodies survive
            out += &format!(
                "    <requestresponse>\n      <request base64=\"true\">{}</request>\n      <response base64=\"true\">{}</response>\n    </requestresponse>\n",
                encode(&e.req),
                encode(&e.resp)
            );
        }
        out += "  </issue>\n";
    }
    out + "</issues>\n"
}

/// Writes a report next to the projects (`~/.burpcraft/reports/`), returning its path.
pub fn write(
    issues: &[Issue],
    history: &[Entry],
    as_html: bool,
) -> std::io::Result<std::path::PathBuf> {
    let dir = crate::net::data_dir().join("reports");
    std::fs::create_dir_all(&dir)?;
    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
    let path = dir.join(format!(
        "report-{stamp}.{}",
        if as_html { "html" } else { "xml" }
    ));
    let body = if as_html {
        html(issues, history, "BurpCraft scan report")
    } else {
        xml(issues, history)
    };
    std::fs::write(&path, body)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports() {
        let issue = Issue {
            id: 1,
            name: "Cross-site <scripting>",
            severity: Severity::High,
            confidence: "Certain",
            origin: "https://a.test".into(),
            path: "/q".into(),
            detail: "x & y".into(),
            background: "b",
            remediation: "r",
            entry_id: 5,
        };
        let entry = Entry {
            id: 5,
            host: "a.test".into(),
            port: 443,
            tls: true,
            method: "GET".into(),
            url: "/q".into(),
            status: 200,
            req: b"GET /q HTTP/1.1\r\n\r\n".to_vec(),
            resp: b"HTTP/1.1 200 OK\r\n\r\n<script>\x01".to_vec(),
            edited: false,
            time: String::new(),
            ip: String::new(),
            listener: 8080,
            comment: String::new(),
            highlight: None,
            tool: "Proxy",
        };
        let h = html(
            std::slice::from_ref(&issue),
            std::slice::from_ref(&entry),
            "R",
        );
        assert!(
            h.contains("Cross-site &lt;scripting&gt;")
                && h.contains("&lt;script&gt;")
                && !h.contains("<script>")
        );
        assert!(h.contains("<td class=High>High</td><td>1</td>"));
        let x = xml(&[issue], &[entry]);
        assert!(
            x.contains("<name>Cross-site &lt;scripting&gt;</name>")
                && x.contains("<issueDetail>x &amp; y</issueDetail>")
        );
        assert!(x.contains(
            "<response base64=\"true\">SFRUUC8xLjEgMjAwIE9LDQoNCjxzY3JpcHQ+AQ==</response>"
        ));
    }
}
