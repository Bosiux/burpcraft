//! BApp Store client: fetch the catalogue and install BApps from a self-hosted burpcraft-server.
use super::runtime::load;

// ------------------------------------------------------------ BApp Store client

/// Catalogue entry: (name, version, description, file, sha256 of the file).
pub type BApp = (String, String, String, String, String);

/// `server` is `host[:port]` (plain HTTP) or `https://host[:port]` (certificate-verified TLS).
fn http_get(server: &str, path: &str) -> Result<Vec<u8>, String> {
    let (tls, server) = match server.strip_prefix("https://") {
        Some(s) => (true, s),
        None => (false, server.strip_prefix("http://").unwrap_or(server)),
    };
    let default = if tls { 443 } else { 80 };
    let (host, port) = server
        .rsplit_once(':')
        .map(|(h, p)| (h.to_string(), p.parse().unwrap_or(default)))
        .unwrap_or((server.to_string(), default));
    let req = format!("GET {path} HTTP/1.1\r\nHost: {server}\r\nConnection: close\r\n\r\n");
    let resp = if tls {
        crate::http::net::send_verified(&host, port, req.as_bytes())
    } else {
        crate::http::net::send(&host, port, false, req.as_bytes())
    }
    .map_err(|e| e.to_string())?;
    if !String::from_utf8_lossy(crate::proxy::head(&resp)).starts_with("HTTP/1.1 200") {
        return Err(String::from_utf8_lossy(crate::proxy::head(&resp))
            .lines()
            .next()
            .unwrap_or("")
            .to_string());
    }
    Ok(crate::proxy::body_bytes(&resp))
}

pub fn store_list(server: &str) -> Result<Vec<BApp>, String> {
    Ok(parse_catalog(&http_get(server, "/burpcraft/bapps")?))
}

/// One BApp per line: name, version, description, file, sha256 (tab-separated). Lines without a
/// well-formed hash are skipped: an entry that cannot be verified is never offered.
fn parse_catalog(body: &[u8]) -> Vec<BApp> {
    String::from_utf8_lossy(body)
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            (f.len() == 5 && f[4].len() == 64 && f[4].bytes().all(|b| b.is_ascii_hexdigit())).then(
                || {
                    let h = f[4].to_ascii_lowercase();
                    (f[0].into(), f[1].into(), f[2].into(), f[3].into(), h)
                },
            )
        })
        .collect()
}

fn verify(app: &BApp, data: &[u8]) -> Result<(), String> {
    let got = crate::http::codec::hash("SHA-256", data);
    if got == app.4 {
        return Ok(());
    }
    Err(format!(
        "{} does not match the catalogue (sha256 {got}, expected {}); not installed",
        app.3, app.4
    ))
}

/// Downloads a BApp into ~/.burpcraft/bapps and loads it; returns the command line used.
pub fn install(server: &str, app: &BApp) -> Result<String, String> {
    if app.3.contains('/') || app.3.contains("..") {
        return Err("invalid file name in catalogue".into());
    }
    let data = http_get(server, &format!("/burpcraft/bapps/{}", app.3))?;
    // the file is executed next: it must be exactly what the catalogue lists
    verify(app, &data)?;
    let dir = crate::http::net::data_dir().join("bapps");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let file = dir.join(&app.3);
    std::fs::write(&file, &data).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755));
    }
    // scripts run through their interpreter so no shebang/exec bit is needed
    let cmd = match file.extension().and_then(|e| e.to_str()) {
        Some("py") => format!("python3 {}", file.display()),
        Some("js") => format!("node {}", file.display()),
        Some("sh") => format!("sh {}", file.display()),
        _ => file.display().to_string(),
    };
    load(&cmd);
    Ok(cmd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_needs_a_hash() {
        let h = "AB".repeat(32);
        let body = format!(
            "Ok\t1.0\tdesc\tok.py\t{h}\nNo hash\t1.0\tdesc\tx.py\nShort\t1.0\td\ty.py\tabc\nBad hex\t1\td\tz.py\t{}\n",
            "zz".repeat(32)
        );
        let c = parse_catalog(body.as_bytes());
        assert_eq!(c.len(), 1);
        assert_eq!(
            (c[0].3.as_str(), c[0].4.as_str()),
            ("ok.py", h.to_lowercase().as_str())
        );
    }

    #[test]
    fn verify_matches_the_catalogue_hash() {
        // sha256("abc"), FIPS 180-2 test vector
        let h = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let app =
            parse_catalog(format!("A\t1\td\ta.py\t{}\n", h.to_uppercase()).as_bytes()).remove(0);
        assert!(verify(&app, b"abc").is_ok());
        assert!(verify(&app, b"abd").is_err());
    }

    #[test]
    fn tampered_file_is_not_installed() {
        let dir = std::env::temp_dir().join(format!("burpcraft-bapps-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("catalog.tsv"), "").unwrap();
        std::fs::write(dir.join("t.py"), "print('evil')").unwrap();
        let srv = burpcraft_server::start(burpcraft_server::Config {
            bapps: Some(dir.clone()),
            ..Default::default()
        })
        .unwrap();
        let good = crate::http::codec::hash("SHA-256", b"print('hi')");
        std::fs::write(dir.join("catalog.tsv"), format!("T\t1\td\tt.py\t{good}\n")).unwrap();
        let server = format!("127.0.0.1:{}", srv.http_port);
        let app = store_list(&server).unwrap().remove(0);
        let e = install(&server, &app).unwrap_err();
        // checked before anything is written to ~/.burpcraft/bapps or run
        assert!(e.contains("does not match"), "{e}");
        let _ = std::fs::remove_dir_all(dir);
    }
}
