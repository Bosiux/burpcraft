//! BApp Store client: fetch the catalogue and install BApps from a self-hosted burpcraft-server.
use super::runtime::load;

// ------------------------------------------------------------ BApp Store client

/// Catalogue entry: (name, version, description, file).
pub type BApp = (String, String, String, String);

fn http_get(server: &str, path: &str) -> Result<Vec<u8>, String> {
    let (host, port) = server
        .rsplit_once(':')
        .map(|(h, p)| (h.to_string(), p.parse().unwrap_or(80)))
        .unwrap_or((server.to_string(), 80));
    let req = format!("GET {path} HTTP/1.1\r\nHost: {server}\r\nConnection: close\r\n\r\n");
    let resp = crate::net::send(&host, port, false, req.as_bytes()).map_err(|e| e.to_string())?;
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
    let body = http_get(server, "/burpcraft/bapps")?;
    Ok(String::from_utf8_lossy(&body)
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            (f.len() == 4).then(|| (f[0].into(), f[1].into(), f[2].into(), f[3].into()))
        })
        .collect())
}

/// Downloads a BApp into ~/.burpcraft/bapps and loads it; returns the command line used.
pub fn install(server: &str, app: &BApp) -> Result<String, String> {
    if app.3.contains('/') || app.3.contains("..") {
        return Err("invalid file name in catalogue".into());
    }
    let data = http_get(server, &format!("/burpcraft/bapps/{}", app.3))?;
    let dir = crate::net::data_dir().join("bapps");
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
