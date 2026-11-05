//! `burpcraft-server`: self-hosted Collaborator. Example (public, needs root for low ports and an
//! NS record delegating the domain to this host):
//!   burpcraft-server --domain oast.example.com --public-ip 203.0.113.7 --bind 0.0.0.0 --dns 53 --http 80 --smtp 25 --secret s3cret
//! Local testing (no DNS, path-based payloads):
//!   burpcraft-server --http 8053
use burpcraft_server::{Config, start};

const USAGE: &str = "usage: burpcraft-server [--domain D] [--public-ip IP] [--bind IP] [--http PORT] [--dns PORT] [--smtp PORT] [--secret S] [--bapps DIR]";

fn main() {
    let mut cfg = Config {
        http_port: 8053,
        ..Default::default()
    };
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let Some(v) = args.next() else {
            eprintln!("{USAGE}");
            std::process::exit(2);
        };
        let port = || v.parse::<u16>().unwrap_or_else(|_| panic!("bad port: {v}"));
        match flag.as_str() {
            "--domain" => cfg.domain = v.clone(),
            "--public-ip" => cfg.public_ip = v.parse().expect("bad --public-ip"),
            "--bind" => cfg.bind = v.parse().expect("bad --bind"),
            "--http" => cfg.http_port = port(),
            "--dns" => cfg.dns_port = Some(port()),
            "--smtp" => cfg.smtp_port = Some(port()),
            "--secret" => cfg.secret = v.clone(),
            "--bapps" => cfg.bapps = Some(v.clone().into()),
            _ => {
                eprintln!("{USAGE}");
                std::process::exit(2);
            }
        }
    }
    let srv = start(cfg.clone()).unwrap_or_else(|e| {
        eprintln!("failed to start: {e}");
        std::process::exit(1);
    });
    println!(
        "BurpCraft Collaborator on {}: http {}, dns {}, smtp {}, domain {:?}{}",
        cfg.bind,
        srv.http_port,
        srv.dns_port.map_or("off".into(), |p| p.to_string()),
        srv.smtp_port.map_or("off".into(), |p| p.to_string()),
        cfg.domain,
        if cfg.secret.is_empty() {
            " (no poll secret)"
        } else {
            ""
        }
    );
    loop {
        std::thread::park();
    }
}
