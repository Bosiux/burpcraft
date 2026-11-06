//! Payload sets, their generators, payload processing rules, and built-in lists.

#[derive(Clone, PartialEq)]
pub enum Payload {
    List(Vec<String>),
    Numbers {
        from: i64,
        to: i64,
        step: i64,
    },
    /// One payload per line of a file, read when the attack starts.
    RuntimeFile(String),
    /// Every string over `charset` with length min..=max.
    BruteForce {
        charset: String,
        min: usize,
        max: usize,
    },
    /// N empty payloads: repeats the base request.
    Null(usize),
    /// `base` repeated from..=to times (step), for length/overflow tests.
    CharBlocks {
        base: String,
        from: usize,
        to: usize,
        step: usize,
    },
    /// N unique Collaborator payloads, minted when the attack starts.
    Collaborator(usize),
}

pub const PAYLOAD_TYPES: [&str; 7] = [
    "Simple list",
    "Runtime file",
    "Numbers",
    "Brute forcer",
    "Null payloads",
    "Character blocks",
    "Collaborator payloads",
];
pub(crate) const MAX_PAYLOADS: usize = 1_000_000;

impl Payload {
    pub(crate) fn kind(&self) -> usize {
        match self {
            Payload::List(_) => 0,
            Payload::RuntimeFile(_) => 1,
            Payload::Numbers { .. } => 2,
            Payload::BruteForce { .. } => 3,
            Payload::Null(_) => 4,
            Payload::CharBlocks { .. } => 5,
            Payload::Collaborator(_) => 6,
        }
    }
    pub(crate) fn of_kind(k: usize) -> Self {
        match k {
            1 => Payload::RuntimeFile(String::new()),
            2 => Payload::Numbers {
                from: 1,
                to: 10,
                step: 1,
            },
            3 => Payload::BruteForce {
                charset: "abcdefghijklmnopqrstuvwxyz0123456789".into(),
                min: 1,
                max: 3,
            },
            4 => Payload::Null(10),
            5 => Payload::CharBlocks {
                base: "A".into(),
                from: 1,
                to: 1000,
                step: 100,
            },
            6 => Payload::Collaborator(10),
            _ => Payload::List(vec![]),
        }
    }
    /// Values for an attack: like `values`, but Collaborator payloads are minted for real.
    pub fn resolve(&self) -> Vec<String> {
        match self {
            Payload::Collaborator(n) => {
                let mut c = crate::collab::client().lock().unwrap();
                (0..(*n).min(10_000))
                    .filter_map(|_| c.payload("Intruder"))
                    .collect()
            }
            _ => self.values(),
        }
    }
    pub fn values(&self) -> Vec<String> {
        match self {
            Payload::List(v) => v.clone(),
            Payload::RuntimeFile(path) => std::fs::read_to_string(path.trim())
                .map(|t| {
                    t.lines()
                        .filter(|l| !l.is_empty())
                        .take(MAX_PAYLOADS)
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default(),
            Payload::Null(n) => vec![String::new(); (*n).min(MAX_PAYLOADS)],
            // placeholders for counting; `resolve` mints the real ones
            Payload::Collaborator(n) => vec!["<collaborator payload>".into(); (*n).min(10_000)],
            Payload::CharBlocks {
                base,
                from,
                to,
                step,
            } => (*from..=*to)
                .step_by((*step).max(1))
                .take(MAX_PAYLOADS)
                .map(|n| base.repeat(n))
                .collect(),
            Payload::BruteForce { charset, min, max } => {
                let chars: Vec<char> = charset.chars().collect();
                let mut out = vec![];
                if chars.is_empty() {
                    return out;
                }
                for len in *min..=*max {
                    // odometer over `len` digits in base chars.len()
                    let mut idx = vec![0usize; len];
                    loop {
                        if out.len() >= MAX_PAYLOADS {
                            return out;
                        }
                        out.push(idx.iter().map(|&i| chars[i]).collect());
                        let Some(i) = (0..len).rev().find(|&i| idx[i] + 1 < chars.len()) else {
                            break;
                        };
                        idx[i] += 1;
                        idx[i + 1..].iter_mut().for_each(|x| *x = 0);
                    }
                }
                out
            }
            Payload::Numbers { from, to, step } => {
                let step = (*step).max(1);
                let mut out = vec![];
                let mut n = *from;
                while (from <= to && n <= *to) || (from > to && n >= *to) {
                    out.push(n.to_string());
                    n += if from <= to { step } else { -step };
                    if out.len() > 1_000_000 {
                        break;
                    }
                }
                out
            }
        }
    }
}

pub const RULES: [&str; 11] = [
    "Add prefix",
    "Add suffix",
    "Match/replace (regex)",
    "URL-encode all characters",
    "Base64-encode",
    "HTML-encode",
    "Hash (MD5, SHA-1, SHA-256)",
    "Reverse",
    "Convert to lower case",
    "Convert to upper case",
    "Skip if matches regex",
];

/// Applies payload processing rules in order; None means the payload is skipped.
pub fn process(rules: &[(usize, String, String)], v: &str) -> Option<String> {
    let mut v = v.to_string();
    for (kind, a, b) in rules {
        v = match kind {
            0 => format!("{a}{v}"),
            1 => format!("{v}{a}"),
            2 => regex::Regex::new(a)
                .map(|re| re.replace_all(&v, b.as_str()).into_owned())
                .unwrap_or(v),
            3 => crate::codec::url_encode(v.as_bytes(), true),
            4 => crate::codec::base64_encode(v.as_bytes()),
            5 => crate::codec::html_encode(v.as_bytes(), false),
            6 => crate::codec::hash(
                if a.trim().is_empty() { "MD5" } else { a.trim() },
                v.as_bytes(),
            ),
            7 => v.chars().rev().collect(),
            8 => v.to_lowercase(),
            9 => v.to_uppercase(),
            _ if regex::Regex::new(a).is_ok_and(|re| re.is_match(&v)) => return None,
            _ => v,
        };
    }
    Some(v)
}

pub(crate) fn intruder_encode(v: &str) -> String {
    v.chars()
        .map(|c| {
            if "./\\=<>?+&*;:\"{}|^`# ".contains(c) {
                format!("%{:02x}", c as u32)
            } else {
                c.to_string()
            }
        })
        .collect()
}

pub(crate) fn builtin_lists() -> Vec<(&'static str, Vec<&'static str>)> {
    vec![
        (
            "Usernames",
            vec![
                "admin",
                "administrator",
                "root",
                "test",
                "guest",
                "user",
                "info",
                "adm",
                "mysql",
                "oracle",
            ],
        ),
        (
            "Passwords",
            vec![
                "password",
                "123456",
                "12345678",
                "admin",
                "qwerty",
                "letmein",
                "welcome",
                "monkey",
                "password1",
                "abc123",
            ],
        ),
        (
            "Fuzzing - quick",
            vec![
                "'",
                "\"",
                "<",
                ">",
                "'--",
                "\" or 1=1--",
                "<script>alert(1)</script>",
                "../../../../etc/passwd",
                "${7*7}",
                "{{7*7}}",
                "%00",
                "|id",
            ],
        ),
        (
            "Directories - short",
            vec![
                "admin", "login", "api", "backup", "config", "uploads", "images", "js", "css",
                ".git", "test", "dev",
            ],
        ),
    ]
}
