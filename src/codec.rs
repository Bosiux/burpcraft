//! Encoders/decoders used by Decoder, the Inspector and the cert export.

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::new();
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                out.push(B64[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Lenient decoder: accepts the URL-safe alphabet, missing padding and whitespace.
pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0);
    for ch in s.bytes() {
        let v = match ch {
            b'A'..=b'Z' => ch - b'A',
            b'a'..=b'z' => ch - b'a' + 26,
            b'0'..=b'9' => ch - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' | b' ' | b'\r' | b'\n' | b'\t' => continue,
            _ => return None,
        };
        acc = acc << 6 | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

pub fn url_encode(data: &[u8], all: bool) -> String {
    data.iter()
        .map(|&b| {
            if !all && (b.is_ascii_alphanumeric() || b"-_.~".contains(&b)) {
                (b as char).to_string()
            } else {
                format!("%{b:02x}")
            }
        })
        .collect()
}

pub fn url_decode(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                match (
                    (b[i + 1] as char).to_digit(16),
                    (b[i + 2] as char).to_digit(16),
                ) {
                    (Some(h), Some(l)) => {
                        out.push((h * 16 + l) as u8);
                        i += 3;
                        continue;
                    }
                    _ => out.push(b'%'),
                }
            }
            b'+' => out.push(b' '),
            c => out.push(c),
        }
        i += 1;
    }
    out
}

pub fn html_encode(data: &[u8], all: bool) -> String {
    String::from_utf8_lossy(data)
        .chars()
        .map(|c| match c {
            '<' => "&lt;".into(),
            '>' => "&gt;".into(),
            '&' => "&amp;".into(),
            '"' => "&quot;".into(),
            '\'' => "&#x27;".into(),
            c if all => format!("&#x{:x};", c as u32),
            c => c.to_string(),
        })
        .collect()
}

pub fn html_decode(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let Some(end) = rest[..rest.len().min(12)].find(';') else {
            out.push('&');
            rest = &rest[1..];
            continue;
        };
        let ent = &rest[1..end];
        let ch = match ent {
            "lt" => Some('<'),
            "gt" => Some('>'),
            "amp" => Some('&'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            "nbsp" => Some('\u{a0}'),
            _ if ent.starts_with("#x") || ent.starts_with("#X") => {
                u32::from_str_radix(&ent[2..], 16)
                    .ok()
                    .and_then(char::from_u32)
            }
            _ if ent.starts_with('#') => ent[1..].parse().ok().and_then(char::from_u32),
            _ => None,
        };
        match ch {
            Some(c) => {
                out.push(c);
                rest = &rest[end + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out + rest
}

pub fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

pub fn octal_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("\\{b:o}")).collect()
}

pub fn binary_encode(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{b:08b}"))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn hash(alg: &str, data: &[u8]) -> String {
    use ring::digest::*;
    if alg == "MD5" {
        return format!("{:x}", md5::compute(data));
    }
    let a = match alg {
        "SHA-1" => &SHA1_FOR_LEGACY_USE_ONLY,
        "SHA-256" => &SHA256,
        "SHA-384" => &SHA384,
        _ => &SHA512,
    };
    hex_encode(digest(a, data).as_ref())
}

/// Classic hex dump rows: (offset, 16 hex bytes, ascii).
pub fn hexdump_rows(data: &[u8]) -> impl Iterator<Item = (usize, String, String)> + '_ {
    data.chunks(16).enumerate().map(|(i, c)| {
        let hex = c
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        let asc = c
            .iter()
            .map(|&b| {
                if (0x20..0x7f).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        (i * 16, hex, asc)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips() {
        for s in ["", "f", "fo", "foo", "foob", "fooba", "foobar"] {
            assert_eq!(
                base64_decode(&base64_encode(s.as_bytes())).unwrap(),
                s.as_bytes()
            );
        }
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(url_decode("a%20b+c%zz%4"), b"a b c%zz%4");
        assert_eq!(url_encode(b"a b/", false), "a%20b%2f");
        assert_eq!(html_decode("&lt;a&gt; &#65;&#x42; &bogus"), "<a> AB &bogus");
        assert_eq!(hex_decode("41 42"), Some(b"AB".to_vec()));
        assert_eq!(hash("SHA-256", b"").len(), 64);
    }
}
