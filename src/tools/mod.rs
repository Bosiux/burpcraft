//! Repeater, Decoder and Comparer.
mod comparer;
mod decoder;
mod repeater;

pub(crate) use comparer::Comparer;
pub(crate) use decoder::Decoder;
pub(crate) use repeater::{Repeater, fix_content_length};

#[cfg(test)]
use comparer::{Tag, diff};
#[cfg(test)]
use decoder::{apply, smart_decode};
#[cfg(test)]
use repeater::set_protocol;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_length_and_decode() {
        assert_eq!(
            fix_content_length("POST / HTTP/1.1\r\nContent-Length: 1\r\n\r\nabc"),
            "POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc"
        );
        assert_eq!(
            fix_content_length("GET / HTTP/1.1\r\nHost: a"),
            "GET / HTTP/1.1\r\nHost: a\r\n\r\n"
        );
        assert_eq!(smart_decode("JTNDYSUzRQ=="), "<a>");
        let h2 = set_protocol(
            "GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n",
            true,
        );
        assert_eq!(h2, "GET / HTTP/2\r\nHost: a\r\n\r\n");
        assert_eq!(
            set_protocol(&h2, false),
            "GET / HTTP/1.1\r\nHost: a\r\n\r\n"
        );
        assert_eq!(apply("d:Gzip", &apply("e:Gzip", "hello")), "hello");
        assert_eq!(apply("h:MD5", ""), "d41d8cd98f00b204e9800998ecf8427e");
        let (l, r) = diff("a b c", "a x c", true);
        assert!(l.iter().any(|(t, s)| *t == Tag::Modified && s == "b"));
        assert!(r.iter().any(|(t, s)| *t == Tag::Modified && s == "x"));
    }
}

pub mod engage;
pub mod search;
pub mod sequencer;
pub mod target;
