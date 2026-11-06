//! Intruder: § positions, four attack types, payload sets, attack results windows.

mod payload;
mod positions;
mod results;
mod ui;

pub(crate) use payload::*;
pub(crate) use positions::*;
pub(crate) use results::*;
pub(crate) use ui::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attack_types() {
        let t = "a=§1§&b=§2§";
        let s = vec![
            vec!["x".into(), "y".into()],
            vec!["p".into(), "q".into(), "r".into()],
        ];
        let sn: Vec<String> = generate(t, 0, &s).into_iter().map(|j| j.1).collect();
        assert_eq!(sn, ["a=x&b=2", "a=y&b=2", "a=1&b=x", "a=1&b=y"]);
        let br: Vec<String> = generate(t, 1, &s).into_iter().map(|j| j.1).collect();
        assert_eq!(br, ["a=x&b=x", "a=y&b=y"]);
        let pf: Vec<String> = generate(t, 2, &s).into_iter().map(|j| j.1).collect();
        assert_eq!(pf, ["a=x&b=p", "a=y&b=q"]);
        assert_eq!(generate(t, 3, &s).len(), 6);
        assert_eq!(
            Payload::Numbers {
                from: 3,
                to: 1,
                step: 1
            }
            .values(),
            ["3", "2", "1"]
        );
        assert_eq!(
            auto_positions("GET /?a=1&b=2 HTTP/1.1\r\nHost: h\r\n\r\n"),
            "GET /?a=§1§&b=§2§ HTTP/1.1\r\nHost: h\r\n\r\n"
        );
    }

    #[test]
    fn pro_payloads_processing_grep() {
        assert_eq!(
            Payload::BruteForce {
                charset: "ab".into(),
                min: 1,
                max: 2
            }
            .values(),
            ["a", "b", "aa", "ab", "ba", "bb"]
        );
        assert_eq!(Payload::Null(3).values(), ["", "", ""]);
        assert_eq!(
            Payload::CharBlocks {
                base: "A".into(),
                from: 1,
                to: 5,
                step: 2
            }
            .values(),
            ["A", "AAA", "AAAAA"]
        );
        assert!(
            Payload::RuntimeFile("/nonexistent".into())
                .values()
                .is_empty()
        );
        let rules = vec![
            (0, "<".into(), String::new()),
            (2, "b+".into(), "X".into()),
            (9, String::new(), String::new()),
        ];
        assert_eq!(process(&rules, "abbc").as_deref(), Some("<AXC"));
        assert_eq!(
            process(&[(6, "SHA-256".into(), String::new())], "a")
                .unwrap()
                .len(),
            64
        );
        assert_eq!(
            process(&[(10, "^skip".into(), String::new())], "skip me"),
            None
        );
        let g = Grep {
            matches: vec!["SQL syntax".into()],
            extracts: vec![regex::Regex::new("<title>(.*?)</title>").unwrap()],
            payloads: true,
        };
        assert_eq!(
            g.columns(),
            ["SQL syntax", "<title>(.*?)</title>", "Payload reflected"]
        );
        assert_eq!(
            g.cells(
                "<title>Err</title> You have an error in your sql syntax near '<x>'",
                &["%3cx%3e".into()]
            ),
            ["Yes", "Err", "Yes"]
        );
        assert_eq!(g.cells("ok", &["zz".into()]), ["", "", ""]);
    }
}
