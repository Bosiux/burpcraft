//! API-definition scanning: turns an OpenAPI 3 / Swagger 2 document (JSON or YAML) into one ready
//! request per operation (path, query, header and JSON/form body parameters filled from schema examples).
use crate::scan::{Target, parse_url};

#[derive(Clone, Debug, PartialEq)]
pub enum J {
    Null,
    Bool(bool),
    Num(String),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
}

impl J {
    pub fn get(&self, k: &str) -> Option<&J> {
        match self {
            J::Obj(v) => v.iter().find(|(x, _)| x == k).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn str(&self) -> Option<&str> {
        if let J::Str(s) = self { Some(s) } else { None }
    }
    fn entries(&self) -> &[(String, J)] {
        if let J::Obj(v) = self { v } else { &[] }
    }
    pub fn items(&self) -> &[J] {
        if let J::Arr(v) = self { v } else { &[] }
    }
    pub fn to_json(&self) -> String {
        match self {
            J::Null => "null".into(),
            J::Bool(b) => b.to_string(),
            J::Num(n) => n.clone(),
            J::Str(s) => {
                let mut o = String::with_capacity(s.len() + 2);
                o.push('"');
                for c in s.chars() {
                    match c {
                        '"' => o.push_str("\\\""),
                        '\\' => o.push_str("\\\\"),
                        '\n' => o.push_str("\\n"),
                        '\r' => o.push_str("\\r"),
                        '\t' => o.push_str("\\t"),
                        c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
                        c => o.push(c),
                    }
                }
                o.push('"');
                o
            }
            J::Arr(v) => format!(
                "[{}]",
                v.iter().map(J::to_json).collect::<Vec<_>>().join(",")
            ),
            J::Obj(v) => format!(
                "{{{}}}",
                v.iter()
                    .map(|(k, v)| format!("{}:{}", J::Str(k.clone()).to_json(), v.to_json()))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        }
    }
}

pub fn parse(s: &str) -> Result<J, String> {
    let b = s.as_bytes();
    let mut i = 0;
    let v = value(b, &mut i, 0)?;
    ws(b, &mut i);
    if i != b.len() {
        Err(format!("trailing data at byte {i}"))
    } else {
        Ok(v)
    }
}

fn ws(b: &[u8], i: &mut usize) {
    while *i < b.len() && b[*i].is_ascii_whitespace() {
        *i += 1;
    }
}

fn value(b: &[u8], i: &mut usize, depth: usize) -> Result<J, String> {
    if depth > 200 {
        return Err("nesting too deep".into());
    }
    ws(b, i);
    let err = |i: usize| format!("unexpected input at byte {i}");
    match b.get(*i) {
        Some(b'{') => {
            *i += 1;
            let mut v = vec![];
            loop {
                ws(b, i);
                if b.get(*i) == Some(&b'}') {
                    *i += 1;
                    return Ok(J::Obj(v));
                }
                let J::Str(k) = value(b, i, depth + 1)? else {
                    return Err(err(*i));
                };
                ws(b, i);
                if b.get(*i) != Some(&b':') {
                    return Err(err(*i));
                }
                *i += 1;
                v.push((k, value(b, i, depth + 1)?));
                ws(b, i);
                match b.get(*i) {
                    Some(b',') => *i += 1,
                    Some(b'}') => {}
                    _ => return Err(err(*i)),
                }
            }
        }
        Some(b'[') => {
            *i += 1;
            let mut v = vec![];
            loop {
                ws(b, i);
                if b.get(*i) == Some(&b']') {
                    *i += 1;
                    return Ok(J::Arr(v));
                }
                v.push(value(b, i, depth + 1)?);
                ws(b, i);
                match b.get(*i) {
                    Some(b',') => *i += 1,
                    Some(b']') => {}
                    _ => return Err(err(*i)),
                }
            }
        }
        Some(b'"') => {
            *i += 1;
            let mut out = Vec::new();
            while let Some(&c) = b.get(*i) {
                *i += 1;
                match c {
                    b'"' => {
                        return String::from_utf8(out)
                            .map(J::Str)
                            .map_err(|_| "invalid UTF-8".into());
                    }
                    b'\\' => {
                        let e = *b.get(*i).ok_or_else(|| err(*i))?;
                        *i += 1;
                        match e {
                            b'n' => out.push(b'\n'),
                            b't' => out.push(b'\t'),
                            b'r' => out.push(b'\r'),
                            b'b' => out.push(8),
                            b'f' => out.push(12),
                            b'u' => {
                                let hex =
                                    std::str::from_utf8(b.get(*i..*i + 4).ok_or_else(|| err(*i))?)
                                        .map_err(|_| err(*i))?;
                                *i += 4;
                                let ch = char::from_u32(
                                    u32::from_str_radix(hex, 16).map_err(|_| err(*i))?,
                                )
                                .unwrap_or('\u{FFFD}');
                                out.extend_from_slice(ch.to_string().as_bytes());
                            }
                            c => out.push(c),
                        }
                    }
                    c => out.push(c),
                }
            }
            Err("unterminated string".into())
        }
        Some(b't') if b[*i..].starts_with(b"true") => {
            *i += 4;
            Ok(J::Bool(true))
        }
        Some(b'f') if b[*i..].starts_with(b"false") => {
            *i += 5;
            Ok(J::Bool(false))
        }
        Some(b'n') if b[*i..].starts_with(b"null") => {
            *i += 4;
            Ok(J::Null)
        }
        Some(c) if c.is_ascii_digit() || *c == b'-' => {
            let s = *i;
            while *i < b.len() && (b[*i].is_ascii_digit() || b"+-.eE".contains(&b[*i])) {
                *i += 1;
            }
            Ok(J::Num(String::from_utf8_lossy(&b[s..*i]).into_owned()))
        }
        _ => Err(err(*i)),
    }
}

/// Follows a local `$ref` (`#/components/schemas/X`, `#/definitions/X`).
fn resolve<'a>(doc: &'a J, mut s: &'a J) -> &'a J {
    for _ in 0..20 {
        let Some(r) = s
            .get("$ref")
            .and_then(J::str)
            .and_then(|r| r.strip_prefix("#/"))
        else {
            break;
        };
        match r.split('/').try_fold(doc, |acc, k| acc.get(k)) {
            Some(t) => s = t,
            None => break,
        }
    }
    s
}

/// Example value for a schema: example/default/enum, else a typical value of its type.
pub fn example(doc: &J, schema: &J, depth: usize) -> J {
    let s = resolve(doc, schema);
    if let Some(v) = s
        .get("example")
        .or(s.get("default"))
        .or_else(|| s.get("enum").and_then(|e| e.items().first()))
    {
        return v.clone();
    }
    if depth > 8 {
        return J::Null;
    }
    match s
        .get("type")
        .and_then(J::str)
        .unwrap_or(if s.get("properties").is_some() {
            "object"
        } else {
            "string"
        }) {
        "integer" | "number" => J::Num("1".into()),
        "boolean" => J::Bool(true),
        "array" => J::Arr(vec![example(
            doc,
            s.get("items").unwrap_or(&J::Null),
            depth + 1,
        )]),
        "object" => J::Obj(
            s.get("properties")
                .map(|p| {
                    p.entries()
                        .iter()
                        .map(|(k, v)| (k.clone(), example(doc, v, depth + 1)))
                        .collect()
                })
                .unwrap_or_default(),
        ),
        _ => J::Str("test".into()),
    }
}

fn scalar(j: &J) -> String {
    match j {
        J::Str(s) => s.clone(),
        J::Null => String::new(),
        other => other.to_json(),
    }
}

/// One raw request per operation. `base` (e.g. the scan URL) overrides the document's server.
pub fn requests(doc: &J, base: Option<&str>) -> Result<Vec<(Target, String)>, String> {
    let server = match base {
        Some(b) => b.trim_end_matches('/').to_string(),
        None => {
            if let Some(u) = doc
                .get("servers")
                .and_then(|s| s.items().first())
                .and_then(|s| s.get("url"))
                .and_then(J::str)
            {
                u.trim_end_matches('/').to_string()
            } else if let Some(h) = doc.get("host").and_then(J::str) {
                let scheme = doc
                    .get("schemes")
                    .and_then(|s| s.items().first())
                    .and_then(J::str)
                    .unwrap_or("https");
                format!(
                    "{scheme}://{h}{}",
                    doc.get("basePath")
                        .and_then(J::str)
                        .unwrap_or("")
                        .trim_end_matches('/')
                )
            } else {
                return Err(
                    "the definition has no server; enter the API's base URL in the URLs box".into(),
                );
            }
        }
    };
    let (target, prefix) =
        parse_url(&server).ok_or_else(|| format!("not an absolute http(s) URL: {server}"))?;
    let prefix = prefix.trim_end_matches('/').to_string();
    let host = if (target.tls && target.port == 443) || (!target.tls && target.port == 80) {
        target.host.clone()
    } else {
        format!("{}:{}", target.host, target.port)
    };
    let paths = doc.get("paths").ok_or("no \"paths\" in the definition")?;
    let mut out = vec![];
    for (path, item) in paths.entries() {
        let shared: Vec<&J> = item
            .get("parameters")
            .map(|p| p.items().iter().collect())
            .unwrap_or_default();
        for (method, op) in item.entries().iter().filter(|(m, _)| {
            ["get", "post", "put", "patch", "delete", "head", "options"].contains(&m.as_str())
        }) {
            let (mut p, mut query, mut headers, mut body, mut ctype) =
                (path.clone(), vec![], String::new(), String::new(), "");
            let params = shared.iter().copied().chain(
                op.get("parameters")
                    .map(|p| p.items().iter().collect::<Vec<_>>())
                    .unwrap_or_default(),
            );
            for param in params {
                let param = resolve(doc, param);
                let name = param.get("name").and_then(J::str).unwrap_or("");
                // Swagger 2 keeps the type on the parameter, OpenAPI 3 in `schema`
                let v = param
                    .get("example")
                    .cloned()
                    .unwrap_or_else(|| example(doc, param.get("schema").unwrap_or(param), 0));
                match param.get("in").and_then(J::str).unwrap_or("") {
                    "path" => {
                        p = p.replace(
                            &format!("{{{name}}}"),
                            &crate::http::codec::url_encode(scalar(&v).as_bytes(), false),
                        )
                    }
                    "query" => query.push(format!(
                        "{name}={}",
                        crate::http::codec::url_encode(scalar(&v).as_bytes(), false)
                    )),
                    "header" => headers += &format!("{name}: {}\r\n", scalar(&v)),
                    "body" => (body, ctype) = (v.to_json(), "application/json"),
                    "formData" => {
                        body += &format!(
                            "{}{name}={}",
                            if body.is_empty() { "" } else { "&" },
                            crate::http::codec::url_encode(scalar(&v).as_bytes(), false)
                        );
                        ctype = "application/x-www-form-urlencoded";
                    }
                    _ => {}
                }
            }
            if let Some(content) = op
                .get("requestBody")
                .map(|b| resolve(doc, b))
                .and_then(|b| b.get("content"))
            {
                if let Some(m) = content.get("application/json").or_else(|| {
                    content
                        .entries()
                        .iter()
                        .find(|(k, _)| k.contains("json"))
                        .map(|(_, v)| v)
                }) {
                    let schema = m.get("schema").unwrap_or(&J::Null);
                    (body, ctype) = (
                        m.get("example")
                            .cloned()
                            .unwrap_or_else(|| example(doc, schema, 0))
                            .to_json(),
                        "application/json",
                    );
                } else if let Some(m) = content.get("application/x-www-form-urlencoded") {
                    let ex = example(doc, m.get("schema").unwrap_or(&J::Null), 0);
                    body = ex
                        .entries()
                        .iter()
                        .map(|(k, v)| {
                            format!(
                                "{k}={}",
                                crate::http::codec::url_encode(scalar(v).as_bytes(), false)
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("&");
                    ctype = "application/x-www-form-urlencoded";
                }
            }
            let q = if query.is_empty() {
                String::new()
            } else {
                format!("?{}", query.join("&"))
            };
            let ct = if body.is_empty() {
                String::new()
            } else {
                format!(
                    "Content-Type: {ctype}\r\nContent-Length: {}\r\n",
                    body.len()
                )
            };
            let req = format!(
                "{} {prefix}{p}{q} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 (BurpCraft Scanner)\r\nAccept: */*\r\n{headers}{ct}Connection: close\r\n\r\n{body}",
                method.to_ascii_uppercase()
            );
            out.push((target.clone(), req));
        }
    }
    Ok(out)
}

/// Parses a YAML document into the same tree as `parse` (first document of a stream).
// ponytail: aliases are expanded by copy (yaml-rust2), so a hostile "billion laughs" file can eat
// memory; fine for definitions the user picks, add an expansion budget if they ever come from the network
pub fn parse_yaml(s: &str) -> Result<J, String> {
    let docs = yaml_rust2::YamlLoader::load_from_str(s).map_err(|e| format!("YAML: {e}"))?;
    from_yaml(docs.first().ok_or("empty YAML document")?, 0)
}

fn from_yaml(y: &yaml_rust2::Yaml, depth: usize) -> Result<J, String> {
    use yaml_rust2::Yaml;
    if depth > 200 {
        return Err("nesting too deep".into());
    }
    Ok(match y {
        Yaml::Null => J::Null,
        Yaml::Boolean(b) => J::Bool(*b),
        Yaml::Integer(i) => J::Num(i.to_string()),
        // YAML reals (`.5`, `+1e3`, `.inf`) are not all valid JSON numbers: normalise them
        Yaml::Real(r) => match r.parse::<f64>() {
            Ok(f) if f.is_finite() => J::Num(f.to_string()),
            _ => J::Str(r.clone()),
        },
        Yaml::String(s) => J::Str(s.clone()),
        Yaml::Array(v) => J::Arr(
            v.iter()
                .map(|x| from_yaml(x, depth + 1))
                .collect::<Result<_, _>>()?,
        ),
        Yaml::Hash(h) => {
            let (mut out, mut merged): (Vec<(String, J)>, Vec<(String, J)>) = (vec![], vec![]);
            for (k, v) in h {
                let v = from_yaml(v, depth + 1)?;
                // `<<: *base` merge keys: explicit keys win over merged ones
                if k.as_str() == Some("<<") {
                    for m in std::iter::once(&v).chain(v.items()) {
                        merged.extend(m.entries().iter().cloned());
                    }
                    continue;
                }
                let k = match from_yaml(k, depth + 1)? {
                    J::Str(s) | J::Num(s) => s,
                    J::Bool(b) => b.to_string(),
                    J::Null => "null".into(),
                    _ => return Err("YAML: complex mapping keys are not supported".into()),
                };
                out.push((k, v));
            }
            for (k, v) in merged {
                if !out.iter().any(|(x, _)| *x == k) {
                    out.push((k, v));
                }
            }
            J::Obj(out)
        }
        Yaml::Alias(_) | Yaml::BadValue => return Err("YAML: unresolved alias".into()),
    })
}

/// Parses a definition from text, choosing YAML or JSON by content (JSON starts with `{`).
pub fn parse_any(text: &str) -> Result<J, String> {
    if text.trim_start().starts_with('{') {
        parse(text)
    } else {
        parse_yaml(text)
    }
}

/// Loads a definition file: YAML by extension (.yaml/.yml) or when it does not start with `{`.
pub fn load(path: &str, base: Option<&str>) -> Result<Vec<(Target, String)>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let lower = path.to_ascii_lowercase();
    let doc = if lower.ends_with(".yaml") || lower.ends_with(".yml") {
        parse_yaml(&text)?
    } else {
        parse_any(&text)?
    };
    requests(&doc, base)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OA3: &str = r##"{
          "openapi": "3.0.0", "servers": [{"url": "http://api.test:8080/v1"}],
          "components": {"schemas": {"User": {"type": "object", "properties": {"name": {"type": "string", "example": "bob"}, "age": {"type": "integer"}}}}},
          "paths": {
            "/users/{id}": {
              "parameters": [{"name": "id", "in": "path", "schema": {"type": "integer"}}],
              "get": {"parameters": [{"name": "fields", "in": "query", "schema": {"type": "string", "enum": ["all"]}}, {"name": "X-Key", "in": "header", "schema": {"type": "string"}}]},
              "put": {"requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/User"}}}}}
            }
          }}"##;
    const SW2: &str = r#"{"swagger": "2.0", "host": "old.test", "basePath": "/api", "schemes": ["https"],
          "paths": {"/login": {"post": {"parameters": [{"name": "user", "in": "formData", "type": "string"}, {"name": "pin", "in": "formData", "type": "integer"}]}}}}"#;

    #[test]
    fn json_parser() {
        let j = parse(r#" {"a": [1, -2.5e3, true, null], "b\"": "xé\n", "c": {}} "#).unwrap();
        assert_eq!(
            j.get("a"),
            Some(&J::Arr(vec![
                J::Num("1".into()),
                J::Num("-2.5e3".into()),
                J::Bool(true),
                J::Null
            ]))
        );
        assert_eq!(j.get("b\"").and_then(J::str), Some("xé\n"));
        assert_eq!(parse(&j.to_json()).unwrap(), j);
        assert!(
            parse("{\"a\":}").is_err()
                && parse("[1,2").is_err()
                && parse("1 2").is_err()
                && parse(&"[".repeat(500)).is_err()
        );
    }

    #[test]
    fn openapi3_and_swagger2() {
        let doc = parse(OA3).unwrap();
        let r = requests(&doc, None).unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!((r[0].0.host.as_str(), r[0].0.port), ("api.test", 8080));
        assert!(
            r[0].1
                .starts_with("GET /v1/users/1?fields=all HTTP/1.1\r\nHost: api.test:8080\r\n")
                && r[0].1.contains("X-Key: test\r\n")
        );
        assert!(
            r[1].1.starts_with("PUT /v1/users/1 HTTP/1.1")
                && r[1].1.ends_with("\r\n\r\n{\"name\":\"bob\",\"age\":1}")
                && r[1].1.contains("Content-Length: 22")
        );
        assert_eq!(crate::scan::points(&r[1].1).len(), 3); // name, age, User-Agent

        let sw = parse(SW2).unwrap();
        let r = requests(&sw, None).unwrap();
        assert!(
            r[0].0.tls
                && r[0]
                    .1
                    .starts_with("POST /api/login HTTP/1.1\r\nHost: old.test\r\n")
                && r[0].1.ends_with("user=test&pin=1")
        );
        // the scan URL overrides the document's server
        assert_eq!(
            requests(&sw, Some("http://127.0.0.1:9000")).unwrap()[0]
                .0
                .port,
            9000
        );
        assert!(requests(&parse(r#"{"paths": {}}"#).unwrap(), None).is_err());
    }

    #[test]
    fn parse_any_detects_format() {
        // JSON starts with `{`; anything else is treated as YAML
        assert_eq!(
            parse_any(r#"{"a":1}"#).unwrap(),
            parse_yaml("a: 1").unwrap()
        );
        assert_eq!(
            parse_any("a: 1\nb: 2").unwrap(),
            parse("{\"a\":1,\"b\":2}").unwrap()
        );
    }

    #[test]
    fn yaml_matches_json() {
        let oa3 = r##"
openapi: 3.0.0
servers:
  - url: http://api.test:8080/v1
components:
  schemas:
    User:
      type: object
      properties:
        name: {type: string, example: bob}
        age:
          type: integer
paths:
  /users/{id}:
    parameters:
      - name: id
        in: path
        schema: {type: integer}
    get:
      parameters:
        - {name: fields, in: query, schema: {type: string, enum: [all]}}
        - name: X-Key   # header
          in: header
          schema:
            type: string
    put:
      requestBody:
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/User'
"##;
        let sw = "swagger: '2.0'\nhost: old.test\nbasePath: /api\nschemes: [https]\npaths:\n  /login:\n    post:\n      parameters:\n        - {name: user, in: formData, type: string}\n        - {name: pin, in: formData, type: integer}\n";
        for (y, j) in [(oa3, OA3), (sw, SW2)] {
            let (y, j) = (parse_yaml(y).unwrap(), parse(j).unwrap());
            assert_eq!(y, j);
            let reqs = |d| {
                requests(d, None)
                    .unwrap()
                    .into_iter()
                    .map(|r| r.1)
                    .collect::<Vec<_>>()
            };
            assert_eq!(reqs(&y), reqs(&j));
        }
    }

    #[test]
    fn yaml_petstore() {
        let doc = parse_yaml(
            r##"
# petstore-like
openapi: "3.0.3"
info: {title: Petstore, version: 1.0.0}
servers: [{url: "https://pets.test/api/"}]
x-common: &common
  in: query
  schema: {type: integer, default: 20}
paths:
  /pets:
    get:
      parameters:
        - name: limit
          <<: *common
        - $ref: '#/components/parameters/Tag'
      responses:
        200: {description: ok}
    post:
      requestBody:
        $ref: '#/components/requestBodies/Pet'
components:
  parameters:
    Tag: {name: tag, in: query, schema: {type: string, example: "a b"}}
  requestBodies:
    Pet:
      content:
        application/json:
          schema: {$ref: '#/components/schemas/Pet'}
  schemas:
    Pet:
      type: object
      properties:
        name: {type: string, example: 'Rex'}
        price: {type: number, example: .5}
        note:
          type: string
          example: >
            folded
            text
        tags: {type: array, items: {type: string}}
"##,
        )
        .unwrap();
        let r = requests(&doc, None).unwrap();
        assert!(
            r[0].0.tls
                && r[0].1.starts_with(
                    "GET /api/pets?limit=20&tag=a%20b HTTP/1.1\r\nHost: pets.test\r\n"
                )
        );
        assert!(
            r[1].1.starts_with("POST /api/pets HTTP/1.1")
                && r[1].1.ends_with(
                    r#"{"name":"Rex","price":0.5,"note":"folded text\n","tags":["test"]}"#
                )
        );
        let get = doc
            .get("paths")
            .and_then(|p| p.get("/pets"))
            .and_then(|p| p.get("get"))
            .unwrap();
        assert!(get.get("responses").and_then(|r| r.get("200")).is_some());

        // load(): YAML by extension, and by content when the extension says nothing
        let dir = std::env::temp_dir();
        for name in ["bc-openapi-test.yml", "bc-openapi-test.txt"] {
            let f = dir.join(name);
            std::fs::write(&f, "swagger: '2.0'\nhost: h.test\npaths: {/a: {get: {}}}\n").unwrap();
            let r = load(f.to_str().unwrap(), None).unwrap();
            std::fs::remove_file(&f).unwrap();
            assert!(r[0].1.starts_with("GET /a HTTP/1.1\r\nHost: h.test\r\n"));
        }
        assert!(parse_yaml("a: [1").is_err() && parse_yaml("").is_err());
    }
}
