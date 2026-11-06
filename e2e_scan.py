#!/usr/bin/env python3
"""End-to-end check of BurpCraft's scanner, Intruder, Collaborator, Repeater and intercept (stdlib only).

Starts a deliberately vulnerable web app on 127.0.0.1 (one endpoint per issue class, each with a safe
twin under /safe/ that must stay clean), then drives the RUNNING app over its REST API and MCP server.
Prints a PASS/FAIL table and exits non-zero on any failure.

    BURPCRAFT_API=1337 BURPCRAFT_MCP=1338 burpcraft &      # then:
    python3 e2e_scan.py                                    # or let it start an isolated app:
    python3 e2e_scan.py --launch target/debug/burpcraft    # temp HOME, ports from E2E_* below

Ports: E2E_PROXY (8080), E2E_API (1337), E2E_MCP (1338), E2E_APP (9020; E2E_APP+1 is an out-of-scope
origin the scanner must never touch). Nothing is executed: injections are simulated by pattern matching,
and the only outbound fetches go to 127.0.0.1 (the built-in Collaborator).
"""
import json, os, re, socket, socketserver, subprocess, sys, tempfile, threading, time
import urllib.parse, urllib.request

PROXY = int(os.environ.get("E2E_PROXY", 8080))
API = int(os.environ.get("E2E_API", 1337))
MCP = int(os.environ.get("E2E_MCP", 1338))
APP = int(os.environ.get("E2E_APP", 9020))
OOS = APP + 1
SMUGGLE = APP + 2  # raw CL.TE/TE.CL front end, only started when E2E_SMUGGLE=1
BASE = f"http://127.0.0.1:{APP}"
BCHECK_LOADED = False  # set in main() when --launch wrote a BCheck into the app's data dir

LOG = []  # (method, target, headers dict, body) of every request the app received
LOCK = threading.Lock()
INFLIGHT = [0, 0]  # current, max concurrent requests
OOS_HITS = []

# ------------------------------------------------------------------ the vulnerable app

INDEX = """<html><body><h1>Shop</h1>
<a href="/sqli/error?id=1">a</a> <a href="/safe/sqli/error?id=1">a</a>
<a href="/sqli/bool?id=1">b</a> <a href="/safe/sqli/bool?id=1">b</a>
<a href="/sqli/time?id=1">c</a> <a href="/safe/sqli/time?id=1">c</a>
<a href="/xss/query?q=hi">d</a> <a href="/safe/xss/query?q=hi">d</a>
<a href="/file?name=a.txt">e</a> <a href="/safe/file?name=a.txt">e</a>
<a href="/tpl?name=bob">f</a> <a href="/safe/tpl?name=bob">f</a>
<a href="/go?url=/home">g</a> <a href="/safe/go?url=/home">g</a>
<a href="/hdr?lang=en">h</a> <a href="/safe/hdr?lang=en">h</a>
<a href="/cmd?host=example.org">i</a> <a href="/safe/cmd?host=example.org">i</a>
<a href="/fetch?u=http://example.invalid/">j</a> <a href="/safe/fetch?u=http://example.invalid/">j</a>
<a href="/account?q=me">k</a> <a href="/logo.png">img</a>
<a href="http://127.0.0.1:{oos}/oos?x=1">out of scope</a> <a href="//127.0.0.1:{oos}/proto?x=1">oos2</a>
<form method="post" action="/xss/body"><input name="comment" value="hi"></form>
<form method="post" action="/safe/xss/body"><input name="comment" value="hi"></form>
<form method="post" action="http://127.0.0.1:{oos}/oosform"><input name="z"></form>
<form method="post" action="/login"><input name="user"><input type="password" name="pass"></form>
</body></html>"""

OPENAPI = {
    "openapi": "3.0.0",
    "info": {"title": "shop", "version": "1"},
    "servers": [{"url": BASE}],
    "paths": {
        "/api/search": {"get": {"parameters": [{"name": "q", "in": "query", "schema": {"type": "string"}}]}},
        "/api/safe/search": {"get": {"parameters": [{"name": "q", "in": "query", "schema": {"type": "string"}}]}},
        "/api/items": {"post": {"requestBody": {"content": {"application/json": {"schema": {
            "type": "object", "properties": {"name": {"type": "string"}}}}}}}},
    },
}

SESSION = "s3ss10n-ok"
STORE = {False: "", True: ""}  # last comment stored per side (vulnerable / safe), for stored XSS
ESC = lambda s: s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;")


def sleep_for(v, patterns):
    """Simulated injection: sleeps when a payload pattern (seconds in group 1) matches. Capped at 6 s."""
    for p in patterns:
        m = re.search(p, v, re.I)
        if m:
            time.sleep(min(int(m.group(1)), 6))
            return


def collab_fetch(url):
    """SSRF/OOB simulation: only ever fetches http://127.0.0.1:<port>/... (the built-in Collaborator)."""
    m = re.match(r"http://127\.0\.0\.1:(\d+)(/[^\s;|&`$]*)?", url)
    if m and int(m.group(1)) not in (APP, OOS, PROXY, API, MCP):
        try:
            urllib.request.urlopen(url[: m.end()], timeout=3).read()
        except Exception:
            pass


def route(method, path, q, h, body):
    """Returns (status, [(header, value)], body)."""
    html = lambda b, extra=(): ("200 OK", [("Content-Type", "text/html")] + list(extra), b)
    arg = lambda k: q.get(k, [""])[0]
    cookies = dict(c.strip().split("=", 1) for c in h.get("cookie", "").split(";") if "=" in c)
    safe = path.startswith("/safe/") or path.startswith("/api/safe/")
    p = path.replace("/safe/", "/", 1)
    if path == "/":
        return html(INDEX.format(oos=OOS))
    if p == "/sqli/error":
        v = arg("id")
        if not safe and ("'" in v or '"' in v):
            return html("<b>Warning</b>: You have an error in your SQL syntax; check the manual near '" + ESC(v) + "'")
        return html("Item: a red chair" if v == "1" else "No such item")
    if p == "/sqli/bool":
        v = arg("id")
        # vulnerable: the condition after the id is "evaluated"; safe: only the literal id 1 matches
        true = v == "1" or (not safe and re.fullmatch(r"1(' AND '1'='1| AND 1=1)", v))
        return html("Item 1: a red chair, comfortable and cheap, in stock" if true else "No such item")
    if p == "/sqli/time":
        if not safe:
            sleep_for(arg("id"), [r"SLEEP\((\d+)\)", r"pg_sleep\((\d+)\)", r"WAITFOR DELAY '0:0:(\d+)'"])
        return html("Item: a red chair")
    if p == "/xss/query":
        return html("Results for " + (ESC(arg("q")) if safe else arg("q")))
    if p == "/xss/body":
        return html("Thanks for " + (ESC(arg("comment")) if safe else arg("comment")))
    if p == "/board":  # landing page for a focused stored-XSS crawl (form + rendered-comments link)
        pre = "/safe" if safe else ""
        return html(f'<a href="{pre}/comments">see</a>'
                    f'<form method="post" action="{pre}/comment"><input name="comment" value="hi"></form>')
    if p == "/comment":  # stored XSS: save the comment, render it later on /comments
        STORE[safe] = arg("comment")
        return html("stored")
    if p == "/comments":
        v = STORE[safe]
        return html("<ul><li>" + (ESC(v) if safe else v) + "</li></ul>")
    if p == "/xxe":
        # Detection-only: never reads a real file. Returns the passwd marker only when the body
        # carries the classic external entity the scanner's XXE probe plants. Safe twin ignores it.
        if not safe and 'SYSTEM "file:///etc/passwd"' in body:
            return html("root:x:0:0:root:/root:/bin/bash\n")
        return html("parsed ok")
    if p == "/deser":  # endpoint is irrelevant; the passive check inspects the request we send
        return html("ok")
    if p == "/xss/cookie":
        v = urllib.parse.unquote(cookies.get("pref", ""))
        return html("Theme " + (ESC(v) if safe else v))
    if p == "/xss/json":
        try:
            v = str(json.loads(body or "{}").get("name", ""))
        except ValueError:
            v = ""
        return html("Hello " + (ESC(v) if safe else v))
    if p == "/xss/header":
        v = h.get("referer", "")
        return html("Back to " + (ESC(v) if safe else v))
    if p == "/file":
        v = arg("name")
        if not safe and "etc/passwd" in v and (".." in v or v.startswith("/")):
            return html("root:x:0:0:root:/root:/bin/bash\n")
        return html("file contents")
    if p == "/tpl":
        v = arg("name")
        if not safe:
            v = re.sub(r"\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}", lambda m: str(int(m[1]) * int(m[2])), v)
        return html("Hello " + ESC(v))
    if p == "/go":
        v = re.sub(r"[\r\n]", "", arg("url"))  # CRLF is /hdr's class; here only the target is tested
        if safe and (not v.startswith("/") or v.startswith("//")):
            v = "/"
        return ("302 Found", [("Location", v)], "")
    if p == "/hdr":
        v = arg("lang")
        if safe:
            v = re.sub(r"[\r\n]", "", v)
        return html("ok", [("X-Lang", v)])
    if p == "/cmd":
        v = arg("host")
        if not safe:
            sleep_for(v, [r"[;|]\s*sleep\s+(\d+)", r"\$\(sleep\s+(\d+)\)", r"`sleep\s+(\d+)`", r"ping -n (\d+)"])
            m = re.search(r"[;|&]\s*curl\s+(\S+)", v)
            if m:
                collab_fetch(m.group(1))
        return html("Pinged")
    if p == "/fetch":
        if not safe:
            collab_fetch(arg("u"))
        return html("fetched")
    if p == "/login":
        if arg("user") == "admin" and arg("pass") == "secret":
            return ("302 Found", [("Location", "/account?q=me"), ("Set-Cookie", f"session={SESSION}; Path=/; HttpOnly")], "")
        return html("Invalid login")
    if p == "/account":
        if cookies.get("session") != SESSION:
            return ("302 Found", [("Location", "/login")], "")
        return html("Your account: " + arg("q"))
    if p == "/bearer":
        if h.get("authorization") != "Bearer t0k3n":
            return ("401 Unauthorized", [("Content-Type", "text/plain")], "no")
        return html("Token page: " + arg("q"))
    if path == "/openapi.json":
        return ("200 OK", [("Content-Type", "application/json")], json.dumps(OPENAPI))
    if p == "/api/search":
        return html("Found " + (ESC(arg("q")) if safe else arg("q")))
    if p == "/api/items":
        try:
            v = str(json.loads(body or "{}").get("name", ""))
        except ValueError:
            v = ""
        if "'" in v:
            return ("500 Internal Server Error", [("Content-Type", "text/html")], "pg_query(): Query failed: ERROR: unterminated quoted string")
        return ("201 Created", [("Content-Type", "application/json")], '{"ok":true}')
    if p == "/passive":
        if safe:
            return html("<p>clean</p>", [("Set-Cookie", "sid=1; Secure; HttpOnly"), ("Content-Security-Policy", "frame-ancestors 'self'"),
                                         ("X-Content-Type-Options", "nosniff")])
        return html('<form method="post"><input type="password" name="pw"></form> mail admin@shop.example',
                    [("Set-Cookie", "sid=1; Path=/"), ("Server", "Apache/2.4.1"), ("Access-Control-Allow-Origin", "*"),
                     ("Access-Control-Allow-Credentials", "true")])
    if p == "/intr":
        if arg("a") == "admin":
            return ("500 Internal Server Error", [("Content-Type", "text/plain")], "boom " * 20)
        return html(f"a={ESC(arg('a'))} b={ESC(arg('b'))}")
    if p == "/echo":
        return html("echo " + ESC(body) + " " + ESC(arg("m")))
    return ("404 Not Found", [("Content-Type", "text/plain")], "nope")


class Handler(socketserver.StreamRequestHandler):
    oos = False

    def handle(self):
        line = self.rfile.readline().decode("latin1")
        if not line:
            return
        h = {}
        while (l := self.rfile.readline().decode("latin1")) not in ("\r\n", "\n", ""):
            k, _, v = l.partition(":")
            h[k.strip().lower()] = v.strip()
        body = self.rfile.read(int(h.get("content-length", 0) or 0)).decode("latin1")
        method, target = (line.split() + ["", ""])[:2]
        if self.oos:
            OOS_HITS.append(line.strip())
            self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            return
        with LOCK:
            LOG.append((method, target, h, body))
            INFLIGHT[0] += 1
            INFLIGHT[1] = max(INFLIGHT)
        try:
            u = urllib.parse.urlsplit(target)
            form = body if "x-www-form-urlencoded" in h.get("content-type", "") else ""
            q = urllib.parse.parse_qs(u.query + "&" + form, keep_blank_values=True)
            status, headers, out = route(method, u.path, q, h, body)
        finally:
            with LOCK:
                INFLIGHT[0] -= 1
        out = out.encode("latin1", "replace")
        head = f"HTTP/1.1 {status}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers)
        self.wfile.write(head.encode("latin1", "replace") + f"Content-Length: {len(out)}\r\nConnection: close\r\n\r\n".encode() + out)


class OosHandler(Handler):
    oos = True


class SmuggleHandler(socketserver.StreamRequestHandler):
    """Raw front end that hangs whenever a request carries both Content-Length and Transfer-Encoding
    (a CL.TE/TE.CL desync), and answers everything else at once - what the timing probe looks for."""

    def handle(self):
        if not self.rfile.readline():
            return
        cl = te = False
        while (l := self.rfile.readline()) not in (b"\r\n", b"\n", b""):
            k = l.split(b":", 1)[0].strip().lower()
            cl = cl or k == b"content-length"
            te = te or k == b"transfer-encoding"
        if cl and te:
            time.sleep(15)  # back-end left waiting for a chunk/body that never arrives
            return
        self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")


def serve():
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    socketserver.ThreadingTCPServer.daemon_threads = True
    for port, cls in ((APP, Handler), (OOS, OosHandler)):
        srv = socketserver.ThreadingTCPServer(("127.0.0.1", port), cls)
        threading.Thread(target=srv.serve_forever, daemon=True).start()


# ------------------------------------------------------------------ clients for the app


def rest(method, path, body=None):
    req = urllib.request.Request(f"http://127.0.0.1:{API}{path}", method=method,
                                 data=json.dumps(body).encode() if body is not None else None)
    with urllib.request.urlopen(req, timeout=30) as r:
        txt = r.read().decode()
        return r.status, dict(r.headers), json.loads(txt) if txt else None


_rpc = [0]


def mcp(tool, **args):
    _rpc[0] += 1
    msg = {"jsonrpc": "2.0", "id": _rpc[0], "method": "tools/call", "params": {"name": tool, "arguments": args}}
    req = urllib.request.Request(f"http://127.0.0.1:{MCP}/mcp", data=json.dumps(msg).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=600) as r:
        res = json.loads(r.read())["result"]
    text = res["content"][0]["text"]
    if res.get("isError"):
        raise RuntimeError(f"{tool}: {text}")
    return json.loads(text)


def via_proxy(path, headers=""):
    s = socket.create_connection(("127.0.0.1", PROXY), timeout=30)
    s.sendall(f"GET {BASE}{path} HTTP/1.1\r\nHost: 127.0.0.1:{APP}\r\n{headers}Connection: close\r\n\r\n".encode())
    data = b""
    try:
        while chunk := s.recv(65536):
            data += chunk
    except OSError:
        pass
    return data.decode("latin1")


def wait_scan_rest(tid, timeout=900):
    t0 = time.time()
    while time.time() - t0 < timeout:
        _, _, j = rest("GET", f"/v0.1/scan/{tid}")
        if j["scan_status"] != "running":
            return j, time.time() - t0
        time.sleep(1)
    raise TimeoutError(f"scan {tid} still running after {timeout}s")


def wait_scan_mcp(tid, timeout=900):
    t0 = time.time()
    while time.time() - t0 < timeout:
        j = mcp("scan_status", task_id=tid)
        if j["scan_status"] != "running":
            return j, time.time() - t0
        time.sleep(1)
    raise TimeoutError(f"scan {tid} still running after {timeout}s")


# ------------------------------------------------------------------ checks

ACTIVE = {"SQL injection", "Cross-site scripting (reflected)", "OS command injection", "File path traversal",
          "Server-side template injection", "Open redirection", "HTTP response header injection",
          "External service interaction"}
RESULTS = []


def check(area, name, ok, detail=""):
    RESULTS.append((area, name, bool(ok), detail))


def issues():
    return [i["issue"] for i in rest("GET", "/v0.1/issues")[2]]


def found(path, name):
    return any(i["path"] == path and i["name"] == name for i in issues())


def raw(method, path, headers="", body=""):
    return f"{method} {path} HTTP/1.1\nHost: 127.0.0.1:{APP}\nUser-Agent: e2e\n{headers}\n{body}"


def scan_one(label, req, expect_path, name, safe_path, thorough=False):
    """Audits one raw request (and its /safe/ twin) via MCP scan_start."""
    for path, want in ((expect_path, True), (safe_path, False)):
        tid = mcp("scan_start", request=req.replace(expect_path, path, 1), target=BASE, thorough=thorough)["task_id"]
        wait_scan_mcp(tid)
        if want:
            check("Audit (request)", f"{label}: {name} on {path}", found(path, name))
    hits = [i["name"] for i in issues() if i["path"] == safe_path and i["name"] in ACTIVE]
    check("False positives", f"{label}: safe twin {safe_path} clean", not hits, ", ".join(hits))


def run():
    serve()
    rest("GET", "/v0.1/")  # API up
    mcp("collaborator", builtin=True)

    # 1. crawl + audit, thorough (time-based checks on), started over the REST API
    LOG.clear()
    INFLIGHT[1] = 0
    st, hdrs, _ = rest("POST", "/v0.1/scan", {"urls": [BASE + "/"], "scan_configurations": [{"name": "thorough"}]})
    check("REST", "POST /v0.1/scan -> 201 + Location", st == 201 and hdrs.get("Location"))
    j, took = wait_scan_rest(hdrs["Location"])
    n_req = j["scan_metrics"]["requests_made"]
    check("REST", "scan finished", j["scan_status"] == "succeeded", f"{took:.0f}s, {n_req} requests, {j['message']}")
    check("Scope", "crawler never hit the out-of-scope origin", not OOS_HITS, "; ".join(OOS_HITS[:3]))
    check("Rate limits", "<= 6 concurrent requests (thorough default threads)", INFLIGHT[1] <= 6, f"max {INFLIGHT[1]}")
    crawled = {urllib.parse.urlsplit(t).path for _, t, _, _ in LOG}
    check("Crawler", "followed links and forms", {"/sqli/error", "/xss/body", "/safe/xss/body", "/login"} <= crawled)
    check("Crawler", "skipped static files", "/logo.png" not in crawled)
    for path, name in [
        ("/sqli/error", "SQL injection"), ("/sqli/bool", "SQL injection"), ("/sqli/time", "SQL injection"),
        ("/xss/query", "Cross-site scripting (reflected)"), ("/xss/body", "Cross-site scripting (reflected)"),
        ("/file", "File path traversal"), ("/tpl", "Server-side template injection"), ("/go", "Open redirection"),
        ("/hdr", "HTTP response header injection"), ("/cmd", "OS command injection"),
        ("/fetch", "External service interaction"),
    ]:
        check("Crawl + audit", f"{name} on {path}", found(path, name))
    st_issues = issues()
    for path in sorted({p for p in crawled if p.startswith("/safe/")}):
        hits = [i["name"] for i in st_issues if i["path"] == path and i["name"] in ACTIVE]
        check("False positives", f"safe twin {path} clean", not hits, ", ".join(hits))
    for path in ("/sqli/error", "/sqli/bool", "/sqli/time", "/xss/query", "/file", "/tpl", "/go", "/hdr", "/cmd", "/fetch"):
        extra = sorted({i["name"] for i in st_issues if i["path"] == path and i["name"] in ACTIVE})
        check("False positives", f"{path}: only the planted class", len(extra) <= 1 + (path == "/cmd"), ", ".join(extra))
    check("Crawl + audit", "unauthenticated crawl found nothing behind /account",
          not any(i["path"] == "/account" and i["name"] in ACTIVE for i in st_issues))

    # 2. single-request audits: cookie, JSON, header insertion points
    scan_one("cookie", raw("GET", "/xss/cookie", "Cookie: pref=light\n"), "/xss/cookie",
             "Cross-site scripting (reflected)", "/safe/xss/cookie")
    scan_one("JSON", raw("POST", "/xss/json", "Content-Type: application/json\n", '{"name":"bob"}'), "/xss/json",
             "Cross-site scripting (reflected)", "/safe/xss/json")
    scan_one("header", raw("GET", "/xss/header", "Referer: http://127.0.0.1/\n"), "/xss/header",
             "Cross-site scripting (reflected)", "/safe/xss/header")

    # 3. OpenAPI definition scan
    tid = mcp("scan_start", openapi=json.dumps(OPENAPI))["task_id"]
    wait_scan_mcp(tid)
    check("OpenAPI", "XSS on /api/search (query from the definition)", found("/api/search", "Cross-site scripting (reflected)"))
    check("OpenAPI", "SQLi on /api/items (JSON body from the schema)", found("/api/items", "SQL injection"))
    check("OpenAPI", "/api/safe/search clean", not any(i["path"] == "/api/safe/search" and i["name"] in ACTIVE for i in issues()))

    # 4. authenticated scans: recorded login (cookie) and extra header
    login = raw("POST", "/login", "Content-Type: application/x-www-form-urlencoded\n", "user=admin&pass=secret")
    tid = mcp("scan_start", request=raw("GET", "/account?q=me"), target=BASE, login=login)["task_id"]
    wait_scan_mcp(tid)
    check("Authenticated", "login cookie: XSS behind /account", found("/account", "Cross-site scripting (reflected)"))
    tid = mcp("scan_start", request=raw("GET", "/bearer?q=me"), target=BASE, headers="Authorization: Bearer t0k3n")["task_id"]
    wait_scan_mcp(tid)
    check("Authenticated", "extra header: XSS behind /bearer", found("/bearer", "Cross-site scripting (reflected)"))

    # 5. passive checks on proxied traffic
    via_proxy("/passive")
    via_proxy("/safe/passive")
    time.sleep(0.5)
    names = {i["name"] for i in issues() if i["path"] == "/passive"}
    for n in ["Cookie missing HttpOnly attribute", "Password form served over HTTP", "Server software version exposed",
              "Email addresses in response", "Page can be framed by other sites", "No Content-Security-Policy",
              "MIME sniffing not prevented", "Permissive CORS with credentials"]:
        check("Passive", n, n in names)
    clean = [i["name"] for i in issues() if i["path"] == "/safe/passive"]
    check("False positives", "passive: /safe/passive clean", not clean, ", ".join(clean))

    # 6. Intruder: request counts and payload placement per attack type
    tpl = f"GET /intr?a=§x§&b=§y§ HTTP/1.1\nHost: 127.0.0.1:{APP}\nX-Run: RUN\n\n"
    sets = [["p1", "admin", "p3"], ["q1", "q2"]]
    expect = {
        "sniper": [("p1", "y"), ("admin", "y"), ("p3", "y"), ("x", "p1"), ("x", "admin"), ("x", "p3")],
        "battering_ram": [("p1", "p1"), ("admin", "admin"), ("p3", "p3")],
        "pitchfork": [("p1", "q1"), ("admin", "q2")],
        "cluster_bomb": [(a, b) for b in sets[1] for a in sets[0]],
    }
    for attack, want in expect.items():
        LOG.clear()
        rows = mcp("intruder", request=tpl.replace("RUN", attack), target=BASE, attack=attack, payloads=sets, grep="a=p3")
        got = []
        for _, t, h, _ in LOG:
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(t).query)
            got.append((q["a"][0], q["b"][0]))
        check("Intruder", f"{attack}: {len(want)} requests", len(rows) == len(want) and len(got) == len(want), f"rows {len(rows)}, received {len(got)}")
        check("Intruder", f"{attack}: payload placement", sorted(got) == sorted(want), str(sorted(set(got) ^ set(want))))
    a = mcp("intruder", request=tpl, target=BASE, attack="sniper", payloads=sets, grep="a=p3", anomalies=True)
    odd = sorted(r["payloads"][0] for r in a["anomalies"])
    check("Intruder", "anomalies: only the 500 + grep rows", odd == ["admin", "admin", "p3"], str([(r["payloads"], r["reasons"]) for r in a["anomalies"]]))

    # 7. Collaborator: mint a payload, trigger it, poll
    pl = mcp("collaborator", payloads=1)["payloads"][0]
    urllib.request.urlopen(f"http://{pl}", timeout=5).read()
    pid = pl.rsplit("/", 1)[-1]
    inter = mcp("collaborator")["interactions"]
    check("Collaborator", "HTTP interaction recorded for a minted payload", any(pid in i["raw"] and i["protocol"] == "HTTP" for i in inter))

    # 8. Repeater-like send: line endings and Content-Length fixed, response returned, logged
    LOG.clear()
    r = mcp("send", request=f"POST /echo?m=hey HTTP/1.1\nHost: 127.0.0.1:{APP}\nContent-Type: text/plain\nContent-Length: 1\n\nbody-123", target=BASE)
    text = json.dumps(r)
    check("Send", "response returned", "echo body-123 hey" in text)
    check("Send", "Content-Length fixed", LOG and LOG[0][3] == "body-123", str(LOG[:1]))
    check("Send", "logged in Logger as MCP", any("/echo" in e["url"] for e in mcp("history_list", source="logger", grep="body-123")))

    # 9. intercept: hold, edit + forward, drop
    mcp("intercept", enabled=True, host="127.0.0.1")
    try:
        out = {}
        th = threading.Thread(target=lambda: out.update(fwd=via_proxy("/echo?m=orig")))
        th.start()
        held = []
        for _ in range(50):
            held = [m for m in mcp("intercept_queue") if "/echo?m=orig" in m.get("message", "")]
            if held:
                break
            time.sleep(0.1)
        check("Intercept", "request held in the queue", held)
        if held:
            mcp("intercept_forward", id=held[0]["id"], message=held[0]["message"].replace("m=orig", "m=edited"))
        th.join(10)
        check("Intercept", "edited request forwarded", "echo  edited" in out.get("fwd", ""), out.get("fwd", "")[-40:])
        th = threading.Thread(target=lambda: out.update(drop=via_proxy("/echo?m=dropme")))
        th.start()
        for _ in range(50):
            held = [m for m in mcp("intercept_queue") if "m=dropme" in m.get("message", "")]
            if held:
                break
            time.sleep(0.1)
        if held:
            mcp("intercept_drop", id=held[0]["id"])
        th.join(10)
        check("Intercept", "dropped request never reached the app", held and not any("dropme" in t for _, t, _, _ in LOG))
    finally:
        mcp("intercept", enabled=False)

    # 9b. Stored XSS: a focused crawl of /board (its own small page, so the bounded stored-XSS
    # re-fetch budget isn't spent by the big crawl's many points). /comment stores, /comments renders
    # it unescaped; the safe twin HTML-escapes. The issue is reported on the storing request (/comment).
    for board in ("/board", "/safe/board"):
        tid = mcp("scan_start", urls=[BASE + board])["task_id"]
        wait_scan_mcp(tid)
    check("Crawl + audit", "Cross-site scripting (stored) on /comment", found("/comment", "Cross-site scripting (stored)"))
    check("False positives", "stored XSS: /safe/comment clean", not found("/safe/comment", "Cross-site scripting (stored)"))

    # 10. XXE: audit an XML request whose element text is an insertion point. The in-band file probe
    # plants `<!ENTITY xxe SYSTEM "file:///etc/passwd">`; the mock returns the passwd marker (never a
    # real file). Safe twin ignores entities.
    xreq = raw("POST", "/xxe", "Content-Type: application/xml\n", '<?xml version="1.0"?><data>bob</data>')
    scan_one("XXE", xreq, "/xxe", "XML external entity injection", "/safe/xxe")
    check("False positives", "XXE: /safe/xxe clean", not found("/safe/xxe", "XML external entity injection"))

    # 11. Insecure deserialization (passive): a serialized Java object in a proxied request's cookie.
    via_proxy("/deser", "Cookie: obj=rO0ABXNyEmphdmEubGFuZy5TdHJpbmc\r\n")  # base64 Java magic rO0AB
    via_proxy("/safe/deser", "Cookie: obj=plain-session-abc123\r\n")        # normal token: no signal
    time.sleep(0.5)
    check("Passive", "deser: serialized object in request flagged", found("/deser", "Serialized object in request"))
    check("False positives", "deser: /safe/deser clean (normal token)", not found("/safe/deser", "Serialized object in request"))

    # 12. HTTP request smuggling (timing). The check already ran against the app in the thorough scan
    # above and must not false-positive (the app answers normally, never hangs).
    check("False positives", "smuggling: well-behaved app not flagged",
          not any(i["name"] == "HTTP request smuggling" for i in issues()))
    # A faithful CL.TE/TE.CL detection needs a raw front end that HANGS on a both-CL-and-TE request,
    # which ties up sockets for the 10 s per-probe timeout; too slow/flaky for default CI, so it is
    # opt-in via E2E_SMUGGLE=1. The mock hangs exactly on the desync the probe sends.
    if os.environ.get("E2E_SMUGGLE") == "1":
        threading.Thread(
            target=socketserver.ThreadingTCPServer(("127.0.0.1", SMUGGLE), SmuggleHandler).serve_forever,
            daemon=True).start()
        tid = mcp("scan_start", urls=[f"http://127.0.0.1:{SMUGGLE}/"], thorough=True)["task_id"]
        wait_scan_mcp(tid)
        check("Smuggling", "CL.TE/TE.CL desync detected (opt-in E2E_SMUGGLE=1)", found("/", "HTTP request smuggling"))

    # 13. BChecks loops + variables: a custom check using `run for each:` and `define:` on a query
    # insertion point. It is loaded by dropping a .bcheck into the launched app's data dir (main()),
    # the only headless way to install one; skipped when the app is external (we don't know its HOME).
    if BCHECK_LOADED:
        for path in ("/xss/query", "/safe/xss/query"):
            tid = mcp("scan_start", request=raw("GET", f"{path}?q=hi"), target=BASE)["task_id"]
            wait_scan_mcp(tid)
        check("BChecks", "run-for-each + define BCheck reports on /xss/query", found("/xss/query", "E2E loop probe"))
        check("False positives", "BCheck: /safe/xss/query clean", not found("/safe/xss/query", "E2E loop probe"))

    # OpenAPI YAML: the scanner parses YAML definitions (openapi::parse_yaml), but only the GUI New-scan
    # file dialog uses it; the MCP/REST `openapi` argument is JSON-only (openapi::parse), so YAML import
    # cannot be driven headlessly without a src change. Noted in ROADMAP "Not covered".


def main():
    global BCHECK_LOADED
    app = None
    if "--launch" in sys.argv:
        home = tempfile.mkdtemp(prefix="burpcraft-e2e-")
        # Install a BCheck exercising `run for each:` + `define:` on a query insertion point. It
        # appends a marker containing `<`; the vulnerable /xss/query reflects it raw (match), the safe
        # twin HTML-escapes it (no match). Written before launch so it loads on the first scan.
        bdir = os.path.join(home, ".burpcraft", "bchecks")
        os.makedirs(bdir, exist_ok=True)
        with open(os.path.join(bdir, "e2e_loop.bcheck"), "w") as f:
            f.write(
                'metadata:\n    name: "E2E loop probe"\n    description: "run-for-each + define reflection check"\n'
                'run for each:\n    tag = "lpA", "lpB"\n'
                'define:\n    probe = "{tag}<e2e"\n'
                'given query insertion point then\n    send payload:\n        appending: "{probe}"\n'
                '    if "{probe}" in {latest.response.body} then\n        report issue:\n'
                '            severity: info\n            confidence: firm\n'
                '            detail: "Reflected {probe}"\n            remediation: "Encode output"\n'
            )
        BCHECK_LOADED = True
        env = dict(os.environ, HOME=home, BURPCRAFT_PROXY=str(PROXY), BURPCRAFT_API=str(API), BURPCRAFT_MCP=str(MCP))
        app = subprocess.Popen([sys.argv[sys.argv.index("--launch") + 1]], env=env,
                               stdout=subprocess.DEVNULL, stderr=open(os.path.join(home, "app.log"), "w"))
        for _ in range(150):
            try:
                socket.create_connection(("127.0.0.1", MCP), timeout=1).close()
                break
            except OSError:
                time.sleep(0.2)
    t0 = time.time()
    try:
        run()
    except Exception as e:  # an unreachable app or a tool error is a failure, not a traceback
        check("Harness", "run completed", False, f"{type(e).__name__}: {e}")
    finally:
        if app:
            app.terminate()
    w = max(len(f"{a}: {n}") for a, n, _, _ in RESULTS)
    for a, n, ok, d in RESULTS:
        print(f"{'PASS' if ok else 'FAIL'}  {f'{a}: {n}':<{w}}  {' '.join(d.split())}")
    bad = sum(not ok for _, _, ok, _ in RESULTS)
    print(f"\n{len(RESULTS) - bad}/{len(RESULTS)} passed in {time.time() - t0:.0f}s")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
