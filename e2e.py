#!/usr/bin/env python3
"""End-to-end check of the BurpCraft proxy with local servers (stdlib only).

Starts an HTTP server (gzip + chunked + Set-Cookie) and a WebSocket echo server,
then drives traffic through the proxy on 127.0.0.1:8080. Run with the app already up.
"""
import base64, gzip, hashlib, os, socket, struct, sys, threading

PROXY = ("127.0.0.1", 8080)
HTTP_PORT, WS_PORT = 9010, 9011
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def read_head(sock):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
    return data.decode("latin1")


def http_server():
    srv = socket.create_server(("127.0.0.1", HTTP_PORT))
    while True:
        c, _ = srv.accept()
        head = read_head(c)
        body = gzip.compress(b'{"hello":"world","items":[1,2,3]}')
        token = base64.b64encode(os.urandom(12)).decode()
        chunked = b"%x\r\n%s\r\n0\r\n\r\n" % (len(body), body)
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\n"
                  b"Transfer-Encoding: chunked\r\nSet-Cookie: sid=" + token.encode() + b"; Path=/\r\n"
                  b"Connection: close\r\n\r\n" + chunked)
        c.close()


def ws_frame(payload: bytes, mask: bool) -> bytes:
    head = bytes([0x81])
    n = len(payload)
    m = 0x80 if mask else 0
    head += bytes([m | n]) if n < 126 else bytes([m | 126]) + struct.pack(">H", n)
    if not mask:
        return head + payload
    key = os.urandom(4)
    return head + key + bytes(b ^ key[i % 4] for i, b in enumerate(payload))


def ws_read(sock) -> bytes:
    b0, b1 = sock.recv(2)
    n = b1 & 0x7F
    if n == 126:
        n = struct.unpack(">H", sock.recv(2))[0]
    key = sock.recv(4) if b1 & 0x80 else None
    data = b""
    while len(data) < n:
        data += sock.recv(n - len(data))
    return bytes(b ^ key[i % 4] for i, b in enumerate(data)) if key else data


def ws_server():
    srv = socket.create_server(("127.0.0.1", WS_PORT))
    while True:
        c, _ = srv.accept()
        threading.Thread(target=ws_conn, args=(c,), daemon=True).start()


def ws_conn(c):
    head = read_head(c)
    key = [l.split(":", 1)[1].strip() for l in head.split("\r\n") if l.lower().startswith("sec-websocket-key")][0]
    accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
    c.sendall(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Accept: {accept}\r\n\r\n").encode())
    try:
        while True:
            msg = ws_read(c)
            c.sendall(ws_frame(b"echo: " + msg, mask=False))
    except Exception:
        c.close()


def upgrade_request(target):
    key = base64.b64encode(os.urandom(16)).decode()
    return (f"GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{WS_PORT}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode()


def check(name, ok):
    print(("PASS " if ok else "FAIL ") + name)
    return ok


def main():
    for f in (http_server, ws_server):
        threading.Thread(target=f, daemon=True).start()
    results = []

    # 1. plain HTTP through the proxy, gzip + chunked must reach the client untouched
    s = socket.create_connection(PROXY)
    s.sendall(f"GET http://127.0.0.1:{HTTP_PORT}/api?x=1 HTTP/1.1\r\nHost: 127.0.0.1:{HTTP_PORT}\r\nConnection: close\r\n\r\n".encode())
    data = b""
    while chunk := s.recv(4096):
        data += chunk
    results.append(check("http via proxy", b"200 OK" in data and b"Set-Cookie: sid=" in data))

    # 2. ws:// over a CONNECT tunnel (plain, not TLS)
    s = socket.create_connection(PROXY)
    s.sendall(f"CONNECT 127.0.0.1:{WS_PORT} HTTP/1.1\r\nHost: 127.0.0.1:{WS_PORT}\r\n\r\n".encode())
    read_head(s)
    s.sendall(upgrade_request("/chat"))
    results.append(check("ws handshake via CONNECT", "101" in read_head(s)))
    s.sendall(ws_frame(b"hello over connect", mask=True))
    results.append(check("ws echo via CONNECT", ws_read(s) == b"echo: hello over connect"))
    s.close()

    # 3. ws:// with an absolute-form upgrade request
    s = socket.create_connection(PROXY)
    s.sendall(upgrade_request(f"http://127.0.0.1:{WS_PORT}/live"))
    results.append(check("ws handshake absolute-form", "101" in read_head(s)))
    for i in range(3):
        s.sendall(ws_frame(f"msg {i}".encode(), mask=True))
        results.append(check(f"ws echo {i}", ws_read(s) == f"echo: msg {i}".encode()))
    s.close()

    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
