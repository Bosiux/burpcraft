#!/usr/bin/env python3
"""BurpCraft extension: adds an X-Pentest header to every proxied request."""
import base64, json, sys

print(json.dumps({"type": "register", "name": "Request tagger", "hooks": ["request"]}), flush=True)
for line in sys.stdin:
    m = json.loads(line)
    if m.get("type") == "request":
        req = base64.b64decode(m["request"]).replace(b"\r\n", b"\r\nX-Pentest: burpcraft\r\n", 1)
        print(json.dumps({"type": "request", "id": m["id"], "request": base64.b64encode(req).decode()}), flush=True)
