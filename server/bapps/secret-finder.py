#!/usr/bin/env python3
"""BurpCraft extension: reports responses that leak secrets (protocol: see Extensions > APIs)."""
import base64, json, re, sys

PATTERNS = {
    "AWS access key": rb"AKIA[0-9A-Z]{16}",
    "Private key": rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "Generic API key": rb"(?i)api[_-]?key['\"]?\s*[:=]\s*['\"][0-9a-zA-Z_\-]{20,}",
}

def send(msg):
    print(json.dumps(msg), flush=True)

send({"type": "register", "name": "Secret finder", "hooks": ["response"]})
for line in sys.stdin:
    m = json.loads(line)
    if m.get("type") != "response":
        continue
    body = base64.b64decode(m["response"])
    for name, rx in PATTERNS.items():
        if re.search(rx, body):
            send({"type": "issue", "name": "Secret disclosed: " + name, "severity": "high", "url": m["url"], "detail": name + " found in the response"})
