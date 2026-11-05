#!/usr/bin/env python3
"""Generate banner-{dark,light}.svg from logo.svg: crab tile, title, and HTTP traffic in three depths."""
import html
from pathlib import Path

HERE = Path(__file__).parent
CRAB = (HERE / "logo.svg").read_text()
CRAB = CRAB[CRAB.index('<rect x="8"'):CRAB.rindex("</svg>")].replace("url(#o)", "url(#tile)").strip()

THEMES = {
    "dark": dict(bg0="#17171c", bg1="#2a1a10", grid=0.14, title="#ffffff", sub="#e6e6ea",
                 name="#8d8d99", val="#d8d8de", acc="#ff8a3d", pill="#ff8a3d", pilltxt="#1a0f08",
                 ok="#7ee2a8", far="#e8590c", glow=0.35),
    "light": dict(bg0="#fffaf5", bg1="#ffe8d6", grid=0.09, title="#1f1f24", sub="#3a3a44",
                  name="#9a8c80", val="#3a3a44", acc="#d9480f", pill="#e8590c", pilltxt="#ffffff",
                  ok="#1f8a4c", far="#d9480f", glow=0.22),
}

# far layer: (x, y, size, text), heavily blurred
FAR = [
    (700, 50, 13, "POST /api/v2/login HTTP/1.1"),
    (1010, 46, 12, "Cookie: session=7f3a9c2e; csrf=b81d"),
    (740, 142, 12, "{\"user\":\"admin\",\"pass\":\"§x§\"}"),
    (1080, 144, 13, "' OR 1=1--"),
    (690, 202, 12, "Set-Cookie: JSESSIONID=a91f; HttpOnly"),
    (1100, 200, 12, "../../../../etc/passwd"),
    (760, 274, 13, "Upgrade: websocket"),
    (1040, 274, 12, "nslookup q8x.oast.example"),
]
# mid layer, lightly blurred; kept clear of the sharp block (y 56-124 and 208-254)
MID = [
    (880, 26, 13, "HTTP/1.1 302 Found"),
    (1070, 26, 13, "Location: /admin"),
    (900, 174, 13, "<script>alert(1)</script>"),
    (1150, 174, 13, "{{7*7}}"),
    (880, 302, 12, "X-Forwarded-For: 127.0.0.1"),
    (1130, 302, 12, "Accept: */*"),
]

def esc(s):
    return html.escape(s, quote=False)


def sharp(t):
    """The in-focus request/response, syntax-coloured, with the payload position as a pill."""
    mono = 'xml:space="preserve" font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace" font-size="15"'
    n, v, a = t["name"], t["val"], t["acc"]
    return f"""  <g {mono}>
    <text x="900" y="76"><tspan fill="{a}" font-weight="700">GET</tspan><tspan fill="{v}"> /search?q=</tspan></text>
    <rect x="1031" y="61" width="90" height="21" rx="5" fill="{t['pill']}"/>
    <text x="1036" y="76" fill="{t['pilltxt']}" font-weight="700">§payload§</text>
    <text x="1130" y="76" fill="{n}">HTTP/2</text>
    <text x="900" y="102"><tspan fill="{n}">Host: </tspan><tspan fill="{v}">target.example</tspan></text>
    <text x="900" y="126"><tspan fill="{n}">Cookie: </tspan><tspan fill="{v}">session=§a1b2§</tspan></text>
    <text x="900" y="228"><tspan fill="{n}">HTTP/2 </tspan><tspan fill="{t['ok']}" font-weight="700">200</tspan><tspan fill="{n}"> · 12.4 kB · 87 ms</tspan></text>
    <circle cx="906" cy="249" r="5" fill="{a}"/>
    <text x="918" y="254"><tspan fill="{v}" font-weight="700">SQL injection</tspan><tspan fill="{n}">  High · Certain</tspan></text>
  </g>"""


def layer(items, color, opacity, blur, fid):
    rows = "\n".join(f'    <text x="{x}" y="{y}" font-size="{s}">{esc(txt)}</text>' for x, y, s, txt in items)
    return f"""  <g filter="url(#{fid})" mask="url(#fade)" fill="{color}" fill-opacity="{opacity}"
     font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace">
{rows}
  </g>"""


def banner(t):
    crab = "\n".join("    " + l.strip() for l in CRAB.splitlines())
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1280 320" width="1280" height="320">
  <title>BurpCraft: web security testing toolkit in pure Rust</title>
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="{t['bg0']}"/>
      <stop offset="1" stop-color="{t['bg1']}"/>
    </linearGradient>
    <pattern id="grid" width="32" height="32" patternUnits="userSpaceOnUse">
      <path d="M32 0 H0 V32" fill="none" stroke="#e8590c" stroke-opacity="{t['grid']}" stroke-width="1"/>
    </pattern>
    <linearGradient id="tile" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#ff8a3d"/>
      <stop offset="1" stop-color="#d9480f"/>
    </linearGradient>
    <radialGradient id="glow" cx="0.5" cy="0.5" r="0.5">
      <stop offset="0" stop-color="#ff8a3d" stop-opacity="{t['glow']}"/>
      <stop offset="1" stop-color="#ff8a3d" stop-opacity="0"/>
    </radialGradient>
    <!-- traffic dissolves before it reaches the title -->
    <linearGradient id="fadeg" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0.52" stop-color="#fff" stop-opacity="0"/>
      <stop offset="0.70" stop-color="#fff" stop-opacity="1"/>
    </linearGradient>
    <mask id="fade" maskUnits="userSpaceOnUse" x="0" y="0" width="1280" height="320">
      <rect width="1280" height="320" fill="url(#fadeg)"/>
    </mask>
    <filter id="far" x="-10%" y="-50%" width="120%" height="200%"><feGaussianBlur stdDeviation="2.4"/></filter>
    <filter id="mid" x="-10%" y="-50%" width="120%" height="200%"><feGaussianBlur stdDeviation="0.9"/></filter>
    <clipPath id="card"><rect width="1280" height="320" rx="24"/></clipPath>
  </defs>
  <g clip-path="url(#card)">
  <rect width="1280" height="320" fill="url(#bg)"/>
  <rect width="1280" height="320" fill="url(#grid)"/>
  <circle cx="186" cy="160" r="190" fill="url(#glow)"/>
{layer(FAR, t['far'], 0.55, 2.4, 'far')}
{layer(MID, t['far'], 0.6, 0.9, 'mid')}
{sharp(t)}
  </g>
  <g transform="translate(96 64) scale(0.75)">
{crab}
  </g>
  <g font-family="-apple-system, 'Segoe UI', Inter, Helvetica, Arial, sans-serif">
    <text x="320" y="150" font-size="72" font-weight="800" fill="{t['title']}" letter-spacing="-1.5">Burp<tspan fill="#e8590c">Craft</tspan></text>
    <text x="324" y="196" font-size="26" font-weight="600" fill="{t['sub']}">Web security testing, built in pure Rust</text>
    <text x="324" y="236" font-size="18" fill="{t['sub']}" fill-opacity="0.75">Proxy · Repeater · Intruder · Scanner · Collaborator · REST API</text>
  </g>
</svg>
"""


for name, t in THEMES.items():
    svg = HERE / f"banner-{name}.svg"
    svg.write_text(banner(t))
    print(svg)
