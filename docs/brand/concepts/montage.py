#!/usr/bin/env python3
# montage.py <svg_dir> <out.png> [title] — grid of every *.svg, light+dark, big + 32px + 16px.
import sys, os, glob, subprocess, tempfile, html
d, out = sys.argv[1], sys.argv[2]
title = sys.argv[3] if len(sys.argv) > 3 else os.path.basename(d.rstrip('/'))
svgs = sorted(glob.glob(os.path.join(d, '*.svg')))
cells = []
for s in svgs:
    name = html.escape(os.path.splitext(os.path.basename(s))[0])
    rel = os.path.basename(s)
    cells.append(f'''<div class=card><div class=nm>{name}</div>
      <div class=tw><div class="p light"><img class=b src="{rel}"><div class=sz><img src="{rel}" width=32 height=32><img src="{rel}" width=16 height=16></div></div>
      <div class="p dark"><img class=b src="{rel}"><div class=sz><img src="{rel}" width=32 height=32><img src="{rel}" width=16 height=16></div></div></div></div>''')
cols = 4
h = f'''<!doctype html><meta charset=utf8><style>
 body{{margin:0;font-family:-apple-system,'Segoe UI',sans-serif;background:#eee}}
 h1{{font-size:18px;padding:14px 18px;margin:0}}
 .grid{{display:grid;grid-template-columns:repeat({cols},1fr);gap:10px;padding:0 12px 20px}}
 .card{{background:#fff;border-radius:10px;overflow:hidden}}
 .nm{{font:600 11px ui-monospace,monospace;padding:7px 10px;border-bottom:1px solid #eee;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
 .tw{{display:flex}} .p{{flex:1;padding:14px 0;text-align:center}}
 .light{{background:#fffaf5}} .dark{{background:#17171c}}
 .b{{width:96px;height:96px}} .sz{{margin-top:8px;display:flex;gap:10px;justify-content:center;align-items:flex-end}}
</style><h1>{html.escape(title)} — {len(svgs)} design</h1><div class=grid>{''.join(cells)}</div>'''
hp = os.path.join(d, '_montage.html'); open(hp, 'w').write(h)
rows = (len(svgs) + cols - 1) // cols
height = 70 + rows * 210
C = os.path.expanduser('~/Applications/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing')
P = tempfile.mkdtemp()
subprocess.run([C, '--headless=new', '--disable-gpu', '--hide-scrollbars', f'--user-data-dir={P}',
    '--force-device-scale-factor=2', f'--window-size=1280,{height}', f'--screenshot={out}', f'file://{hp}'],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
print(f'{len(svgs)} svg -> {out}')
