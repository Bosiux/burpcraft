#!/usr/bin/env python3
"""Native 'enamel pin' renderer: silhouette mask -> beveled, lit, textured 3D emblem on a tile."""
import sys, numpy as np
from PIL import Image, ImageFilter

MASK, OUT = sys.argv[1], sys.argv[2]
SZ = 1024
# --- load subject mask (black subject on transparent) -> alpha in [0,1]
m = Image.open(MASK).convert("RGBA").resize((SZ, SZ))
a = (np.asarray(m)[..., 3].astype(np.float32) / 255.0)
sub = a > 0.5

def edt(mask):  # exact squared Euclidean distance transform (Felzenszwalb 1D, two passes)
    INF = 1e12
    f = np.where(mask, 0.0, INF).astype(np.float64)
    def d1(f):
        n = len(f); d = np.empty(n); v = np.zeros(n, int); z = np.empty(n + 1)
        k = 0; v[0] = 0; z[0] = -INF; z[1] = INF
        for q in range(1, n):
            s = ((f[q] + q*q) - (f[v[k]] + v[k]*v[k])) / (2*q - 2*v[k])
            while s <= z[k]:
                k -= 1; s = ((f[q] + q*q) - (f[v[k]] + v[k]*v[k])) / (2*q - 2*v[k])
            k += 1; v[k] = q; z[k] = s; z[k+1] = INF
        k = 0
        for q in range(n):
            while z[k+1] < q: k += 1
            d[q] = (q - v[k])**2 + f[v[k]]
        return d
    out = np.apply_along_axis(d1, 0, f)
    out = np.apply_along_axis(d1, 1, out)
    return np.sqrt(out)

dist = edt(sub)                      # distance from edge, inside the subject
R = 46.0                             # bevel shoulder width (px)
d = np.clip(dist, 0, R)
height = np.sqrt(np.clip(2*R*d - d*d, 0, None)) / R   # 0 at edge -> 1 at R, then flat
height = np.where(sub, np.maximum(height, (dist > R) * 1.0), 0.0)
height = np.asarray(Image.fromarray((height*255).astype(np.uint8)).filter(ImageFilter.GaussianBlur(3)), np.float32)/255.0

# --- normals from height gradient
gy, gx = np.gradient(height * 70.0)
nz = np.ones_like(height)
nl = np.sqrt(gx*gx + gy*gy + nz*nz)
nx, ny, nz = -gx/nl, -gy/nl, nz/nl

def norm(v): v = np.array(v, float); return v/np.linalg.norm(v)
L = norm([-0.45, -0.6, 0.72])        # key light upper-left, toward viewer
V = norm([0, 0, 1])
H = norm(L + V)
diff = np.clip(nx*L[0] + ny*L[1] + nz*L[2], 0, 1)*0.55
spec = np.clip(nx*H[0] + ny*H[1] + nz*H[2], 0, 1) ** 22
rim  = np.clip(1 - nz, 0, 1) ** 2 * np.clip(nx*(-L[0]) + ny*(-L[1]), 0, 1)

# --- enamel material: orange, shaded top->bottom + lighting
top = np.array([1.0,1.0,1.0]); bot = np.array([0.80,0.84,0.92])
yy = np.linspace(0, 1, SZ)[:, None, None]
base = top*(1-yy) + bot*yy
ambient = 0.74
shade = (ambient + 0.85*diff)[..., None]
col = base * shade
col = col + spec[..., None]*np.array([1,1,1])*1.3          # specular gloss
col = col + rim[..., None]*np.array([1.0,0.80,0.55])*0.6          # warm rim light
# inner ambient-occlusion near edges (subtle dark line at the base of the bevel)
ao = np.clip(1 - (dist/ (R*0.5)), 0, 1)**2 * (dist < R*0.5)
col = col * (1 - 0.35*ao[..., None])
ramp = np.clip(1-np.linspace(0,1,SZ)[:,None]*1.6,0,1)
col = np.clip(col + (ramp*0.12*height)[...,None], 0, 1)

# --- tile background: orange radial gradient + fine grain + vignette, rounded corners
Y, X = np.mgrid[0:SZ, 0:SZ].astype(np.float32)
r = np.sqrt((X-SZ*0.42)**2 + (Y-SZ*0.36)**2) / (SZ*0.9)
bg = (np.array([1.0,0.58,0.24])*(1-r)[...,None] + np.array([0.70,0.18,0.02])*r[...,None])
bg = np.clip(bg,0,1)
grain = (np.random.default_rng(7).standard_normal((SZ,SZ))*0.015)[...,None]
bg = np.clip(bg + grain, 0, 1)

# soft drop shadow of the subject
sh = Image.fromarray((sub*255).astype(np.uint8)).filter(ImageFilter.GaussianBlur(22))
sh = np.asarray(sh, np.float32)/255.0
sh = np.roll(np.roll(sh, 16, 0), 10, 1)
bg = bg * (1 - 0.45*sh[...,None])

# composite subject over tile
amask = np.asarray(Image.fromarray((sub*255).astype(np.uint8)).filter(ImageFilter.GaussianBlur(0.6)),np.float32)/255.0
out = bg*(1-amask[...,None]) + col*amask[...,None]

# rounded-corner tile alpha
rad = 180
corner = np.ones((SZ,SZ), np.float32)
for (cy,cx) in [(rad,rad),(rad,SZ-rad),(SZ-rad,rad),(SZ-rad,SZ-rad)]:
    dd = np.sqrt((X-cx)**2+(Y-cy)**2)
    inx = ((X< rad)&(Y<rad))|((X>SZ-rad)&(Y<rad))|((X<rad)&(Y>SZ-rad))|((X>SZ-rad)&(Y>SZ-rad))
out_rgba = np.dstack([np.clip(out*255,0,255).astype(np.uint8), np.full((SZ,SZ),255,np.uint8)])
# build rounded mask properly
from PIL import ImageDraw
rm = Image.new("L",(SZ,SZ),0); ImageDraw.Draw(rm).rounded_rectangle([0,0,SZ-1,SZ-1], radius=rad, fill=255)
img = Image.fromarray(out_rgba); img.putalpha(rm)
img.save(OUT)
print("wrote", OUT)
