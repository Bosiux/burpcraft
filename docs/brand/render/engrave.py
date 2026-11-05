#!/usr/bin/env python3
"""Native engraving: white subject on orange tile, shaded with variable-thickness incised lines."""
import sys, numpy as np
from PIL import Image, ImageFilter, ImageDraw
MASKF, FEATF, OUT = sys.argv[1], sys.argv[2], sys.argv[3]
SZ=1024
def alpha(p): return np.asarray(Image.open(p).convert("RGBA").resize((SZ,SZ)),np.float32)[...,3]/255.0
mask=alpha(MASKF); sub=mask>0.5
feat=alpha(FEATF)

# exact EDT for a domed height (reuse)
def edt(m):
    INF=1e12; f=np.where(m,0.0,INF)
    def d1(f):
        n=len(f); d=np.empty(n); v=np.zeros(n,int); z=np.empty(n+1); k=0; z[0]=-INF; z[1]=INF
        for q in range(1,n):
            s=((f[q]+q*q)-(f[v[k]]+v[k]*v[k]))/(2*q-2*v[k])
            while s<=z[k]:
                k-=1; s=((f[q]+q*q)-(f[v[k]]+v[k]*v[k]))/(2*q-2*v[k])
            k+=1; v[k]=q; z[k]=s; z[k+1]=INF
        k=0
        for q in range(n):
            while z[k+1]<q: k+=1
            d[q]=(q-v[k])**2+f[v[k]]
        return d
    return np.sqrt(np.apply_along_axis(d1,1,np.apply_along_axis(d1,0,f)))
dist=edt(sub)
dome=np.clip(dist/70.0,0,1)                       # 0 edge -> 1 interior
# tone: lit by top-left + vertical falloff (bottom darker) -> T in [0,1], 1=light
Y,X=np.mgrid[0:SZ,0:SZ].astype(np.float32)
light = 0.55 + 0.9*dome - 0.55*(Y/SZ) + 0.25*((SZ-X)/SZ - .5)
T=np.clip(light,0,1)
# engraving: horizontal lines every sp px, half-thickness grows where dark (1-T)
sp=13.0
dc=np.abs(((Y+sp/2)%sp)-sp/2)                      # distance to nearest line center
half=np.clip(0.3+2.1*(1-T),0.0,3.1)           # thicker in shadow
line=np.clip(half-dc+0.5,0,1)                      # AA-ish 0..1
# cross-hatch in the darkest zones
dcx=np.abs(((X+sp/2)%sp)-sp/2)
halfx=np.clip(2.0*(0.25-T)/0.25,0,2.4)*(T<0.25)
line=np.clip(line+np.clip(halfx-dcx+0.5,0,1),0,1)

white=np.array([1.0,1.0,1.0]); carve=np.array([0.80,0.34,0.07])  # orange incised line
col = white[None,None,:]*(1-line[...,None]) + carve[None,None,:]*line[...,None]
# features (eyes, inner-ear, nose): solid dark carve
fk=np.clip(feat,0,1)
dark=np.array([0.55,0.22,0.05])
col = col*(1-fk[...,None]) + dark[None,None,:]*fk[...,None]

# orange tile bg + grain + radial light + vignette
r=np.sqrt((X-SZ*0.42)**2+(Y-SZ*0.34)**2)/(SZ*0.9)
bg=np.clip(np.array([1.0,0.58,0.24])*(1-r)[...,None]+np.array([0.70,0.17,0.02])*r[...,None],0,1)
bg=np.clip(bg+np.random.default_rng(5).standard_normal((SZ,SZ))[...,None]*0.015,0,1)
# soft drop shadow
sh=np.asarray(Image.fromarray((sub*255).astype(np.uint8)).filter(ImageFilter.GaussianBlur(20)),np.float32)/255.0
sh=np.roll(np.roll(sh,14,0),9,1); bg=bg*(1-0.4*sh[...,None])
am=np.asarray(Image.fromarray((sub*255).astype(np.uint8)).filter(ImageFilter.GaussianBlur(0.6)),np.float32)/255.0
out=bg*(1-am[...,None])+np.clip(col,0,1)*am[...,None]
# rounded tile
rm=Image.new("L",(SZ,SZ),0); ImageDraw.Draw(rm).rounded_rectangle([0,0,SZ-1,SZ-1],radius=180,fill=255)
img=Image.fromarray(np.clip(out*255,0,255).astype(np.uint8)); img.putalpha(rm); img.save(OUT)
print("wrote",OUT)
