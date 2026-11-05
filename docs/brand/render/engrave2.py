#!/usr/bin/env python3
"""Fast native engraving (scipy EDT). Usage: engrave2.py mask.png feat.png out.png"""
import sys, numpy as np
from PIL import Image, ImageFilter, ImageDraw
from scipy.ndimage import distance_transform_edt
MASKF,FEATF,OUT=sys.argv[1],sys.argv[2],sys.argv[3]; SZ=1024
A=lambda p: np.asarray(Image.open(p).convert("RGBA").resize((SZ,SZ)),np.float32)[...,3]/255.0
mask=A(MASKF); sub=mask>0.5; feat=A(FEATF) if FEATF!="-" else np.zeros((SZ,SZ),np.float32)
dist=distance_transform_edt(sub)
dome=np.clip(dist/70.0,0,1)
Y,X=np.mgrid[0:SZ,0:SZ].astype(np.float32)
T=np.clip(0.55+0.9*dome-0.55*(Y/SZ)+0.25*((SZ-X)/SZ-.5),0,1)
sp=13.0
dc=np.abs(((Y+sp/2)%sp)-sp/2); half=np.clip(0.3+2.1*(1-T),0,3.1); line=np.clip(half-dc+0.5,0,1)
dcx=np.abs(((X+sp/2)%sp)-sp/2); halfx=np.clip(2.0*(0.25-T)/0.25,0,2.4)*(T<0.25); line=np.clip(line+np.clip(halfx-dcx+0.5,0,1),0,1)
white=np.array([1.,1.,1.]); carve=np.array([0.80,0.34,0.07])
col=white*(1-line[...,None])+carve*line[...,None]
fk=np.clip(feat,0,1); dark=np.array([0.55,0.22,0.05]); col=col*(1-fk[...,None])+dark*fk[...,None]
r=np.sqrt((X-SZ*0.42)**2+(Y-SZ*0.34)**2)/(SZ*0.9)
bg=np.clip(np.array([1.,0.58,0.24])*(1-r)[...,None]+np.array([0.70,0.17,0.02])*r[...,None],0,1)
bg=np.clip(bg+np.random.default_rng(5).standard_normal((SZ,SZ))[...,None]*0.015,0,1)
sh=np.asarray(Image.fromarray((sub*255).astype(np.uint8)).filter(ImageFilter.GaussianBlur(20)),np.float32)/255.0
sh=np.roll(np.roll(sh,14,0),9,1); bg=bg*(1-0.4*sh[...,None])
am=np.asarray(Image.fromarray((sub*255).astype(np.uint8)).filter(ImageFilter.GaussianBlur(0.6)),np.float32)/255.0
out=bg*(1-am[...,None])+np.clip(col,0,1)*am[...,None]
rm=Image.new("L",(SZ,SZ),0); ImageDraw.Draw(rm).rounded_rectangle([0,0,SZ-1,SZ-1],radius=180,fill=255)
img=Image.fromarray(np.clip(out*255,0,255).astype(np.uint8)); img.putalpha(rm); img.save(OUT)
