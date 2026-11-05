import sys,numpy as np
from PIL import Image
svgpng,mout,fout=sys.argv[1],sys.argv[2],sys.argv[3]
im=np.asarray(Image.open(svgpng).convert("RGBA").resize((1024,1024)),np.float32)
r,g,b,a=[im[...,i] for i in range(4)]; op=a>40; lum=(r+g+b)/3
mask=((lum>170)&op)
feat=((r>60)&(r<150)&(g<110)&(b<80)&op)
def rgba(m):
    o=np.zeros((1024,1024,4),np.uint8); o[...,3]=(m*255).astype(np.uint8); return Image.fromarray(o,"RGBA")
rgba(mask).save(mout); rgba(feat).save(fout)
