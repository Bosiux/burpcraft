import urllib.parse, urllib.request, io, os, time
from PIL import Image
ANIM=[
("fox","red fox, pointy ears, big fluffy tail"),
("raccoon","raccoon with dark bandit mask over the eyes, striped tail"),
("chameleon","chameleon with curled tail and swivel eye"),
("crab","orange crab with two big claws"),
("otter","river otter holding tiny paws"),
("ferret","long slim ferret"),
("mongoose","alert mongoose, slim body"),
("bee","round striped honeybee with tiny wings"),
("hedgehog","round hedgehog with soft rounded spikes"),
("honeybadger","honey badger with white dorsal stripe"),
("pufferfish","round pufferfish with short blunt spikes"),
("pangolin","pangolin curled up with rounded scales"),
("owl","owl with two big round front eyes"),
("cat","sitting cat with pointy ears"),
("beaver","beaver with big front teeth and flat tail"),
("meerkat","standing meerkat sentinel, upright"),
("tardigrade","chubby tardigrade water bear with eight stubby legs"),
("axolotl","pink axolotl with feathery gills and a smile"),
("narwhal","narwhal with a single front horn"),
("platypus","platypus with a flat duck bill"),
("mantisshrimp","colorful mantis shrimp with stalked eyes"),
]
TMPL=("cute chibi kawaii {a}, one simple character, big round head, soft rounded body, "
      "two simple dot eyes, thick smooth flat-3d shapes, warm friendly, "
      "solid muted cream background, centered, soft studio light, no text, no watermark")
def gen(item):
    slug,a=item
    p=TMPL.format(a=a)
    url="https://image.pollinations.ai/prompt/"+urllib.parse.quote(p)+"?width=768&height=768&nologo=true&model=flux&seed=42"
    if os.path.exists(f"mascots/{slug}.png"): return slug,"skip"
    for attempt in range(6):
        try:
            data=urllib.request.urlopen(url,timeout=150).read()
            im=Image.open(io.BytesIO(data)).convert("RGB")
            w,h=im.size; im=im.crop((0,0,w,h-int(h*0.055)))
            im.save(f"mascots/{slug}.png","PNG"); return slug,"ok"
        except Exception as e:
            time.sleep(4*(attempt+1))
            if attempt==5: return slug,f"ERR {e.__class__.__name__}"
for it in ANIM:
    slug,st=gen(it); print(f"{slug:14} {st}",flush=True); time.sleep(2)
