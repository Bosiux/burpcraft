#!/bin/sh
# Dev helper: ./shot.sh <MainTab> [ProxyTab] -> scratch screenshot PNG of that screen with sample traffic.
OUT=${OUT:-/tmp/burpcraft-shot}
BURPCRAFT_SHOT=$OUT.bmp BURPCRAFT_SHOT_FRAMES=240 BURPCRAFT_TAB="$1" BURPCRAFT_PROXY_TAB="$2" ./target/debug/burpcraft &
until nc -z 127.0.0.1 8080 2>/dev/null; do sleep 0.2; done
curl -s -o /dev/null -x http://127.0.0.1:8080 'http://example.com/?a=1&b=2'
curl -s -o /dev/null --cacert ~/.burpcraft/ca.pem -x http://127.0.0.1:8080 -d 'user=admin&pass=secret' 'https://httpbin.org/post?x=1'
curl -s -o /dev/null --cacert ~/.burpcraft/ca.pem -x http://127.0.0.1:8080 -H 'Cookie: session=abc; theme=dark' 'https://example.com/login'
wait
sips -s format png $OUT.bmp --out $OUT.png >/dev/null && echo $OUT.png
