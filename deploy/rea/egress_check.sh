#!/bin/sh
# Egress acceptance for the rea_model personality (README.md "Acceptance from inside a slot").
# Runs INSIDE a container on bb-rea-model with the rea-agent worker env (HTTP(S)_PROXY injected):
#   docker exec -i <blastbox-worker-…> sh -s < egress_check.sh          (a live rea-agent slot)
#   P=http://10.231.200.2:8888; docker run --rm -i --runtime=runsc --user 10001:10001 \
#     --network bb-rea-model --read-only --tmpfs /tmp:rw,nosuid,noexec,size=512m -e HOME=/tmp \
#     -e HTTP_PROXY=$P -e HTTPS_PROXY=$P -e http_proxy=$P -e https_proxy=$P \
#     --entrypoint sh blastbox-rea-agent:<tag> -s < egress_check.sh

P=10.231.200.2:8888
hr() { echo; echo "### $*"; }
run() { echo "\$ $*"; out=$("$@" 2>&1); rc=$?; printf '%s\n' "$out" | tail -n 3 | cut -c1-300; echo "  [rc=$rc]"; }
hr "env (as the dispatcher injects it)"; env | grep -i -E '^(https?_proxy|BLASTBOX_NET_EGRESS)=' | sort
hr "ip/route view"; cat /etc/resolv.conf | grep -v '^#'; python3 -c "import socket;print('hostname',socket.gethostname())"
hr "1. model through the proxy (MUST answer)"
run curl -sS -m 30 http://172.18.101.13:8888/v1/models -o /tmp/models.json -w 'http=%{http_code} bytes=%{size_download}\n'
python3 -c "import json;d=json.load(open('/tmp/models.json'));print('models:',[m['id'] for m in d['data']])"
hr "2. direct, no proxy (MUST fail)"
run curl -sS -m 8 --noproxy '*' http://1.1.1.1/
run curl -sS -m 8 --noproxy '*' https://1.1.1.1/
run curl -sS -m 8 --noproxy '*' http://172.18.101.15:8001/
run curl -sS -m 8 --noproxy '*' http://172.18.101.13:8888/v1/models
run curl -sS -m 8 --noproxy '*' http://192.168.128.1/
run python3 -c "import socket;print(socket.getaddrinfo('example.com',80))"
run python3 -c "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(3);s.sendto(b'x',('1.1.1.1',53));print(s.recvfrom(10))"
hr "3. other destinations via the proxy (MUST fail)"
run curl -sS -m 15 -o /dev/null -w 'http=%{http_code}\n' https://example.com/
run curl -sS -m 15 -o /dev/null -w 'http=%{http_code}\n' -p http://example.com:443/
run curl -sS -m 15 -o /dev/null -w 'http=%{http_code}\n' http://example.com/
run curl -sS -m 15 -o /dev/null -w 'http=%{http_code}\n' http://1.1.1.1/
run curl -sS -m 15 -o /dev/null -w 'http=%{http_code}\n' http://172.18.101.15:8001/
run curl -sS -m 15 -o /dev/null -w 'http=%{http_code}\n' https://172.18.101.13:8888/v1/models
hr "4. request-line / Host: tricks sent raw to the proxy (MUST fail)"
cat > /tmp/raw.py <<'PY'
import socket, sys
P = ("10.231.200.2", 8888)
cases = [
  ("CONNECT example.com:443", b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"),
  ("CONNECT 172.18.101.13:8888 (the model itself, still CONNECT)", b"CONNECT 172.18.101.13:8888 HTTP/1.1\r\nHost: 172.18.101.13:8888\r\n\r\n"),
  ("absolute URI allowed IP, other port :22", b"GET http://172.18.101.13:22/ HTTP/1.1\r\nHost: 172.18.101.13:8888\r\n\r\n"),
  ("absolute URI allowed IP, no port (:80)", b"GET http://172.18.101.13/ HTTP/1.1\r\nHost: 172.18.101.13:8888\r\n\r\n"),
  ("absolute URI to example.com, Host: says model", b"GET http://example.com/ HTTP/1.1\r\nHost: 172.18.101.13:8888\r\n\r\n"),
  ("origin-form GET with Host: model", b"GET /v1/models HTTP/1.1\r\nHost: 172.18.101.13:8888\r\n\r\n"),
  ("origin-form GET with Host: model host, port 22", b"GET / HTTP/1.1\r\nHost: 172.18.101.13:22\r\n\r\n"),
  ("origin-form GET with Host: model:8888@1.1.1.1", b"GET / HTTP/1.1\r\nHost: 172.18.101.13:8888@1.1.1.1\r\n\r\n"),
  ("origin-form GET, two Host: headers (example.com first)", b"GET / HTTP/1.1\r\nHost: example.com\r\nHost: 172.18.101.13:8888\r\n\r\n"),
  ("origin-form GET with Host: example.com", b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
  ("userinfo trick http://172.18.101.13:8888@example.com/", b"GET http://172.18.101.13:8888@example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"),
  ("userinfo trick http://172.18.101.13:8888@172.18.101.15:8001/", b"GET http://172.18.101.13:8888@172.18.101.15:8001/ HTTP/1.1\r\nHost: x\r\n\r\n"),
  ("prefix trick http://172.18.101.13:88880/", b"GET http://172.18.101.13:88880/ HTTP/1.1\r\nHost: x\r\n\r\n"),
  ("suffix-host trick http://172.18.101.13.nip.io:8888/", b"GET http://172.18.101.13.nip.io:8888/ HTTP/1.1\r\nHost: x\r\n\r\n"),
  ("hex IP http://0xac12650d:8888/v1/models", b"GET http://0xac12650d:8888/v1/models HTTP/1.1\r\nHost: x\r\n\r\n"),
  ("uppercase scheme HTTP://172.18.101.13:22/", b"GET HTTP://172.18.101.13:22/ HTTP/1.1\r\nHost: x\r\n\r\n"),
  ("ftp:// scheme to model host", b"GET ftp://172.18.101.13:8888/ HTTP/1.1\r\nHost: x\r\n\r\n"),
  ("control: allowed URL raw (MUST be 200)", b"GET http://172.18.101.13:8888/v1/models HTTP/1.1\r\nHost: 172.18.101.13:8888\r\nConnection: close\r\n\r\n"),
]
for name, req in cases:
    s = socket.create_connection(P, timeout=20)
    s.sendall(req)
    try:
        data = s.recv(400)
    except socket.timeout:
        data = b"<timeout>"
    s.close()
    first = data.split(b"\r\n", 1)[0].decode("latin-1")
    print(f"{name:62s} -> {first}")
PY
python3 /tmp/raw.py
