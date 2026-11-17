#!/bin/ash
set -eu
trap 'echo PASSWALL_VM_TEST_FAIL' EXIT

if command -v udhcpc >/dev/null 2>&1; then
    udhcpc -i br-lan -q -n || udhcpc -i eth0 -q -n
fi

wget -q http://10.0.2.2:8000/passwall-ssh-core.apk -O /tmp/passwall-ssh-core.apk
wget -q http://10.0.2.2:8000/core.env -O /tmp/core.env
apk update
apk add curl
apk add --allow-untrusted /tmp/passwall-ssh-core.apk

BIN=/usr/bin/passwall-ssh-core
grep -qx "$BIN" /lib/apk/packages/passwall-ssh-core.list
[ -x "$BIN" ]
"$BIN" -h >/tmp/ssh-core-help.txt
grep -q 'max-clients' /tmp/ssh-core-help.txt

nohup "$BIN" -env /tmp/core.env -log /tmp/ssh-core.log >/tmp/ssh-core.out 2>&1 &
i=0
while [ "$i" -lt 40 ]; do
    if grep -q 'SOCKS5 Listening' /tmp/ssh-core.log 2>/dev/null; then
        break
    fi
    i=$((i + 1))
    sleep 1
done
grep -q 'SOCKS5 Listening' /tmp/ssh-core.log

curl --fail --silent --show-error --socks5-hostname 127.0.0.1:1080 \
    http://127.0.0.1:18080/payload -o /tmp/payload.bin
[ "$(wc -c </tmp/payload.bin)" -eq 1048576 ]
grep -q 'PASSWALL_SSH_CORE_VM_OK' /tmp/payload.bin

printf 'bidirectional-post-check' >/tmp/post.in
curl --fail --silent --show-error --socks5-hostname 127.0.0.1:1080 \
    --data-binary @/tmp/post.in http://127.0.0.1:18080/echo -o /tmp/post.out
cmp /tmp/post.in /tmp/post.out

pids=""
n=1
while [ "$n" -le 6 ]; do
    curl --fail --silent --show-error --socks5-hostname 127.0.0.1:1080 \
        http://127.0.0.1:18080/payload -o "/tmp/concurrent-$n.bin" &
    pids="$pids $!"
    n=$((n + 1))
done
for pid in $pids; do
    wait "$pid"
done
n=1
while [ "$n" -le 6 ]; do
    [ "$(wc -c <"/tmp/concurrent-$n.bin")" -eq 1048576 ]
    n=$((n + 1))
done

trap - EXIT
echo PASSWALL_VM_TEST_PASS
