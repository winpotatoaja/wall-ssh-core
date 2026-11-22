#!/bin/sh
# Sustained MIPS/QEMU SOCKS5 download benchmark against the deterministic host fixture.
# Runs inside OpenWrt guest after the integration suite has installed the package.
# Usage: sh qemu_speedtest.sh [duration_seconds]
set -u

DURATION=${1:-60}
URL=${URL:-http://10.0.2.2:18080/slow-download}
SOCKS=${SOCKS:-127.0.0.1:1080}
LOG=/tmp/mips-test
RESULT="$LOG/qemu-speedtest"
BIN=/usr/bin/passwall-ssh-core
HZ=$(getconf CLK_TCK 2>/dev/null)
case "$HZ" in ''|*[!0-9]*) HZ=100;; esac
case "$DURATION" in ''|*[!0-9]*) echo "ERROR: duration must be integer seconds"; return 2 2>/dev/null || :;; esac
[ "$DURATION" -ge 10 ] || { echo "ERROR: duration must be at least 10 seconds"; return 2 2>/dev/null || :; }
[ -x "$BIN" ] || { echo "ERROR: core binary missing"; return 2 2>/dev/null || :; }
command -v curl >/dev/null 2>&1 || { echo "ERROR: curl missing"; return 2 2>/dev/null || :; }
mkdir -p "$RESULT"
: > "$RESULT/curl-results.log"
: > "$RESULT/samples.log"

echo "QEMU_SPEEDTEST_START=$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)"
echo "TARGET=$URL SOCKS=$SOCKS DURATION=$DURATION HZ=$HZ"
echo "GUEST=$(uname -a)"
echo "CPU_INFO=$(grep -c '^processor' /proc/cpuinfo 2>/dev/null)"

# Start a fresh core instance using the same SSH fixture credentials as integration tests.
"$BIN" -env "$LOG/tcp.env" -log "$RESULT/core.log" -log-backpressure 1 -log-perf 1 >"$RESULT/core-stdout.log" 2>&1 &
CORE_PID=$!
READY=0
N=0
while [ "$N" -lt 45 ]; do
    if grep -q 'SOCKS5 Listening' "$RESULT/core.log" 2>/dev/null; then READY=1; break; fi
    kill -0 "$CORE_PID" 2>/dev/null || break
    N=$((N+1))
    sleep 1
done
if [ "$READY" -ne 1 ]; then
    echo "ERROR: SOCKS listener did not become ready"
    cat "$RESULT/core-stdout.log" "$RESULT/core.log" 2>/dev/null
    kill -TERM "$CORE_PID" 2>/dev/null || :
    return 2 2>/dev/null || :
fi
curl -4 -fsS --socks5-hostname "$SOCKS" --connect-timeout 10 --max-time 30 "$URL" -o /dev/null >/dev/null 2>&1
if [ "$?" -ne 0 ]; then
    echo "ERROR: SOCKS5 fixture preflight failed"
    kill -TERM "$CORE_PID" 2>/dev/null || :
    return 2 2>/dev/null || :
fi

read_proc_ticks() {
    awk '{s=$0;sub(/^.*\\) /,"",s);n=split(s,a," ");if(n>=13)printf "%.0f",a[12]+a[13];else print 0}' "/proc/$1/stat" 2>/dev/null
}
read_cpu() {
    awk '/^cpu[0-9]*[ \\t]/ {t=0;for(i=2;i<=NF;i++)t+=$i;idle=$5+$6;print $1,t-idle,t}' /proc/stat 2>/dev/null
}
read_net() {
    awk -v d="/sys/class/net/eth0/statistics/" 'BEGIN{for(i=1;i<=2;i++){p=d (i==1?"rx_bytes":"tx_bytes");if((getline x<p)>0)printf "%.0f ",x;close(p)}printf "\\n"}'
}

# Warm-up is excluded from measurement. Start a continuous sequence of 32 MiB downloads.
START=$(awk '{print $1}' /proc/uptime)
DL_START=$(date +%s)
(
    END_AT=$((DL_START + DURATION))
    while [ "$(date +%s)" -lt "$END_AT" ]; do
        curl -4 -fsS --socks5-hostname "$SOCKS" --connect-timeout 10 --max-time 120 \\
          -o /dev/null -w '%{size_download} %{time_total} %{speed_download}\\n' "$URL" >> "$RESULT/curl-results.log" || {
            echo "CURL_ERROR=$?" >> "$RESULT/curl-errors.log"
            break
        }
    done
) &
DL_PID=$!

PREV_TICKS=$(read_proc_ticks "$CORE_PID")
PREV_CPU=$(read_cpu)
PREV_NET=$(read_net)
PREV_UP=$(awk '{print $1}' /proc/uptime)
SAMPLE=0
while kill -0 "$DL_PID" 2>/dev/null; do
    sleep 1
    NOW_UP=$(awk '{print $1}' /proc/uptime)
    CUR_TICKS=$(read_proc_ticks "$CORE_PID")
    CUR_CPU=$(read_cpu)
    CUR_NET=$(read_net)
    awk -v old="$PREV_TICKS" -v now="$CUR_TICKS" -v hz="$HZ" -v dt=1 \\
      'BEGIN{d=now-old;if(d<0)d=0;printf "proc_cpu=%.1f%% ",100*d/hz/dt}' > "$RESULT/.proc"
    awk 'FNR==NR{b[$1]=$2;t[$1]=$3;next}{dt=$3-t[$1];db=$2-b[$1];if(dt>0){p=100*db/dt;if($1=="cpu")all=p;else cores=cores sprintf("%s=%.0f%%,",$1,p)}}END{printf "sys_cpu=%.0f%% cores=[%s]",all,cores}' \\
      <<EOF_CPU "$RESULT/.cpu"
$PREV_CPU
EOF_CPU
$CUR_CPU
EOF_CPU
    NET_LINE=$(awk -v old="$PREV_NET" -v cur="$CUR_NET" 'BEGIN{split(old,a," ");split(cur,b," ");printf "eth0_rx=%.2fMBps eth0_tx=%.2fMBps",(b[1]-a[1])/1048576,(b[2]-a[2])/1048576}')
    SAMPLE=$((SAMPLE+1))
    printf 'sample=%d t=%ss ' "$SAMPLE" "$NOW_UP" >> "$RESULT/samples.log"
    cat "$RESULT/.proc" >> "$RESULT/samples.log"
    printf '%s %s\\n' "$NET_LINE" "$(cat "$RESULT/.cpu" 2>/dev/null)" >> "$RESULT/samples.log"
    PREV_TICKS=$CUR_TICKS
    PREV_CPU=$CUR_CPU
    PREV_NET=$CUR_NET
done
wait "$DL_PID"
DL_RC=$?
END=$(awk '{print $1}' /proc/uptime)
kill -TERM "$CORE_PID" 2>/dev/null || :
WAIT_N=0
while kill -0 "$CORE_PID" 2>/dev/null && [ "$WAIT_N" -lt 10 ]; do sleep 1; WAIT_N=$((WAIT_N+1)); done
kill -KILL "$CORE_PID" 2>/dev/null || :

awk '
{bytes+=$1;seconds+=$2;speed+=$3;if($3>peak)peak=$3;n++}
END {
  printf "downloads=%d bytes=%.0f transfer_seconds=%.3f avg_mbps=%.2f peak_curl_mbps=%.2f\\n",
    n,bytes,seconds,(seconds>0?bytes*8/seconds/1000000:0),peak*8/1000000
}' "$RESULT/curl-results.log" | tee "$RESULT/summary.txt"
echo "SAMPLE_COUNT=$SAMPLE CURL_RC=$DL_RC"
echo "RESULT_DIR=$RESULT"
echo "QEMU_SPEEDTEST_END=$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)"
[ "$DL_RC" -eq 0 ] || return "$DL_RC" 2>/dev/null || :
