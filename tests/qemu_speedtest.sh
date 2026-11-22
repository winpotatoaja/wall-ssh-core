#!/bin/sh
# Real Internet bandwidth benchmark through passwall-ssh-core SOCKS5.
# Uses Cloudflare public speed-test endpoints; no local fixture traffic.
# Usage: sh qemu_speedtest.sh [duration_seconds]
set -u

main() {
    DURATION=${1:-60}
    SOCKS=${SOCKS:-127.0.0.1:1080}
    DOWN_URL=${DOWN_URL:-https://speed.cloudflare.com/__down?bytes=100000000}
    UP_URL=${UP_URL:-https://speed.cloudflare.com/__up}
    LOG=/tmp/mips-test
    RESULT="$LOG/qemu-speedtest"
    BIN=/usr/bin/passwall-ssh-core
    HZ=$(getconf CLK_TCK 2>/dev/null)
    case "$HZ" in ''|*[!0-9]*) HZ=100;; esac
    case "$DURATION" in ''|*[!0-9]*) echo "ERROR: duration must be integer seconds"; return 2;; esac
    [ "$DURATION" -ge 10 ] || { echo "ERROR: duration must be at least 10 seconds"; return 2; }
    [ -x "$BIN" ] || { echo "ERROR: core binary missing"; return 2; }
    command -v curl >/dev/null 2>&1 || { echo "ERROR: curl missing"; return 2; }
    mkdir -p "$RESULT" || return 2
    : > "$RESULT/download-results.log"
    : > "$RESULT/upload-results.log"
    : > "$RESULT/errors.log"
    : > "$RESULT/samples.log"

    cpu_snapshot() {
        awk '/^cpu[0-9]*[ \t]/ {t=0;for(i=2;i<=NF;i++)t+=$i;idle=$5+$6;print $1,t-idle,t}' /proc/stat
    }
    net_snapshot() {
        awk 'BEGIN {
            if ((getline rx < "/sys/class/net/eth0/statistics/rx_bytes") <= 0) rx=0
            if ((getline tx < "/sys/class/net/eth0/statistics/tx_bytes") <= 0) tx=0
            printf "%.0f %.0f\n",rx,tx
        }'
    }
    proc_ticks() {
        awk '{s=$0;sub(/^.*\) /,"",s);n=split(s,a," ");if(n>=13)printf "%.0f",a[12]+a[13];else print 0}' "/proc/$1/stat" 2>/dev/null
    }

    echo "QEMU_INTERNET_SPEEDTEST_START=$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)"
    echo "DOWNLOAD_URL=$DOWN_URL"
    echo "UPLOAD_URL=$UP_URL"
    echo "SOCKS5=$SOCKS DURATION_PER_DIRECTION=${DURATION}s HZ=$HZ"
    echo "GUEST=$(uname -a)"
    echo "VCPU_COUNT=$(grep -c '^processor' /proc/cpuinfo 2>/dev/null)"

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
        echo "ERROR: SOCKS5 listener did not become ready"
        cat "$RESULT/core-stdout.log" "$RESULT/core.log" 2>/dev/null
        kill -TERM "$CORE_PID" 2>/dev/null || :
        return 2
    fi

    PREFLIGHT_URL=${PREFLIGHT_URL:-https://speed.cloudflare.com/__down?bytes=1024}
    if ! curl -4 -fsS --socks5-hostname "$SOCKS" --connect-timeout 15 --max-time 45 "$PREFLIGHT_URL" -o /dev/null >/dev/null 2>&1; then
        echo "ERROR: Internet download preflight through SOCKS5 failed"
        echo "Check guest WAN/DNS, SSH tunnel and Cloudflare speed-test reachability."
        kill -TERM "$CORE_PID" 2>/dev/null || :
        return 2
    fi
    dd if=/dev/zero of="$RESULT/upload-64MiB.bin" bs=1M count=64 2>/dev/null || {
        echo "ERROR: could not create upload payload"
        kill -TERM "$CORE_PID" 2>/dev/null || :
        return 2
    }

    cpu_snapshot > "$RESULT/cpu.prev"
    net_snapshot > "$RESULT/net.prev"
    PREV_TICKS=$(proc_ticks "$CORE_PID")
    SAMPLE=0
    sample_metrics() {
        cpu_snapshot > "$RESULT/cpu.now"
        net_snapshot > "$RESULT/net.now"
        CUR_TICKS=$(proc_ticks "$CORE_PID")
        PROC_CPU=$(awk -v a="$PREV_TICKS" -v b="$CUR_TICKS" -v hz="$HZ" 'BEGIN{d=b-a;if(d<0)d=0;printf "%.1f",100*d/hz}')
        CPU_LINE=$(awk 'FNR==NR{busy[$1]=$2;total[$1]=$3;next}{dt=$3-total[$1];db=$2-busy[$1];if(dt>0){p=100*db/dt;if($1=="cpu")all=p;else cores=cores sprintf("%s=%.0f%%,",$1,p)}}END{printf "sys=%.0f%% cores=[%s]",all,cores}' "$RESULT/cpu.prev" "$RESULT/cpu.now")
        NET_LINE=$(awk 'FNR==NR{rx=$1;tx=$2;next}{dr=$1-rx;dt=$2-tx;if(dr<0)dr=0;if(dt<0)dt=0;printf "eth0_rx=%.2fMBps eth0_tx=%.2fMBps",dr/1048576,dt/1048576}' "$RESULT/net.prev" "$RESULT/net.now")
        SAMPLE=$((SAMPLE+1))
        printf 'sample=%d proc_cpu=%s%% %s %s\n' "$SAMPLE" "$PROC_CPU" "$CPU_LINE" "$NET_LINE" >> "$RESULT/samples.log"
        cp "$RESULT/cpu.now" "$RESULT/cpu.prev"
        cp "$RESULT/net.now" "$RESULT/net.prev"
        PREV_TICKS=$CUR_TICKS
    }

    echo "=== DOWNLOAD TEST: ${DURATION}s, 100 MB per request ==="
    DOWN_START=$(date +%s)
    DOWN_END=$((DOWN_START + DURATION))
    while [ "$(date +%s)" -lt "$DOWN_END" ]; do
        curl -4 -fsS --socks5-hostname "$SOCKS" --connect-timeout 15 --max-time 180 \
          -o /dev/null -w '%{size_download} %{time_total} %{speed_download} %{http_code}\n' "$DOWN_URL" >> "$RESULT/download-results.log" &
        CURL_PID=$!
        while kill -0 "$CURL_PID" 2>/dev/null; do sample_metrics; sleep 1; done
        wait "$CURL_PID" || { RC=$?; echo "download curl_rc=$RC" >> "$RESULT/errors.log"; break; }
    done
    DOWN_WALL=$(( $(date +%s) - DOWN_START ))

    echo "=== UPLOAD TEST: ${DURATION}s, 64 MiB per request ==="
    UP_START=$(date +%s)
    UP_END=$((UP_START + DURATION))
    while [ "$(date +%s)" -lt "$UP_END" ]; do
        curl -4 -fsS --socks5-hostname "$SOCKS" --connect-timeout 15 --max-time 180 \
          -X POST --data-binary "@$RESULT/upload-64MiB.bin" -o /dev/null \
          -w '%{size_upload} %{time_total} %{speed_upload} %{http_code}\n' "$UP_URL" >> "$RESULT/upload-results.log" &
        CURL_PID=$!
        while kill -0 "$CURL_PID" 2>/dev/null; do sample_metrics; sleep 1; done
        wait "$CURL_PID" || { RC=$?; echo "upload curl_rc=$RC" >> "$RESULT/errors.log"; break; }
    done
    UP_WALL=$(( $(date +%s) - UP_START ))

    kill -TERM "$CORE_PID" 2>/dev/null || :
    WAIT_N=0
    while kill -0 "$CORE_PID" 2>/dev/null && [ "$WAIT_N" -lt 10 ]; do sleep 1; WAIT_N=$((WAIT_N+1)); done
    kill -KILL "$CORE_PID" 2>/dev/null || :

    {
      echo "DOWNLOAD"
      awk -v wall="$DOWN_WALL" '{bytes+=$1;sec+=$2;if($3>peak)peak=$3;n++}END{printf "requests=%d bytes=%.0f wall_seconds=%d average_mbps=%.2f active_average_mbps=%.2f peak_mbps=%.2f\n",n,bytes,wall,(wall>0?bytes*8/wall/1000000:0),(sec>0?bytes*8/sec/1000000:0),peak*8/1000000}' "$RESULT/download-results.log"
      echo "UPLOAD"
      awk -v wall="$UP_WALL" '{bytes+=$1;sec+=$2;if($3>peak)peak=$3;n++}END{printf "requests=%d bytes=%.0f wall_seconds=%d average_mbps=%.2f active_average_mbps=%.2f peak_mbps=%.2f\n",n,bytes,wall,(wall>0?bytes*8/wall/1000000:0),(sec>0?bytes*8/sec/1000000:0),peak*8/1000000}' "$RESULT/upload-results.log"
    } | tee "$RESULT/summary.txt"

    echo "SAMPLE_COUNT=$SAMPLE"
    echo "RESULT_DIR=$RESULT"
    echo "QEMU_INTERNET_SPEEDTEST_END=$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)"
    [ ! -s "$RESULT/errors.log" ] || return 2
    [ -s "$RESULT/download-results.log" ] && [ -s "$RESULT/upload-results.log" ] || return 2
    return 0
}
main "$@"
