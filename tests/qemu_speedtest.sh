#!/bin/sh
# Sustained MIPS/QEMU SOCKS5 download benchmark against the deterministic host fixture.
# Usage: sh qemu_speedtest.sh [duration_seconds]
set -u

main() {
    DURATION=${1:-60}
    URL=${URL:-http://10.0.2.2:18080/slow-download}
    SOCKS=${SOCKS:-127.0.0.1:1080}
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
    : > "$RESULT/curl-results.log"
    : > "$RESULT/curl-errors.log"
    : > "$RESULT/samples.log"

    cpu_snapshot() {
        awk '/^cpu[0-9]*[ \\t]/ {t=0;for(i=2;i<=NF;i++)t+=$i;idle=$5+$6;print $1,t-idle,t}' /proc/stat
    }
    net_snapshot() {
        for x in rx_bytes tx_bytes; do
            cat "/sys/class/net/eth0/statistics/$x" 2>/dev/null || echo 0
        done
    }
    proc_ticks() {
        awk '{s=$0;sub(/^.*\\) /,"",s);n=split(s,a," ");if(n>=13)printf "%.0f",a[12]+a[13];else print 0}' "/proc/$1/stat" 2>/dev/null
    }

    echo "QEMU_SPEEDTEST_START=$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)"
    echo "TARGET=$URL SOCKS=$SOCKS DURATION=$DURATION HZ=$HZ"
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
        echo "ERROR: SOCKS listener did not become ready"
        cat "$RESULT/core-stdout.log" "$RESULT/core.log" 2>/dev/null
        kill -TERM "$CORE_PID" 2>/dev/null || :
        return 2
    fi
    if ! curl -4 -fsS --socks5-hostname "$SOCKS" --connect-timeout 10 --max-time 30 "$URL" -o /dev/null >/dev/null 2>&1; then
        echo "ERROR: SOCKS5 fixture preflight failed"
        kill -TERM "$CORE_PID" 2>/dev/null || :
        return 2
    fi

    cpu_snapshot > "$RESULT/cpu.prev"
    net_snapshot > "$RESULT/net.prev"
    PREV_TICKS=$(proc_ticks "$CORE_PID")
    START=$(date +%s)
    (
        END_AT=$((START + DURATION))
        while [ "$(date +%s)" -lt "$END_AT" ]; do
            curl -4 -fsS --socks5-hostname "$SOCKS" --connect-timeout 10 --max-time 120 \\
              -o /dev/null -w '%{size_download} %{time_total} %{speed_download}\\n' "$URL" >> "$RESULT/curl-results.log" || {
                RC=$?
                echo "curl_rc=$RC at $(date +%s)" >> "$RESULT/curl-errors.log"
                break
            }
        done
    ) &
    DL_PID=$!

    SAMPLE=0
    while kill -0 "$DL_PID" 2>/dev/null; do
        sleep 1
        SAMPLE=$((SAMPLE+1))
        cpu_snapshot > "$RESULT/cpu.now"
        net_snapshot > "$RESULT/net.now"
        CUR_TICKS=$(proc_ticks "$CORE_PID")
        PROC_CPU=$(awk -v a="$PREV_TICKS" -v b="$CUR_TICKS" -v hz="$HZ" 'BEGIN{d=b-a;if(d<0)d=0;printf "%.1f",100*d/hz}')
        CPU_LINE=$(awk 'FNR==NR{busy[$1]=$2;total[$1]=$3;next}{dt=$3-total[$1];db=$2-busy[$1];if(dt>0){p=100*db/dt;if($1=="cpu")all=p;else cores=cores sprintf("%s=%.0f%%,",$1,p)}}END{printf "sys=%.0f%% cores=[%s]",all,cores}' "$RESULT/cpu.prev" "$RESULT/cpu.now")
        NET_LINE=$(awk 'FNR==NR{rx=$1;tx=$2;next}{dr=$1-rx;dt=$2-tx;if(dr<0)dr=0;if(dt<0)dt=0;printf "eth0_rx=%.2fMBps eth0_tx=%.2fMBps",dr/1048576,dt/1048576}' "$RESULT/net.prev" "$RESULT/net.now")
        printf 'sample=%d elapsed=%ss proc_cpu=%s%% %s %s\\n' "$SAMPLE" "$SAMPLE" "$PROC_CPU" "$CPU_LINE" "$NET_LINE" >> "$RESULT/samples.log"
        cp "$RESULT/cpu.now" "$RESULT/cpu.prev"
        cp "$RESULT/net.now" "$RESULT/net.prev"
        PREV_TICKS=$CUR_TICKS
    done
    wait "$DL_PID"
    DL_RC=$?

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
    [ "$DL_RC" -eq 0 ] || return "$DL_RC"
    [ -s "$RESULT/curl-results.log" ] || return 2
    return 0
}

main "$@"
