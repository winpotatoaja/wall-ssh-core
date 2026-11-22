#!/bin/sh
# Download exactly one test file from each public endpoint through r37 SOCKS5.
# No upload test and no local fixture benchmark.
set -u

main() {
    SOCKS=${SOCKS:-127.0.0.1:1080}
    LOG=/tmp/mips-test
    RESULT="$LOG/qemu-speedtest"
    BIN=/usr/bin/passwall-ssh-core
    HZ=$(getconf CLK_TCK 2>/dev/null)
    case "$HZ" in ''|*[!0-9]*) HZ=100;; esac
    [ -x "$BIN" ] || { echo "ERROR: core binary missing"; return 2; }
    command -v curl >/dev/null 2>&1 || { echo "ERROR: curl missing"; return 2; }
    mkdir -p "$RESULT" || return 2
    : > "$RESULT/download-results.log"
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
        awk '{s=$0;sub(/^.*\\) /,"",s);n=split(s,a," ");if(n>=13)printf "%.0f",a[12]+a[13];else print 0}' "/proc/$1/stat" 2>/dev/null
    }

    echo "R37_TWO_ENDPOINT_DOWNLOAD_TEST_START=$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)"
    echo "SOCKS5=$SOCKS"
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

    cpu_snapshot > "$RESULT/cpu.prev"
    net_snapshot > "$RESULT/net.prev"

    test_download() {
        LABEL=$1
        URL=$2
        OUT="$RESULT/$LABEL.curl.log"
        echo "=== DOWNLOAD $LABEL ==="
        echo "URL=$URL"
        START=$(date +%s)
        curl -4 -fL --retry 2 --retry-delay 2 --connect-timeout 20 --max-time 900 \
          --socks5-hostname "$SOCKS" -o /dev/null \
          -w '%{size_download} %{time_total} %{speed_download} %{http_code} %{remote_ip} %{content_type}\n' \
          "$URL" > "$OUT" &
        CURL_PID=$!
        while kill -0 "$CURL_PID" 2>/dev/null; do
            sample_metrics
            sleep 1
        done
        wait "$CURL_PID"
        RC=$?
        WALL=$(( $(date +%s) - START ))
        if [ "$RC" -ne 0 ]; then
            echo "ERROR: $LABEL curl_rc=$RC wall_seconds=$WALL" | tee -a "$RESULT/errors.log"
            return 2
        fi
        if [ ! -s "$OUT" ]; then
            echo "ERROR: $LABEL produced no curl statistics" | tee -a "$RESULT/errors.log"
            return 2
        fi
        awk -v label="$LABEL" -v wall="$WALL" '{
          bytes=$1;sec=$2;speed=$3;code=$4;ip=$5;type=$6;
          printf "%s bytes=%.0f (%.2f MiB) wall_seconds=%d curl_seconds=%.3f average_mbps=%.2f http_code=%s remote_ip=%s content_type=%s\n",
            label,bytes,bytes/1048576,wall,sec,(wall>0?bytes*8/wall/1000000:0),code,ip,type
        }' "$OUT" | tee -a "$RESULT/download-results.log"
        return 0
    }

    test_download vultr-singapore "https://sgp-ping.vultr.com/vultr.com.100MB.bin" || {
        kill -TERM "$CORE_PID" 2>/dev/null || :
        return 2
    }
    test_download ovh "https://proof.ovh.net/files/100Mb.dat" || {
        kill -TERM "$CORE_PID" 2>/dev/null || :
        return 2
    }

    kill -TERM "$CORE_PID" 2>/dev/null || :
    WAIT_N=0
    while kill -0 "$CORE_PID" 2>/dev/null && [ "$WAIT_N" -lt 10 ]; do sleep 1; WAIT_N=$((WAIT_N+1)); done
    kill -KILL "$CORE_PID" 2>/dev/null || :

    {
      echo "R37 DOWNLOAD SUMMARY"
      cat "$RESULT/download-results.log"
      echo "SAMPLE_COUNT=$SAMPLE"
      echo "VCPU_COUNT=$(grep -c '^processor' /proc/cpuinfo 2>/dev/null)"
    } | tee "$RESULT/summary.txt"

    echo "RESULT_DIR=$RESULT"
    echo "R37_TWO_ENDPOINT_DOWNLOAD_TEST_END=$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)"
    [ ! -s "$RESULT/errors.log" ] || return 2
    [ "$(wc -l < "$RESULT/download-results.log")" -ge 2 ] || return 2
    return 0
}
main "$@"
