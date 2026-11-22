#!/bin/sh
# Compare direct and r39 SOCKS5 downloads from two Singapore 100 MB test endpoints.
# Each endpoint is downloaded once direct and once through the single SSH SOCKS5 session.
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
    : > "$RESULT/skipped.log"
    : > "$RESULT/pairs.log"
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

    echo "R39_100MB_50SEC_DIRECT_VS_SOCKS5_TEST_START=$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)"
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
        MODE=$3
        MIN_BYTES=95000000
        OUT="$RESULT/$LABEL-$MODE.curl.log"
        ERR_OUT="$OUT.stderr"
        echo "=== DOWNLOAD $LABEL mode=$MODE (hard timeout 50s) ==="
        echo "URL=$URL"
        START=$(date +%s)
        if [ "$MODE" = "socks5" ]; then
            curl -4 -sS -fL --connect-timeout 15 --max-time 50 --max-filesize 110000000 --retry 0 \
              --socks5-hostname "$SOCKS" -o /dev/null \
              -w '%{size_download} %{time_total} %{speed_download} %{http_code} %{remote_ip} %{content_type}\n' \
              "$URL" > "$OUT" 2>"$ERR_OUT" &
        else
            env -u ALL_PROXY -u all_proxy -u HTTP_PROXY -u http_proxy -u HTTPS_PROXY -u https_proxy \
              curl -4 -sS -fL --connect-timeout 15 --max-time 50 --max-filesize 110000000 --retry 0 \
              --noproxy '*' -o /dev/null \
              -w '%{size_download} %{time_total} %{speed_download} %{http_code} %{remote_ip} %{content_type}\n' \
              "$URL" > "$OUT" 2>"$ERR_OUT" &
        fi
        CURL_PID=$!
        while kill -0 "$CURL_PID" 2>/dev/null; do
            if [ "$MODE" = "socks5" ]; then sample_metrics; fi
            sleep 1
        done
        wait "$CURL_PID"
        RC=$?
        WALL=$(( $(date +%s) - START ))

        BYTES=0
        HTTP_CODE=000
        if [ -s "$OUT" ]; then
            BYTES=$(awk 'NF >= 1 {printf "%.0f", $1; exit}' "$OUT")
            HTTP_CODE=$(awk 'NF >= 4 {print $4; exit}' "$OUT")
        fi
        case "$BYTES" in ''|*[!0-9]*) BYTES=0;; esac
        [ -n "$HTTP_CODE" ] || HTTP_CODE=000

        if [ "$RC" -ne 0 ]; then
            echo "SKIP: $LABEL mode=$MODE curl_rc=$RC downloaded_bytes=$BYTES wall_seconds=$WALL http_code=$HTTP_CODE (50-second per-download limit or endpoint error)" | tee -a "$RESULT/skipped.log"
            [ ! -s "$ERR_OUT" ] || cat "$ERR_OUT"
            return 1
        fi
        if [ "$BYTES" -lt "$MIN_BYTES" ] || [ "$HTTP_CODE" != "200" ]; then
            echo "SKIP: $LABEL mode=$MODE downloaded_bytes=$BYTES http_code=$HTTP_CODE; need >=95,000,000 bytes and HTTP 200" | tee -a "$RESULT/skipped.log"
            [ ! -s "$ERR_OUT" ] || cat "$ERR_OUT"
            return 1
        fi
        awk -v label="$LABEL" -v mode="$MODE" -v wall="$WALL" '{
          bytes=$1;sec=$2;speed=$3;code=$4;ip=$5;type=$6;
          printf "%s mode=%s bytes=%.0f (%.2f MiB) wall_seconds=%d curl_seconds=%.3f average_MiBps=%.2f curl_MiBps=%.2f http_code=%s remote_ip=%s content_type=%s\n",
            label,mode,bytes,bytes/1048576,wall,sec,speed/1048576,(wall>0?bytes/wall/1048576:0),code,ip,type
        }' "$OUT" | tee -a "$RESULT/download-results.log"
        return 0
    }

    PAIR_COUNT=0
    run_endpoint() {
        LABEL=$1
        URL=$2
        if test_download "$LABEL" "$URL" direct; then
            if test_download "$LABEL" "$URL" socks5; then
                DIRECT_BYTES=$(awk 'NF >= 4 {printf "%.0f", $1; exit}' "$RESULT/$LABEL-direct.curl.log")
                SOCKS_BYTES=$(awk 'NF >= 4 {printf "%.0f", $1; exit}' "$RESULT/$LABEL-socks5.curl.log")
                if [ "$DIRECT_BYTES" = "$SOCKS_BYTES" ]; then
                    PAIR_COUNT=$((PAIR_COUNT+1))
                    echo "PAIR PASS: $LABEL direct_bytes=$DIRECT_BYTES socks5_bytes=$SOCKS_BYTES" | tee -a "$RESULT/pairs.log"
                else
                    echo "ERROR: $LABEL direct/SOCKS byte counts differ: direct=$DIRECT_BYTES socks5=$SOCKS_BYTES" | tee -a "$RESULT/errors.log"
                fi
            else
                echo "SKIP: $LABEL direct passed but SOCKS5 did not finish within its 50-second cap; continue with next endpoint" | tee -a "$RESULT/skipped.log"
            fi
        else
            echo "SKIP: $LABEL direct failed or exceeded 50 seconds; SOCKS5 for this endpoint is not attempted" | tee -a "$RESULT/skipped.log"
        fi
    }

    URL_DIGITALOCEAN="http://speedtest-sgp1.digitalocean.com/100mb.test"
    URL_OVH="https://sin1-sgp.speedtest.network.ovh.net/files/100Mb.dat"

    echo "=== 100 MB DIRECT + SOCKS5; EACH REQUEST HAS A HARD 50-SECOND CAP ==="
    run_endpoint digitalocean-singapore "$URL_DIGITALOCEAN"
    run_endpoint ovh-singapore "$URL_OVH"

    kill -TERM "$CORE_PID" 2>/dev/null || :
    WAIT_N=0
    while kill -0 "$CORE_PID" 2>/dev/null && [ "$WAIT_N" -lt 10 ]; do sleep 1; WAIT_N=$((WAIT_N+1)); done
    kill -KILL "$CORE_PID" 2>/dev/null || :

    {
      echo "R39 100 MB DIRECT VS SOCKS5 SUMMARY (50s hard cap per transfer)"
      cat "$RESULT/download-results.log"
      echo "--- PAIRS ---"
      cat "$RESULT/pairs.log"
      echo "--- SKIPPED ---"
      cat "$RESULT/skipped.log"
      echo "PAIR_COUNT=$PAIR_COUNT"
      echo "SAMPLE_COUNT=$SAMPLE"
      echo "VCPU_COUNT=$(grep -c '^processor' /proc/cpuinfo 2>/dev/null)"
    } | tee "$RESULT/summary.txt"

    echo "RESULT_DIR=$RESULT"
    echo "R39_100MB_50SEC_DIRECT_VS_SOCKS5_TEST_END=$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)"
    [ ! -s "$RESULT/errors.log" ] || return 2
    [ "$PAIR_COUNT" -ge 1 ] || {
        echo "ERROR: no endpoint completed a full direct+SOCKS5 100 MB pair" | tee -a "$RESULT/errors.log"
        return 2
    }
    return 0
}
main "$@"
