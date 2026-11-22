#!/bin/sh
proc_stat_ticks() {
    STAT_PATH="$1"
    awk '{
        s=$0
        sub(/^.*\) /, "", s)
        n=split(s, a, " ")
        if (n >= 13) printf "%.0f", a[12] + a[13]
        else printf "0"
    }' "$STAT_PATH" 2>/dev/null
}

proc_ticks() {
    proc_stat_ticks "/proc/$1/stat"
}

thread_snapshot() {
    PID="$1"
    TASK_ROOT="$2"
    [ -n "$TASK_ROOT" ] || TASK_ROOT="/proc/$PID/task"
    for STAT_FILE in "$TASK_ROOT"/*/stat; do
        [ -r "$STAT_FILE" ] || continue
        TASK_DIR=$(dirname "$STAT_FILE")
        TID=$(basename "$TASK_DIR")
        TICKS=$(proc_stat_ticks "$STAT_FILE")
        COMM=$(cat "$TASK_DIR/comm" 2>/dev/null | tr ' ' '_')
        [ -n "$COMM" ] || COMM=unknown
        printf '%s %s %s\n' "$TID" "$TICKS" "$COMM"
    done
}

thread_cpu_line() {
    PREV_FILE="$1"
    NOW_FILE="$2"
    ELAPSED="$3"
    HZ_VALUE="$4"
    awk -v elapsed="$ELAPSED" -v hz="$HZ_VALUE" '
        FNR == NR { old_ticks[$1] = $2 + 0; next }
        {
            delta = ($2 + 0) - (old_ticks[$1] + 0)
            if (delta < 0) delta = 0
            pct = (elapsed > 0 && hz > 0) ? 100 * delta / (elapsed * hz) : 0
            printf "tid=%s/%s:%.1f%%,", $1, $3, pct
            if (pct > max_pct) {
                max_pct = pct
                max_tid = $1
                max_name = $3
            }
            count++
        }
        END {
            if (count == 0) printf "no_threads"
            else printf "max_tid=%s/%s:%.1f%%", max_tid, max_name, max_pct
        }
    ' "$PREV_FILE" "$NOW_FILE"
}

default_route_iface() {
    ROUTE_FILE="$1"
    [ -n "$ROUTE_FILE" ] || ROUTE_FILE=/proc/net/route
    awk 'NR > 1 && $2 == "00000000" { print $1; exit }' "$ROUTE_FILE" 2>/dev/null
}

net_snapshot() {
    NET_ROOT="$1"
    [ -n "$NET_ROOT" ] || NET_ROOT=/sys/class/net
    for NET_PATH in "$NET_ROOT"/*; do
        [ -d "$NET_PATH/statistics" ] || continue
        NET_NAME=$(basename "$NET_PATH")
        [ "$NET_NAME" = lo ] && continue
        NET_RX=$(cat "$NET_PATH/statistics/rx_bytes" 2>/dev/null)
        NET_TX=$(cat "$NET_PATH/statistics/tx_bytes" 2>/dev/null)
        case "$NET_RX" in ''|*[!0-9]*) NET_RX=0;; esac
        case "$NET_TX" in ''|*[!0-9]*) NET_TX=0;; esac
        printf '%s %s %s\n' "$NET_NAME" "$NET_RX" "$NET_TX"
    done
}

net_rate_line() {
    PREV_FILE="$1"
    NOW_FILE="$2"
    DEFAULT_IFACE="$3"
    ELAPSED="$4"
    awk -v def="$DEFAULT_IFACE" -v elapsed="$ELAPSED" '
        FNR == NR {
            old_rx[$1] = $2 + 0
            old_tx[$1] = $3 + 0
            known[$1] = 1
            next
        }
        {
            count++
            if (!known[$1]) {
                printf "%s_rx=baseline-pending %s_tx=baseline-pending ", $1, $1
                next
            }
            dr = ($2 + 0) - old_rx[$1]
            dt = ($3 + 0) - old_tx[$1]
            if (dr < 0) dr = 0
            if (dt < 0) dt = 0
            rx_rate = elapsed > 0 ? dr / 1048576 / elapsed : 0
            tx_rate = elapsed > 0 ? dt / 1048576 / elapsed : 0
            tag = ($1 == def && def != "" && def != "unknown") ? "(default)" : ""
            printf "%s%s_rx=%.2fMiB/s %s%s_tx=%.2fMiB/s ", $1, tag, rx_rate, $1, tag, tx_rate
        }
        END {
            if (count == 0) printf "net_ifaces=unavailable"
        }
    ' "$PREV_FILE" "$NOW_FILE"
}

run_diag_self_test() {
    TEST_ROOT="/tmp/r39-speedtest-diag-test.$"
    rm -rf "$TEST_ROOT"
    mkdir -p "$TEST_ROOT/tasks/4242" "$TEST_ROOT/net/testnet/statistics" "$TEST_ROOT/net/lo/statistics" || return 2

    printf '%s\n' '4242 (worker ) name) S 1 2 3 4 5 6 7 8 9 10 123 45 16 17 18' > "$TEST_ROOT/tasks/4242/stat"
    printf '%s\n' 'relay_owner' > "$TEST_ROOT/tasks/4242/comm"
    TICKS=$(proc_stat_ticks "$TEST_ROOT/tasks/4242/stat")
    if [ "$TICKS" != "168" ]; then
        echo "DIAG SELF-TEST FAIL: /proc stat parser expected 168 ticks, got $TICKS"
        rm -rf "$TEST_ROOT"
        return 1
    fi

    thread_snapshot 4242 "$TEST_ROOT/tasks" > "$TEST_ROOT/threads.now"
    if ! grep -Fq '4242 168 relay_owner' "$TEST_ROOT/threads.now"; then
        echo "DIAG SELF-TEST FAIL: per-TID snapshot did not retain TID/name/ticks"
        rm -rf "$TEST_ROOT"
        return 1
    fi
    printf '%s\n' '4242 100 relay_owner' > "$TEST_ROOT/threads.prev"
    THREAD_TEST=$(thread_cpu_line "$TEST_ROOT/threads.prev" "$TEST_ROOT/threads.now" 1 100)
    if ! printf '%s' "$THREAD_TEST" | grep -Fq 'tid=4242/relay_owner:68.0%'; then
        echo "DIAG SELF-TEST FAIL: per-TID CPU delta calculation is incorrect: $THREAD_TEST"
        rm -rf "$TEST_ROOT"
        return 1
    fi

    printf '%s\n' '1048576' > "$TEST_ROOT/net/testnet/statistics/rx_bytes"
    printf '%s\n' '2097152' > "$TEST_ROOT/net/testnet/statistics/tx_bytes"
    printf '%s\n' '0' > "$TEST_ROOT/net/lo/statistics/rx_bytes"
    printf '%s\n' '0' > "$TEST_ROOT/net/lo/statistics/tx_bytes"
    net_snapshot "$TEST_ROOT/net" > "$TEST_ROOT/net.prev"
    printf '%s\n' '3145728' > "$TEST_ROOT/net/testnet/statistics/rx_bytes"
    printf '%s\n' '4194304' > "$TEST_ROOT/net/testnet/statistics/tx_bytes"
    net_snapshot "$TEST_ROOT/net" > "$TEST_ROOT/net.now"
    printf '%s\n' 'Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT' \
        'testnet 00000000 0100000A 0003 0 0 0 00000000 0 0 0' > "$TEST_ROOT/route"
    ROUTE_IFACE=$(default_route_iface "$TEST_ROOT/route")
    NET_TEST=$(net_rate_line "$TEST_ROOT/net.prev" "$TEST_ROOT/net.now" "$ROUTE_IFACE" 2)
    if [ "$ROUTE_IFACE" != "testnet" ] ||
       ! printf '%s' "$NET_TEST" | grep -Fq 'testnet(default)_rx=1.00MiB/s' ||
       ! printf '%s' "$NET_TEST" | grep -Fq 'testnet(default)_tx=1.00MiB/s'; then
        echo "DIAG SELF-TEST FAIL: interface detection/rate calculation failed: $NET_TEST"
        rm -rf "$TEST_ROOT"
        return 1
    fi

    rm -rf "$TEST_ROOT"
    echo "DIAG SELF-TEST PASS: proc stat, per-TID CPU, default route, all-interface RX/TX rates"
    return 0
}

# Compare direct and r39 SOCKS5 downloads from two Singapore 100 MB test endpoints.
# Each endpoint is downloaded once direct and once through the single SSH SOCKS5 session.
set -u

main() {
    if [ "${1:-}" = "--self-test" ]; then
        run_diag_self_test
        return $?
    fi
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
    thread_snapshot "$CORE_PID" "" > "$RESULT/threads.prev"
    PREV_SAMPLE_TS=$(date +%s)
    DEFAULT_IFACE=$(default_route_iface /proc/net/route)
    [ -n "$DEFAULT_IFACE" ] || DEFAULT_IFACE=unknown
    echo "DEFAULT_ROUTE_INTERFACE=$DEFAULT_IFACE"
    SAMPLE=0
    sample_metrics() {
        cpu_snapshot > "$RESULT/cpu.now"
        net_snapshot "" > "$RESULT/net.now"
        CUR_SAMPLE_TS=$(date +%s)
        SAMPLE_ELAPSED=$((CUR_SAMPLE_TS - PREV_SAMPLE_TS))
        [ "$SAMPLE_ELAPSED" -gt 0 ] || SAMPLE_ELAPSED=1
        CUR_TICKS=$(proc_ticks "$CORE_PID")
        thread_snapshot "$CORE_PID" "" > "$RESULT/threads.now"
        PROC_CPU=$(awk -v a="$PREV_TICKS" -v b="$CUR_TICKS" -v hz="$HZ" -v elapsed="$SAMPLE_ELAPSED" 'BEGIN{d=b-a;if(d<0)d=0;if(hz<=0||elapsed<=0)printf "0.0";else printf "%.1f",100*d/(hz*elapsed)}')
        THREAD_LINE=$(thread_cpu_line "$RESULT/threads.prev" "$RESULT/threads.now" "$SAMPLE_ELAPSED" "$HZ")
        CPU_LINE=$(awk 'FNR==NR{busy[$1]=$2;total[$1]=$3;next}{dt=$3-total[$1];db=$2-busy[$1];if(dt>0){p=100*db/dt;if($1=="cpu")all=p;else cores=cores sprintf("%s=%.0f%%,",$1,p)}}END{if(all=="")all=0;printf "sys=%.0f%% cores=[%s]",all,cores}' "$RESULT/cpu.prev" "$RESULT/cpu.now")
        NET_LINE=$(net_rate_line "$RESULT/net.prev" "$RESULT/net.now" "$DEFAULT_IFACE" "$SAMPLE_ELAPSED")
        SAMPLE=$((SAMPLE+1))
        printf 'sample=%d elapsed=%ss proc_cpu=%s%% threads=[%s] %s net_default=%s %s\n' "$SAMPLE" "$SAMPLE_ELAPSED" "$PROC_CPU" "$THREAD_LINE" "$CPU_LINE" "$DEFAULT_IFACE" "$NET_LINE" >> "$RESULT/samples.log"
        cp "$RESULT/cpu.now" "$RESULT/cpu.prev"
        cp "$RESULT/net.now" "$RESULT/net.prev"
        cp "$RESULT/threads.now" "$RESULT/threads.prev"
        PREV_TICKS=$CUR_TICKS
        PREV_SAMPLE_TS=$CUR_SAMPLE_TS
    }

    cpu_snapshot > "$RESULT/cpu.prev"
    net_snapshot "" > "$RESULT/net.prev"

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
          printf "%s mode=%s bytes=%.0f (%.2f MiB) wall_seconds=%d curl_seconds=%.3f curl_avg_MiBps=%.2f http_code=%s remote_ip=%s content_type=%s\n",
            label,mode,bytes,bytes/1048576,wall,sec,speed/1048576,code,ip,type
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

    URL_DATAPACKET="http://sgp.download.datapacket.com/100mb.bin"
    URL_OVH="https://sin1-sgp.speedtest.network.ovh.net/files/100Mb.dat"

    echo "=== 100 MB DIRECT + SOCKS5; EACH REQUEST HAS A HARD 50-SECOND CAP ==="
    run_endpoint datapacket-singapore "$URL_DATAPACKET"
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
