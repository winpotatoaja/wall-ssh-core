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

DIAG_TIMER=${DIAG_TIMER:-/tmp/mips-test/diag-timer}

monotonic_milliseconds() {
    [ -x "$DIAG_TIMER" ] || {
        echo "ERROR: monotonic timer helper missing: $DIAG_TIMER"
        return 2
    }
    "$DIAG_TIMER" now-ms
}

sleep_microseconds() {
    [ -x "$DIAG_TIMER" ] || {
        echo "ERROR: nanosleep helper missing: $DIAG_TIMER"
        return 2
    }
    "$DIAG_TIMER" sleep-us "$1"
}

elapsed_seconds() {
    awk -v before="$1" -v after="$2" 'BEGIN {
        elapsed = (after - before) / 1000
        if (elapsed < 0.001) elapsed = 0.001
        printf "%.3f", elapsed
    }'
}

wait_until_next_sample() {
    # CPU and WAN baselines are sampled before the per-sample timestamp.
    # On the MIPS guest that pre-snapshot costs about 50 ms. Schedule at 200 ms
    # so the timestamp-to-timestamp cadence (including that work) is ~250 ms.
    TARGET_SAMPLE_MS=$((PREV_SAMPLE_MS + 200))
    NOW_SAMPLE_MS=$(monotonic_milliseconds) || return 2
    REMAINING_SAMPLE_MS=$((TARGET_SAMPLE_MS - NOW_SAMPLE_MS))
    if [ "$REMAINING_SAMPLE_MS" -gt 0 ]; then
        sleep_microseconds "$((REMAINING_SAMPLE_MS * 1000))" || return 2
    fi
    return 0
}

thread_snapshot() {
    PID="$1"
    TASK_ROOT="$2"
    [ -n "$TASK_ROOT" ] || TASK_ROOT="/proc/$PID/task"
    # One awk process reads all per-thread stat files. Avoid spawning dirname,
    # basename, cat, tr and one awk per TID on the slow MIPS guest.
    awk -v owner="$PID" '
        {
            path = FILENAME
            path_count = split(path, path_part, "/")
            tid = path_part[path_count - 1]

            comm = $0
            sub(/^.*\(/, "", comm)
            sub(/\).*/, "", comm)
            gsub(/[[:space:]]+/, "_", comm)
            if (tid == owner)
                comm = "ssh_owner"
            if (comm == "")
                comm = "unknown"

            stat = $0
            sub(/^.*\) /, "", stat)
            count = split(stat, field, " ")
            ticks = count >= 13 ? field[12] + field[13] : 0
            printf "%s %.0f %s\n", tid, ticks, comm
        }
    ' "$TASK_ROOT"/*/stat 2>/dev/null
}

cpu_reference_ticks() {
    PREV_CPU_FILE="$1"
    NOW_CPU_FILE="$2"
    awk '
        FNR == NR {
            if ($1 ~ /^cpu[0-9]+$/) old_total[$1] = $3 + 0
            next
        }
        $1 ~ /^cpu[0-9]+$/ {
            delta = ($3 + 0) - (old_total[$1] + 0)
            if (delta > 0) {
                sum += delta
                count++
            }
        }
        END {
            if (count > 0) printf "%.2f", sum / count
            else printf "0"
        }
    ' "$PREV_CPU_FILE" "$NOW_CPU_FILE"
}

thread_cpu_line() {
    PREV_FILE="$1"
    NOW_FILE="$2"
    CPU_REFERENCE_TICKS="$3"
    awk -v ref_ticks="$CPU_REFERENCE_TICKS" '
        FNR == NR { old_ticks[$1] = $2 + 0; next }
        {
            delta = ($2 + 0) - (old_ticks[$1] + 0)
            if (delta < 0) delta = 0
            total_delta += delta
            pct = ref_ticks > 0 ? 100 * delta / ref_ticks : 0
            thread_line = thread_line sprintf("tid=%s/%s:%.1f%%,", $1, $3, pct)
            if (pct > max_pct) {
                max_pct = pct
                max_tid = $1
                max_name = $3
            }
            count++
        }
        END {
            process_pct = ref_ticks > 0 ? 100 * total_delta / ref_ticks : 0
            if (count == 0)
                thread_line = "no_threads"
            printf "%.1f|%s|max_tid=%s/%s:%.1f%%", process_pct, thread_line, max_tid, max_name, max_pct
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
    if [ "$NET_ROOT" = /sys/class/net ]; then
        # /proc/net/dev exposes every interface's RX/TX byte counters in one read.
        awk '
            NR > 2 {
                line = $0
                sub(/^[[:space:]]+/, "", line)
                count = split(line, part, ":")
                if (count < 2)
                    next
                name = part[1]
                if (name == "lo")
                    next
                data = part[2]
                sub(/^[[:space:]]+/, "", data)
                fields = split(data, value, /[[:space:]]+/)
                if (fields >= 9)
                    printf "%s %.0f %.0f\n", name, value[1], value[9]
            }
        ' /proc/net/dev 2>/dev/null
        return
    fi

    # Small filesystem-backed path retained for the isolated diagnostic self-test.
    for NET_PATH in "$NET_ROOT"/*; do
        [ -d "$NET_PATH/statistics" ] || continue
        NET_NAME=${NET_PATH##*/}
        [ "$NET_NAME" = lo ] && continue
        NET_RX=0
        NET_TX=0
        IFS= read -r NET_RX < "$NET_PATH/statistics/rx_bytes" || NET_RX=0
        IFS= read -r NET_TX < "$NET_PATH/statistics/tx_bytes" || NET_TX=0
        case "$NET_RX" in ''|*[!0-9]*) NET_RX=0;; esac
        case "$NET_TX" in ''|*[!0-9]*) NET_TX=0;; esac
        printf '%s %s %s\n' "$NET_NAME" "$NET_RX" "$NET_TX"
    done
}

copy_snapshot_file() {
    SOURCE="$1"
    DEST="$2"
    {
        while IFS= read -r SNAPSHOT_LINE; do
            printf '%s\n' "$SNAPSHOT_LINE"
        done < "$SOURCE"
    } > "$DEST"
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
    TEST_ROOT="/tmp/r52-speedtest-diag-test"
    if [ ! -x "$DIAG_TIMER" ]; then
        echo "DIAG SELF-TEST FAIL: MIPS monotonic timer helper is missing: $DIAG_TIMER"
        return 2
    fi
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
    if ! grep -Fq '4242 168 ssh_owner' "$TEST_ROOT/threads.now"; then
        echo "DIAG SELF-TEST FAIL: per-TID snapshot did not retain TID/name/ticks"
        rm -rf "$TEST_ROOT"
        return 1
    fi
    printf '%s\n' 'cpu 400 400' 'cpu0 50 100' 'cpu1 50 100' 'cpu2 50 100' 'cpu3 50 100' > "$TEST_ROOT/cpu.prev"
    printf '%s\n' 'cpu 800 800' 'cpu0 100 200' 'cpu1 100 200' 'cpu2 100 200' 'cpu3 100 200' > "$TEST_ROOT/cpu.now"
    CPU_REFERENCE=$(cpu_reference_ticks "$TEST_ROOT/cpu.prev" "$TEST_ROOT/cpu.now")
    if [ "$CPU_REFERENCE" != "100.00" ]; then
        echo "DIAG SELF-TEST FAIL: per-vCPU tick reference expected 100, got $CPU_REFERENCE"
        rm -rf "$TEST_ROOT"
        return 1
    fi
    printf '%s\n' '4242 68 ssh_owner' > "$TEST_ROOT/threads.prev"
    THREAD_TEST=$(thread_cpu_line "$TEST_ROOT/threads.prev" "$TEST_ROOT/threads.now" "$CPU_REFERENCE")
    if ! printf '%s' "$THREAD_TEST" | grep -Fq 'tid=4242/ssh_owner:100.0%'; then
        echo "DIAG SELF-TEST FAIL: per-TID CPU delta calculation is incorrect: $THREAD_TEST"
        rm -rf "$TEST_ROOT"
        return 1
    fi
    case "$THREAD_TEST" in
        100.0\|*) ;;
        *)
            echo "DIAG SELF-TEST FAIL: aggregated process CPU should be 100.0%, got $THREAD_TEST"
            rm -rf "$TEST_ROOT"
            return 1
            ;;
    esac

    PROC_TEST=$(awk -v a=68 -v b=168 -v ref="$CPU_REFERENCE" 'BEGIN{d=b-a;if(d<0)d=0;printf "%.1f",(ref>0?100*d/ref:0)}')
    if [ "$PROC_TEST" != "100.0" ]; then
        echo "DIAG SELF-TEST FAIL: process CPU normalization is incorrect: $PROC_TEST"
        rm -rf "$TEST_ROOT"
        return 1
    fi
    ELAPSED_TEST=$(elapsed_seconds "12340" "12590")
    if [ "$ELAPSED_TEST" != "0.250" ]; then
        echo "DIAG SELF-TEST FAIL: monotonic-ms elapsed calculation expected 0.250, got $ELAPSED_TEST"
        rm -rf "$TEST_ROOT"
        return 1
    fi
    SLEEP_START=$(monotonic_milliseconds)
    sleep_microseconds 250000 || {
        echo "DIAG SELF-TEST FAIL: nanosleep helper rejected 250000 microseconds"
        rm -rf "$TEST_ROOT"
        return 1
    }
    sleep_microseconds 250000 || {
        echo "DIAG SELF-TEST FAIL: second nanosleep helper call failed"
        rm -rf "$TEST_ROOT"
        return 1
    }
    sleep_microseconds 250000 || {
        echo "DIAG SELF-TEST FAIL: third nanosleep helper call failed"
        rm -rf "$TEST_ROOT"
        return 1
    }
    SLEEP_END=$(monotonic_milliseconds)
    SLEEP_TEST=$(elapsed_seconds "$SLEEP_START" "$SLEEP_END")
    if ! awk -v elapsed="$SLEEP_TEST" 'BEGIN { exit !(elapsed >= 0.60 && elapsed <= 1.50) }'; then
        echo "DIAG SELF-TEST FAIL: three nanosleep 250ms calls should total 0.60-1.50s, got $SLEEP_TEST"
        rm -rf "$TEST_ROOT"
        return 1
    fi

    thread_snapshot "$$" "" > "$TEST_ROOT/runtime-threads"
    if ! grep -Eq "^$$ [0-9]+ ssh_owner$" "$TEST_ROOT/runtime-threads"; then
        echo "DIAG SELF-TEST FAIL: live /proc thread snapshot did not find the current shell owner"
        rm -rf "$TEST_ROOT"
        return 1
    fi
    net_snapshot "" > "$TEST_ROOT/runtime-net"
    if ! grep -Eq '^[^ ]+ [0-9]+ [0-9]+$' "$TEST_ROOT/runtime-net"; then
        echo "DIAG SELF-TEST FAIL: live /proc/net/dev snapshot returned no RX/TX interface counters"
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

# Focused Datapacket direct-vs-r46-SOCKS5 diagnostic retest (100 MB).
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
    echo "r52_100MB_50SEC_DIRECT_VS_SOCKS5_TEST_START=$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)"
    SOCKS_INFO="SOCKS5=$SOCKS"
    GUEST_INFO="GUEST=$(uname -a)"
    VCPU_COUNT=$(grep -c '^processor' /proc/cpuinfo 2>/dev/null)
    case "$VCPU_COUNT" in ''|*[!0-9]*) VCPU_COUNT=0;; esac
    CPU_TOPOLOGY=""
    : > "$RESULT/cpu-topology.keys"
    for CPU_PATH in /sys/devices/system/cpu/cpu[0-9]*; do
        [ -d "$CPU_PATH/topology" ] || continue
        CPU_ID=${CPU_PATH##*cpu}
        CORE_ID=$(cat "$CPU_PATH/topology/core_id" 2>/dev/null)
        PACKAGE_ID=$(cat "$CPU_PATH/topology/physical_package_id" 2>/dev/null)
        [ -n "$CORE_ID" ] || continue
        [ -n "$PACKAGE_ID" ] || PACKAGE_ID=0
        printf '%s:%s\n' "$PACKAGE_ID" "$CORE_ID" >> "$RESULT/cpu-topology.keys"
        CPU_TOPOLOGY="${CPU_TOPOLOGY}${CPU_ID}:package${PACKAGE_ID}:core${CORE_ID};"
    done
    CPU_TOPOLOGY_PHYSICAL_CORES=$(sort -u "$RESULT/cpu-topology.keys" | wc -l | tr -d ' ')
    case "$CPU_TOPOLOGY_PHYSICAL_CORES" in ''|*[!0-9]*) CPU_TOPOLOGY_PHYSICAL_CORES=0;; esac
    SAMPLE_INTERVAL_MS=250
    {
        echo "r52_100MB_50SEC_DIRECT_VS_SOCKS5_TEST_START=$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)"
        echo "$SOCKS_INFO"
        echo "$GUEST_INFO"
        echo "VCPU_COUNT=$VCPU_COUNT"
        echo "CPU_TOPOLOGY=$CPU_TOPOLOGY"
        echo "CPU_TOPOLOGY_PHYSICAL_CORES=$CPU_TOPOLOGY_PHYSICAL_CORES"
        echo "SAMPLE_INTERVAL_MS=$SAMPLE_INTERVAL_MS"
        echo "SAMPLE_CLOCK=clock_gettime(CLOCK_MONOTONIC)"
    } | tee "$RESULT/environment.log"

    if [ "$VCPU_COUNT" -ne 4 ] || [ "$CPU_TOPOLOGY_PHYSICAL_CORES" -ne 2 ]; then
        echo "ERROR: expected MT7621A topology of 4 Linux CPUs across 2 physical cores; got vcpus=$VCPU_COUNT physical_cores=$CPU_TOPOLOGY_PHYSICAL_CORES" | tee -a "$RESULT/errors.log"
        return 2
    fi

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

    if ! grep -Fq 'SSH Cipher: chacha20-poly1305@openssh.com' "$RESULT/core.log"; then
        echo "ERROR: ChaCha20-Poly1305 was not negotiated; skipping both 100 MB downloads"
        cat "$RESULT/core.log" 2>/dev/null
        kill -TERM "$CORE_PID" 2>/dev/null || :
        return 2
    fi
    echo "PASS: ChaCha20-Poly1305 negotiated before bandwidth tests begin."

    # Do not spend the two 100 MB transfers unless the inbound ChaCha worker
    # pool was actually created during the SSH key exchange.
    CRYPTO_WORKERS_READY=0
    N=0
    while [ "$N" -lt 10 ]; do
        if grep -Eq '\[ChaCha\] r51 S2C payload: detected_cpus=4 detected_cores=2 owner_payload_lanes=0 crypto_workers=3 poly1305_workers=1 chacha_payload_workers=3 active_worker_lanes=3 threshold=4096 bytes' "$RESULT/core.log"; then
            CRYPTO_WORKERS_READY=1
            break
        fi
        kill -0 "$CORE_PID" 2>/dev/null || break
        N=$((N+1))
        sleep 1
    done
    if [ "$CRYPTO_WORKERS_READY" -ne 1 ]; then
        echo "ERROR: expected r51 authenticated 3-worker ChaCha plan was not active; skipping both 100 MB downloads"
        grep -E '\[PERF\]|ChaCha|SSH Cipher' "$RESULT/core.log" 2>/dev/null || :
        kill -TERM "$CORE_PID" 2>/dev/null || :
        return 2
    fi
    echo "PASS: MT7621A topology detected as 2 physical cores / 4 Linux CPUs; r51 authenticated with Poly1305 first, then used all 3 workers for ChaCha20."

    thread_snapshot "$CORE_PID" "" > "$RESULT/threads.prev"
    PREV_SAMPLE_MS=$(monotonic_milliseconds)
    DEFAULT_IFACE=$(default_route_iface /proc/net/route)
    [ -n "$DEFAULT_IFACE" ] || DEFAULT_IFACE=unknown
    echo "DEFAULT_ROUTE_INTERFACE=$DEFAULT_IFACE CPU_REFERENCE=average_per_vCPU_proc_stat_delta"
    SAMPLE=0
    sample_metrics() {
        cpu_snapshot > "$RESULT/cpu.now"
        net_snapshot "" > "$RESULT/net.now"
        CUR_SAMPLE_MS=$(monotonic_milliseconds)
        SAMPLE_DELTA_MS=$((CUR_SAMPLE_MS - PREV_SAMPLE_MS))
        [ "$SAMPLE_DELTA_MS" -gt 0 ] || SAMPLE_DELTA_MS=1
        SAMPLE_ELAPSED=$(printf '%d.%03d' "$((SAMPLE_DELTA_MS / 1000))" "$((SAMPLE_DELTA_MS % 1000))")
        thread_snapshot "$CORE_PID" "" > "$RESULT/threads.now"
        CPU_REFERENCE=$(cpu_reference_ticks "$RESULT/cpu.prev" "$RESULT/cpu.now")
        THREAD_METRICS=$(thread_cpu_line "$RESULT/threads.prev" "$RESULT/threads.now" "$CPU_REFERENCE")
        PROC_CPU=${THREAD_METRICS%%|*}
        THREAD_LINE=${THREAD_METRICS#*|}
        THREAD_LINE=${THREAD_LINE%%|*}
        THREAD_MAX=${THREAD_METRICS##*|}
        CPU_LINE=$(awk 'FNR==NR{busy[$1]=$2;total[$1]=$3;next}{dt=$3-total[$1];db=$2-busy[$1];if(dt>0){p=100*db/dt;if($1=="cpu")all=p;else cores=cores sprintf("%s=%.0f%%,",$1,p)}}END{if(all=="")all=0;printf "sys=%.0f%% cores=[%s]",all,cores}' "$RESULT/cpu.prev" "$RESULT/cpu.now")
        NET_LINE=$(net_rate_line "$RESULT/net.prev" "$RESULT/net.now" "$DEFAULT_IFACE" "$SAMPLE_ELAPSED")
        SAMPLE=$((SAMPLE+1))
        printf 'sample=%d elapsed=%ss proc_cpu=%s%% threads=[%s%s] %s net_default=%s %s\n' "$SAMPLE" "$SAMPLE_ELAPSED" "$PROC_CPU" "$THREAD_LINE" "$THREAD_MAX" "$CPU_LINE" "$DEFAULT_IFACE" "$NET_LINE" >> "$RESULT/samples.log"
        copy_snapshot_file "$RESULT/cpu.now" "$RESULT/cpu.prev"
        copy_snapshot_file "$RESULT/net.now" "$RESULT/net.prev"
        copy_snapshot_file "$RESULT/threads.now" "$RESULT/threads.prev"
        PREV_SAMPLE_MS=$CUR_SAMPLE_MS
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
            # Reset counters after the direct transfer so samples describe only
            # the relay path, not the preceding direct download.
            cpu_snapshot > "$RESULT/cpu.prev"
            net_snapshot "" > "$RESULT/net.prev"
            thread_snapshot "$CORE_PID" "" > "$RESULT/threads.prev"
            PREV_SAMPLE_MS=$(monotonic_milliseconds)
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
            if [ "$MODE" = "socks5" ]; then
                if ! wait_until_next_sample; then
                    echo "ERROR: monotonic 250 ms sample scheduler failed"
                    kill -TERM "$CORE_PID" 2>/dev/null || :
                    return 2
                fi
                if kill -0 "$CURL_PID" 2>/dev/null; then
                    sample_metrics
                fi
            else
                sleep 1
            fi
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

    echo "=== SINGLE ENDPOINT DATAPACKET 100 MB DIRECT + SOCKS5; 50-SECOND HARD CAP ==="
    run_endpoint datapacket-singapore "$URL_DATAPACKET"

    kill -TERM "$CORE_PID" 2>/dev/null || :
    WAIT_N=0
    while kill -0 "$CORE_PID" 2>/dev/null && [ "$WAIT_N" -lt 10 ]; do sleep 1; WAIT_N=$((WAIT_N+1)); done
    kill -KILL "$CORE_PID" 2>/dev/null || :

    {
      echo "r52 DATAPACKET 100 MB DIRECT VS SOCKS5 DIAGNOSTIC SUMMARY (50s hard cap per transfer)"
      cat "$RESULT/environment.log"
      cat "$RESULT/download-results.log"
      echo "--- PAIRS ---"
      cat "$RESULT/pairs.log"
      echo "--- SKIPPED ---"
      cat "$RESULT/skipped.log"
      echo "PAIR_COUNT=$PAIR_COUNT"
      echo "SAMPLE_COUNT=$SAMPLE"
      echo "VCPU_COUNT=$(grep -c '^processor' /proc/cpuinfo 2>/dev/null)"
      echo "SAMPLE_INTERVAL_MS=$SAMPLE_INTERVAL_MS"
    } | tee "$RESULT/summary.txt"

    echo "RESULT_DIR=$RESULT"
    echo "r52_100MB_50SEC_DIRECT_VS_SOCKS5_TEST_END=$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)"
    [ ! -s "$RESULT/errors.log" ] || return 2
    [ "$PAIR_COUNT" -ge 1 ] || {
        echo "ERROR: no endpoint completed a full direct+SOCKS5 100 MB pair" | tee -a "$RESULT/errors.log"
        return 2
    }
    return 0
}
main "$@"
