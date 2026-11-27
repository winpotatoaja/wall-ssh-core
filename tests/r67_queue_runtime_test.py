#!/usr/bin/env python3
"""Validate R67 [QUEUE] records in TCP and TLS guest runtime logs."""
from pathlib import Path
import re
import sys

FIELD_RE = re.compile(r"([a-z][a-z0-9_]*)=([^\s]+)")
REQUIRED = (
    "span_ms", "transport", "up_rxq_valid", "up_rxq_bytes", "up_txq_valid", "up_txq_bytes",
    "tls_rx_buffered_bytes", "tls_tx_buffered_bytes", "tls_queue_capacity_bytes", "socks_clients",
    "socks_rxq_samples", "socks_rxq_bytes_sum", "socks_rxq_bytes_max", "socks_rxq_fail",
    "socks_txq_samples", "socks_txq_bytes_sum", "socks_txq_bytes_max", "socks_txq_fail",
    "c2s_ring_bytes_sum", "c2s_ring_bytes_max", "s2c_ring_bytes_sum", "s2c_ring_bytes_max",
)

def parse(line):
    return dict(FIELD_RE.findall(line)) if "[QUEUE]" in line else None

def valid(fields, transport):
    if not fields or any(k not in fields for k in REQUIRED): return False, "missing fields"
    if fields["transport"] != transport: return False, "transport mismatch"
    try: v = {k: int(fields[k], 10) for k in REQUIRED if k != "transport"}
    except ValueError: return False, "non-integer field"
    if v["span_ms"] < 1000: return False, "interval below one second"
    if v["up_rxq_valid"] != 1 or v["up_txq_valid"] != 1: return False, "upstream ioctl invalid"
    if transport == "TLS":
        if v["tls_queue_capacity_bytes"] <= 0: return False, "TLS capacity missing"
        if v["tls_rx_buffered_bytes"] > v["tls_queue_capacity_bytes"] or v["tls_tx_buffered_bytes"] > v["tls_queue_capacity_bytes"]:
            return False, "TLS occupancy exceeds capacity"
    elif v["tls_queue_capacity_bytes"] != 0: return False, "TCP unexpectedly has TLS capacity"
    if v["socks_rxq_samples"] > 0 and v["socks_rxq_bytes_max"] > v["socks_rxq_bytes_sum"]: return False, "SOCKS RX max exceeds sum"
    if v["socks_txq_samples"] > 0 and v["socks_txq_bytes_max"] > v["socks_txq_bytes_sum"]: return False, "SOCKS TX max exceeds sum"
    return True, "valid"

def check_log(path, transport):
    try: lines = Path(path).read_text(errors="replace").splitlines()
    except OSError as exc:
        print(f"FAIL: cannot read {path}: {exc}", file=sys.stderr); return False
    seen = 0
    for line in lines:
        fields = parse(line)
        if fields is None: continue
        seen += 1
        ok, reason = valid(fields, transport)
        if ok:
            print(f"PASS: {transport} QUEUE snapshot (up_rxq={fields['up_rxq_bytes']} up_txq={fields['up_txq_bytes']} socks_rx_samples={fields['socks_rxq_samples']} socks_tx_samples={fields['socks_txq_samples']})")
            return True
    print(f"FAIL: no valid {transport} QUEUE record in {path} (records_seen={seen})", file=sys.stderr); return False

TLSFAIR_REQUIRED = (
    "span_ms", "poll_calls", "poll_wakeups", "poll_timeouts",
    "poll_wait_us", "poll_wait_max_us", "poll_in", "poll_out",
    "poll_both", "owner_wake", "rx_calls", "rx_ok", "rx_bytes",
    "rx_service_us", "rx_want_read", "rx_want_write", "rx_both_ready",
    "rx_while_tx_pending", "rx_burst_max", "tx_calls", "tx_ok",
    "tx_bytes", "tx_service_us", "tx_want_read", "tx_want_write",
    "tx_both_ready", "tx_while_rx_buffered", "tx_burst_max",
    "rx_ring_full",
)

def parse_tlsfair(line):
    if "[TLSFAIR]" not in line: return None
    return dict(FIELD_RE.findall(line))

def valid_tlsfair(fields):
    if not fields or any(k not in fields for k in TLSFAIR_REQUIRED):
        return False, "missing fairness fields"
    try: v = {k: int(fields[k], 10) for k in TLSFAIR_REQUIRED}
    except ValueError: return False, "non-integer fairness field"
    if v["span_ms"] < 1000: return False, "interval below one second"
    if v["poll_calls"] == 0 or v["poll_wakeups"] == 0:
        return False, "TLS worker poll activity missing"
    if v["rx_calls"] == 0 or v["tx_calls"] == 0:
        return False, "RX/TX service calls missing"
    if v["rx_ok"] == 0 or v["tx_ok"] == 0:
        return False, "successful RX/TX operations missing"
    if v["rx_bytes"] == 0 or v["tx_bytes"] == 0:
        return False, "RX/TX byte counters missing"
    if v["rx_burst_max"] == 0 or v["tx_burst_max"] == 0:
        return False, "RX/TX burst counters missing"
    if v["rx_ok"] > v["rx_calls"] or v["tx_ok"] > v["tx_calls"]:
        return False, "successful operations exceed attempts"
    return True, "valid"

def check_tlsfair_log(path):
    try: lines = Path(path).read_text(errors="replace").splitlines()
    except OSError as exc:
        print(f"FAIL: cannot read TLS fairness log {path}: {exc}", file=sys.stderr); return False
    seen = 0
    for line in lines:
        fields = parse_tlsfair(line)
        if fields is None: continue
        seen += 1
        ok, reason = valid_tlsfair(fields)
        if ok:
            print("PASS: TLSFAIR interval "
                  f"poll={fields['poll_calls']} rx_bytes={fields['rx_bytes']} "
                  f"tx_bytes={fields['tx_bytes']} rx_burst_max={fields['rx_burst_max']} "
                  f"tx_burst_max={fields['tx_burst_max']}")
            return True
    print(f"FAIL: no valid TLSFAIR record in {path} (records_seen={seen})",
          file=sys.stderr)
    return False

S2CAGE_REQUIRED = (
    "span_ms", "nonempty_clients", "age_samples", "age_untracked",
    "age_us_avg", "age_us_max",
)

TCPINFO_REQUIRED = (
    "span_ms", "samples", "fail", "rtt_us_avg", "rtt_us_max",
    "rttvar_us_max", "unacked_segments_sum", "unacked_segments_max",
    "snd_cwnd_segments_sum", "snd_cwnd_segments_max", "total_retrans_sum",
    "total_retrans_max", "notsent_supported", "notsent_samples",
    "notsent_fail", "notsent_bytes_sum", "notsent_bytes_max",
)

def parse_tag(line, tag):
    return dict(FIELD_RE.findall(line)) if f"[{tag}]" in line else None

def valid_s2cage(fields):
    if not fields or any(k not in fields for k in S2CAGE_REQUIRED):
        return False, "missing S2CAGE fields"
    try: v = {k: int(fields[k], 10) for k in S2CAGE_REQUIRED}
    except ValueError: return False, "non-integer S2CAGE field"
    if v["span_ms"] < 1000: return False, "S2CAGE interval below one second"
    if v["age_samples"] > v["nonempty_clients"] or v["age_untracked"] > v["nonempty_clients"]:
        return False, "S2CAGE sample counts exceed nonempty clients"
    if v["age_samples"] + v["age_untracked"] > v["nonempty_clients"]:
        return False, "S2CAGE tracked and untracked counts exceed clients"
    if v["age_us_avg"] > v["age_us_max"]:
        return False, "S2CAGE average age exceeds maximum"
    if v["age_samples"] == 0 and (v["age_us_avg"] or v["age_us_max"]):
        return False, "S2CAGE age present without samples"
    return True, "valid"

def valid_tcpinfo(fields):
    if not fields or any(k not in fields for k in TCPINFO_REQUIRED):
        return False, "missing TCPINFO fields"
    try: v = {k: int(fields[k], 10) for k in TCPINFO_REQUIRED}
    except ValueError: return False, "non-integer TCPINFO field"
    if v["span_ms"] < 1000: return False, "TCPINFO interval below one second"
    if v["notsent_supported"] not in (0, 1):
        return False, "invalid SIOCOUTQNSD support flag"
    if v["rtt_us_avg"] > v["rtt_us_max"]:
        return False, "TCP RTT average exceeds maximum"
    if v["unacked_segments_max"] > v["unacked_segments_sum"]:
        return False, "TCP unacked maximum exceeds sum"
    if v["snd_cwnd_segments_max"] > v["snd_cwnd_segments_sum"]:
        return False, "TCP congestion window maximum exceeds sum"
    if v["total_retrans_max"] > v["total_retrans_sum"]:
        return False, "TCP retransmit maximum exceeds sum"
    if v["notsent_bytes_max"] > v["notsent_bytes_sum"]:
        return False, "notsent maximum exceeds sum"
    if v["samples"] == 0 and any(v[k] for k in (
        "rtt_us_avg", "rtt_us_max", "rttvar_us_max", "unacked_segments_sum",
        "unacked_segments_max", "snd_cwnd_segments_sum",
        "snd_cwnd_segments_max", "total_retrans_sum", "total_retrans_max"
    )):
        return False, "TCPINFO metrics present without samples"
    if v["notsent_supported"] == 0 and (
        v["notsent_samples"] or v["notsent_fail"] or
        v["notsent_bytes_sum"] or v["notsent_bytes_max"]
    ):
        return False, "unsupported SIOCOUTQNSD reports measurements"
    return True, "valid"

def check_tag_log(path, tag, validator):
    try: lines = Path(path).read_text(errors="replace").splitlines()
    except OSError as exc:
        print(f"FAIL: cannot read {tag} log {path}: {exc}", file=sys.stderr); return False
    seen = 0
    for line in lines:
        fields = parse_tag(line, tag)
        if fields is None: continue
        seen += 1
        ok, reason = validator(fields)
        if ok:
            print(f"PASS: {tag} interval ({fields.get('span_ms')} ms)")
            return True
    print(f"FAIL: no valid {tag} record in {path} (records_seen={seen})",
          file=sys.stderr)
    return False

def self_test():
    sample = "[QUEUE] span_ms=1004 transport=TLS up_rxq_valid=1 up_rxq_bytes=0 up_txq_valid=1 up_txq_bytes=12 tls_rx_buffered_bytes=7 tls_tx_buffered_bytes=9 tls_queue_capacity_bytes=65536 socks_clients=1 socks_rxq_samples=1 socks_rxq_bytes_sum=10 socks_rxq_bytes_max=10 socks_rxq_fail=0 socks_txq_samples=1 socks_txq_bytes_sum=20 socks_txq_bytes_max=20 socks_txq_fail=0 c2s_ring_bytes_sum=0 c2s_ring_bytes_max=0 s2c_ring_bytes_sum=4 s2c_ring_bytes_max=4"
    fields = parse(sample)
    fair_sample = {
        "span_ms":"1001", "poll_calls":"50", "poll_wakeups":"45",
        "poll_timeouts":"5", "poll_wait_us":"600000", "poll_wait_max_us":"990000",
        "poll_in":"20", "poll_out":"30", "poll_both":"10", "owner_wake":"12",
        "rx_calls":"20", "rx_ok":"18", "rx_bytes":"1048576", "rx_service_us":"4000",
        "rx_want_read":"8", "rx_want_write":"0", "rx_both_ready":"4", "rx_while_tx_pending":"6",
        "rx_burst_max":"5", "tx_calls":"22", "tx_ok":"19", "tx_bytes":"1048576",
        "tx_service_us":"5000", "tx_want_read":"1", "tx_want_write":"1",
        "tx_both_ready":"4", "tx_while_rx_buffered":"7", "tx_burst_max":"6",
        "rx_ring_full":"0",
    }
    s2cage_sample = {
        "span_ms":"1001", "nonempty_clients":"2", "age_samples":"2",
        "age_untracked":"0", "age_us_avg":"2500", "age_us_max":"4000",
    }
    tcpinfo_sample = {
        "span_ms":"1001", "samples":"2", "fail":"0", "rtt_us_avg":"1200",
        "rtt_us_max":"1800", "rttvar_us_max":"300", "unacked_segments_sum":"3",
        "unacked_segments_max":"2", "snd_cwnd_segments_sum":"20",
        "snd_cwnd_segments_max":"12", "total_retrans_sum":"1",
        "total_retrans_max":"1", "notsent_supported":"1", "notsent_samples":"2",
        "notsent_fail":"0", "notsent_bytes_sum":"4096", "notsent_bytes_max":"4096",
    }
    checks = [(valid(fields, "TLS")[0], "complete TLS record accepted"),
              (not valid(fields, "TCP")[0], "transport mismatch rejected"),
              (not valid({**fields, "up_rxq_valid":"0"}, "TLS")[0], "invalid ioctl rejected"),
              (not valid({**fields, "tls_rx_buffered_bytes":"65537"}, "TLS")[0], "TLS over-capacity record rejected"),
              (valid_tlsfair(fair_sample)[0], "complete TLS fairness interval accepted"),
              (not valid_tlsfair({**fair_sample, "tx_bytes":"0"})[0], "empty TX activity rejected"),
              (not valid_tlsfair({**fair_sample, "rx_ok":"25"})[0], "success count above attempt count rejected"),
              (valid_s2cage(s2cage_sample)[0], "complete S2C age interval accepted"),
              (not valid_s2cage({**s2cage_sample, "age_us_avg":"5000"})[0], "S2C age average above max rejected"),
              (valid_tcpinfo(tcpinfo_sample)[0], "complete TCP_INFO/SIOCOUTQNSD interval accepted"),
              (valid_tcpinfo({**tcpinfo_sample, "notsent_supported":"0", "notsent_samples":"0", "notsent_fail":"0", "notsent_bytes_sum":"0", "notsent_bytes_max":"0"})[0], "unsupported SIOCOUTQNSD fallback accepted"),
              (not valid_tcpinfo({**tcpinfo_sample, "notsent_bytes_max":"8192"})[0], "notsent maximum above sum rejected")]
    passed = True
    for ok, label in checks:
        print(("PASS: " if ok else "FAIL: ") + label); passed = passed and ok
    return passed

def main():
    if len(sys.argv) == 1: return 0 if self_test() else 1
    if len(sys.argv) != 3:
        print("usage: r67_queue_runtime_test.py TCP_LOG TLS_LOG", file=sys.stderr); return 2
    if not check_log(sys.argv[1], "TCP"): return 1
    if not check_log(sys.argv[2], "TLS"): return 1
    if not check_tlsfair_log(sys.argv[2]): return 1
    for path in sys.argv[1:]:
        if not check_tag_log(path, "S2CAGE", valid_s2cage): return 1
        if not check_tag_log(path, "TCPINFO", valid_tcpinfo): return 1
    return 0

if __name__ == "__main__":
    sys.exit(main())
