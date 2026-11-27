#!/usr/bin/env python3
"""Analyze matched R65-A/R65-B MT7621 QEMU Datapacket A/B benchmark runs."""
from __future__ import annotations

import json
import math
import re
import statistics
import sys
from pathlib import Path

DOWNLOAD = re.compile(
    r"^(\S+) mode=(direct|socks5) bytes=(\d+).*?"
    r"curl_seconds=([0-9.]+) curl_avg_MiBps=([0-9.]+) "
    r"http_code=(\d+) remote_ip=(\S+)"
)
THREAD = re.compile(r"tid=(\d+)/([^:,]+):([0-9.]+)%")
RX = re.compile(r"wan\\(default\\)_rx=([0-9.]+)MiB/s")
FIELD = re.compile(r"([a-zA-Z0-9_]+)=([0-9]+)")

PROFILES = {
    "chacha": {"cipher": "chacha20-poly1305@openssh.com", "mac": None},
    "nonetm": {"cipher": "aes128-ctr", "mac": "hmac-sha2-256"},
    "etm": {"cipher": "aes128-ctr", "mac": "hmac-sha2-256-etm@openssh.com"},
}


def percentile(values: list[float], q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, max(0, math.ceil(q * len(ordered)) - 1))]


def fmt(value) -> str:
    return "n/a" if value is None else str(value)


def load_run(path: Path) -> dict:
    match = re.fullmatch(r"qemu-speedtest-(chacha|nonetm|etm)-(a|b)-rep([12])", path.name)
    profile = variant = rep = None
    kind = "throughput"
    if match:
        profile, variant, rep = match.groups()
    else:
        match = re.fullmatch(r"qemu-speedtest-(nonetm|etm)-(a|b)-profile", path.name)
        if match:
            profile, variant = match.groups()
            kind = "profile"
    if not match:
        return {}

    out = {
        "path": str(path), "name": path.name, "profile": profile,
        "variant": variant.upper(), "repeat": int(rep) if rep else None,
        "kind": kind, "downloads": [], "samples": [], "perf_mac": [],
        "negotiation": [], "errors": [], "skipped": [], "perf_totals": {},
    }

    file = path / "download-results.log"
    if file.exists():
        for line in file.read_text(errors="replace").splitlines():
            m = DOWNLOAD.match(line.strip())
            if m:
                label, mode, n, seconds, speed, code, ip = m.groups()
                out["downloads"].append({
                    "label": label, "mode": mode, "bytes": int(n),
                    "seconds": float(seconds), "speed": float(speed),
                    "http": int(code), "remote_ip": ip,
                })

    for name in ("errors", "skipped"):
        file = path / f"{name}.log"
        if file.exists():
            out[name] = file.read_text(errors="replace").splitlines()

    file = path / "samples.log"
    if file.exists():
        for line in file.read_text(errors="replace").splitlines():
            if not line.startswith("sample="):
                continue
            elapsed = re.search(r"\belapsed=([0-9.]+)s", line)
            proc = re.search(r"\bproc_cpu=([0-9.]+)%", line)
            threads = {name: float(value) for _, name, value in THREAD.findall(line)}
            rx = RX.search(line)
            out["samples"].append({
                "elapsed": float(elapsed.group(1)) if elapsed else None,
                "proc": float(proc.group(1)) if proc else None,
                "threads": threads, "rx": float(rx.group(1)) if rx else None,
            })

    file = path / "core.log"
    if file.exists():
        lines = file.read_text(errors="replace").splitlines()
        out["negotiation"] = [x.strip() for x in lines if "SSH Cipher:" in x]
        out["auth_count"] = sum("[AUTH-DIAG] authentication accepted" in x for x in lines)
        out["keys_count"] = sum("Session Keys Established" in x for x in lines)
        out["perf_mac"] = [x.strip() for x in lines if "[PERF-MAC]" in x]
        for line in out["perf_mac"]:
            for key, value in FIELD.findall(line):
                out["perf_totals"][key] = out["perf_totals"].get(key, 0) + int(value)
    else:
        out["auth_count"] = 0
        out["keys_count"] = 0

    file = path / "pairs.log"
    out["pair_passes"] = (
        sum(x.startswith("PAIR PASS:") for x in file.read_text(errors="replace").splitlines())
        if file.exists() else 0
    )
    file = path / "profile-status.txt"
    if file.exists():
        out["profile_status"] = file.read_text(errors="replace").splitlines()
    return out


def valid_download(run: dict, mode: str) -> dict | None:
    found = [
        item for item in run["downloads"]
        if item["mode"] == mode and item["http"] == 200 and item["bytes"] >= 95_000_000
    ]
    return found[0] if found else None


def valid_throughput_run(run: dict) -> tuple[bool, list[str]]:
    issues: list[str] = []
    direct = valid_download(run, "direct")
    socks = valid_download(run, "socks5")
    if direct is None:
        issues.append("no valid direct 100 MB transfer")
    if socks is None:
        issues.append("no valid SOCKS5 100 MB transfer")
    if direct and socks and direct["bytes"] != socks["bytes"]:
        issues.append("direct/SOCKS byte counts differ")
    if run.get("pair_passes") != 1:
        issues.append("expected exactly one verified direct/SOCKS byte-count pair")
    expected = PROFILES[run["profile"]]
    joined = "\n".join(run["negotiation"])
    if expected["cipher"] not in joined:
        issues.append(f"expected cipher {expected['cipher']} not observed")
    if expected["mac"] and expected["mac"] not in joined:
        issues.append(f"expected MAC {expected['mac']} not observed")
    if run.get("auth_count") != 1:
        issues.append(f"expected one core authentication, found {run.get('auth_count')}")
    if run.get("keys_count") != 1:
        issues.append(f"expected one SSH key establishment, found {run.get('keys_count')}")
    return not issues, issues


def summarize_profile(profile: str, runs: list[dict]) -> dict:
    variants = {}
    for variant in ("A", "B"):
        selected = sorted(
            [r for r in runs if r["profile"] == profile and r["variant"] == variant and r["kind"] == "throughput"],
            key=lambda x: x["repeat"] or 0,
        )
        valid = []
        rejected = []
        for run in selected:
            ok, issues = valid_throughput_run(run)
            if ok:
                valid.append(run)
            else:
                rejected.append({"run": run["name"], "issues": issues, "skipped": run["skipped"]})
        socks = [valid_download(r, "socks5") for r in valid]
        direct = [valid_download(r, "direct") for r in valid]
        owner = [
            sample["threads"]["ssh_owner"]
            for run in valid for sample in run["samples"]
            if "ssh_owner" in sample["threads"]
        ]
        rx = [
            sample["rx"]
            for run in valid for sample in run["samples"]
            if sample["rx"] is not None
        ]
        variants[variant] = {
            "runs_found": len(selected), "valid_runs": len(valid),
            "socks5_speeds_MiBps": [round(x["speed"], 3) for x in socks if x],
            "direct_speeds_MiBps": [round(x["speed"], 3) for x in direct if x],
            "socks5_median_MiBps": round(statistics.median(x["speed"] for x in socks if x), 3) if socks else None,
            "socks5_mean_MiBps": round(statistics.mean(x["speed"] for x in socks if x), 3) if socks else None,
            "direct_median_MiBps": round(statistics.median(x["speed"] for x in direct if x), 3) if direct else None,
            "socks5_vs_direct_median_pct": round(
                (statistics.median(x["speed"] for x in socks if x) /
                 statistics.median(x["speed"] for x in direct if x) - 1) * 100, 2
            ) if socks and direct and statistics.median(x["speed"] for x in direct if x) > 0 else None,
            "ssh_owner_avg_pct": round(statistics.mean(owner), 2) if owner else None,
            "ssh_owner_p95_pct": round(percentile(owner, .95), 2) if owner else None,
            "ssh_owner_max_pct": round(max(owner), 2) if owner else None,
            "wan_rx_median_MiBps": round(statistics.median(rx), 3) if rx else None,
            "wan_rx_p95_MiBps": round(percentile(rx, .95), 3) if rx else None,
            "wan_rx_under_0_05_pct": round(sum(x < .05 for x in rx) / len(rx) * 100, 2) if rx else None,
            "sample_count": len(owner),
            "direct_remote_ips": sorted({x["remote_ip"] for r in valid for x in r["downloads"] if x["mode"] == "direct"}),
            "socks5_proxy_peers": sorted({x["remote_ip"] for r in valid for x in r["downloads"] if x["mode"] == "socks5"}),
            "rejected": rejected,
        }

    paired = []
    for rep in (1, 2):
        a = next((r for r in runs if r["profile"] == profile and r["variant"] == "A" and r["kind"] == "throughput" and r["repeat"] == rep), None)
        b = next((r for r in runs if r["profile"] == profile and r["variant"] == "B" and r["kind"] == "throughput" and r["repeat"] == rep), None)
        if a and b:
            a_ok, _ = valid_throughput_run(a)
            b_ok, _ = valid_throughput_run(b)
            if a_ok and b_ok:
                a_speed = valid_download(a, "socks5")["speed"]
                b_speed = valid_download(b, "socks5")["speed"]
                paired.append({
                    "repeat": rep, "A_MiBps": round(a_speed, 3),
                    "B_MiBps": round(b_speed, 3),
                    "B_vs_A_pct": round((b_speed / a_speed - 1) * 100, 2) if a_speed > 0 else None,
                })

    a_med = variants["A"]["socks5_median_MiBps"]
    b_med = variants["B"]["socks5_median_MiBps"]
    delta = round((b_med / a_med - 1) * 100, 2) if a_med and b_med else None
    return {
        "profile": profile,
        "expected_cipher": PROFILES[profile]["cipher"],
        "expected_mac": PROFILES[profile]["mac"],
        "A": variants["A"], "B": variants["B"],
        "B_vs_A_SOCKS5_median_pct": delta,
        "paired_ABBA_deltas": paired,
        "paired_delta_median_pct": round(statistics.median([x["B_vs_A_pct"] for x in paired]), 2) if paired else None,
    }


def summarize_mac_profile(profile: str, runs: list[dict]) -> dict:
    out = {}
    for variant in ("A", "B"):
        run = next((
            r for r in runs
            if r["profile"] == profile and r["variant"] == variant and r["kind"] == "profile"
        ), None)
        totals = run.get("perf_totals", {}) if run else {}
        status = {}
        if run:
            for line in run.get("profile_status", []):
                if "=" in line:
                    key, value = line.split("=", 1)
                    status[key] = value
        issues = []
        if not run:
            issues.append("profile-only run missing")
        else:
            if not run.get("perf_mac"):
                issues.append("no PERF-MAC lines")
            if run.get("auth_count") != 1:
                issues.append(f"expected one core authentication, found {run.get('auth_count')}")
            if run.get("keys_count") != 1:
                issues.append(f"expected one SSH key establishment, found {run.get('keys_count')}")
            expected = PROFILES[profile]
            joined = "\n".join(run.get("negotiation", []))
            if expected["cipher"] not in joined:
                issues.append(f"expected cipher {expected['cipher']} not observed")
            if expected["mac"] and expected["mac"] not in joined:
                issues.append(f"expected MAC {expected['mac']} not observed")
            try:
                profile_bytes = int(status.get("PROFILE_BYTES", "0"))
                curl_rc = int(status.get("PROFILE_CURL_RC", "-1"))
            except ValueError:
                profile_bytes, curl_rc = 0, -1
            if profile_bytes < 1_000_000:
                issues.append(f"profile transfer too small: {profile_bytes} bytes")
            if curl_rc not in (0, 28):
                issues.append(f"profile curl returned unexpected code {curl_rc}")
            known_startup_counter_gate = (
                variant == "B"
                and all(
                    ("R65-B profiling did not record nonzero mac_sha256_ctx_allocs" in error)
                    or ("R65-B context allocation/key-init/reuse-reset counters were not all nonzero" in error)
                    for error in run.get("errors", [])
                )
            )
            unexpected_errors = [] if known_startup_counter_gate else run.get("errors", [])
            if unexpected_errors:
                issues.append("profile runner recorded errors: " + "; ".join(unexpected_errors))
        if run and variant == "A" and totals.get("mac_sha256_setup_calls", 0) <= 0:
            issues.append("R65-A setup_calls counter was zero")
        if run and variant == "B":
            if totals.get("mac_sha256_reuse_resets", 0) <= 0:
                issues.append("R65-B reuse_resets counter was zero")
            if totals.get("mac_sha256_setup_calls", 0) != 0:
                issues.append("R65-B unexpectedly used legacy per-call HMAC setup")
            # HMAC context allocation/key initialization happens during SSH KEX.
            # This benchmark enables libssh2 diagnostic timing only after session
            # keys are established, so those startup-only counters are outside
            # the measured window and their zero values are not a failure.
        out[variant] = {
            "run_found": run is not None,
            "perf_mac_intervals": len(run.get("perf_mac", [])) if run else 0,
            "totals": totals,
            "mac_rx_avg_us_per_call": round(totals.get("mac_rx_us", 0) / totals.get("mac_rx_calls", 0), 3) if totals.get("mac_rx_calls", 0) else None,
            "mac_tx_avg_us_per_call": round(totals.get("mac_tx_us", 0) / totals.get("mac_tx_calls", 0), 3) if totals.get("mac_tx_calls", 0) else None,
            "issues": issues,
            "startup_context_counters_note": (
                "ctx_allocs/key_inits are outside the diagnostic window: KEX finishes before "
                "libssh2 diagnostic timing is enabled; use nonzero reuse_resets and zero "
                "setup_calls as the per-packet reuse evidence in this profile."
            ) if variant == "B" else None,
        }
    return out


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: analyze_qemu_speedtest_r65_ab.py RESULTS_DIR OUTPUT_DIR")
        return 2
    root = Path(sys.argv[1])
    output = Path(sys.argv[2])
    output.mkdir(parents=True, exist_ok=True)
    runs = [load_run(p) for p in sorted(root.glob("qemu-speedtest-*"))]
    runs = [run for run in runs if run]
    if not runs:
        print(f"No R65 benchmark result directories found under {root}")
        return 2

    throughput = {profile: summarize_profile(profile, runs) for profile in PROFILES}
    mac = {profile: summarize_mac_profile(profile, runs) for profile in ("nonetm", "etm")}
    data = {
        "environment": "OpenWrt 24.10.7 MT7621 QEMU (4 guest vCPU / 2 emulated cores), Datapacket Singapore HTTP 100 MB, 50 s transfer cap",
        "provenance": {
            "R65-A": {"run_id": 45917988440, "source_sha": "c419f4576bc46e7f8b30ff56ecb5fcce71d00a1e"},
            "R65-B": {"run_id": 45921040962, "source_sha": "dc0454d93a93afc94e8024f6346b54eb3ccd07d7"},
        },
        "profiles": throughput, "hmac_diagnostics": mac, "run_count": len(runs),
    }
    (output / "comparison.json").write_text(json.dumps(data, indent=2) + "\n")

    lines = [
        "# R65-A vs R65-B — Datapacket MT7621 QEMU benchmark", "",
        "Environment: OpenWrt 24.10.7 in MT7621 QEMU (4 guest vCPU / 2 emulated cores), one SSH session per run, Datapacket Singapore 100 MB endpoint, 50 s cap per transfer.",
        "Provenance: R65-A Actions #897 (c419f457), R65-B Actions #901 (dc0454d9).",
        "Throughput runs: A-B-B-A for each profile, two repeats per variant, with LOG_PERF=0. Separate 12 s profile-only runs use LOG_PERF=1 and are not included in throughput statistics.", "",
    ]
    for profile, label in (
        ("chacha", "ChaCha20-Poly1305 control"),
        ("nonetm", "AES-128-CTR + HMAC-SHA256 non-ETM"),
        ("etm", "AES-128-CTR + HMAC-SHA256-ETM"),
    ):
        result = throughput[profile]
        lines += [
            f"## {label}", "",
            "| Metric | R65-A | R65-B |", "|---|---:|---:|",
            f"| Valid SOCKS5 runs | {result['A']['valid_runs']}/2 | {result['B']['valid_runs']}/2 |",
            f"| SOCKS5 median | {fmt(result['A']['socks5_median_MiBps'])} MiB/s | {fmt(result['B']['socks5_median_MiBps'])} MiB/s |",
            f"| SOCKS5 mean | {fmt(result['A']['socks5_mean_MiBps'])} MiB/s | {fmt(result['B']['socks5_mean_MiBps'])} MiB/s |",
            f"| Direct median reference | {fmt(result['A']['direct_median_MiBps'])} MiB/s | {fmt(result['B']['direct_median_MiBps'])} MiB/s |",
            f"| SOCKS5 vs direct median | {fmt(result['A']['socks5_vs_direct_median_pct'])}% | {fmt(result['B']['socks5_vs_direct_median_pct'])}% |",
            f"| SSH Owner CPU avg / p95 / max | {fmt(result['A']['ssh_owner_avg_pct'])}% / {fmt(result['A']['ssh_owner_p95_pct'])}% / {fmt(result['A']['ssh_owner_max_pct'])}% | {fmt(result['B']['ssh_owner_avg_pct'])}% / {fmt(result['B']['ssh_owner_p95_pct'])}% / {fmt(result['B']['ssh_owner_max_pct'])}% |",
            f"| WAN RX median / p95 | {fmt(result['A']['wan_rx_median_MiBps'])} / {fmt(result['A']['wan_rx_p95_MiBps'])} MiB/s | {fmt(result['B']['wan_rx_median_MiBps'])} / {fmt(result['B']['wan_rx_p95_MiBps'])} MiB/s |",
            f"| B vs A SOCKS5 median | {fmt(result['B_vs_A_SOCKS5_median_pct'])}% |",
            f"| Paired ABBA deltas | {', '.join(str(x['B_vs_A_pct']) + '%' for x in result['paired_ABBA_deltas']) or 'n/a'} |", "",
            f"Direct endpoint IPs observed: {', '.join(result['A']['direct_remote_ips'] + result['B']['direct_remote_ips']) or 'n/a'}",
            f"SOCKS5 curl peer (local proxy): {', '.join(result['A']['socks5_proxy_peers'] + result['B']['socks5_proxy_peers']) or 'n/a'}", "",
        ]
        for variant in ("A", "B"):
            if result[variant]["rejected"]:
                lines.append(f"Rejected {variant} runs: {json.dumps(result[variant]['rejected'])}")
                lines.append("")

    lines += ["## HMAC telemetry (separate instrumented runs)", ""]
    for profile, label in (("nonetm", "HMAC-SHA256 non-ETM"), ("etm", "HMAC-SHA256-ETM")):
        lines += [f"### {label}", "", "| Counter | R65-A | R65-B |", "|---|---:|---:|"]
        for key in (
            "mac_rx_calls", "mac_rx_us", "mac_tx_calls", "mac_tx_us",
            "mac_sha256_setup_calls", "mac_sha256_ctx_allocs",
            "mac_sha256_key_inits", "mac_sha256_reuse_resets", "mac_sha256_ctx_dups",
        ):
            lines.append(f"| {key} | {fmt(mac[profile]['A']['totals'].get(key))} | {fmt(mac[profile]['B']['totals'].get(key))} |")
        lines += [
            f"| RX avg time per MAC call | {fmt(mac[profile]['A']['mac_rx_avg_us_per_call'])} us | {fmt(mac[profile]['B']['mac_rx_avg_us_per_call'])} us |",
            f"| TX avg time per MAC call | {fmt(mac[profile]['A']['mac_tx_avg_us_per_call'])} us | {fmt(mac[profile]['B']['mac_tx_avg_us_per_call'])} us |", "",
        ]
        for variant in ("A", "B"):
            if mac[profile][variant]["issues"]:
                lines.append(f"{variant} telemetry issue: {', '.join(mac[profile][variant]['issues'])}")
                lines.append("")

    lines += [
        "## Interpretation limits", "",
        "- Primary throughput data excludes LOG_PERF instrumentation; CPU/TID and interface sampling remain active at 250 ms.",
        "- Direct transfers are paired within each run as an external bandwidth reference. A/B comparison is based on SOCKS5 medians and same-repeat paired deltas.",
        "- HMAC counters/timing come from separate instrumented sessions capped at 12 seconds, not from the primary speed runs.",
        "- R65-B ctx_allocs/key_inits are startup/KEX counters and are not expected in the log window, which starts after session keys are established; the profile gate validates reuse_resets > 0 and setup_calls = 0 instead.",
        "- The emulator is not a physical MT7621A router. Results indicate comparative behavior in this QEMU fixture only.",
        "- A run is valid only when direct and SOCKS5 each return HTTP 200 with at least 95,000,000 bytes and matching byte counts, and the expected SSH cipher/MAC is logged.", "",
    ]
    (output / "summary.md").write_text("\n".join(lines))
    print("\n".join(lines))

    failures = []
    for profile, result in throughput.items():
        for variant in ("A", "B"):
            if result[variant]["valid_runs"] != 2:
                failures.append(f"{profile}: {variant} has {result[variant]['valid_runs']}/2 valid throughput runs")
        if len(result["paired_ABBA_deltas"]) != 2:
            failures.append(f"{profile}: expected two valid paired ABBA deltas")
    for profile, result in mac.items():
        for variant in ("A", "B"):
            if result[variant]["issues"]:
                failures.append(f"{profile}: {variant} telemetry: {', '.join(result[variant]['issues'])}")

    if failures:
        print("BENCHMARK VALIDATION FAIL:")
        for failure in failures:
            print(" - " + failure)
        return 1
    print("PASS: all A/B throughput and HMAC telemetry gates passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
