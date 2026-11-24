#!/usr/bin/env python3
"""Static invariants for r52 topology fallback and worker lifetime hardening."""
from pathlib import Path
import sys


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: r52_hardening_test.py SSH_CORE_C LIBSSH2_SOURCE_DIR", file=sys.stderr)
        return 2
    core = Path(sys.argv[1]).read_text()
    root = Path(sys.argv[2])
    chacha = (root / "src/chacha.c").read_text()
    marker = root / ".passwall-r52-worker-lifecycle-patched"

    a = core.find("static long detect_available_physical_core_count(")
    b = core.find("\n/* CPU count selects auxiliary socket-I/O threads only. */", a)
    detect = core[a:b] if a >= 0 and b > a else ""
    checks = {
        "unknown/incomplete sysfs topology returns 0": bool(detect) and "return logical_cpu_count" not in detect and detect.count("return 0L;") >= 3,
        "core_id and package_id both required": 'read_cpu_topology_value(cpu_id, "core_id", &core_id)' in detect and 'read_cpu_topology_value(cpu_id, "physical_package_id",' in detect and "(void)read_cpu_topology_value" not in detect,
        "unknown core count uses serial path": "static long g_detected_physical_core_count = 0;" in core and "if (core_count <= 1L) return 0U;" in core,
        "r52 worker marker exists": marker.is_file(),
    }

    s = chacha.find("static int\nchacha_parallel_pool_stop(")
    e = chacha.find("\nvoid\nchacha_parallel_pool_destroy(", s)
    stop = chacha[s:e] if s >= 0 and e > s else ""
    checks["pool joins before clearing packet pointers"] = bool(stop) and stop.find("pthread_join") < stop.find("pool->source = NULL") and stop.find("if(first_error != 0)") < stop.find("pool->source = NULL")
    checks["join failure preserves started flag"] = "if(rc == 0)\n                pool->workers[i].started = 0;" in stop and "first_error = rc;" in stop
    checks["pool destroy will not free after stop failure"] = "if(chacha_parallel_pool_stop(pool) != 0)\n        return;" in chacha

    f = chacha.find("int\nchacha_decrypt_poly_worker_only(")
    e = chacha.find("\n}\n", f)
    body = chacha[f:e] if f >= 0 and e > f else ""
    checks["both error phases stop/join before returning"] = body.count("chacha_parallel_pool_stop(pool)") == 2 and "while(pool->active_workers > 0U)" not in body

    failed = []
    for name, ok in checks.items():
        print(("PASS: " if ok else "FAIL: ") + name)
        if not ok:
            failed.append(name)
    if failed:
        return 1
    print("PASS: r52 topology and worker lifecycle invariants")
    return 0


if __name__ == "__main__":
    sys.exit(main())
