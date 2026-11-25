#!/usr/bin/env python3
"""Passwall r57: split authenticated ChaCha20-Poly1305 worker timings."""
from pathlib import Path
import sys


def replace_once(path: Path, old: str, new: str, label: str) -> None:
    source = path.read_text()
    count = source.count(old)
    if count != 1:
        raise RuntimeError(f"{path.name}: {label}: expected one anchor, found {count}")
    path.write_text(source.replace(old, new, 1))


def replace_nth_text(source: str, old: str, new: str, nth: int,
                     expected: int, label: str) -> str:
    count = source.count(old)
    if count != expected:
        raise RuntimeError(f"{label}: expected {expected} anchors, found {count}")
    position = -1
    start = 0
    for _ in range(nth):
        position = source.find(old, start)
        if position < 0:
            raise RuntimeError(f"{label}: occurrence {nth} not found")
        start = position + len(old)
    return source[:position] + new + source[position + len(old):]


def find_matching_brace(source: str, brace: int) -> int:
    depth = 0
    quote = None
    line_comment = False
    block_comment = False
    i = brace
    while i < len(source):
        c = source[i]
        n = source[i + 1] if i + 1 < len(source) else ""
        if line_comment:
            if c == "\n":
                line_comment = False
        elif block_comment:
            if c == "*" and n == "/":
                block_comment = False
                i += 2
                continue
        elif quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = None
        elif c == "/" and n == "/":
            line_comment = True
            i += 2
            continue
        elif c == "/" and n == "*":
            block_comment = True
            i += 2
            continue
        elif c in ("'", '"'):
            quote = c
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise RuntimeError("unterminated C function")


def get_function(source: str, signature: str):
    start = source.find(signature)
    if start < 0 or source.find(signature, start + 1) >= 0:
        raise RuntimeError(f"expected exactly one function {signature!r}")
    brace = source.find("{", start)
    if brace < 0:
        raise RuntimeError(f"function body missing for {signature!r}")
    end = find_matching_brace(source, brace)
    return start, end, source[start:end]


def replace_function(path: Path, signature: str, transform, label: str):
    source = path.read_text()
    start, end, function = get_function(source, signature)
    updated = transform(function)
    if updated == function:
        raise RuntimeError(f"{path.name}: {label}: no change applied")
    path.write_text(source[:start] + updated + source[end:])


def patch(root: Path) -> None:
    required = (
        ".passwall-r51-auth-before-decrypt-patched",
        ".passwall-r52-worker-lifecycle-patched",
        ".passwall-r53-mips32r2-chacha-asm-patched",
        ".passwall-r54-mips32r2-poly1305-asm-patched",
        ".passwall-r55-out-of-place-chachapoly-patched",
        ".passwall-r56-skip-padding-memmove-patched",
    )
    missing = [name for name in required if not (root / name).is_file()]
    if missing:
        raise RuntimeError("r57 requires prior patches: " + ", ".join(missing))

    version = (root / "include/libssh2.h").read_text()
    if '#define LIBSSH2_VERSION "1.11.1"' not in version:
        raise RuntimeError("r57 patch is pinned to libssh2 1.11.1")

    marker = root / ".passwall-r57-chachapoly-profile-patched"
    if marker.exists():
        raise RuntimeError("r57 ChaCha profile patch is already present")

    chacha_c = root / "src/chacha.c"
    replace_once(
        chacha_c,
        "    unsigned long long poly_ns;\n"
        "    unsigned int measure_poly;\n"
        "    const u8 *source;",
        "    unsigned long long poly_ns;\n"
        "    unsigned long long poly_wall_ns;\n"
        "    unsigned long long decrypt_wall_ns;\n"
        "    unsigned long long decrypt_worker_ns;\n"
        "    unsigned long long decrypt_worker_max_ns;\n"
        "    unsigned int measure_poly;\n"
        "    unsigned int measure_decrypt;\n"
        "    const u8 *source;",
        "add phase and per-worker timing state to the persistent pool",
    )

    def patch_worker(function: str) -> str:
        function = function.replace(
            "        unsigned int measure_poly;\n"
            "        unsigned long long poly_started_ns = 0ULL;\n"
            "        unsigned long long poly_ended_ns = 0ULL;",
            "        unsigned int measure_poly;\n"
            "        unsigned int measure_decrypt;\n"
            "        unsigned long long poly_started_ns = 0ULL;\n"
            "        unsigned long long poly_ended_ns = 0ULL;\n"
            "        unsigned long long decrypt_started_ns = 0ULL;\n"
            "        unsigned long long decrypt_ended_ns = 0ULL;",
            1,
        )
        function = function.replace(
            "        measure_poly = pool->measure_poly;\n"
            "        if(task_kind == CHACHA_TASK_DECRYPT ||",
            "        measure_poly = pool->measure_poly;\n"
            "        measure_decrypt = pool->measure_decrypt;\n"
            "        if(task_kind == CHACHA_TASK_DECRYPT ||",
            1,
        )
        function = function.replace(
            "        (void)pthread_mutex_unlock(&pool->mutex);\n"
            "        if(task_kind == CHACHA_TASK_POLY1305) {",
            "        (void)pthread_mutex_unlock(&pool->mutex);\n"
            "        if(measure_decrypt &&\n"
            "           (task_kind == CHACHA_TASK_DECRYPT ||\n"
            "            task_kind == CHACHA_TASK_DECRYPT_SKIP_FIRST))\n"
            "            decrypt_started_ns = chacha_parallel_now_ns();\n"
            "        if(task_kind == CHACHA_TASK_POLY1305) {",
            1,
        )
        function = function.replace(
            "        chacha_parallel_wipe(&local_state, sizeof(local_state));\n"
            "        if(pthread_mutex_lock(&pool->mutex) != 0)",
            "        if(decrypt_started_ns)\n"
            "            decrypt_ended_ns = chacha_parallel_now_ns();\n"
            "        chacha_parallel_wipe(&local_state, sizeof(local_state));\n"
            "        if(pthread_mutex_lock(&pool->mutex) != 0)",
            1,
        )
        function = function.replace(
            "        if(pool->active_workers > 0U)\n            pool->active_workers--;",
            "        if(decrypt_started_ns && decrypt_ended_ns >= decrypt_started_ns) {\n"
            "            unsigned long long elapsed = decrypt_ended_ns - decrypt_started_ns;\n"
            "            pool->decrypt_worker_ns += elapsed;\n"
            "            if(elapsed > pool->decrypt_worker_max_ns)\n"
            "                pool->decrypt_worker_max_ns = elapsed;\n"
            "        }\n"
            "        if(pool->active_workers > 0U)\n            pool->active_workers--;",
            1,
        )
        if "measure_decrypt = pool->measure_decrypt;" not in function:
            raise RuntimeError("chacha worker: missing measure_decrypt assignment")
        if "pool->decrypt_worker_ns += elapsed;" not in function:
            raise RuntimeError("chacha worker: missing per-worker accounting")
        return function

    replace_function(
        chacha_c, "static void *\nchacha_parallel_worker_main(void *opaque)",
        patch_worker, "instrument decrypt worker execution",
    )

    chacha_h = root / "src/chacha.h"
    replace_once(
        chacha_h,
        "                                    const u_char wire_tag[16],\n"
        "                                    unsigned long long *poly_ns_out,\n"
        "                                    int measure);",
        "                                    const u_char wire_tag[16],\n"
        "                                    unsigned long long *poly_ns_out,\n"
        "                                    unsigned long long *poly_wall_ns_out,\n"
        "                                    unsigned long long *decrypt_wall_ns_out,\n"
        "                                    unsigned long long *decrypt_worker_ns_out,\n"
        "                                    unsigned long long *decrypt_worker_max_ns_out,\n"
        "                                    int measure);",
        "expose independent crypto phase timing outputs",
    )

    def patch_worker_only(function: str) -> str:
        signature = (
            "                                unsigned long long *poly_ns_out, int measure)"
        )
        if signature not in function:
            raise RuntimeError("worker-only signature does not match r56")
        function = function.replace(
            signature,
            "                                unsigned long long *poly_ns_out,\n"
            "                                unsigned long long *poly_wall_ns_out,\n"
            "                                unsigned long long *decrypt_wall_ns_out,\n"
            "                                unsigned long long *decrypt_worker_ns_out,\n"
            "                                unsigned long long *decrypt_worker_max_ns_out,\n"
            "                                int measure)",
            1,
        )
        function = function.replace(
            "    unsigned int tag_diff = 0U;\n"
            "    int rc = -1;",
            "    unsigned int tag_diff = 0U;\n"
            "    unsigned long long poly_wall_started_ns = 0ULL;\n"
            "    unsigned long long poly_wall_ended_ns = 0ULL;\n"
            "    unsigned long long decrypt_wall_started_ns = 0ULL;\n"
            "    unsigned long long decrypt_wall_ended_ns = 0ULL;\n"
            "    int rc = -1;",
            1,
        )
        function = function.replace(
            "    pool->poly_ns = 0ULL;\n"
            "    pool->measure_poly = measure ? 1U : 0U;",
            "    pool->poly_ns = 0ULL;\n"
            "    pool->poly_wall_ns = 0ULL;\n"
            "    pool->decrypt_wall_ns = 0ULL;\n"
            "    pool->decrypt_worker_ns = 0ULL;\n"
            "    pool->decrypt_worker_max_ns = 0ULL;\n"
            "    pool->measure_poly = measure ? 1U : 0U;\n"
            "    pool->measure_decrypt = measure ? 1U : 0U;",
            1,
        )

        dispatch = (
            "    pool->generation++;\n"
            "    (void)pthread_cond_broadcast(&pool->work_ready);"
        )
        if function.count(dispatch) != 2:
            raise RuntimeError(
                "worker-only helper: expected two phase dispatches, "
                f"found {function.count(dispatch)}"
            )
        function = replace_nth_text(
            function, dispatch,
            "    if(measure)\n"
            "        poly_wall_started_ns = chacha_parallel_now_ns();\n"
            + dispatch,
            1, 2, "Poly1305 phase dispatch",
        )
        function = replace_nth_text(
            function, dispatch,
            "    if(measure)\n"
            "        decrypt_wall_started_ns = chacha_parallel_now_ns();\n"
            + dispatch,
            2, 2, "ChaCha decrypt phase dispatch",
        )

        function = function.replace(
            "    for(worker = 0U; worker < POLY1305_TAGLEN; worker++)\n"
            "        tag_diff |= (unsigned int)(pool->poly_tag[worker] ^ wire_tag[worker]);\n"
            "    if(poly_ns_out)\n"
            "        *poly_ns_out = pool->poly_ns;",
            "    if(measure) {\n"
            "        poly_wall_ended_ns = chacha_parallel_now_ns();\n"
            "        if(poly_wall_ended_ns >= poly_wall_started_ns)\n"
            "            pool->poly_wall_ns = poly_wall_ended_ns - poly_wall_started_ns;\n"
            "    }\n"
            "    if(poly_ns_out)\n"
            "        *poly_ns_out = pool->poly_ns;\n"
            "    if(poly_wall_ns_out)\n"
            "        *poly_wall_ns_out = pool->poly_wall_ns;\n"
            "    for(worker = 0U; worker < POLY1305_TAGLEN; worker++)\n"
            "        tag_diff |= (unsigned int)(pool->poly_tag[worker] ^ wire_tag[worker]);",
            1,
        )

        function = function.replace(
            "    pool->measure_poly = 0U;\n"
            "    chacha_parallel_wipe(pool->poly_key, sizeof(pool->poly_key));",
            "    pool->measure_poly = 0U;\n"
            "    pool->measure_decrypt = 0U;\n"
            "    chacha_parallel_wipe(pool->poly_key, sizeof(pool->poly_key));",
            1,
        )

        function = function.replace(
            "    rc = 1;\n\ncleanup:",
            "    if(measure) {\n"
            "        decrypt_wall_ended_ns = chacha_parallel_now_ns();\n"
            "        if(decrypt_wall_ended_ns >= decrypt_wall_started_ns)\n"
            "            pool->decrypt_wall_ns =\n"
            "                decrypt_wall_ended_ns - decrypt_wall_started_ns;\n"
            "    }\n"
            "    if(decrypt_wall_ns_out)\n"
            "        *decrypt_wall_ns_out = pool->decrypt_wall_ns;\n"
            "    if(decrypt_worker_ns_out)\n"
            "        *decrypt_worker_ns_out = pool->decrypt_worker_ns;\n"
            "    if(decrypt_worker_max_ns_out)\n"
            "        *decrypt_worker_max_ns_out = pool->decrypt_worker_max_ns;\n"
            "    rc = 1;\n\ncleanup:",
            1,
        )
        if "poly_wall_ns_out" not in function or "decrypt_worker_max_ns_out" not in function:
            raise RuntimeError("worker-only helper timing outputs were not installed")
        return function

    replace_function(
        chacha_c, "int\nchacha_decrypt_poly_worker_only(",
        patch_worker_only, "measure authentication and ChaCha worker phases",
    )

    cipher_c = root / "src/cipher-chachapoly.c"
    replace_once(
        cipher_c,
        "    unsigned long long poly_worker_ns = 0ULL;\n",
        "    unsigned long long poly_worker_ns = 0ULL;\n"
        "    unsigned long long poly_wall_ns = 0ULL;\n"
        "    unsigned long long decrypt_wall_ns = 0ULL;\n"
        "    unsigned long long decrypt_worker_ns = 0ULL;\n"
        "    unsigned long long decrypt_worker_max_ns = 0ULL;\n"
        "    unsigned long long parallel_elapsed_ns = 0ULL;\n",
        "add local per-packet profile results",
    )
    replace_once(
        cipher_c,
        "            &poly_worker_ns, diag_enabled);",
        "            &poly_worker_ns, &poly_wall_ns, &decrypt_wall_ns,\n"
        "            &decrypt_worker_ns, &decrypt_worker_max_ns, diag_enabled);",
        "collect independent phase and worker timings",
    )
    def patch_parallel_metrics(function: str) -> str:
        branch_start = function.find("        if(parallel_rc == 1) {")
        branch_end = function.find("        else if(parallel_rc < 0)", branch_start)
        if branch_start < 0 or branch_end < 0:
            raise RuntimeError("cipher-chachapoly.c: parallel success branch not found")
        branch = function[branch_start:branch_end]

        elapsed_anchor = (
            "                    unsigned long long elapsed = phase_ended - phase_started;\n"
            "                    session->passwall_diag.chacha20_payload_ns += elapsed;"
        )
        if branch.count(elapsed_anchor) != 1:
            raise RuntimeError(
                "cipher-chachapoly.c: parallel elapsed anchor in worker-success branch "
                f"expected one, found {branch.count(elapsed_anchor)}"
            )
        branch = branch.replace(
            elapsed_anchor,
            "                    unsigned long long elapsed = phase_ended - phase_started;\n"
            "                    parallel_elapsed_ns = elapsed;\n"
            "                    session->passwall_diag.chacha20_payload_ns += elapsed;",
            1,
        )

        metrics_anchor = (
            "                session->passwall_diag.chacha_poly1305_ns += poly_worker_ns;\n"
            "                session->passwall_diag.chacha_poly1305_offloaded_packets++;"
        )
        if branch.count(metrics_anchor) != 1:
            raise RuntimeError(
                "cipher-chachapoly.c: profile metrics anchor in worker-success branch "
                f"expected one, found {branch.count(metrics_anchor)}"
            )
        branch = branch.replace(
            metrics_anchor,
            "                session->passwall_diag.chacha_poly1305_ns += poly_worker_ns;\n"
            "                session->passwall_diag.chacha_poly1305_wall_ns += poly_wall_ns;\n"
            "                session->passwall_diag.chacha20_decrypt_wall_ns += decrypt_wall_ns;\n"
            "                session->passwall_diag.chacha20_worker_cpu_ns += decrypt_worker_ns;\n"
            "                session->passwall_diag.chacha20_worker_critical_ns += decrypt_worker_max_ns;\n"
            "                if(parallel_elapsed_ns >= poly_wall_ns + decrypt_wall_ns)\n"
            "                    session->passwall_diag.chacha20_parallel_other_ns +=\n"
            "                        parallel_elapsed_ns - poly_wall_ns - decrypt_wall_ns;\n"
            "                session->passwall_diag.chacha20_profile_packets++;\n"
            "                session->passwall_diag.chacha_poly1305_offloaded_packets++;",
            1,
        )
        return function[:branch_start] + branch + function[branch_end:]

    replace_function(
        cipher_c, "int\nchachapoly_crypt(",
        patch_parallel_metrics,
        "record worker-only ChaCha phase and coordination timings",
    )

    priv = root / "src/libssh2_priv.h"
    # The session counters and snapshot share LIBSSH2_DIAG_TIMING.
    # Extend that one declaration; there is no separate passwall_diag struct.
    replace_once(
        priv,
        "    unsigned long long chacha20_parallel_packets;\n"
        "} LIBSSH2_DIAG_TIMING;",
        "    unsigned long long chacha20_parallel_packets;\n"
        "    unsigned long long chacha_poly1305_wall_ns;\n"
        "    unsigned long long chacha20_decrypt_wall_ns;\n"
        "    unsigned long long chacha20_worker_cpu_ns;\n"
        "    unsigned long long chacha20_worker_critical_ns;\n"
        "    unsigned long long chacha20_parallel_other_ns;\n"
        "    unsigned long long chacha20_profile_packets;\n"
        "} LIBSSH2_DIAG_TIMING;",
        "extend public diagnostic snapshot layout",
    )

    session_c = root / "src/session.c"
    replace_once(
        session_c,
        "    timing->chacha20_parallel_packets =\n"
        "        session->passwall_diag.chacha20_parallel_packets;\n\n"
        "    if(reset) {",
        "    timing->chacha20_parallel_packets =\n"
        "        session->passwall_diag.chacha20_parallel_packets;\n"
        "    timing->chacha_poly1305_wall_ns =\n"
        "        session->passwall_diag.chacha_poly1305_wall_ns;\n"
        "    timing->chacha20_decrypt_wall_ns =\n"
        "        session->passwall_diag.chacha20_decrypt_wall_ns;\n"
        "    timing->chacha20_worker_cpu_ns =\n"
        "        session->passwall_diag.chacha20_worker_cpu_ns;\n"
        "    timing->chacha20_worker_critical_ns =\n"
        "        session->passwall_diag.chacha20_worker_critical_ns;\n"
        "    timing->chacha20_parallel_other_ns =\n"
        "        session->passwall_diag.chacha20_parallel_other_ns;\n"
        "    timing->chacha20_profile_packets =\n"
        "        session->passwall_diag.chacha20_profile_packets;\n\n"
        "    if(reset) {",
        "copy ChaCha phase profile into the public timing snapshot",
    )
    replace_once(
        session_c,
        "        session->passwall_diag.chacha20_parallel_packets = 0;\n"
        "        session->passwall_diag.packet_queue_enqueued_packets = 0;",
        "        session->passwall_diag.chacha20_parallel_packets = 0;\n"
        "        session->passwall_diag.chacha_poly1305_wall_ns = 0;\n"
        "        session->passwall_diag.chacha20_decrypt_wall_ns = 0;\n"
        "        session->passwall_diag.chacha20_worker_cpu_ns = 0;\n"
        "        session->passwall_diag.chacha20_worker_critical_ns = 0;\n"
        "        session->passwall_diag.chacha20_parallel_other_ns = 0;\n"
        "        session->passwall_diag.chacha20_profile_packets = 0;\n"
        "        session->passwall_diag.packet_queue_enqueued_packets = 0;",
        "reset ChaCha phase profile counters with each PERF interval",
    )

    marker.write_text(
        ".passwall-r57-chachapoly-profile-patched\n"
        "libssh2 1.11.1 Passwall r57 separate Poly1305/ChaCha worker phase profiling\n"
    )
    print(
        "PASS: r57 records Poly1305 wall/worker time, ChaCha decrypt wall/worker "
        "time, per-packet critical worker time and parallel coordination remainder"
    )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: apply_libssh2_r57_chachapoly_profile.py LIBSSH2_SOURCE_DIR")
    patch(Path(sys.argv[1]))
