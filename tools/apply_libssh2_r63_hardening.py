#!/usr/bin/env python3
"""R63: harden ChaCha worker dispatch/lifecycle, secret wiping and transport errors."""
from pathlib import Path
import re
import sys


MARKER = ".passwall-r63-crypto-transport-hardening-patched"


def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one anchor, found {count}")
    return source.replace(old, new, 1)


def matching_brace(source: str, brace: int) -> int:
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
    raise RuntimeError("unterminated C block")


def function_bounds(source: str, signature: str):
    start = source.find(signature)
    if start < 0 or source.find(signature, start + 1) >= 0:
        raise RuntimeError(f"expected exactly one function {signature!r}")
    brace = source.find("{", start)
    if brace < 0:
        raise RuntimeError(f"missing function body for {signature!r}")
    return start, matching_brace(source, brace)


def patch_chachapoly(root: Path) -> None:
    path = root / "src/cipher-chachapoly.c"
    source = path.read_text()
    helper = r'''
/* R63: volatile stores prevent the compiler from deleting secret erasure. */
static void
chachapoly_secure_wipe(void *buffer, size_t length)
{
    volatile unsigned char *p = (volatile unsigned char *)buffer;
    while(length != 0U) {
        *p++ = 0U;
        length--;
    }
}
'''
    source = replace_once(
        source, '#include "cipher-chachapoly.h"\n',
        '#include "cipher-chachapoly.h"\n' + helper + "\n",
        "add non-elidable ChaCha secret wipe"
    )

    sig = "int\nchachapoly_crypt("
    start, end = function_bounds(source, sig)
    fn = source[start:end]
    fn = replace_once(fn, "        int parallel_rc = 0;\n", "",
                      "remove legacy parallel fallback state")
    fn = replace_once(
        fn,
        "        if(!do_encrypt && ctx->parallel_pool && !drop_first)\n"
        "            parallel_rc = chacha_encrypt_bytes_parallel(\n"
        "                ctx->parallel_pool, &ctx->main_ctx, src + aadlen,\n"
        "                dest + dest_aadlen, len);\n\n",
        "        /* R63: worker-only dispatch above is the sole threshold gate. */\n",
        "remove fixed-4-KiB legacy worker fallback"
    )
    fn = replace_once(
        fn,
        "        if(parallel_rc < 0) {\n"
        "            r = LIBSSH2_ERROR_DECRYPT;\n"
        "            goto out;\n"
        "        }\n\n",
        "",
        "remove legacy worker error branch"
    )
    branch = "        else if(parallel_rc > 0 && !do_encrypt) {"
    branch_start = fn.find(branch)
    if branch_start < 0:
        raise RuntimeError("legacy parallel accounting branch missing")
    branch_brace = fn.find("{", branch_start)
    branch_end = matching_brace(fn, branch_brace)
    serial_else = fn.find("\n        else {", branch_end)
    if serial_else < 0:
        raise RuntimeError("serial ChaCha fallback after legacy worker branch missing")
    fn = fn[:branch_start] + fn[serial_else + 1:]

    # Restrict secret erasure replacements to the function's final cleanup
    # block. Earlier memset calls initialize state and must remain ordinary
    # zero-initialization. This also avoids ambiguous whole-function anchors.
    cleanup_label = "\nout:\n"
    cleanup_start = fn.rfind(cleanup_label)
    if cleanup_start < 0:
        raise RuntimeError("ChaCha cleanup label not found")
    cleanup = fn[cleanup_start:]
    for name in ("expected_tag", "seqbuf", "poly_key", "first_keystream", "zero_block"):
        old = f"    memset({name}, 0, sizeof({name}));"
        new = f"    chachapoly_secure_wipe({name}, sizeof({name}));"
        count = cleanup.count(old)
        if count != 1:
            raise RuntimeError(
                f"ChaCha cleanup {name}: expected exactly one memset, found {count}"
            )
        cleanup = cleanup.replace(old, new, 1)
    fn = fn[:cleanup_start] + cleanup

    source = source[:start] + fn + source[end:]

    cleanup_sig = "void\nchachapoly_cleanup("
    cleanup_start, cleanup_end = function_bounds(source, cleanup_sig)
    cleanup_fn = source[cleanup_start:cleanup_end]
    cleanup_fn = replace_once(
        cleanup_fn,
        "    memset(ctx, 0, sizeof(*ctx));",
        "    chachapoly_secure_wipe(ctx, sizeof(*ctx));",
        "securely wipe the ChaCha context/key schedule at cleanup"
    )
    source = source[:cleanup_start] + cleanup_fn + source[cleanup_end:]
    path.write_text(source)


def patch_worker_failure(root: Path) -> None:
    path = root / "src/chacha.c"
    source = path.read_text()

    if not source.startswith("#ifndef _GNU_SOURCE"):
        source = replace_once(
            source, '#include "chacha.h"\n',
            '#ifndef _GNU_SOURCE\n#define _GNU_SOURCE\n#endif\n\n#include "chacha.h"\n',
            "enable GNU/POSIX clock declarations"
        )
    for header in ("stdlib.h", "time.h"):
        include = f"#include <{header}>\n"
        if include not in source:
            source = replace_once(source, "#include <pthread.h>\n",
                                  "#include <pthread.h>\n" + include,
                                  "include " + header)

    source = replace_once(
        source, "    int work_done_initialized;\n",
        "    int work_done_initialized;\n    int work_done_monotonic;\n",
        "track the work_done condition-variable clock"
    )
    source = replace_once(
        source,
        "    rc = pthread_cond_init(&pool->work_done, NULL);\n"
        "    if(rc != 0) {\n"
        "        errno = rc;\n"
        "        goto fail;\n"
        "    }\n"
        "    pool->work_done_initialized = 1;",
        "    {\n"
        "        pthread_condattr_t work_done_attr;\n"
        "        int attr_ready = 0;\n"
        "        int use_monotonic = 0;\n"
        "        rc = pthread_condattr_init(&work_done_attr);\n"
        "        if(rc == 0) {\n"
        "            attr_ready = 1;\n"
        "#if defined(CLOCK_MONOTONIC)\n"
        "            if(pthread_condattr_setclock(&work_done_attr, CLOCK_MONOTONIC) == 0)\n"
        "                use_monotonic = 1;\n"
        "#endif\n"
        "        }\n"
        "        rc = pthread_cond_init(&pool->work_done,\n"
        "                              attr_ready ? &work_done_attr : NULL);\n"
        "        if(attr_ready)\n"
        "            (void)pthread_condattr_destroy(&work_done_attr);\n"
        "        if(rc != 0) {\n"
        "            errno = rc;\n"
        "            goto fail;\n"
        "        }\n"
        "        pool->work_done_initialized = 1;\n"
        "        pool->work_done_monotonic = use_monotonic;\n"
        "    }",
        "initialize work_done with CLOCK_MONOTONIC when available"
    )

    # A failed join must not return to the caller while workers can reference
    # caller-owned packet storage. Abort is the deliberate fail-stop policy.
    stop_sig = "static int\nchacha_parallel_pool_stop(chacha_parallel_pool_t *pool)"
    a, b = function_bounds(source, stop_sig)
    stop_fn = source[a:b]
    stop_fn = replace_once(
        stop_fn,
        "    if(first_error != 0) {\n"
        "        errno = first_error;\n"
        "        return first_error;\n"
        "    }",
        "    if(first_error != 0) {\n"
        "        errno = first_error;\n"
        "        abort();\n"
        "    }",
        "fail-stop if a crypto worker cannot be joined"
    )
    source = source[:a] + stop_fn + source[b:]

    finalize_sig = "static int\nchacha_parallel_pool_finalize(chacha_parallel_pool_t *pool)"
    a, b = function_bounds(source, finalize_sig)
    finalize_fn = source[a:b]
    finalize_fn = replace_once(
        finalize_fn,
        "    rc = chacha_parallel_pool_stop(pool);\n"
        "    if(rc != 0)\n"
        "        return rc;",
        "    rc = chacha_parallel_pool_stop(pool);\n"
        "    if(rc != 0)\n"
        "        abort();",
        "fail-stop before releasing pool storage if workers remain"
    )
    source = source[:a] + finalize_fn + source[b:]

    helper = r'''
/* Publish failure even when a worker cannot reacquire the pool mutex. */
static void
chacha_parallel_report_worker_error(chacha_parallel_pool_t *pool, int error)
{
    unsigned int value = error > 0 ? (unsigned int)error : (unsigned int)EIO;
    __atomic_store_n(&pool->worker_error, value, __ATOMIC_RELEASE);
    (void)pthread_cond_broadcast(&pool->work_done);
    (void)pthread_cond_broadcast(&pool->work_ready);
}

/* Called with pool->mutex held. A single deadline bounds spurious wakeups. */
static int
chacha_parallel_wait_for_workers(chacha_parallel_pool_t *pool,
                                 unsigned int workers)
{
    struct timespec deadline;
#if defined(CLOCK_MONOTONIC)
    clockid_t clock_id = pool->work_done_monotonic ?
                         CLOCK_MONOTONIC : CLOCK_REALTIME;
#else
    clockid_t clock_id = CLOCK_REALTIME;
#endif
    int rc;

    if(clock_gettime(clock_id, &deadline) != 0)
        return errno ? errno : EIO;
    deadline.tv_sec += 10;
    while(pool->completed < workers &&
          __atomic_load_n(&pool->stopping, __ATOMIC_ACQUIRE) == 0U &&
          __atomic_load_n(&pool->worker_error, __ATOMIC_ACQUIRE) == 0U) {
        rc = pthread_cond_timedwait(&pool->work_done, &pool->mutex, &deadline);
        if(rc != 0)
            return rc;
    }
    return 0;
}

'''
    if "chacha_parallel_wait_for_workers(" not in source:
        source = replace_once(
            source, "int\nchacha_decrypt_poly_worker_only(",
            helper + "int\nchacha_decrypt_poly_worker_only(",
            "add a clock-matched bounded worker wait helper"
        )

    worker_prototype = (
        "static void chacha_parallel_report_worker_error("
        "chacha_parallel_pool_t *pool, int error);\n\n"
    )
    source = replace_once(
        source,
        "static void *\nchacha_parallel_worker_main(void *opaque)",
        worker_prototype + "static void *\nchacha_parallel_worker_main(void *opaque)",
        "declare worker error notifier before worker_main"
    )
    sig = "static void *\nchacha_parallel_worker_main(void *opaque)"
    a, b = function_bounds(source, sig)
    worker = source[a:b]
    worker = replace_once(
        worker,
        "    if(pthread_mutex_lock(&pool->mutex) != 0)\n"
        "        return NULL;",
        "    {\n"
        "        int lock_rc = pthread_mutex_lock(&pool->mutex);\n"
        "        if(lock_rc != 0) {\n"
        "            chacha_parallel_report_worker_error(pool, lock_rc);\n"
        "            return NULL;\n"
        "        }\n"
        "    }",
        "report worker startup mutex failure"
    )
    worker = replace_once(
        worker,
        "        if(pthread_mutex_lock(&pool->mutex) != 0)\n"
        "            return NULL;",
        "        {\n"
        "            int lock_rc = pthread_mutex_lock(&pool->mutex);\n"
        "            if(lock_rc != 0) {\n"
        "                chacha_parallel_report_worker_error(pool, lock_rc);\n"
        "                return NULL;\n"
        "            }\n"
        "        }",
        "report worker completion mutex failure"
    )
    source = source[:a] + worker + source[b:]

    sig = "int\nchacha_decrypt_poly_worker_only("
    a, b = function_bounds(source, sig)
    fn = source[a:b]
    fn = replace_once(
        fn,
        "    if(pthread_mutex_lock(&pool->mutex) != 0)\n"
        "        return -1;\n"
        "    if(pool->stopping || pool->worker_error) {\n"
        "        (void)pthread_mutex_unlock(&pool->mutex);\n"
        "        return -1;\n"
        "    }",
        "    if(pthread_mutex_lock(&pool->mutex) != 0) {\n"
        "        if(chacha_parallel_pool_stop(pool) != 0) abort();\n"
        "        chacha_parallel_wipe(destination + dest_aadlen,\n"
        "                             skip_first ? bytes - 1U : bytes);\n"
        "        if(padding_length_out) *padding_length_out = 0U;\n"
        "        return -1;\n"
        "    }\n"
        "    if(__atomic_load_n(&pool->stopping, __ATOMIC_ACQUIRE) != 0U ||\n"
        "       __atomic_load_n(&pool->worker_error, __ATOMIC_ACQUIRE) != 0U) {\n"
        "        (void)pthread_mutex_unlock(&pool->mutex);\n"
        "        if(chacha_parallel_pool_stop(pool) != 0) abort();\n"
        "        chacha_parallel_wipe(destination + dest_aadlen,\n"
        "                             skip_first ? bytes - 1U : bytes);\n"
        "        if(padding_length_out) *padding_length_out = 0U;\n"
        "        return -1;\n"
        "    }",
        "join unhealthy pool before returning to packet owner"
    )

    old_wait = (
        "    while(pool->completed < workers && !pool->stopping) {\n"
        "        int wait_rc = pthread_cond_wait(&pool->work_done, &pool->mutex);\n"
        "        if(wait_rc != 0) {\n"
        "            pool->worker_error = (unsigned int)wait_rc;\n"
        "            pool->stopping = 1U;\n"
        "            (void)pthread_cond_broadcast(&pool->work_ready);\n"
        "            break;\n"
        "        }\n"
        "    }\n\n"
        "    if(pool->stopping || pool->worker_error || pool->completed != workers) {\n"
        "        (void)pthread_mutex_unlock(&pool->mutex);\n"
        "        (void)chacha_parallel_pool_stop(pool);\n"
        "        return -1;\n"
        "    }"
    )
    new_wait = (
        "    {\n"
        "        int wait_rc = chacha_parallel_wait_for_workers(pool, workers);\n"
        "        if(wait_rc != 0) {\n"
        "            __atomic_store_n(&pool->worker_error, (unsigned int)wait_rc, __ATOMIC_RELEASE);\n"
        "            __atomic_store_n(&pool->stopping, 1U, __ATOMIC_RELEASE);\n"
        "            (void)pthread_cond_broadcast(&pool->work_ready);\n"
        "            (void)pthread_cond_broadcast(&pool->work_done);\n"
        "        }\n"
        "    }\n\n"
        "    if(__atomic_load_n(&pool->stopping, __ATOMIC_ACQUIRE) != 0U ||\n"
        "       __atomic_load_n(&pool->worker_error, __ATOMIC_ACQUIRE) != 0U ||\n"
        "       pool->completed != workers) {\n"
        "        (void)pthread_mutex_unlock(&pool->mutex);\n"
        "        if(chacha_parallel_pool_stop(pool) != 0) abort();\n"
        "        chacha_parallel_wipe(destination + dest_aadlen,\n"
        "                             skip_first ? bytes - 1U : bytes);\n"
        "        if(padding_length_out) *padding_length_out = 0U;\n"
        "        return -1;\n"
        "    }"
    )
    if fn.count(old_wait) != 2:
        raise RuntimeError("expected two unbounded worker waits to replace, found " +
                           str(fn.count(old_wait)))
    fn = fn.replace(old_wait, new_wait, 2)
    source = source[:a] + fn + source[b:]

    source = source.replace(
        "(void)__sync_lock_test_and_set(&pool->stopping, 1U);",
        "__atomic_store_n(&pool->stopping, 1U, __ATOMIC_RELEASE);"
    )
    source = re.sub(
        r"pool->stopping\s*=\s*([^;]+);",
        r"__atomic_store_n(&pool->stopping, \1, __ATOMIC_RELEASE);",
        source
    )
    source = re.sub(
        r"pool->worker_error\s*=\s*([^;]+);",
        r"__atomic_store_n(&pool->worker_error, \1, __ATOMIC_RELEASE);",
        source
    )
    source = re.sub(
        r"(?<![&\w])pool->stopping\b",
        "__atomic_load_n(&pool->stopping, __ATOMIC_ACQUIRE)",
        source
    )
    source = re.sub(
        r"(?<![&\w])pool->worker_error\b",
        "__atomic_load_n(&pool->worker_error, __ATOMIC_ACQUIRE)",
        source
    )

    path.write_text(source)

def patch_poly1305_wipe(root: Path) -> None:
    path = root / "src/poly1305.c"
    source = path.read_text()
    helper = r'''
#if LIBSSH2_HAVE_MIPS32R2_POLY1305_ASM
/* R63: keep Poly1305 key-derived state erasure in optimized builds. */
static void
poly1305_secure_wipe(void *buffer, size_t length)
{
    volatile unsigned char *p = (volatile unsigned char *)buffer;
    while(length != 0U) {
        *p++ = 0U;
        length--;
    }
}
#endif

'''
    source = replace_once(
        source, "void\npoly1305_auth(",
        helper + "void\npoly1305_auth(",
        "add MIPS-only non-elidable Poly1305 secret wipe"
    )
    sig = "void\npoly1305_auth("
    start, end = function_bounds(source, sig)
    fn = source[start:end]
    for old, new, label in (
        ("memset(final_block, 0, sizeof(final_block));",
         "poly1305_secure_wipe(final_block, sizeof(final_block));",
         "wipe Poly1305 tail scratch"),
        ("memset(&state, 0, sizeof(state));",
         "poly1305_secure_wipe(&state, sizeof(state));",
         "wipe Poly1305 accumulator"),
        ("memset(pad, 0, sizeof(pad));",
         "poly1305_secure_wipe(pad, sizeof(pad));",
         "wipe Poly1305 key pad"),
    ):
        if old not in fn:
            raise RuntimeError(label + ": anchor missing")
        fn = fn.replace(old, new)
    path.write_text(source[:start] + fn + source[end:])


def patch_mips_asm_guard(root: Path) -> None:
    path = root / "src/CMakeLists.txt"
    source = path.read_text()
    source = replace_once(
        source,
        'if(CMAKE_SYSTEM_PROCESSOR MATCHES "mips")\n'
        '  enable_language(ASM)\n'
        '  set(_chacha_mips_asm "\x24{CMAKE_CURRENT_SOURCE_DIR}/chacha-core.S")\n'
        '  list(APPEND _sources "\x24{_chacha_mips_asm}")\n'
        '  set_source_files_properties("\x24{_chacha_mips_asm}" PROPERTIES\n'
        '    COMPILE_OPTIONS "-mno-mips16;-mips32r2")\n'
        'endif()',
        'if(CMAKE_SYSTEM_PROCESSOR MATCHES "mips" AND CMAKE_SIZEOF_VOID_P EQUAL 4)\n'
        '  enable_language(ASM)\n'
        '  set(_chacha_mips_asm "\x24{CMAKE_CURRENT_SOURCE_DIR}/chacha-core.S")\n'
        '  list(APPEND _sources "\x24{_chacha_mips_asm}")\n'
        '  set_source_files_properties("\x24{_chacha_mips_asm}" PROPERTIES\n'
        '    COMPILE_OPTIONS "-mno-mips16;-mips32r2")\n'
        'endif()',
        "restrict the o32 ChaCha assembly source to 32-bit MIPS targets"
    )
    path.write_text(source)


def patch_core_error_policy(project_root: Path) -> None:
    path = project_root / "ssh-core.c"
    source = path.read_text()
    marker = "/* R63: fatal SSH integrity/protocol errors invalidate the upstream session. */"
    if marker in source:
        required = (
            "LIBSSH2_ERROR_DECRYPT", "LIBSSH2_ERROR_MAC_FAILURE",
            "LIBSSH2_ERROR_OUT_OF_BOUNDARY", "LIBSSH2_ERROR_PROTO",
            "if (op == PENDING_KEEPALIVE)", "if (op == PENDING_FREE)",
            "c->state == ST_CLOSING"
        )
        missing = [item for item in required if item not in source]
        if missing:
            raise RuntimeError("partial R63 SSH policy already present: " + ", ".join(missing))
        return

    source = replace_once(
        source,
        "static int is_libssh2_socket_fatal(int err) {\n"
        "    return (err == LIBSSH2_ERROR_SOCKET_RECV ||\n"
        "            err == LIBSSH2_ERROR_SOCKET_SEND ||\n"
        "            err == LIBSSH2_ERROR_SOCKET_DISCONNECT);\n"
        "}\n",
        "static int is_libssh2_socket_fatal(int err) {\n"
        "    return (err == LIBSSH2_ERROR_SOCKET_RECV ||\n"
        "            err == LIBSSH2_ERROR_SOCKET_SEND ||\n"
        "            err == LIBSSH2_ERROR_SOCKET_DISCONNECT);\n"
        "}\n\n"
        + marker + "\n"
        "static int is_libssh2_protocol_fatal(int err) {\n"
        "    int fatal = (err == LIBSSH2_ERROR_DECRYPT ||\n"
        "                 err == LIBSSH2_ERROR_MAC_FAILURE ||\n"
        "                 err == LIBSSH2_ERROR_OUT_OF_BOUNDARY ||\n"
        "                 err == LIBSSH2_ERROR_PROTO);\n"
        "    if(fatal) g_skip_libssh2_cleanup = 1;\n"
        "    return fatal;\n"
        "}\n",
        "add fatal SSH integrity/decrypt/framing/protocol classification"
    )

    source = replace_once(
        source,
        "        if (u->hup_seen) {\n"
        "            clear_pending_operation();\n"
        "            return 1;\n"
        "        }\n"
        '        log_red("SSH keepalive retry failed: %d", rc);',
        "        if (is_libssh2_protocol_fatal(rc)) return -1;\n"
        "        if (u->hup_seen) {\n"
        "            clear_pending_operation();\n"
        "            return 1;\n"
        "        }\n"
        '        log_red("SSH keepalive retry failed: %d", rc);',
        "make pending keepalive protocol errors session-fatal"
    )
    source = replace_once(
        source,
        "return (is_libssh2_socket_fatal(err) && !u->hup_seen) ? -1 : 1;",
        "if (is_libssh2_protocol_fatal(err)) return -1;\n"
        "        return (is_libssh2_socket_fatal(err) && !u->hup_seen) ? -1 : 1;",
        "propagate pending channel-open protocol failures"
    )
    source = replace_once(
        source,
        "        c->write_waiting_window = 0;\n"
        "        c->write_wait_rx_seq = 0;\n"
        "        clear_pending_operation();\n"
        "        if (u->hup_seen || u->rx_terminal || u->tx_terminal) {",
        "        c->write_waiting_window = 0;\n"
        "        c->write_wait_rx_seq = 0;\n"
        "        clear_pending_operation();\n"
        "        if (is_libssh2_protocol_fatal((int)w)) return -1;\n"
        "        if (u->hup_seen || u->rx_terminal || u->tx_terminal) {",
        "make pending write integrity errors session-fatal"
    )
    source = replace_once(
        source,
        "        clear_pending_operation();\n"
        "        if (u->hup_seen || u->rx_terminal || u->tx_terminal) {\n"
        "            c->need_send_eof = 0;",
        "        clear_pending_operation();\n"
        "        if (is_libssh2_protocol_fatal(rc)) return -1;\n"
        "        if (u->hup_seen || u->rx_terminal || u->tx_terminal) {\n"
        "            c->need_send_eof = 0;",
        "make pending EOF integrity errors session-fatal"
    )
    source = replace_once(
        source,
        "        clear_pending_operation();\n"
        "        if (!discard_output && u->hup_seen &&\n"
        "            is_libssh2_socket_fatal((int)r)) {",
        "        clear_pending_operation();\n"
        "        if (is_libssh2_protocol_fatal((int)r)) return -1;\n"
        "        if (!discard_output && u->hup_seen &&\n"
        "            is_libssh2_socket_fatal((int)r)) {",
        "make pending read integrity errors session-fatal"
    )
    source = replace_once(
        source,
        "        c->channel = NULL;\n"
        "        clear_pending_operation();\n"
        "        remove_client(epfd, c);\n"
        "        return 1;\n"
        "    }\n\n    clear_pending_operation();",
        "        if (is_libssh2_protocol_fatal(rc)) return -1;\n"
        "        c->channel = NULL;\n"
        "        clear_pending_operation();\n"
        "        remove_client(epfd, c);\n"
        "        return 1;\n"
        "    }\n\n    clear_pending_operation();",
        "make pending channel-free protocol errors session-fatal"
    )
    source = replace_once(
        source,
        "                    } else {\n"
        "                        g_opening_client = NULL;\n"
        "                        if (!c->abort_on_open && !c->abort_on_pending && !c->close_after_ctrl && c->fd >= 0) {",
        "                    } else {\n"
        "                        if (is_libssh2_protocol_fatal(err)) {\n"
        "                            g_opening_client = NULL;\n"
        "                            *agg_dirs_out = agg_dirs;\n"
        "                            note_upstream_rx_progress(u, rx_before, &did_ssh_read);\n"
        "                            *did_ssh_read_out = did_ssh_read;\n"
        "                            return -1;\n"
        "                        }\n"
        "                        g_opening_client = NULL;\n"
        "                        if (!c->abort_on_open && !c->abort_on_pending && !c->close_after_ctrl && c->fd >= 0) {",
        "make immediate channel-open integrity errors session-fatal"
    )
    source = replace_once(
        source,
        "                        c->write_wait_rx_seq = 0;\n"
        "                        if (u->hup_seen || u->rx_terminal || u->tx_terminal) {",
        "                        c->write_wait_rx_seq = 0;\n"
        "                        if (is_libssh2_protocol_fatal((int)w)) {\n"
        "                            *agg_dirs_out = agg_dirs;\n"
        "                            note_upstream_rx_progress(u, rx_before, &did_ssh_read);\n"
        "                            *did_ssh_read_out = did_ssh_read;\n"
        "                            return -1;\n"
        "                        }\n"
        "                        if (u->hup_seen || u->rx_terminal || u->tx_terminal) {",
        "make immediate channel-write integrity errors session-fatal"
    )
    source = replace_once(
        source,
        "                } else {\n"
        "                    if (u->hup_seen || u->rx_terminal || u->tx_terminal) {\n"
        "                        c->need_send_eof = 0;",
        "                } else {\n"
        "                    if (is_libssh2_protocol_fatal(rc)) {\n"
        "                        *agg_dirs_out = agg_dirs;\n"
        "                        note_upstream_rx_progress(u, rx_before, &did_ssh_read);\n"
        "                        *did_ssh_read_out = did_ssh_read;\n"
        "                        return -1;\n"
        "                    }\n"
        "                    if (u->hup_seen || u->rx_terminal || u->tx_terminal) {\n"
        "                        c->need_send_eof = 0;",
        "make immediate channel-EOF integrity errors session-fatal"
    )
    source = replace_once(
        source,
        "                    } else {\n"
        "                        if (u->hup_seen && !u->rx_terminal &&\n"
        "                            is_libssh2_socket_fatal((int)r)) {",
        "                    } else {\n"
        "                        if (is_libssh2_protocol_fatal((int)r)) {\n"
        "                            *agg_dirs_out = agg_dirs;\n"
        "                            note_upstream_rx_progress(u, rx_before, &did_ssh_read);\n"
        "                            *did_ssh_read_out = did_ssh_read;\n"
        "                            return -1;\n"
        "                        }\n"
        "                        if (u->hup_seen && !u->rx_terminal &&\n"
        "                            is_libssh2_socket_fatal((int)r)) {",
        "make channel-read integrity errors session-fatal"
    )
    source = replace_once(
        source,
        "            } else {\n"
        "                if (rc < 0) log_yellow(\"libssh2_channel_free cleanup returned %d\", rc);",
        "            } else {\n"
        "                if (is_libssh2_protocol_fatal(rc)) {\n"
        "                    *agg_dirs_out = agg_dirs;\n"
        "                    note_upstream_rx_progress(u, rx_before, &did_ssh_read);\n"
        "                    *did_ssh_read_out = did_ssh_read;\n"
        "                    return -1;\n"
        "                }\n"
        "                if (rc < 0) log_yellow(\"libssh2_channel_free cleanup returned %d\", rc);",
        "make ST_CLOSING channel-free protocol errors session-fatal"
    )
    path.write_text(source)

def patch(root: Path, project_root: Path) -> None:
    if not (root / ".passwall-r62-runtime-ab-controls-patched").is_file():
        raise RuntimeError("r63 requires the R62 runtime control patch")
    if '#define LIBSSH2_VERSION "1.11.1"' not in (root / "include/libssh2.h").read_text():
        raise RuntimeError("r63 is pinned to libssh2 1.11.1")
    if (root / MARKER).exists():
        raise RuntimeError("r63 hardening patch is already applied")

    patch_chachapoly(root)
    patch_worker_failure(root)
    patch_poly1305_wipe(root)
    patch_mips_asm_guard(root)
    patch_core_error_policy(project_root)

    (root / MARKER).write_text(
        "Passwall r63 crypto/transport hardening: single threshold-gated dispatch, "
        "worker error notification and bounded wait, partial-output wipe, "
        "non-elidable ChaCha/Poly1305 secret wipe, MIPS32 assembly ABI guard\n"
    )
    print(
        "PASS: R63 removes the legacy threshold bypass, hardens ChaCha worker "
        "failure handling and secret erasure, restricts MIPS assembly ABI, "
        "and makes SSH transport integrity errors session-fatal"
    )


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: apply_libssh2_r63_hardening.py LIBSSH2_SOURCE_DIR PROJECT_ROOT",
              file=sys.stderr)
        sys.exit(2)
    try:
        patch(Path(sys.argv[1]), Path(sys.argv[2]))
    except Exception as exc:
        print("FAIL: " + str(exc), file=sys.stderr)
        sys.exit(2)
