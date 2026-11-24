#!/usr/bin/env python3
"""r52: synchronously stop and join ChaCha workers on packet-path failure."""
from pathlib import Path
import sys


def function_bounds(src: str, signature: str):
    start = src.find(signature)
    if start < 0 or src.find(signature, start + 1) >= 0:
        raise RuntimeError("expected exactly one function: " + signature)
    brace = src.find("{", start)
    depth = 0
    quote = None
    line_comment = False
    block_comment = False
    i = brace
    while i < len(src):
        c = src[i]
        n = src[i + 1] if i + 1 < len(src) else ""
        if line_comment:
            if c == "\n": line_comment = False
        elif block_comment:
            if c == "*" and n == "/":
                block_comment = False
                i += 2
                continue
        elif quote:
            if c == chr(92): i += 2; continue
            if c == quote: quote = None
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
            if depth == 0: return start, i + 1
        i += 1
    raise RuntimeError("unterminated function: " + signature)


def replace_function(src: str, signature: str, replacement: str) -> str:
    a, b = function_bounds(src, signature)
    return src[:a] + replacement.rstrip() + src[b:]


def replace_once(src: str, old: str, new: str, label: str) -> str:
    if src.count(old) != 1:
        raise RuntimeError(label + ": expected one anchor")
    return src.replace(old, new, 1)


STOP = r'''
static int
chacha_parallel_pool_stop(chacha_parallel_pool_t *pool)
{
    unsigned int i;
    int first_error = 0;
    int rc;

    if(!pool)
        return 0;

    if(pool->mutex_ready) {
        rc = pthread_mutex_lock(&pool->mutex);
        if(rc == 0) {
            pool->stopping = 1U;
            if(pool->work_ready_initialized)
                (void)pthread_cond_broadcast(&pool->work_ready);
            if(pool->work_done_initialized)
                (void)pthread_cond_broadcast(&pool->work_done);
            (void)pthread_mutex_unlock(&pool->mutex);
        } else {
            (void)__sync_lock_test_and_set(&pool->stopping, 1U);
            if(pool->work_ready_initialized)
                (void)pthread_cond_broadcast(&pool->work_ready);
            if(pool->work_done_initialized)
                (void)pthread_cond_broadcast(&pool->work_done);
        }
    } else {
        (void)__sync_lock_test_and_set(&pool->stopping, 1U);
    }

    /* Join before clearing packet references or destroying synchronization. */
    for(i = 0U; i < pool->worker_count; i++) {
        if(pool->workers[i].started) {
            rc = pthread_join(pool->workers[i].thread, NULL);
            if(rc == 0)
                pool->workers[i].started = 0;
            else if(first_error == 0)
                first_error = rc;
        }
    }
    if(first_error != 0) {
        errno = first_error;
        return first_error;
    }

    pool->source = NULL;
    pool->destination = NULL;
    pool->poly_input = NULL;
    pool->poly_len = 0U;
    pool->measure_poly = 0U;
    pool->active_workers = 0U;
    pool->completed = pool->worker_count;
    chacha_parallel_wipe(pool->states, sizeof(pool->states));
    chacha_parallel_wipe(pool->poly_key, sizeof(pool->poly_key));
    chacha_parallel_wipe(pool->poly_tag, sizeof(pool->poly_tag));
    memset(pool->offsets, 0, sizeof(pool->offsets));
    memset(pool->lengths, 0, sizeof(pool->lengths));
    for(i = 0U; i < pool->worker_count; i++)
        pool->task_kind[i] = CHACHA_TASK_IDLE;

    if(pool->work_done_initialized) {
        rc = pthread_cond_destroy(&pool->work_done);
        if(rc != 0) { errno = rc; return rc; }
        pool->work_done_initialized = 0;
    }
    if(pool->work_ready_initialized) {
        rc = pthread_cond_destroy(&pool->work_ready);
        if(rc != 0) { errno = rc; return rc; }
        pool->work_ready_initialized = 0;
    }
    if(pool->mutex_ready) {
        rc = pthread_mutex_destroy(&pool->mutex);
        if(rc != 0) { errno = rc; return rc; }
        pool->mutex_ready = 0;
    }
    return 0;
}
'''

DESTROY = r'''
void
chacha_parallel_pool_destroy(struct chacha_parallel_pool *opaque_pool)
{
    chacha_parallel_pool_t *pool = (chacha_parallel_pool_t *)opaque_pool;
    if(!pool)
        return;
    if(chacha_parallel_pool_stop(pool) != 0)
        return;
    chacha_parallel_wipe(pool, sizeof(*pool));
    free(pool);
}
'''


def patch(root: Path) -> None:
    if not (root / ".passwall-r51-auth-before-decrypt-patched").is_file():
        raise RuntimeError("Run r51 authenticate-before-decrypt patch first")
    marker = root / ".passwall-r52-worker-lifecycle-patched"
    if marker.exists():
        raise RuntimeError("r52 lifecycle patch already exists")

    path = root / "src/chacha.c"
    src = path.read_text()
    src = replace_function(
        src, "static void\nchacha_parallel_pool_stop(chacha_parallel_pool_t *pool)", STOP
    )
    src = replace_function(
        src, "void\nchacha_parallel_pool_destroy(struct chacha_parallel_pool *opaque_pool)", DESTROY
    )
    src = replace_once(
        src,
        "fail:\n    chacha_parallel_pool_stop(pool);\n    free(pool);\n    return NULL;",
        "fail:\n    if(chacha_parallel_pool_stop(pool) == 0)\n        free(pool);\n    return NULL;",
        "preserve pool on partial-thread join failure",
    )

    sig = "int\nchacha_decrypt_poly_worker_only("
    a, b = function_bounds(src, sig)
    body = src[a:b]
    old = r'''if(pool->stopping || pool->worker_error || pool->completed != workers) {
        (void)pthread_cond_broadcast(&pool->work_ready);
        while(pool->active_workers > 0U) {
            int drain_rc = pthread_cond_wait(&pool->work_done, &pool->mutex);
            if(drain_rc != 0)
                break;
        }
        if(pool->active_workers > 0U) {
            /* Do not clear the borrowed packet pointer while a worker may use it. */
            (void)pthread_mutex_unlock(&pool->mutex);
            return -1;
        }
        goto cleanup;
    }'''
    new = r'''if(pool->stopping || pool->worker_error || pool->completed != workers) {
        /*
         * The caller may release packet storage as soon as this returns.
         * Stop and join every worker instead of trusting active_workers after
         * an error from pthread_cond_wait.
         */
        (void)pthread_mutex_unlock(&pool->mutex);
        (void)chacha_parallel_pool_stop(pool);
        return -1;
    }'''
    if body.count(old) != 2:
        raise RuntimeError("expected two r51 worker-error blocks, found " + str(body.count(old)))
    body = body.replace(old, new)
    src = src[:a] + body + src[b:]
    path.write_text(src)
    marker.write_text("libssh2 1.11.1 Passwall r52 join-before-return worker lifecycle hardening\n")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: apply_libssh2_r52_worker_lifecycle.py LIBSSH2_SOURCE_DIR")
    patch(Path(sys.argv[1]))
