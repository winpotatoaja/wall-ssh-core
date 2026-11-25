#!/usr/bin/env python3
"""Passwall r62: runtime ChaCha worker count and dispatch threshold controls."""
from pathlib import Path
import sys

MARKER = ".passwall-r62-runtime-ab-controls-patched"

def once(path: Path, old: str, new: str, label: str) -> None:
    source = path.read_text()
    count = source.count(old)
    if count != 1:
        raise RuntimeError(f"{path.name}: {label}: expected one anchor, found {count}")
    path.write_text(source.replace(old, new, 1))

def patch(root: Path) -> None:
    if not (root / ".passwall-r61-window-backpressure-patched").is_file():
        raise RuntimeError("r62 requires R61 and earlier libssh2 patches")
    if (root / MARKER).exists():
        raise RuntimeError("r62 runtime controls already applied")
    if '#define LIBSSH2_VERSION "1.11.1"' not in (root / "include/libssh2.h").read_text():
        raise RuntimeError("r62 is pinned to libssh2 1.11.1")

    priv = root / "src/libssh2_priv.h"
    once(priv,
         "        unsigned int chacha_workers_requested;\n"
         "        unsigned int chacha_workers_active;\n",
         "        unsigned int chacha_workers_requested;\n"
         "        unsigned int chacha_workers_active;\n"
         "        unsigned int chacha_threshold_bytes;\n",
         "private session threshold")
    once(priv,
         "    unsigned int chacha_workers_requested;\n"
         "    unsigned int chacha_workers_active;\n",
         "    unsigned int chacha_workers_requested;\n"
         "    unsigned int chacha_workers_active;\n"
         "    unsigned int chacha_threshold_bytes;\n",
         "snapshot threshold field")
    once(priv,
         "LIBSSH2_API void\n"
         "libssh2_session_set_chacha_workers(LIBSSH2_SESSION *session,\n"
         "                                   unsigned int workers);",
         "LIBSSH2_API void\n"
         "libssh2_session_set_chacha_workers(LIBSSH2_SESSION *session,\n"
         "                                   unsigned int workers);\n"
         "LIBSSH2_API int\n"
         "libssh2_session_set_chacha_threshold(LIBSSH2_SESSION *session,\n"
         "                                     unsigned int threshold_bytes);",
         "threshold API declaration")

    chacha_h = root / "src/chacha.h"
    once(chacha_h,
         "struct chacha_parallel_pool *chacha_parallel_pool_create(unsigned int workers);",
         "struct chacha_parallel_pool *chacha_parallel_pool_create(unsigned int workers,\n"
         "                                                          unsigned int min_parallel_bytes);",
         "pool API")
    chacha_c = root / "src/chacha.c"
    once(chacha_c, "    unsigned int worker_count;\n",
         "    unsigned int worker_count;\n    unsigned int min_parallel_bytes;\n",
         "pool threshold field")
    once(chacha_c, "chacha_parallel_pool_create(unsigned int workers)\n{",
         "chacha_parallel_pool_create(unsigned int workers,\n"
         "                            unsigned int min_parallel_bytes)\n{",
         "pool constructor signature")
    once(chacha_c,
         "    if(workers == 0U || workers > CHACHA_PARALLEL_MAX_WORKERS) {\n"
         "        errno = EINVAL;\n"
         "        return NULL;\n"
         "    }",
         "    if(workers == 0U || workers > CHACHA_PARALLEL_MAX_WORKERS ||\n"
         "       (min_parallel_bytes != 4096U && min_parallel_bytes != 8192U &&\n"
         "        min_parallel_bytes != 16384U && min_parallel_bytes != 24576U &&\n"
         "        min_parallel_bytes != 32768U)) {\n"
         "        errno = EINVAL;\n"
         "        return NULL;\n"
         "    }",
         "validate pool configuration")
    once(chacha_c, "    pool->worker_count = workers;\n",
         "    pool->worker_count = workers;\n    pool->min_parallel_bytes = min_parallel_bytes;\n",
         "store pool threshold")
    once(chacha_c,
         "    if(!pool || !base_state || !source || !destination || !poly_key ||\n"
         "       !wire_tag || bytes < 4096U)\n"
         "        return 0;",
         "    if(!pool || !base_state || !source || !destination || !poly_key ||\n"
         "       !wire_tag)\n"
         "        return 0;\n"
         "    if(bytes < pool->min_parallel_bytes)\n"
         "        return 0;",
         "replace fixed dispatch threshold")
    once(chacha_c,
         "    if(workers < 2U || workers > CHACHA_PARALLEL_MAX_WORKERS)\n"
         "        return 0;",
         "    if(workers == 0U || workers > CHACHA_PARALLEL_MAX_WORKERS)\n"
         "        return 0;",
         "allow single worker pool dispatch")

    cipher_h = root / "src/cipher-chachapoly.h"
    once(cipher_h,
         "int chachapoly_init(struct chachapoly_ctx *cpctx,\n"
         "                    const u_char *key, u_int keylen,\n"
         "                    unsigned int parallel_workers);",
         "int chachapoly_init(struct chachapoly_ctx *cpctx,\n"
         "                    const u_char *key, u_int keylen,\n"
         "                    unsigned int parallel_workers,\n"
         "                    unsigned int min_parallel_bytes);",
         "crypto init prototype")
    cipher_c = root / "src/cipher-chachapoly.c"
    once(cipher_c,
         "chachapoly_init(struct chachapoly_ctx *ctx, const u_char *key, u_int keylen,\n"
         "                unsigned int parallel_workers)\n{",
         "chachapoly_init(struct chachapoly_ctx *ctx, const u_char *key, u_int keylen,\n"
         "                unsigned int parallel_workers,\n"
         "                unsigned int min_parallel_bytes)\n{",
         "crypto init definition")
    once(cipher_c,
         "    if(!key || keylen != (32 + 32)) /* 2 x 256 bit keys */\n"
         "        return LIBSSH2_ERROR_INVAL;\n"
         "    chacha_keysetup(&ctx->main_ctx, key, 256);\n"
         "    chacha_keysetup(&ctx->header_ctx, key + 32, 256);\n"
         "    if(parallel_workers > 0U)\n"
         "        ctx->parallel_pool = chacha_parallel_pool_create(parallel_workers);",
         "    if(!key || keylen != (32 + 32)) /* 2 x 256 bit keys */\n"
         "        return LIBSSH2_ERROR_INVAL;\n"
         "    if(min_parallel_bytes != 4096U && min_parallel_bytes != 8192U &&\n"
         "       min_parallel_bytes != 16384U && min_parallel_bytes != 24576U &&\n"
         "       min_parallel_bytes != 32768U)\n"
         "        return LIBSSH2_ERROR_INVAL;\n"
         "    chacha_keysetup(&ctx->main_ctx, key, 256);\n"
         "    chacha_keysetup(&ctx->header_ctx, key + 32, 256);\n"
         "    if(parallel_workers > 0U)\n"
         "        ctx->parallel_pool = chacha_parallel_pool_create(\n"
         "            parallel_workers, min_parallel_bytes);",
         "validate threshold and create pool")
    crypt_c = root / "src/crypt.c"
    once(crypt_c,
         "    if(chachapoly_init(&ctx->chachapoly_ctx, secret, method->secret_len,\n"
         "                       encrypt ? 0U : session->passwall_diag.chacha_workers_requested)) {",
         "    if(chachapoly_init(&ctx->chachapoly_ctx, secret, method->secret_len,\n"
         "                       encrypt ? 0U : session->passwall_diag.chacha_workers_requested,\n"
         "                       encrypt ? 4096U : session->passwall_diag.chacha_threshold_bytes)) {",
         "pass threshold into crypto context")

    session_c = root / "src/session.c"
    once(session_c,
         "    unsigned int requested_workers;\n"
         "    unsigned int active_workers;\n"
         "    if(!session)",
         "    unsigned int requested_workers;\n"
         "    unsigned int active_workers;\n"
         "    unsigned int threshold_bytes;\n"
         "    if(!session)",
         "save threshold local")
    once(session_c,
         "    requested_workers = session->passwall_diag.chacha_workers_requested;\n"
         "    active_workers = session->passwall_diag.chacha_workers_active;\n"
         "    memset(&session->passwall_diag, 0, sizeof(session->passwall_diag));\n"
         "    session->passwall_diag.chacha_workers_requested = requested_workers;\n"
         "    session->passwall_diag.chacha_workers_active = active_workers;",
         "    requested_workers = session->passwall_diag.chacha_workers_requested;\n"
         "    active_workers = session->passwall_diag.chacha_workers_active;\n"
         "    threshold_bytes = session->passwall_diag.chacha_threshold_bytes;\n"
         "    memset(&session->passwall_diag, 0, sizeof(session->passwall_diag));\n"
         "    session->passwall_diag.chacha_workers_requested = requested_workers;\n"
         "    session->passwall_diag.chacha_workers_active = active_workers;\n"
         "    session->passwall_diag.chacha_threshold_bytes = threshold_bytes;",
         "preserve threshold across diagnostic reset")
    once(session_c,
         "    timing->chacha_workers_active =\n"
         "        session->passwall_diag.chacha_workers_active;",
         "    timing->chacha_workers_active =\n"
         "        session->passwall_diag.chacha_workers_active;\n"
         "    timing->chacha_threshold_bytes =\n"
         "        session->passwall_diag.chacha_threshold_bytes;",
         "snapshot threshold")
    if "libssh2_session_set_chacha_threshold(" in session_c.read_text():
        raise RuntimeError("threshold setter already exists")
    with session_c.open("a") as handle:
        handle.write("""
/* Configure the authenticated ChaCha20-Poly1305 payload dispatch threshold. */
LIBSSH2_API int
libssh2_session_set_chacha_threshold(LIBSSH2_SESSION *session,
                                     unsigned int threshold_bytes)
{
    if(!session)
        return LIBSSH2_ERROR_BAD_USE;
    if(threshold_bytes != 4096U && threshold_bytes != 8192U &&
       threshold_bytes != 16384U && threshold_bytes != 24576U &&
       threshold_bytes != 32768U)
        return LIBSSH2_ERROR_INVAL;
    session->passwall_diag.chacha_threshold_bytes = threshold_bytes;
    return 0;
}
""")
    (root / MARKER).write_text(
        "libssh2 1.11.1 Passwall r62 runtime workers 0..3 and thresholds 4/8/16/24/32 KiB\n"
    )
    print("PASS: R62 runtime workers 0..3, threshold matrix 4/8/16/24/32 KiB, single-worker dispatch")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: apply_libssh2_r62_runtime_controls.py LIBSSH2_SOURCE_DIR", file=sys.stderr)
        sys.exit(2)
    patch(Path(sys.argv[1]))
