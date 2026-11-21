#ifndef PASSWALL_SSH_CORE_TLS_ENGINE_H
#define PASSWALL_SSH_CORE_TLS_ENGINE_H

#include <stddef.h>
#include <stdint.h>
#include <openssl/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tls_engine tls_engine_t;

/* Creates the two SPSC byte queues and the eventfd notification pair. */
tls_engine_t *tls_engine_create(uint32_t queue_capacity);

/*
 * Starts the TLS owner thread. Ownership of fd transfers to the engine only
 * when this function returns 0. The engine creates SSL*, performs the TLS
 * handshake, and owns every subsequent SSL operation through SSL_free().
 * SSL_CTX remains borrowed and must stay alive until tls_engine_destroy().
 */
int tls_engine_start(tls_engine_t *engine, SSL_CTX *ctx, int fd,
                     const char *server_name, int verify_peer,
                     int handshake_timeout_ms);

/* Waits for the bounded TLS handshake to complete. */
int tls_engine_wait_ready(tls_engine_t *engine);
int tls_engine_start_error(const tls_engine_t *engine);
int tls_engine_start_retryable(const tls_engine_t *engine);
int tls_engine_copy_negotiated(tls_engine_t *engine,
                               char *version, size_t version_size,
                               char *cipher, size_t cipher_size);

/* Single SSH-owner producer: queues plaintext SSH bytes for TLS encryption. */
ssize_t tls_engine_send(tls_engine_t *engine, const void *data, size_t length);

/* Single SSH-owner consumer: reads decrypted TLS bytes for libssh2. */
ssize_t tls_engine_recv(tls_engine_t *engine, void *data, size_t length);

int tls_engine_notify_fd(const tls_engine_t *engine);
void tls_engine_drain_notify(tls_engine_t *engine);
int tls_engine_rx_pending(const tls_engine_t *engine);
int tls_engine_tx_pending(const tls_engine_t *engine);

/* Returns 1 when receive-side TLS EOF/error is published, otherwise 0. */
int tls_engine_rx_terminal(const tls_engine_t *engine, int *error_out);
int tls_engine_tx_terminal(const tls_engine_t *engine, int *error_out);

/* Requests bounded shutdown; graceful=0 skips close_notify exchange. */
void tls_engine_stop(tls_engine_t *engine, int graceful,
                     int shutdown_timeout_ms);
int tls_engine_join(tls_engine_t *engine);

/* Stop/join if required, then release queues, eventfds and synchronization. */
void tls_engine_destroy(tls_engine_t *engine);

#ifdef __cplusplus
}
#endif

#endif
