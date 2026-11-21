#define _GNU_SOURCE
#include "../tls_engine.h"

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#define TLS_TEST_BYTES (4U * 1024U * 1024U)
#define TLS_TEST_RING 32768U
#define TLS_TEST_CHUNK 8192U

typedef struct {
    SSL_CTX *ctx;
    int fd;
    int error;
} tls_server_args_t;

static uint8_t expected_byte(uint64_t offset)
{
    uint64_t value = offset * UINT64_C(131) + (offset >> 7) * UINT64_C(17);
    value ^= value >> 11;
    return (uint8_t)value;
}

static long long monotonic_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

static int make_test_certificate(SSL_CTX *ctx)
{
    EVP_PKEY_CTX *key_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *key = NULL;
    X509 *cert = NULL;
    int ok = 0;

    if (!key_ctx) goto done;
    if (EVP_PKEY_keygen_init(key_ctx) <= 0) goto done;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(key_ctx, 2048) <= 0) goto done;
    if (EVP_PKEY_keygen(key_ctx, &key) <= 0) goto done;

    cert = X509_new();
    if (!cert) goto done;
    if (X509_set_version(cert, 2) != 1) goto done;
    if (ASN1_INTEGER_set(X509_get_serialNumber(cert), 1) != 1) goto done;
    if (!X509_gmtime_adj(X509_get_notBefore(cert), -60)) goto done;
    if (!X509_gmtime_adj(X509_get_notAfter(cert), 3600)) goto done;
    if (X509_set_pubkey(cert, key) != 1) goto done;

    X509_NAME *name = X509_get_subject_name(cert);
    if (!name) goto done;
    if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            (const unsigned char *)"localhost", -1, -1, 0) != 1) goto done;
    if (X509_set_issuer_name(cert, name) != 1) goto done;
    if (X509_sign(cert, key, EVP_sha256()) <= 0) goto done;
    if (SSL_CTX_use_certificate(ctx, cert) != 1) goto done;
    if (SSL_CTX_use_PrivateKey(ctx, key) != 1) goto done;
    if (SSL_CTX_check_private_key(ctx) != 1) goto done;
    ok = 1;

done:
    X509_free(cert);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(key_ctx);
    return ok ? 0 : -1;
}

static int server_write_all(SSL *ssl, const uint8_t *data, size_t length)
{
    size_t done = 0;
    while (done < length) {
        int amount = length - done > TLS_TEST_CHUNK
            ? (int)TLS_TEST_CHUNK : (int)(length - done);
        int rc = SSL_write(ssl, data + done, amount);
        if (rc <= 0) return -1;
        done += (size_t)rc;
    }
    return 0;
}

static int server_shutdown(SSL *ssl)
{
    long long deadline = monotonic_ms() + 15000;
    for (;;) {
        int rc = SSL_shutdown(ssl);
        if (rc == 1) return 0;
        if (rc < 0) {
            int error = SSL_get_error(ssl, rc);
            if (error != SSL_ERROR_WANT_READ &&
                error != SSL_ERROR_WANT_WRITE) return -1;
            struct pollfd pfd = {
                .fd = SSL_get_fd(ssl),
                .events = error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT
            };
            long long remaining = deadline - monotonic_ms();
            if (remaining <= 0) return -1;
            int pr = poll(&pfd, 1, (int)remaining);
            if (pr <= 0) return -1;
        } else {
            /* rc == 0: close_notify sent, wait for the peer alert. */
            struct pollfd pfd = { .fd = SSL_get_fd(ssl), .events = POLLIN };
            long long remaining = deadline - monotonic_ms();
            if (remaining <= 0) return -1;
            int pr = poll(&pfd, 1, (int)remaining);
            if (pr <= 0) return -1;
        }
    }
}

static void *tls_test_server(void *opaque)
{
    tls_server_args_t *args = (tls_server_args_t *)opaque;
    SSL *ssl = SSL_new(args->ctx);
    if (!ssl) {
        args->error = 1;
        close(args->fd);
        return NULL;
    }
    if (SSL_set_fd(ssl, args->fd) != 1 || SSL_accept(ssl) != 1) {
        args->error = 2;
        SSL_free(ssl);
        close(args->fd);
        return NULL;
    }

    uint8_t buffer[TLS_TEST_CHUNK];
    size_t total = 0;
    while (total < TLS_TEST_BYTES) {
        int want = TLS_TEST_BYTES - total > sizeof(buffer)
            ? (int)sizeof(buffer) : (int)(TLS_TEST_BYTES - total);
        int rc = SSL_read(ssl, buffer, want);
        if (rc <= 0) {
            args->error = 3;
            break;
        }
        if (server_write_all(ssl, buffer, (size_t)rc) != 0) {
            args->error = 4;
            break;
        }
        total += (size_t)rc;
    }

    if (!args->error && server_shutdown(ssl) != 0)
        args->error = 5;

    SSL_free(ssl);
    close(args->fd);
    return NULL;
}

static int wait_owner_event(tls_engine_t *engine, int timeout_ms)
{
    struct pollfd pfd = {
        .fd = tls_engine_notify_fd(engine),
        .events = POLLIN
    };
    int rc;
    do {
        rc = poll(&pfd, 1, timeout_ms);
    } while (rc < 0 && errno == EINTR);
    if (rc > 0 && (pfd.revents & POLLIN))
        tls_engine_drain_notify(engine);
    return rc;
}

typedef struct {
    SSL_CTX *ctx;
    int fd;
    const uint8_t *payload;
    size_t payload_length;
    int error;
} tls_close_server_args_t;

static void *tls_close_notify_server(void *opaque)
{
    tls_close_server_args_t *args = (tls_close_server_args_t *)opaque;
    SSL *ssl = SSL_new(args->ctx);
    if (!ssl) {
        args->error = 1;
        close(args->fd);
        return NULL;
    }
    if (SSL_set_fd(ssl, args->fd) != 1 || SSL_accept(ssl) != 1) {
        args->error = 2;
        SSL_free(ssl);
        close(args->fd);
        return NULL;
    }
    if (server_write_all(ssl, args->payload, args->payload_length) != 0)
        args->error = 3;
    if (!args->error && server_shutdown(ssl) != 0)
        args->error = 4;
    SSL_free(ssl);
    close(args->fd);
    return NULL;
}

static int run_close_notify_drain_wakeup_regression(void)
{
    int sockets[2] = {-1, -1};
    SSL_CTX *server_ctx = NULL;
    SSL_CTX *client_ctx = NULL;
    tls_engine_t *engine = NULL;
    pthread_t server_thread;
    int server_started = 0;
    int engine_started = 0;
    int result = 1;
    uint8_t payload[512];
    uint8_t received[sizeof(payload)];
    for (size_t i = 0; i < sizeof(payload); i++)
        payload[i] = expected_byte((uint64_t)i + UINT64_C(0x5a31));

    tls_close_server_args_t server_args;
    memset(&server_args, 0, sizeof(server_args));

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) {
        perror("close_notify socketpair");
        goto done;
    }
    server_ctx = SSL_CTX_new(TLS_server_method());
    client_ctx = SSL_CTX_new(TLS_client_method());
    if (!server_ctx || !client_ctx || make_test_certificate(server_ctx) != 0) {
        fprintf(stderr, "FAIL: close_notify drain-wakeup TLS contexts/certificate\n");
        ERR_print_errors_fp(stderr);
        goto done;
    }
    SSL_CTX_set_verify(client_ctx, SSL_VERIFY_NONE, NULL);

    server_args.ctx = server_ctx;
    server_args.fd = sockets[1];
    server_args.payload = payload;
    server_args.payload_length = sizeof(payload);
    if (pthread_create(&server_thread, NULL, tls_close_notify_server,
                       &server_args) != 0) {
        perror("close_notify server pthread_create");
        goto done;
    }
    server_started = 1;
    sockets[1] = -1;

    engine = tls_engine_create(4096U);
    if (!engine) {
        perror("close_notify tls_engine_create");
        goto done;
    }
    if (tls_engine_start(engine, client_ctx, sockets[0], "localhost",
                         0, 5000) != 0) {
        perror("close_notify tls_engine_start");
        goto done;
    }
    sockets[0] = -1;
    engine_started = 1;
    if (tls_engine_wait_ready(engine) != 0) {
        fprintf(stderr, "FAIL: close_notify drain-wakeup handshake errno=%d\n", errno);
        goto done;
    }

    long long deadline = monotonic_ms() + 5000;
    int rx_error = 0;
    while (!tls_engine_rx_terminal(engine, &rx_error)) {
        if (monotonic_ms() >= deadline) {
            fprintf(stderr, "FAIL: close_notify drain-wakeup terminal timeout\n");
            goto done;
        }
        if (wait_owner_event(engine, 20) < 0) {
            perror("close_notify wait terminal event");
            goto done;
        }
    }
    if (rx_error != 0 || tls_engine_rx_pending(engine) != sizeof(payload)) {
        fprintf(stderr, "FAIL: close_notify was not published with the expected queued plaintext (pending=%d error=%d)\n",
                tls_engine_rx_pending(engine), rx_error);
        goto done;
    }

    /* Discard all pre-existing RX/terminal notifications. After consuming the
     * final queued byte, tls_engine_recv() must generate a fresh owner wake. */
    tls_engine_drain_notify(engine);
    while (wait_owner_event(engine, 0) > 0) { }

    ssize_t n = tls_engine_recv(engine, received, sizeof(received));
    if (n != (ssize_t)sizeof(payload) ||
        memcmp(received, payload, sizeof(payload)) != 0) {
        fprintf(stderr, "FAIL: close_notify queued payload drain n=%ld errno=%d\n",
                (long)n, errno);
        goto done;
    }
    if (wait_owner_event(engine, 1000) <= 0) {
        fprintf(stderr, "FAIL: owner eventfd not re-signalled after terminal RX queue drained\n");
        goto done;
    }

    tls_engine_stop(engine, 1, 3000);
    if (tls_engine_join(engine) != 0) {
        perror("close_notify tls_engine_join");
        goto done;
    }
    engine_started = 0;
    if (pthread_join(server_thread, NULL) != 0) {
        perror("close_notify server pthread_join");
        server_started = 0;
        goto done;
    }
    server_started = 0;
    if (server_args.error != 0) {
        fprintf(stderr, "FAIL: close_notify server stage=%d\n", server_args.error);
        goto done;
    }

    puts("PASS: close_notify terminal wake is repeated after queued RX plaintext drains");
    result = 0;

done:
    if (engine) {
        if (engine_started) {
            tls_engine_stop(engine, 0, 1000);
            (void)tls_engine_join(engine);
        }
        tls_engine_destroy(engine);
    }
    if (sockets[0] >= 0) close(sockets[0]);
    if (server_started) {
        shutdown(server_args.fd, SHUT_RDWR);
        (void)pthread_join(server_thread, NULL);
    }
    if (sockets[1] >= 0) close(sockets[1]);
    SSL_CTX_free(client_ctx);
    SSL_CTX_free(server_ctx);
    return result;
}

int main(void)
{
    if (run_close_notify_drain_wakeup_regression() != 0)
        return 1;

    int sockets[2] = { -1, -1 };
    SSL_CTX *server_ctx = NULL;
    SSL_CTX *client_ctx = NULL;
    tls_engine_t *engine = NULL;
    pthread_t server_thread;
    int server_started = 0;
    int result = 1;
    tls_server_args_t server_args;
    memset(&server_args, 0, sizeof(server_args));

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) {
        perror("socketpair");
        goto done;
    }

    server_ctx = SSL_CTX_new(TLS_server_method());
    client_ctx = SSL_CTX_new(TLS_client_method());
    if (!server_ctx || !client_ctx ||
        make_test_certificate(server_ctx) != 0) {
        fprintf(stderr, "FAIL: create TLS test certificate/context\n");
        ERR_print_errors_fp(stderr);
        goto done;
    }
    SSL_CTX_set_verify(client_ctx, SSL_VERIFY_NONE, NULL);

    server_args.ctx = server_ctx;
    server_args.fd = sockets[1];
    if (pthread_create(&server_thread, NULL, tls_test_server,
                       &server_args) != 0) {
        perror("pthread_create");
        goto done;
    }
    server_started = 1;
    sockets[1] = -1;

    engine = tls_engine_create(TLS_TEST_RING);
    if (!engine) {
        perror("tls_engine_create");
        goto done;
    }
    if (tls_engine_start(engine, client_ctx, sockets[0], "localhost",
                         0, 5000) != 0) {
        perror("tls_engine_start");
        goto done;
    }
    sockets[0] = -1; /* fd ownership transferred to the TLS Engine */

    if (tls_engine_wait_ready(engine) != 0) {
        fprintf(stderr, "FAIL: TLS handshake errno=%d retryable=%d\n",
                errno, tls_engine_start_retryable(engine));
        ERR_print_errors_fp(stderr);
        goto done;
    }

    char version[32];
    char cipher[128];
    if (tls_engine_copy_negotiated(engine, version, sizeof(version),
                                   cipher, sizeof(cipher)) != 0) {
        perror("tls_engine_copy_negotiated");
        goto done;
    }
    printf("TLS_ENGINE negotiated=%s cipher=%s\n", version, cipher);

    uint8_t send_buffer[TLS_TEST_CHUNK];
    uint8_t recv_buffer[TLS_TEST_CHUNK];
    uint64_t sent = 0;
    uint64_t received = 0;
    long long deadline = monotonic_ms() + 180000;

    while (received < TLS_TEST_BYTES && monotonic_ms() < deadline) {
        int made_progress = 0;

        if (sent < TLS_TEST_BYTES) {
            size_t amount = TLS_TEST_BYTES - sent > sizeof(send_buffer)
                ? sizeof(send_buffer) : (size_t)(TLS_TEST_BYTES - sent);
            for (size_t i = 0; i < amount; i++)
                send_buffer[i] = expected_byte(sent + i);

            ssize_t n = tls_engine_send(engine, send_buffer, amount);
            if (n < 0) {
                fprintf(stderr, "FAIL: TLS Engine send errno=%d\n", errno);
                goto done;
            }
            if (n > 0) {
                sent += (uint64_t)n;
                made_progress = 1;
            }
        }

        ssize_t n = tls_engine_recv(engine, recv_buffer, sizeof(recv_buffer));
        if (n > 0) {
            for (ssize_t i = 0; i < n; i++) {
                if (recv_buffer[i] != expected_byte(received + (uint64_t)i)) {
                    fprintf(stderr, "FAIL: TLS echo mismatch offset=%llu\n",
                            (unsigned long long)(received + (uint64_t)i));
                    goto done;
                }
            }
            received += (uint64_t)n;
            made_progress = 1;
        } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            fprintf(stderr, "FAIL: TLS Engine recv errno=%d\n", errno);
            goto done;
        }

        if (!made_progress) {
            if (wait_owner_event(engine, 10) < 0) {
                perror("poll TLS Engine eventfd");
                goto done;
            }
        }
    }

    if (sent != TLS_TEST_BYTES || received != TLS_TEST_BYTES) {
        int rx_error = 0;
        int tx_error = 0;
        int rx_terminal = tls_engine_rx_terminal(engine, &rx_error);
        int tx_terminal = tls_engine_tx_terminal(engine, &tx_error);
        fprintf(stderr, "FAIL: transfer timeout sent=%llu received=%llu "
                        "tx_pending=%d rx_pending=%d rx_terminal=%d rx_error=%d "
                        "tx_terminal=%d tx_error=%d\\n",
                (unsigned long long)sent, (unsigned long long)received,
                tls_engine_tx_pending(engine), tls_engine_rx_pending(engine),
                rx_terminal, rx_error, tx_terminal, tx_error);
        goto done;
    }
    deadline = monotonic_ms() + 5000;
    for (;;) {
        int terminal_error = 0;
        if (tls_engine_rx_terminal(engine, &terminal_error)) {
            if (terminal_error != 0) {
                fprintf(stderr, "FAIL: TLS close_notify mapped to errno=%d\n",
                        terminal_error);
                goto done;
            }
            break;
        }
        if (monotonic_ms() >= deadline) {
            fprintf(stderr, "FAIL: receive terminal notification timeout\n");
            goto done;
        }
        if (wait_owner_event(engine, 20) < 0) {
            perror("poll terminal eventfd");
            goto done;
        }
    }

    tls_engine_stop(engine, 1, 3000);
    if (tls_engine_join(engine) != 0) {
        perror("tls_engine_join");
        goto done;
    }

    if (pthread_join(server_thread, NULL) != 0) {
        perror("pthread_join server");
        server_started = 0;
        goto done;
    }
    server_started = 0;
    if (server_args.error != 0) {
        fprintf(stderr, "FAIL: TLS server stage=%d\n", server_args.error);
        goto done;
    }

    printf("PASS: TLS Engine owner-thread duplex transfer %u bytes; "
           "close_notify and graceful shutdown\n", TLS_TEST_BYTES);
    result = 0;

done:
    if (engine) {
        tls_engine_stop(engine, 0, 1000);
        (void)tls_engine_join(engine);
        tls_engine_destroy(engine);
    }
    if (sockets[0] >= 0) {
        close(sockets[0]);
        sockets[0] = -1;
    }
    if (server_started)
        (void)pthread_join(server_thread, NULL);
    if (sockets[1] >= 0) close(sockets[1]);
    SSL_CTX_free(client_ctx);
    SSL_CTX_free(server_ctx);
    return result;
}
