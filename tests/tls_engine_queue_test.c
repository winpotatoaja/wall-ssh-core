#include "tls_engine.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    tls_engine_queue_snapshot_t snapshot;
    memset(&snapshot, 0xa5, sizeof(snapshot));
    tls_engine_t *engine = tls_engine_create(4096U);
    if (!engine) { perror("tls_engine_create"); return 1; }
    if (tls_engine_queue_snapshot(engine, &snapshot) != 0) {
        perror("tls_engine_queue_snapshot");
        tls_engine_destroy(engine);
        return 1;
    }
    if (snapshot.rx_buffered_bytes != 0U || snapshot.tx_buffered_bytes != 0U ||
        snapshot.capacity_bytes != 4096U ||
        snapshot.socket_rxq_valid != 0 || snapshot.socket_txq_valid != 0 ||
        snapshot.socket_rxq_bytes != 0 || snapshot.socket_txq_bytes != 0) {
        fprintf(stderr, "FAIL: unexpected empty TLS queue snapshot\n");
        tls_engine_destroy(engine);
        return 1;
    }
    errno = 0;
    if (tls_engine_queue_snapshot(NULL, &snapshot) != -1 || errno != EINVAL) {
        fprintf(stderr, "FAIL: NULL engine must fail with EINVAL\n");
        tls_engine_destroy(engine);
        return 1;
    }
    errno = 0;
    if (tls_engine_queue_snapshot(engine, NULL) != -1 || errno != EINVAL) {
        fprintf(stderr, "FAIL: NULL snapshot must fail with EINVAL\n");
        tls_engine_destroy(engine);
        return 1;
    }
    tls_engine_destroy(engine);
    puts("PASS: TLS queue snapshot reports empty rings, capacity and closed socket validity");
    return 0;
}
