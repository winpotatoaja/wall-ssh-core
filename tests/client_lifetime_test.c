#include "client_lifetime.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define CHECK(x) do { if (!(x)) { \
    fprintf(stderr, "FAIL %s:%d: %s (errno=%d)\n", __FILE__, __LINE__, #x, errno); \
    return 1; \
} } while (0)

int main(void)
{
    client_lifetime_t life;

    CHECK(client_lifetime_init(&life, 41U, 7U) == 0);
    CHECK(client_lifetime_completion_current(&life, 41U, 7U) == 1);
    CHECK(client_lifetime_acquire(&life, 41U, 7U) == 0);
    CHECK(client_lifetime_acquire(&life, 41U, 7U) == 0);
    CHECK(life.worker_refs == 2U);

    /* An old generation cannot acquire, complete, or release this object. */
    CHECK(client_lifetime_acquire(&life, 41U, 6U) == -1 && errno == ESTALE);
    CHECK(client_lifetime_completion_current(&life, 41U, 6U) == 0);
    CHECK(client_lifetime_release(&life, 41U, 6U) == -1 && errno == ESTALE);
    CHECK(life.worker_refs == 2U);

    /* Close detaches the client but cannot free storage while tasks are in flight. */
    CHECK(client_lifetime_request_close(&life) == 0);
    CHECK(client_lifetime_completion_current(&life, 41U, 7U) == 0);
    CHECK(client_lifetime_finalize(&life) == -1 && errno == EBUSY);
    CHECK(client_lifetime_acquire(&life, 41U, 7U) == -1 && errno == ECANCELED);

    /* Stale completions still release their own references, without applying data. */
    CHECK(client_lifetime_release(&life, 41U, 7U) == 0);
    CHECK(client_lifetime_release(&life, 41U, 7U) == 1);
    CHECK(life.worker_refs == 0U);
    CHECK(client_lifetime_finalize(&life) == 0);
    CHECK(life.finalized == 1U);
    CHECK(client_lifetime_release(&life, 41U, 7U) == -1 && errno == EALREADY);

    /* A reused logical slot with a new generation rejects the previous token. */
    CHECK(client_lifetime_init(&life, 41U, 8U) == 0);
    CHECK(client_lifetime_completion_current(&life, 41U, 7U) == 0);
    CHECK(client_lifetime_completion_current(&life, 41U, 8U) == 1);
    CHECK(client_lifetime_request_close(&life) == 1);
    CHECK(client_lifetime_finalize(&life) == 0);

    puts("PASS client lifetime tokens, stale completion, deferred close, ref drain and generation reuse");
    return 0;
}
