#include "client_lifetime.h"

#include <errno.h>
#include <string.h>

int client_lifetime_init(client_lifetime_t *life,
                         uint64_t client_id,
                         uint64_t generation)
{
    if (!life || client_id == 0U || generation == 0U) {
        errno = EINVAL;
        return -1;
    }

    memset(life, 0, sizeof(*life));
    life->client_id = client_id;
    life->generation = generation;
    return 0;
}

static int token_matches(const client_lifetime_t *life,
                         uint64_t client_id,
                         uint64_t generation)
{
    return life && client_id != 0U && generation != 0U &&
           life->client_id == client_id &&
           life->generation == generation;
}

int client_lifetime_acquire(client_lifetime_t *life,
                            uint64_t client_id,
                            uint64_t generation)
{
    if (!token_matches(life, client_id, generation)) {
        errno = ESTALE;
        return -1;
    }
    if (life->close_requested || life->finalized) {
        errno = ECANCELED;
        return -1;
    }
    if (life->worker_refs == UINT32_MAX) {
        errno = EOVERFLOW;
        return -1;
    }

    life->worker_refs++;
    return 0;
}

int client_lifetime_completion_current(const client_lifetime_t *life,
                                       uint64_t client_id,
                                       uint64_t generation)
{
    return token_matches(life, client_id, generation) &&
           !life->close_requested && !life->finalized;
}

int client_lifetime_request_close(client_lifetime_t *life)
{
    if (!life || life->finalized) {
        errno = EINVAL;
        return -1;
    }

    life->close_requested = 1U;
    return life->worker_refs == 0U;
}

int client_lifetime_release(client_lifetime_t *life,
                            uint64_t client_id,
                            uint64_t generation)
{
    if (!token_matches(life, client_id, generation)) {
        errno = ESTALE;
        return -1;
    }
    if (life->finalized || life->worker_refs == 0U) {
        errno = EALREADY;
        return -1;
    }

    life->worker_refs--;
    return life->close_requested && life->worker_refs == 0U;
}

int client_lifetime_finalize(client_lifetime_t *life)
{
    if (!life || life->finalized || !life->close_requested) {
        errno = EINVAL;
        return -1;
    }
    if (life->worker_refs != 0U) {
        errno = EBUSY;
        return -1;
    }

    life->finalized = 1U;
    return 0;
}
