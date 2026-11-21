#ifndef PASSWALL_SSH_CORE_CLIENT_LIFETIME_H
#define PASSWALL_SSH_CORE_CLIENT_LIFETIME_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * SSH-Owner-only lifetime accounting for client objects referenced by
 * asynchronous local-socket tasks. Workers never access this structure.
 *
 * The Owner must keep the client FD and ring-buffer storage alive until
 * close_requested is true, worker_refs reaches zero, and finalize succeeds.
 * client_id/generation are copied into every task and completion; IDs must
 * not be reused during one process lifetime.
 */
typedef struct {
    uint64_t client_id;
    uint64_t generation;
    uint32_t worker_refs;
    uint32_t close_requested;
    uint32_t finalized;
} client_lifetime_t;

int client_lifetime_init(client_lifetime_t *life,
                         uint64_t client_id,
                         uint64_t generation);

/* Acquire one task reference before publishing a task to the worker pool. */
int client_lifetime_acquire(client_lifetime_t *life,
                            uint64_t client_id,
                            uint64_t generation);

/*
 * A completion may mutate live client state only while this returns 1.
 * A stale/closing completion must still call release() exactly once.
 */
int client_lifetime_completion_current(const client_lifetime_t *life,
                                       uint64_t client_id,
                                       uint64_t generation);

/* Mark close requested; returns 1 when no task references remain. */
int client_lifetime_request_close(client_lifetime_t *life);

/*
 * Release one task reference using its copied identity token.
 * Returns 1 when deferred finalization is now safe, 0 otherwise, -1 on error.
 */
int client_lifetime_release(client_lifetime_t *life,
                            uint64_t client_id,
                            uint64_t generation);

/* Finalize only after close was requested and all task references drained. */
int client_lifetime_finalize(client_lifetime_t *life);

#ifdef __cplusplus
}
#endif

#endif
