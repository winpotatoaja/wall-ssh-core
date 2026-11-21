#ifndef PASSWALL_SSH_CORE_IO_WORKER_COMPLETION_TRACKER_H
#define PASSWALL_SSH_CORE_IO_WORKER_COMPLETION_TRACKER_H

#include "io_worker_pool.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct io_worker_completion_tracker io_worker_completion_tracker_t;

typedef struct {
    uint64_t task_id;
    uint64_t client_id;
    uint64_t generation;
    uint32_t worker_id;
} io_worker_task_ref_t;

/*
 * Owner-only bounded registry for accepted tasks. Register only after the
 * client lifetime reference has been acquired and before publishing the task.
 * A completion must match all four identity fields before its entry is
 * consumed. Unknown/duplicate completions and mismatched records are rejected.
 */
io_worker_completion_tracker_t *io_worker_completion_tracker_create(
    uint32_t worker_count, uint32_t per_worker_capacity);
int io_worker_completion_tracker_register(
    io_worker_completion_tracker_t *tracker,
    const io_worker_task_ref_t *task_ref);
int io_worker_completion_tracker_take(
    io_worker_completion_tracker_t *tracker,
    const io_worker_completion_t *completion,
    io_worker_task_ref_t *task_ref_out);
/* Roll back a registration if submit fails before the task is accepted. */
int io_worker_completion_tracker_cancel(
    io_worker_completion_tracker_t *tracker,
    const io_worker_task_ref_t *task_ref);
size_t io_worker_completion_tracker_outstanding(
    const io_worker_completion_tracker_t *tracker);
size_t io_worker_completion_tracker_capacity(
    const io_worker_completion_tracker_t *tracker);
void io_worker_completion_tracker_destroy(
    io_worker_completion_tracker_t *tracker);

#ifdef __cplusplus
}
#endif

#endif
