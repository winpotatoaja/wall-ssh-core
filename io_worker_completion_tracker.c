#include "io_worker_completion_tracker.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    io_worker_task_ref_t ref;
    unsigned char state; /* 0 empty, 1 occupied, 2 tombstone */
} tracker_slot_t;

struct io_worker_completion_tracker {
    tracker_slot_t *slots;
    size_t slot_count;
    size_t count;
    size_t tombstones;
    size_t max_outstanding;
    uint32_t worker_count;
};

static uint64_t mix_task_id(uint64_t value)
{
    value ^= value >> 30;
    value *= UINT64_C(0xbf58476d1ce4e5b9);
    value ^= value >> 27;
    value *= UINT64_C(0x94d049bb133111eb);
    value ^= value >> 31;
    return value;
}

static size_t find_slot(const io_worker_completion_tracker_t *tracker,
                        uint64_t task_id, int *found)
{
    size_t mask = tracker->slot_count - 1U;
    size_t index = (size_t)mix_task_id(task_id) & mask;
    size_t first_tombstone = SIZE_MAX;

    for (size_t probes = 0; probes < tracker->slot_count; probes++) {
        const tracker_slot_t *slot = &tracker->slots[index];
        if (slot->state == 0U) {
            *found = 0;
            return first_tombstone != SIZE_MAX ? first_tombstone : index;
        }
        if (slot->state == 1U && slot->ref.task_id == task_id) {
            *found = 1;
            return index;
        }
        if (slot->state == 2U && first_tombstone == SIZE_MAX)
            first_tombstone = index;
        index = (index + 1U) & mask;
    }

    *found = 0;
    return first_tombstone;
}

io_worker_completion_tracker_t *io_worker_completion_tracker_create(
    uint32_t worker_count, uint32_t per_worker_capacity)
{
    if (worker_count == 0U || worker_count > IO_WORKER_POOL_MAX_WORKERS ||
        per_worker_capacity < 2U ||
        (per_worker_capacity & (per_worker_capacity - 1U)) != 0U ||
        (size_t)worker_count > SIZE_MAX / (size_t)per_worker_capacity) {
        errno = EINVAL;
        return NULL;
    }

    size_t max_outstanding = (size_t)worker_count * per_worker_capacity;
    if (max_outstanding > SIZE_MAX / 2U) {
        errno = EOVERFLOW;
        return NULL;
    }
    size_t required = max_outstanding * 2U;
    size_t slot_count = 2U;
    while (slot_count < required) {
        if (slot_count > SIZE_MAX / 2U) {
            errno = EOVERFLOW;
            return NULL;
        }
        slot_count *= 2U;
    }
    if (slot_count > SIZE_MAX / sizeof(tracker_slot_t)) {
        errno = EOVERFLOW;
        return NULL;
    }

    io_worker_completion_tracker_t *tracker = calloc(1, sizeof(*tracker));
    if (!tracker)
        return NULL;
    tracker->slots = calloc(slot_count, sizeof(*tracker->slots));
    if (!tracker->slots) {
        free(tracker);
        return NULL;
    }
    tracker->slot_count = slot_count;
    tracker->max_outstanding = max_outstanding;
    tracker->worker_count = worker_count;
    return tracker;
}

static int validate_ref(const io_worker_completion_tracker_t *tracker,
                        const io_worker_task_ref_t *ref)
{
    return tracker && ref && ref->task_id != 0U && ref->client_id != 0U &&
           ref->generation != 0U && ref->worker_id < tracker->worker_count;
}

int io_worker_completion_tracker_register(
    io_worker_completion_tracker_t *tracker,
    const io_worker_task_ref_t *task_ref)
{
    if (!validate_ref(tracker, task_ref)) {
        errno = EINVAL;
        return -1;
    }
    if (tracker->count >= tracker->max_outstanding) {
        errno = EAGAIN;
        return -1;
    }

    int found = 0;
    size_t index = find_slot(tracker, task_ref->task_id, &found);
    if (found) {
        errno = EEXIST;
        return -1;
    }
    if (index == SIZE_MAX) {
        errno = ENOSPC;
        return -1;
    }

    tracker_slot_t *slot = &tracker->slots[index];
    if (slot->state == 2U)
        tracker->tombstones--;
    slot->ref = *task_ref;
    slot->state = 1U;
    tracker->count++;
    return 0;
}

static int remove_ref(io_worker_completion_tracker_t *tracker,
                      const io_worker_task_ref_t *expected,
                      io_worker_task_ref_t *out)
{
    if (!validate_ref(tracker, expected)) {
        errno = EINVAL;
        return -1;
    }

    int found = 0;
    size_t index = find_slot(tracker, expected->task_id, &found);
    if (!found) {
        errno = ENOENT;
        return -1;
    }

    tracker_slot_t *slot = &tracker->slots[index];
    if (slot->ref.client_id != expected->client_id ||
        slot->ref.generation != expected->generation ||
        slot->ref.worker_id != expected->worker_id) {
        errno = EPROTO;
        return -1;
    }

    if (out)
        *out = slot->ref;
    memset(&slot->ref, 0, sizeof(slot->ref));
    slot->state = 2U;
    tracker->count--;
    tracker->tombstones++;
    return 0;
}

int io_worker_completion_tracker_take(
    io_worker_completion_tracker_t *tracker,
    const io_worker_completion_t *completion,
    io_worker_task_ref_t *task_ref_out)
{
    if (!tracker || !completion || !task_ref_out) {
        errno = EINVAL;
        return -1;
    }
    io_worker_task_ref_t expected = {
        .task_id = completion->task_id,
        .client_id = completion->client_id,
        .generation = completion->generation,
        .worker_id = completion->worker_id
    };
    return remove_ref(tracker, &expected, task_ref_out);
}

int io_worker_completion_tracker_cancel(
    io_worker_completion_tracker_t *tracker,
    const io_worker_task_ref_t *task_ref)
{
    return remove_ref(tracker, task_ref, NULL);
}

size_t io_worker_completion_tracker_outstanding(
    const io_worker_completion_tracker_t *tracker)
{
    return tracker ? tracker->count : 0U;
}

size_t io_worker_completion_tracker_capacity(
    const io_worker_completion_tracker_t *tracker)
{
    return tracker ? tracker->max_outstanding : 0U;
}

void io_worker_completion_tracker_destroy(
    io_worker_completion_tracker_t *tracker)
{
    if (!tracker)
        return;
    free(tracker->slots);
    free(tracker);
}
