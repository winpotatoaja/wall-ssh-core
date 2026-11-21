#include "../io_worker_completion_tracker.h"

#include <errno.h>
#include <poll.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int check(int condition, const char *name)
{
    if (condition)
        return 0;
    fprintf(stderr, "FAIL: %s\n", name);
    return -1;
}

static io_worker_task_ref_t make_ref(uint64_t task_id, uint64_t client_id,
                                     uint64_t generation, uint32_t worker_id)
{
    io_worker_task_ref_t ref = {task_id, client_id, generation, worker_id};
    return ref;
}

static io_worker_completion_t make_completion(io_worker_task_ref_t ref)
{
    io_worker_completion_t completion;
    memset(&completion, 0, sizeof(completion));
    completion.task_id = ref.task_id;
    completion.client_id = ref.client_id;
    completion.generation = ref.generation;
    completion.worker_id = ref.worker_id;
    return completion;
}

static int pipeline_execute(const io_worker_task_t *task,
                            io_worker_completion_t *completion,
                            const void *context)
{
    (void)context;
    completion->result_len = task->payload_len;
    memcpy(completion->result, task->payload, task->payload_len);
    return 0;
}

static int test_register_before_publish_pipeline(void)
{
    io_worker_pool_t *pool = io_worker_pool_create(2, 4, pipeline_execute, NULL);
    io_worker_completion_tracker_t *tracker =
        io_worker_completion_tracker_create(2, 4);
    if (check(pool != NULL && tracker != NULL, "create worker completion pipeline"))
        goto fail;

    io_worker_task_t task;
    memset(&task, 0, sizeof(task));
    task.task_id = 501;
    task.client_id = 9002;
    task.generation = 8;
    task.payload_len = 5;
    memcpy(task.payload, "hello", 5);

    uint32_t worker_id = UINT32_MAX;
    if (check(io_worker_pool_select_worker(pool, &worker_id) == 0 &&
              worker_id < 2, "select worker before task publication"))
        goto fail;

    io_worker_task_ref_t ref = make_ref(task.task_id, task.client_id,
                                        task.generation, worker_id);
    if (check(io_worker_completion_tracker_register(tracker, &ref) == 0,
              "register identity before publishing task"))
        goto fail;
    if (check(io_worker_pool_submit_to_worker(pool, &task, worker_id) == 0,
              "publish task to preselected worker"))
        goto fail;

    struct pollfd pfd = {
        .fd = io_worker_pool_completion_fd(pool, worker_id),
        .events = POLLIN
    };
    if (check(poll(&pfd, 1, 3000) == 1 && (pfd.revents & POLLIN),
              "worker completion eventfd becomes readable"))
        goto fail;

    io_worker_completion_t completion;
    size_t count = io_worker_pool_drain_completions(pool, worker_id,
                                                     &completion, 1);
    io_worker_task_ref_t taken;
    if (check(count == 1 && completion.status == 0 &&
              completion.result_len == 5 &&
              memcmp(completion.result, "hello", 5) == 0 &&
              io_worker_completion_tracker_take(tracker, &completion,
                                                &taken) == 0 &&
              taken.task_id == ref.task_id &&
              taken.client_id == ref.client_id &&
              taken.generation == ref.generation &&
              taken.worker_id == ref.worker_id,
              "completion matches pre-registered identity"))
        goto fail;

    if (io_worker_pool_request_stop(pool, 1) < 0 ||
        io_worker_pool_join(pool, 3000) < 0 ||
        io_worker_pool_destroy(pool) < 0)
        goto fail;
    pool = NULL;
    if (io_worker_completion_tracker_destroy(tracker) < 0)
        goto fail;
    tracker = NULL;
    puts("PASS register-before-publish worker completion pipeline");
    return 0;

fail:
    if (pool) {
        (void)io_worker_pool_request_stop(pool, 0);
        (void)io_worker_pool_join(pool, 3000);
        (void)io_worker_pool_destroy(pool);
    }
    if (tracker)
        (void)io_worker_completion_tracker_destroy(tracker);
    return -1;
}

static int test_exact_once_and_identity(void)
{
    io_worker_completion_tracker_t *tracker =
        io_worker_completion_tracker_create(2, 4);
    if (check(tracker != NULL, "create tracker"))
        return -1;

    io_worker_task_ref_t original = make_ref(77, 9001, 3, 1);
    if (check(io_worker_completion_tracker_register(tracker, &original) == 0,
              "register accepted task"))
        goto fail;
    if (check(io_worker_completion_tracker_outstanding(tracker) == 1,
              "outstanding increments"))
        goto fail;
    errno = 0;
    if (check(io_worker_completion_tracker_destroy(tracker) < 0 && errno == EBUSY,
              "cannot destroy tracker with in-flight task"))
        goto fail;

    io_worker_completion_t completion = make_completion(original);
    io_worker_task_ref_t taken;
    io_worker_completion_t bad = completion;
    bad.worker_id = 0;
    errno = 0;
    if (check(io_worker_completion_tracker_take(tracker, &bad, &taken) < 0 &&
              errno == EPROTO &&
              io_worker_completion_tracker_outstanding(tracker) == 1,
              "wrong worker cannot consume task"))
        goto fail;

    bad = completion;
    bad.generation++;
    errno = 0;
    if (check(io_worker_completion_tracker_take(tracker, &bad, &taken) < 0 &&
              errno == EPROTO &&
              io_worker_completion_tracker_outstanding(tracker) == 1,
              "wrong generation cannot consume task"))
        goto fail;

    if (check(io_worker_completion_tracker_take(tracker, &completion, &taken) == 0 &&
              taken.task_id == original.task_id &&
              taken.client_id == original.client_id &&
              taken.generation == original.generation &&
              taken.worker_id == original.worker_id &&
              io_worker_completion_tracker_outstanding(tracker) == 0,
              "matching completion consumes exact task"))
        goto fail;

    errno = 0;
    if (check(io_worker_completion_tracker_take(tracker, &completion, &taken) < 0 &&
              errno == ENOENT &&
              io_worker_completion_tracker_outstanding(tracker) == 0,
              "duplicate completion cannot release another task"))
        goto fail;

    if (io_worker_completion_tracker_destroy(tracker) < 0) return -1;
    puts("PASS completion identity and exactly-once consumption");
    return 0;
fail:
    (void)io_worker_completion_tracker_destroy(tracker);
    return -1;
}

static int test_capacity_duplicate_and_cancel(void)
{
    io_worker_completion_tracker_t *tracker =
        io_worker_completion_tracker_create(2, 2);
    if (check(tracker != NULL, "create bounded tracker"))
        return -1;

    io_worker_task_ref_t refs[4] = {
        make_ref(1, 10, 1, 0), make_ref(2, 10, 1, 1),
        make_ref(3, 11, 4, 0), make_ref(4, 12, 7, 1)
    };
    for (size_t i = 0; i < 4; i++) {
        if (check(io_worker_completion_tracker_register(tracker, &refs[i]) == 0,
                  "fill tracker to capacity"))
            goto fail;
    }
    io_worker_task_ref_t extra = make_ref(5, 12, 7, 0);
    errno = 0;
    if (check(io_worker_completion_tracker_register(tracker, &extra) < 0 &&
              errno == EAGAIN, "tracker capacity is bounded"))
        goto fail;

    if (check(io_worker_completion_tracker_cancel(tracker, &refs[1]) == 0 &&
              io_worker_completion_tracker_outstanding(tracker) == 3,
              "failed-submit rollback removes registration"))
        goto fail;

    errno = 0;
    if (check(io_worker_completion_tracker_register(tracker, &refs[0]) < 0 &&
              errno == EEXIST, "duplicate task ID is rejected"))
        goto fail;

    errno = 0;
    if (check(io_worker_completion_tracker_cancel(tracker, &refs[1]) < 0 &&
              errno == ENOENT, "rollback cannot consume twice"))
        goto fail;

    if (check(io_worker_completion_tracker_register(tracker, &extra) == 0 &&
              io_worker_completion_tracker_outstanding(tracker) == 4,
              "tombstone slot is reusable"))
        goto fail;

    if (check(io_worker_completion_tracker_cancel(tracker, &refs[0]) == 0 &&
              io_worker_completion_tracker_cancel(tracker, &refs[2]) == 0 &&
              io_worker_completion_tracker_cancel(tracker, &refs[3]) == 0 &&
              io_worker_completion_tracker_cancel(tracker, &extra) == 0 &&
              io_worker_completion_tracker_outstanding(tracker) == 0,
              "all remaining registrations drain before destruction"))
        goto fail;

    if (io_worker_completion_tracker_destroy(tracker) < 0)
        return -1;
    puts("PASS bounded registry, rollback, and slot reuse");
    return 0;
fail:
    io_worker_completion_tracker_destroy(tracker);
    return -1;
}

int main(void)
{
    if (test_register_before_publish_pipeline() < 0)
        return 1;
    if (test_exact_once_and_identity() < 0)
        return 1;
    if (test_capacity_duplicate_and_cancel() < 0)
        return 1;
    return 0;
}
