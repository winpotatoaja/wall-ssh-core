#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int parse_microseconds(const char *text, uint64_t *value)
{
    char *end = NULL;
    unsigned long long parsed;

    if (!text || !*text || !value)
        return 0;

    errno = 0;
    parsed = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0')
        return 0;

    if (parsed > UINT64_C(60000000))
        return 0;

    *value = (uint64_t)parsed;
    return 1;
}

static int print_monotonic_milliseconds(void)
{
    struct timespec now;
    uint64_t milliseconds;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        perror("clock_gettime(CLOCK_MONOTONIC)");
        return 2;
    }

    milliseconds = (uint64_t)now.tv_sec * UINT64_C(1000) +
                   (uint64_t)now.tv_nsec / UINT64_C(1000000);
    if (printf("%" PRIu64 "\n", milliseconds) < 0 || fflush(stdout) != 0) {
        perror("write monotonic clock");
        return 2;
    }

    return 0;
}

static int sleep_microseconds(uint64_t microseconds)
{
    struct timespec remaining;

    remaining.tv_sec = (time_t)(microseconds / UINT64_C(1000000));
    remaining.tv_nsec = (long)((microseconds % UINT64_C(1000000)) *
                               UINT64_C(1000));

    while (nanosleep(&remaining, &remaining) != 0) {
        if (errno == EINTR)
            continue;

        perror("nanosleep");
        return 2;
    }

    return 0;
}

int main(int argc, char **argv)
{
    uint64_t microseconds;

    if (argc == 2 && argv[1] && strcmp(argv[1], "now-ms") == 0)
        return print_monotonic_milliseconds();

    if (argc == 3 && argv[1] && strcmp(argv[1], "sleep-us") == 0) {
        if (!parse_microseconds(argv[2], &microseconds)) {
            fprintf(stderr, "invalid microsecond duration (0..60000000)\n");
            return 2;
        }
        return sleep_microseconds(microseconds);
    }

    fprintf(stderr, "usage: %s now-ms | sleep-us MICROSECONDS\n",
            argc > 0 && argv[0] ? argv[0] : "diag-timer");
    return 2;
}
