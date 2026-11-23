#ifndef PASSWALL_LIBSSH2_DIAG_H
#define PASSWALL_LIBSSH2_DIAG_H

#include <libssh2.h>

typedef struct {
    unsigned long long decrypt_path_ns;
    unsigned long long decrypt_path_calls;
    unsigned long long decrypt_path_bytes;
    unsigned long long transport_read_ns;
    unsigned long long transport_read_calls;
    unsigned long long packet_drain_ns;
    unsigned long long packet_drain_calls;
    unsigned long long packet_drain_bytes;
    unsigned long long packet_drain_removed;
    unsigned long long packet_queue_packets_current;
    unsigned long long packet_queue_bytes_current;
    unsigned long long packet_queue_packets_peak;
    unsigned long long packet_queue_bytes_peak;
    unsigned long long packet_queue_enqueued_packets;
    unsigned long long packet_queue_enqueued_bytes;
} LIBSSH2_DIAG_TIMING;

LIBSSH2_API void
libssh2_session_diag_timing_enable(LIBSSH2_SESSION *session, int enabled);

LIBSSH2_API int
libssh2_session_diag_timing_snapshot(LIBSSH2_SESSION *session,
                                     LIBSSH2_DIAG_TIMING *timing,
                                     int reset);

#endif
