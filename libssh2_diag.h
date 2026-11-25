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
    unsigned int chacha_workers_requested;
    unsigned int chacha_workers_active;
    unsigned int chacha_threshold_bytes;
    unsigned long long chacha_poly1305_ns;
    unsigned long long chacha_poly1305_offloaded_packets;
    unsigned long long chacha20_key_ns;
    unsigned long long chacha20_header_ns;
    unsigned long long chacha20_payload_ns;
    unsigned long long chacha20_serial_ns;
    unsigned long long chacha20_serial_bytes;
    unsigned long long chacha20_serial_packets;
    unsigned long long chacha20_parallel_ns;
    unsigned long long chacha20_parallel_bytes;
    unsigned long long chacha20_parallel_packets;
    unsigned long long chacha_poly1305_wall_ns;
    unsigned long long chacha20_decrypt_wall_ns;
    unsigned long long chacha20_worker_cpu_ns;
    unsigned long long chacha20_worker_critical_ns;
    unsigned long long chacha20_parallel_other_ns;
    unsigned long long chacha20_profile_packets;
} LIBSSH2_DIAG_TIMING;

LIBSSH2_API void
libssh2_session_set_chacha_workers(LIBSSH2_SESSION *session,
                                   unsigned int workers);

LIBSSH2_API int
libssh2_session_set_chacha_threshold(LIBSSH2_SESSION *session,
                                     unsigned int threshold_bytes);

LIBSSH2_API void
libssh2_session_diag_timing_enable(LIBSSH2_SESSION *session, int enabled);

LIBSSH2_API int
libssh2_session_diag_timing_snapshot(LIBSSH2_SESSION *session,
                                     LIBSSH2_DIAG_TIMING *timing,
                                     int reset);

#endif
