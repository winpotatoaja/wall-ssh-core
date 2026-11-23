#!/usr/bin/env python3
"""Apply Passwall r43 timing probes to the pinned OpenWrt libssh2 1.11.1 source."""
from pathlib import Path
import sys

def replace_once(path: Path, old: str, new: str, label: str) -> None:
    text = path.read_text()
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{path.name}: {label}: expected one exact source anchor, found {count}")
    path.write_text(text.replace(old, new, 1))

def patch(root: Path) -> None:
    version = (root / "include/libssh2.h").read_text()
    if '#define LIBSSH2_VERSION "1.11.1"' not in version:
        raise RuntimeError("The r43 diagnostic patch is pinned to libssh2 1.11.1")

    priv = root / "src/libssh2_priv.h"
    replace_once(priv,
"""    /* Configurable timeout for packets. Replaces LIBSSH2_READ_TIMEOUT */
    long packet_read_timeout;
};""",
"""    /* Configurable timeout for packets. Replaces LIBSSH2_READ_TIMEOUT */
    long packet_read_timeout;

    /* Passwall r43 diagnostics. These counters are owner-thread only. */
    struct {
        int enabled;
        unsigned int transport_depth;
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
    } passwall_diag;
};""", "session diagnostic fields")

    replace_once(priv,
"""};

/* session.state bits */""",
"""};

/* Public snapshot layout shared with the app's libssh2_diag.h. */
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

/* High-resolution monotonic clock; called only while r43 diagnostics are enabled. */
static inline unsigned long long
_libssh2_diag_now_ns(void)
{
    struct timespec ts;
    if(clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return ((unsigned long long)ts.tv_sec * 1000000000ULL) +
           (unsigned long long)ts.tv_nsec;
}

static inline void
_libssh2_diag_packet_enqueued(LIBSSH2_SESSION *session, size_t data_len)
{
    if(!session->passwall_diag.enabled)
        return;
    session->passwall_diag.packet_queue_packets_current++;
    session->passwall_diag.packet_queue_bytes_current +=
        (unsigned long long)data_len;
    session->passwall_diag.packet_queue_enqueued_packets++;
    session->passwall_diag.packet_queue_enqueued_bytes +=
        (unsigned long long)data_len;
    if(session->passwall_diag.packet_queue_packets_current >
       session->passwall_diag.packet_queue_packets_peak)
        session->passwall_diag.packet_queue_packets_peak =
            session->passwall_diag.packet_queue_packets_current;
    if(session->passwall_diag.packet_queue_bytes_current >
       session->passwall_diag.packet_queue_bytes_peak)
        session->passwall_diag.packet_queue_bytes_peak =
            session->passwall_diag.packet_queue_bytes_current;
}

static inline void
_libssh2_diag_packet_bytes_consumed(LIBSSH2_SESSION *session, size_t bytes)
{
    if(!session->passwall_diag.enabled)
        return;
    if(session->passwall_diag.packet_queue_bytes_current >=
       (unsigned long long)bytes)
        session->passwall_diag.packet_queue_bytes_current -=
            (unsigned long long)bytes;
    else
        session->passwall_diag.packet_queue_bytes_current = 0;
}

static inline void
_libssh2_diag_packet_dequeued(LIBSSH2_SESSION *session, size_t remaining_bytes)
{
    if(!session->passwall_diag.enabled)
        return;
    if(session->passwall_diag.packet_queue_packets_current)
        session->passwall_diag.packet_queue_packets_current--;
    _libssh2_diag_packet_bytes_consumed(session, remaining_bytes);
}

/* session.state bits */""", "diagnostic timing and packet queue helpers")

    packet = root / "src/packet.c"
    replace_once(packet,
"""        _libssh2_list_add(&session->packets, &packetp->node);

        session->packAdd_state = libssh2_NB_state_sent1;""",
"""        _libssh2_list_add(&session->packets, &packetp->node);
        _libssh2_diag_packet_enqueued(session, datalen);

        session->packAdd_state = libssh2_NB_state_sent1;""", "packet enqueue accounting")
    replace_once(packet,
"""            /* unlink struct from session->packets */
            _libssh2_list_remove(&packet->node);

            LIBSSH2_FREE(session, packet);""",
"""            /* unlink struct from session->packets */
            _libssh2_diag_packet_dequeued(
                session, packet->data_len - packet->data_head);
            _libssh2_list_remove(&packet->node);

            LIBSSH2_FREE(session, packet);""", "packet ask dequeue accounting")

    channel = root / "src/channel.c"
    replace_once(channel,
"""                    LIBSSH2_FREE(channel->session, packet->data);

                    /* remove this packet from the parent's list */
                    _libssh2_list_remove(&packet->node);""",
"""                    LIBSSH2_FREE(channel->session, packet->data);

                    /* remove this packet from the parent's list */
                    _libssh2_diag_packet_dequeued(channel->session,
                                                  packet->data_len - packet->data_head);
                    _libssh2_list_remove(&packet->node);""",
                 "channel flush dequeue accounting")
    replace_once(channel,
"""    LIBSSH2_PACKET *read_packet;
    LIBSSH2_PACKET *read_next;

    _libssh2_debug((session, LIBSSH2_TRACE_CONN,""",
"""    LIBSSH2_PACKET *read_packet;
    LIBSSH2_PACKET *read_next;
    unsigned long long diag_packet_drain_start = 0;
    unsigned long long diag_packet_drain_removed = 0;

    _libssh2_debug((session, LIBSSH2_TRACE_CONN,""",
                 "channel read diagnostic locals")
    replace_once(channel,
"""    read_packet = _libssh2_list_first(&session->packets);
    while(read_packet && (bytes_read < buflen)) {""",
"""    if(session->passwall_diag.enabled)
        diag_packet_drain_start = _libssh2_diag_now_ns();
    read_packet = _libssh2_list_first(&session->packets);
    while(read_packet && (bytes_read < buflen)) {""",
                 "channel queue drain timer start")
    replace_once(channel,
"""            readpkt->data_head += bytes_want;
            bytes_read += bytes_want;""",
"""            readpkt->data_head += bytes_want;
            bytes_read += bytes_want;
            _libssh2_diag_packet_bytes_consumed(session, bytes_want);""",
                 "account partially consumed packet bytes")
    replace_once(channel,
"""            if(unlink_packet) {
                /* detach readpkt from session->packets list */
                _libssh2_list_remove(&readpkt->node);

                LIBSSH2_FREE(session, readpkt->data);""",
"""            if(unlink_packet) {
                /* detach readpkt from session->packets list */
                _libssh2_diag_packet_dequeued(session, 0);
                diag_packet_drain_removed++;
                _libssh2_list_remove(&readpkt->node);

                LIBSSH2_FREE(session, readpkt->data);""",
                 "channel read queue dequeue accounting")
    replace_once(channel,
"""        read_packet = read_next;
    }

    if(!bytes_read) {""",
"""        read_packet = read_next;
    }

    if(diag_packet_drain_start) {
        unsigned long long diag_packet_drain_end = _libssh2_diag_now_ns();
        if(diag_packet_drain_end >= diag_packet_drain_start) {
            session->passwall_diag.packet_drain_ns +=
                diag_packet_drain_end - diag_packet_drain_start;
            session->passwall_diag.packet_drain_calls++;
            session->passwall_diag.packet_drain_bytes +=
                (unsigned long long)bytes_read;
            session->passwall_diag.packet_drain_removed +=
                diag_packet_drain_removed;
        }
    }

    if(!bytes_read) {""",
                 "channel queue drain timer stop")

    transport = root / "src/transport.c"
    replace_once(transport,
"""static int
decrypt(LIBSSH2_SESSION * session, unsigned char *source,
        unsigned char *dest, ssize_t len, int firstlast)""",
"""static int
decrypt_impl(LIBSSH2_SESSION * session, unsigned char *source,
             unsigned char *dest, ssize_t len, int firstlast)""",
                 "rename decrypt implementation")
    replace_once(transport,
"""    return LIBSSH2_ERROR_NONE;         /* all is fine */
}

/*
 * fullpacket()""",
"""    return LIBSSH2_ERROR_NONE;         /* all is fine */
}

static int
decrypt(LIBSSH2_SESSION *session, unsigned char *source,
        unsigned char *dest, ssize_t len, int firstlast)
{
    unsigned long long started = session->passwall_diag.enabled
        ? _libssh2_diag_now_ns() : 0;
    int rc = decrypt_impl(session, source, dest, len, firstlast);

    if(session->passwall_diag.enabled) {
        unsigned long long ended = _libssh2_diag_now_ns();
        session->passwall_diag.decrypt_path_calls++;
        if(len > 0)
            session->passwall_diag.decrypt_path_bytes += (unsigned long long)len;
        if(started && ended >= started)
            session->passwall_diag.decrypt_path_ns += ended - started;
    }
    return rc;
}

/*
 * fullpacket()""",
                 "time packet decrypt helper path")
    replace_once(transport,
"""int _libssh2_transport_read(LIBSSH2_SESSION * session)
{""",
"""static int _libssh2_transport_read_impl(LIBSSH2_SESSION * session)
{""", "rename transport read implementation")
    replace_once(transport,
"""    return LIBSSH2_ERROR_SOCKET_RECV; /* we never reach this point */
}

static int
send_existing""",
"""    return LIBSSH2_ERROR_SOCKET_RECV; /* we never reach this point */
}

int _libssh2_transport_read(LIBSSH2_SESSION *session)
{
    unsigned long long started = 0;
    int outermost = 0;
    int rc;

    if(session->passwall_diag.enabled) {
        outermost = session->passwall_diag.transport_depth == 0;
        session->passwall_diag.transport_depth++;
        if(outermost)
            started = _libssh2_diag_now_ns();
    }

    rc = _libssh2_transport_read_impl(session);

    if(session->passwall_diag.enabled) {
        if(session->passwall_diag.transport_depth)
            session->passwall_diag.transport_depth--;
        if(outermost && started) {
            unsigned long long ended = _libssh2_diag_now_ns();
            if(ended >= started) {
                session->passwall_diag.transport_read_ns += ended - started;
                session->passwall_diag.transport_read_calls++;
            }
        }
    }
    return rc;
}

static int
send_existing""", "timed transport read wrapper")

    session = root / "src/session.c"
    with session.open("a") as f:
        f.write("""
/* Passwall r43 diagnostic API. It is enabled only for the SSH Owner perf log. */
LIBSSH2_API void
libssh2_session_diag_timing_enable(LIBSSH2_SESSION *session, int enabled)
{
    LIBSSH2_PACKET *packet;
    if(!session)
        return;

    memset(&session->passwall_diag, 0, sizeof(session->passwall_diag));
    if(!enabled)
        return;

    packet = _libssh2_list_first(&session->packets);
    while(packet) {
        session->passwall_diag.packet_queue_packets_current++;
        session->passwall_diag.packet_queue_bytes_current +=
            (unsigned long long)(packet->data_len - packet->data_head);
        packet = _libssh2_list_next(&packet->node);
    }
    session->passwall_diag.packet_queue_packets_peak =
        session->passwall_diag.packet_queue_packets_current;
    session->passwall_diag.packet_queue_bytes_peak =
        session->passwall_diag.packet_queue_bytes_current;
    session->passwall_diag.enabled = 1;
}

LIBSSH2_API int
libssh2_session_diag_timing_snapshot(LIBSSH2_SESSION *session,
                                     LIBSSH2_DIAG_TIMING *timing,
                                     int reset)
{
    if(!session || !timing)
        return -1;

    timing->decrypt_path_ns =
        session->passwall_diag.decrypt_path_ns;
    timing->decrypt_path_calls =
        session->passwall_diag.decrypt_path_calls;
    timing->decrypt_path_bytes =
        session->passwall_diag.decrypt_path_bytes;
    timing->transport_read_ns =
        session->passwall_diag.transport_read_ns;
    timing->transport_read_calls =
        session->passwall_diag.transport_read_calls;
    timing->packet_drain_ns =
        session->passwall_diag.packet_drain_ns;
    timing->packet_drain_calls =
        session->passwall_diag.packet_drain_calls;
    timing->packet_drain_bytes =
        session->passwall_diag.packet_drain_bytes;
    timing->packet_drain_removed =
        session->passwall_diag.packet_drain_removed;
    timing->packet_queue_packets_current =
        session->passwall_diag.packet_queue_packets_current;
    timing->packet_queue_bytes_current =
        session->passwall_diag.packet_queue_bytes_current;
    timing->packet_queue_packets_peak =
        session->passwall_diag.packet_queue_packets_peak;
    timing->packet_queue_bytes_peak =
        session->passwall_diag.packet_queue_bytes_peak;
    timing->packet_queue_enqueued_packets =
        session->passwall_diag.packet_queue_enqueued_packets;
    timing->packet_queue_enqueued_bytes =
        session->passwall_diag.packet_queue_enqueued_bytes;

    if(reset) {
        session->passwall_diag.decrypt_path_ns = 0;
        session->passwall_diag.decrypt_path_calls = 0;
        session->passwall_diag.decrypt_path_bytes = 0;
        session->passwall_diag.transport_read_ns = 0;
        session->passwall_diag.transport_read_calls = 0;
        session->passwall_diag.packet_drain_ns = 0;
        session->passwall_diag.packet_drain_calls = 0;
        session->passwall_diag.packet_drain_bytes = 0;
        session->passwall_diag.packet_drain_removed = 0;
        session->passwall_diag.packet_queue_enqueued_packets = 0;
        session->passwall_diag.packet_queue_enqueued_bytes = 0;
        session->passwall_diag.packet_queue_packets_peak =
            session->passwall_diag.packet_queue_packets_current;
        session->passwall_diag.packet_queue_bytes_peak =
            session->passwall_diag.packet_queue_bytes_current;
    }
    return 0;
}
""")

    marker = root / ".passwall-r43-diag-patched"
    marker.write_text("libssh2 1.11.1 Passwall r43 timing probes\n")
    print("PASS: patched libssh2 1.11.1 crypto, transport, packet queue, and channel drain timing")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise RuntimeError("usage: apply_libssh2_r43_diag.py <libssh2-1.11.0-source-dir>")
    patch(Path(sys.argv[1]).resolve())
