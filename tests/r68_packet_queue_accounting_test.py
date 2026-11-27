#!/usr/bin/env python3
"""Verify R68 libssh2 packet-queue lifecycle, snapshots, and accounting invariants."""
import ast
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def check(ok, label):
    print(("PASS: " if ok else "FAIL: ") + label)
    return bool(ok)


def replacement(tree, label):
    for n in ast.walk(tree):
        if (isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                and n.func.id == "replace_once" and len(n.args) >= 4):
            try:
                if ast.literal_eval(n.args[3]) == label:
                    return ast.literal_eval(n.args[2])
            except Exception:
                pass
    raise RuntimeError("missing patch template: " + label)


def api_template(tree):
    for n in ast.walk(tree):
        if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and n.func.attr == "write" and n.args):
            try:
                value = ast.literal_eval(n.args[0])
            except Exception:
                continue
            if isinstance(value, str) and "Passwall r43 diagnostic API" in value:
                return value
    raise RuntimeError("missing appended diagnostic enable/snapshot API template")


def c_function(source, name):
    m = re.search(r"static\s+inline\s+void\s+" + re.escape(name) + r"\s*\(", source)
    if not m:
        raise RuntimeError("missing C helper: " + name)
    start = source.find("{", m.end())
    depth = 0
    for i in range(start, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[m.start():i + 1]
    raise RuntimeError("unterminated C helper: " + name)


def compile_and_run(helpers):
    source = r'''#include <stddef.h>
#include <stdio.h>
#include <string.h>
typedef struct {
    struct {
        int enabled;
        unsigned long long packet_queue_packets_current;
        unsigned long long packet_queue_bytes_current;
        unsigned long long packet_queue_packets_peak;
        unsigned long long packet_queue_bytes_peak;
        unsigned long long packet_queue_enqueued_packets;
        unsigned long long packet_queue_enqueued_bytes;
    } passwall_diag;
} LIBSSH2_SESSION;
''' + helpers + r'''
#define EXPECT(c, s) do { if(!(c)) { fprintf(stderr, "FAIL: %s\n", s); return 1; } puts("PASS: " s); } while(0)
int main(void) {
    LIBSSH2_SESSION s;
    memset(&s, 0, sizeof(s));
    s.passwall_diag.enabled = 1;

    /* CHANNEL_DATA: 9-byte header, partial read, then final dequeue. */
    _libssh2_diag_packet_enqueued(&s, 1000 - 9);
    EXPECT(s.passwall_diag.packet_queue_bytes_current == 991, "CHANNEL_DATA excludes 9-byte header");
    _libssh2_diag_packet_bytes_consumed(&s, 123);
    EXPECT(s.passwall_diag.packet_queue_bytes_current == 868, "partial read subtracts consumed payload");
    _libssh2_diag_packet_dequeued(&s, 1000 - 9 - 123);
    EXPECT(s.passwall_diag.packet_queue_packets_current == 0 && s.passwall_diag.packet_queue_bytes_current == 0,
           "CHANNEL_DATA dequeue reaches zero");

    /* EXTENDED_DATA: 13-byte header. */
    _libssh2_diag_packet_enqueued(&s, 700 - 13);
    EXPECT(s.passwall_diag.packet_queue_bytes_current == 687, "EXTENDED_DATA excludes 13-byte header");
    _libssh2_diag_packet_bytes_consumed(&s, 87);
    _libssh2_diag_packet_dequeued(&s, 700 - 13 - 87);
    EXPECT(s.passwall_diag.packet_queue_packets_current == 0 && s.passwall_diag.packet_queue_bytes_current == 0,
           "EXTENDED_DATA partial read and dequeue reach zero");

    /* packet_ask removes an unread channel payload. */
    _libssh2_diag_packet_enqueued(&s, 100 - 9);
    _libssh2_diag_packet_dequeued(&s, 100 - 9);
    EXPECT(s.passwall_diag.packet_queue_packets_current == 0 && s.passwall_diag.packet_queue_bytes_current == 0,
           "packet_ask removes unread payload exactly once");

    /* channel_flush removes only the payload remaining after a partial read. */
    _libssh2_diag_packet_enqueued(&s, 200 - 13);
    _libssh2_diag_packet_bytes_consumed(&s, 17);
    _libssh2_diag_packet_dequeued(&s, 200 - 13 - 17);
    EXPECT(s.passwall_diag.packet_queue_packets_current == 0 && s.passwall_diag.packet_queue_bytes_current == 0,
           "flush removes only remaining payload");

    /* Control packets have data_head == 0. */
    _libssh2_diag_packet_enqueued(&s, 64);
    _libssh2_diag_packet_dequeued(&s, 64);
    EXPECT(s.passwall_diag.packet_queue_packets_current == 0 && s.passwall_diag.packet_queue_bytes_current == 0,
           "control packet retains full length");
    EXPECT(s.passwall_diag.packet_queue_enqueued_packets == 5 &&
           s.passwall_diag.packet_queue_enqueued_bytes == 2020,
           "cumulative enqueue bytes use payload units");
    EXPECT(s.passwall_diag.packet_queue_bytes_peak >= 991, "peak tracks payload occupancy");
    return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix="r68-queue-") as td:
        cfile, exe = Path(td) / "test.c", Path(td) / "test"
        cfile.write_text(source)
        build = subprocess.run(
            ["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", str(cfile), "-o", str(exe)],
            capture_output=True, text=True
        )
        if build.returncode:
            sys.stderr.write(build.stdout + build.stderr)
            return False
        run = subprocess.run([str(exe)], capture_output=True, text=True)
        sys.stdout.write(run.stdout)
        if run.returncode:
            sys.stderr.write(run.stderr)
            return False
    return True


def compile_and_run_lifecycle(helpers, api):
    """Compile the real helper and session API templates against a tiny list/session model."""
    preamble = r'''#include <stddef.h>
#include <stdio.h>
#include <string.h>

typedef struct _LIBSSH2_PACKET LIBSSH2_PACKET;
typedef struct {
    LIBSSH2_PACKET *next;
} LIBSSH2_LIST_NODE;

struct _LIBSSH2_PACKET {
    LIBSSH2_LIST_NODE node;
    size_t data_len;
    size_t data_head;
};

typedef struct {
    LIBSSH2_PACKET *first;
} LIBSSH2_LIST;

typedef struct {
    LIBSSH2_LIST packets;
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
} LIBSSH2_SESSION;

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

static LIBSSH2_PACKET *_libssh2_list_first(LIBSSH2_LIST *list)
{
    return list->first;
}

static LIBSSH2_PACKET *_libssh2_list_next(LIBSSH2_LIST_NODE *node)
{
    return node->next;
}

#define LIBSSH2_API
'''
    test = r'''
#define EXPECT(c, s) do { \
    if(!(c)) { fprintf(stderr, "FAIL: %s\n", s); return 1; } \
    puts("PASS: " s); \
} while(0)

int main(void)
{
    LIBSSH2_SESSION s;
    LIBSSH2_DIAG_TIMING snap;
    LIBSSH2_PACKET data, extended, control;

    memset(&s, 0, sizeof(s));
    memset(&snap, 0, sizeof(snap));

    EXPECT(libssh2_session_diag_timing_snapshot(NULL, &snap, 0) == -1,
           "snapshot rejects a NULL session");
    EXPECT(libssh2_session_diag_timing_snapshot(&s, NULL, 0) == -1,
           "snapshot rejects a NULL output structure");
    libssh2_session_diag_timing_enable(NULL, 1);
    EXPECT(1, "enable safely ignores a NULL session");

    /* Existing queued packets at enable time: DATA 991, EXTENDED_DATA 687, control 64. */
    memset(&data, 0, sizeof(data));
    memset(&extended, 0, sizeof(extended));
    memset(&control, 0, sizeof(control));
    data.data_len = 1000; data.data_head = 9; data.node.next = &extended;
    extended.data_len = 700; extended.data_head = 13; extended.node.next = &control;
    control.data_len = 64; control.data_head = 0; control.node.next = NULL;
    s.packets.first = &data;

    /* Disabled enable clears every diagnostic counter and does not start tracking. */
    s.passwall_diag.enabled = 1;
    s.passwall_diag.packet_queue_packets_current = 77;
    s.passwall_diag.packet_queue_bytes_current = 777;
    s.passwall_diag.decrypt_path_calls = 9;
    libssh2_session_diag_timing_enable(&s, 0);
    EXPECT(s.passwall_diag.enabled == 0 &&
           s.passwall_diag.packet_queue_packets_current == 0 &&
           s.passwall_diag.packet_queue_bytes_current == 0 &&
           s.passwall_diag.packet_queue_packets_peak == 0 &&
           s.passwall_diag.packet_queue_bytes_peak == 0 &&
           s.passwall_diag.packet_queue_enqueued_packets == 0 &&
           s.passwall_diag.packet_queue_enqueued_bytes == 0 &&
           s.passwall_diag.decrypt_path_calls == 0,
           "enable(0) clears diagnostics and leaves tracking disabled");

    /* Enable must discard stale counters and reconstruct current/peak from the live list. */
    s.passwall_diag.packet_queue_packets_current = 88;
    s.passwall_diag.packet_queue_bytes_current = 888;
    s.passwall_diag.packet_queue_enqueued_bytes = 999;
    s.passwall_diag.transport_depth = 4;
    libssh2_session_diag_timing_enable(&s, 1);
    EXPECT(s.passwall_diag.enabled == 1, "enable(1) enables diagnostics after baseline");
    EXPECT(s.passwall_diag.packet_queue_packets_current == 3 &&
           s.passwall_diag.packet_queue_bytes_current == 1742,
           "enable baseline counts all queued unread payload, excluding DATA headers");
    EXPECT(s.passwall_diag.packet_queue_packets_peak == 3 &&
           s.passwall_diag.packet_queue_bytes_peak == 1742,
           "enable baseline initializes packet and byte peaks to current");
    EXPECT(s.passwall_diag.packet_queue_enqueued_packets == 0 &&
           s.passwall_diag.packet_queue_enqueued_bytes == 0 &&
           s.passwall_diag.transport_depth == 0 &&
           s.passwall_diag.decrypt_path_calls == 0,
           "enable(1) clears stale interval counters and transport nesting");

    /* Snapshot without reset copies values but must not mutate the live counters. */
    memset(&snap, 0xA5, sizeof(snap));
    EXPECT(libssh2_session_diag_timing_snapshot(&s, &snap, 0) == 0,
           "snapshot without reset succeeds");
    EXPECT(snap.packet_queue_packets_current == 3 &&
           snap.packet_queue_bytes_current == 1742 &&
           snap.packet_queue_packets_peak == 3 &&
           snap.packet_queue_bytes_peak == 1742 &&
           snap.packet_queue_enqueued_packets == 0 &&
           snap.packet_queue_enqueued_bytes == 0,
           "first snapshot reports enable baseline and zero interval enqueue totals");
    EXPECT(s.passwall_diag.packet_queue_packets_current == 3 &&
           s.passwall_diag.packet_queue_bytes_current == 1742 &&
           s.passwall_diag.packet_queue_packets_peak == 3 &&
           s.passwall_diag.packet_queue_bytes_peak == 1742,
           "snapshot(reset=0) preserves current and peak in the session");

    /* New packet: enqueue -> partial channel read -> final unlink with zero extra bytes. */
    _libssh2_diag_packet_enqueued(&s, 200);
    EXPECT(s.passwall_diag.packet_queue_packets_current == 4 &&
           s.passwall_diag.packet_queue_bytes_current == 1942 &&
           s.passwall_diag.packet_queue_enqueued_packets == 1 &&
           s.passwall_diag.packet_queue_enqueued_bytes == 200 &&
           s.passwall_diag.packet_queue_packets_peak == 4 &&
           s.passwall_diag.packet_queue_bytes_peak == 1942,
           "enqueue increases current, cumulative totals, and peaks");
    _libssh2_diag_packet_bytes_consumed(&s, 50);
    EXPECT(s.passwall_diag.packet_queue_packets_current == 4 &&
           s.passwall_diag.packet_queue_bytes_current == 1892,
           "partial read decreases unread payload but retains packet count");
    _libssh2_diag_packet_dequeued(&s, 150);
    EXPECT(s.passwall_diag.packet_queue_packets_current == 3 &&
           s.passwall_diag.packet_queue_bytes_current == 1742,
           "final packet unlink removes only its remaining payload");

    /* packet_ask removes a full unread DATA packet from the baseline. */
    _libssh2_diag_packet_dequeued(&s, 991);
    EXPECT(s.passwall_diag.packet_queue_packets_current == 2 &&
           s.passwall_diag.packet_queue_bytes_current == 751,
           "packet_ask removes one packet and its remaining payload");

    /* channel_read consumes part of EXTENDED_DATA; channel_flush removes its tail. */
    _libssh2_diag_packet_bytes_consumed(&s, 200);
    EXPECT(s.passwall_diag.packet_queue_packets_current == 2 &&
           s.passwall_diag.packet_queue_bytes_current == 551,
           "extended-data partial read changes bytes without changing packet count");
    _libssh2_diag_packet_dequeued(&s, 487);
    EXPECT(s.passwall_diag.packet_queue_packets_current == 1 &&
           s.passwall_diag.packet_queue_bytes_current == 64,
           "channel flush subtracts only extended-data payload still unread");

    /* The control packet has data_head == 0, so its full data_len is counted. */
    _libssh2_diag_packet_dequeued(&s, 64);
    EXPECT(s.passwall_diag.packet_queue_packets_current == 0 &&
           s.passwall_diag.packet_queue_bytes_current == 0,
           "control packet dequeue returns current queue to zero");

    EXPECT(libssh2_session_diag_timing_snapshot(&s, &snap, 0) == 0 &&
           snap.packet_queue_packets_current == 0 &&
           snap.packet_queue_bytes_current == 0 &&
           snap.packet_queue_packets_peak == 4 &&
           snap.packet_queue_bytes_peak == 1942 &&
           snap.packet_queue_enqueued_packets == 1 &&
           snap.packet_queue_enqueued_bytes == 200,
           "non-reset snapshot reports zero current and exact interval peak/enqueue totals");
    EXPECT(s.passwall_diag.packet_queue_packets_peak == 4 &&
           s.passwall_diag.packet_queue_bytes_peak == 1942 &&
           s.passwall_diag.packet_queue_enqueued_bytes == 200,
           "repeated snapshot without reset is non-destructive");

    /* reset=1 returns the old interval, then clears interval totals and resets peaks to current. */
    EXPECT(libssh2_session_diag_timing_snapshot(&s, &snap, 1) == 0 &&
           snap.packet_queue_packets_current == 0 &&
           snap.packet_queue_bytes_current == 0 &&
           snap.packet_queue_packets_peak == 4 &&
           snap.packet_queue_bytes_peak == 1942 &&
           snap.packet_queue_enqueued_packets == 1 &&
           snap.packet_queue_enqueued_bytes == 200,
           "snapshot(reset=1) returns the complete interval before clearing it");
    EXPECT(s.passwall_diag.packet_queue_packets_current == 0 &&
           s.passwall_diag.packet_queue_bytes_current == 0 &&
           s.passwall_diag.packet_queue_packets_peak == 0 &&
           s.passwall_diag.packet_queue_bytes_peak == 0 &&
           s.passwall_diag.packet_queue_enqueued_packets == 0 &&
           s.passwall_diag.packet_queue_enqueued_bytes == 0 &&
           s.passwall_diag.enabled == 1,
           "reset clears cumulative totals, resets empty peaks, and keeps diagnostics enabled");

    /* A non-empty reset must set the new peak to current, not zero or the old high-water mark. */
    _libssh2_diag_packet_enqueued(&s, 80);
    _libssh2_diag_packet_enqueued(&s, 20);
    _libssh2_diag_packet_enqueued(&s, 200);
    EXPECT(s.passwall_diag.packet_queue_packets_current == 3 &&
           s.passwall_diag.packet_queue_bytes_current == 300 &&
           s.passwall_diag.packet_queue_packets_peak == 3 &&
           s.passwall_diag.packet_queue_bytes_peak == 300,
           "second interval builds a new current and high-water mark");
    _libssh2_diag_packet_bytes_consumed(&s, 150);
    EXPECT(s.passwall_diag.packet_queue_packets_current == 3 &&
           s.passwall_diag.packet_queue_bytes_current == 150 &&
           s.passwall_diag.packet_queue_bytes_peak == 300,
           "consumption lowers current while preserving the interval high-water mark");
    EXPECT(libssh2_session_diag_timing_snapshot(&s, &snap, 1) == 0 &&
           snap.packet_queue_packets_current == 3 &&
           snap.packet_queue_bytes_current == 150 &&
           snap.packet_queue_packets_peak == 3 &&
           snap.packet_queue_bytes_peak == 300 &&
           snap.packet_queue_enqueued_packets == 3 &&
           snap.packet_queue_enqueued_bytes == 300,
           "non-empty reset snapshot captures current, peak, and enqueue totals");
    EXPECT(s.passwall_diag.packet_queue_packets_current == 3 &&
           s.passwall_diag.packet_queue_bytes_current == 150 &&
           s.passwall_diag.packet_queue_packets_peak == 3 &&
           s.passwall_diag.packet_queue_bytes_peak == 150 &&
           s.passwall_diag.packet_queue_enqueued_packets == 0 &&
           s.passwall_diag.packet_queue_enqueued_bytes == 0,
           "non-empty reset preserves current and rebases peaks to current");

    EXPECT(libssh2_session_diag_timing_snapshot(&s, &snap, 0) == 0 &&
           snap.packet_queue_packets_current == 3 &&
           snap.packet_queue_bytes_current == 150 &&
           snap.packet_queue_packets_peak == 3 &&
           snap.packet_queue_bytes_peak == 150 &&
           snap.packet_queue_enqueued_packets == 0 &&
           snap.packet_queue_enqueued_bytes == 0,
           "post-reset snapshot starts with rebased peaks and zero cumulative totals");

    /* Drain the three packets after reset; peak remains the new interval's rebased high-water mark. */
    _libssh2_diag_packet_dequeued(&s, 50);
    _libssh2_diag_packet_dequeued(&s, 80);
    _libssh2_diag_packet_dequeued(&s, 20);
    EXPECT(s.passwall_diag.packet_queue_packets_current == 0 &&
           s.passwall_diag.packet_queue_bytes_current == 0 &&
           s.passwall_diag.packet_queue_packets_peak == 3 &&
           s.passwall_diag.packet_queue_bytes_peak == 150,
           "post-reset packet drain reaches zero without rewriting the rebased peak");

    /* Defensive underflow/duplicate removal must saturate, never wrap unsigned counters. */
    _libssh2_diag_packet_bytes_consumed(&s, (size_t)-1);
    _libssh2_diag_packet_dequeued(&s, 9);
    EXPECT(s.passwall_diag.packet_queue_packets_current == 0 &&
           s.passwall_diag.packet_queue_bytes_current == 0,
           "over-consume and duplicate dequeue saturate at zero without underflow");

    /* Re-enabling resets the interval and reconstructs the still-live packet-list baseline. */
    libssh2_session_diag_timing_enable(&s, 1);
    EXPECT(s.passwall_diag.packet_queue_packets_current == 3 &&
           s.passwall_diag.packet_queue_bytes_current == 1742 &&
           s.passwall_diag.packet_queue_packets_peak == 3 &&
           s.passwall_diag.packet_queue_bytes_peak == 1742 &&
           s.passwall_diag.packet_queue_enqueued_packets == 0 &&
           s.passwall_diag.packet_queue_enqueued_bytes == 0,
           "re-enable rebuilds current/peak from the live list and clears interval totals");

    libssh2_session_diag_timing_enable(&s, 0);
    EXPECT(s.passwall_diag.enabled == 0 &&
           s.passwall_diag.packet_queue_packets_current == 0 &&
           s.passwall_diag.packet_queue_bytes_current == 0 &&
           s.passwall_diag.packet_queue_packets_peak == 0 &&
           s.passwall_diag.packet_queue_bytes_peak == 0 &&
           s.passwall_diag.packet_queue_enqueued_packets == 0 &&
           s.passwall_diag.packet_queue_enqueued_bytes == 0,
           "final disable clears current, peaks, and cumulative counters");
    return 0;
}
'''
    source = preamble + helpers + "\n\n" + api + "\n\n" + test
    with tempfile.TemporaryDirectory(prefix="r68-snapshot-") as td:
        cfile, exe = Path(td) / "snapshot_test.c", Path(td) / "snapshot_test"
        cfile.write_text(source)
        build = subprocess.run(
            ["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", str(cfile), "-o", str(exe)],
            capture_output=True, text=True
        )
        if build.returncode:
            sys.stderr.write(build.stdout + build.stderr)
            return False
        run = subprocess.run([str(exe)], capture_output=True, text=True)
        sys.stdout.write(run.stdout)
        if run.returncode:
            sys.stderr.write(run.stderr)
            return False
    return True


def main():
    if len(sys.argv) not in (2, 3):
        print("usage: r68_packet_queue_accounting_test.py PATCH_SCRIPT [PATCHED_LIBSSH2_SOURCE_DIR]", file=sys.stderr)
        return 2
    patch_path = Path(sys.argv[1])
    patch = patch_path.read_text()
    tree = ast.parse(patch)
    enqueue = replacement(tree, "packet enqueue accounting")
    ask = replacement(tree, "packet ask dequeue accounting")
    flush = replacement(tree, "channel flush dequeue accounting")
    consume = replacement(tree, "account partially consumed packet bytes")
    read_unlink = replacement(tree, "channel read queue dequeue accounting")
    helpers_template = replacement(tree, "diagnostic timing and packet queue helpers")
    api = api_template(tree)

    checks = [
        check(re.search(r"_libssh2_diag_packet_enqueued\s*\(\s*session\s*,\s*packetp->data_len\s*-\s*packetp->data_head\s*\)", enqueue) is not None,
              "enqueue counts data_len - data_head payload"),
        check("_libssh2_diag_packet_dequeued" in ask and "packet->data_len - packet->data_head" in ask,
              "packet_ask subtracts remaining payload"),
        check("_libssh2_diag_packet_dequeued" in flush and "packet->data_len - packet->data_head" in flush,
              "channel_flush subtracts remaining payload"),
        check("_libssh2_diag_packet_bytes_consumed(session, bytes_want)" in consume,
              "channel_read subtracts bytes as consumed"),
        check("_libssh2_diag_packet_dequeued(session, 0)" in read_unlink,
              "channel_read final unlink avoids double subtraction"),
        check("(unsigned long long)(packet->data_len - packet->data_head)" in patch,
              "enable-time baseline uses remaining payload"),
        check("if(reset)" in api and "packet_queue_packets_peak" in api and
              "packet_queue_bytes_peak" in api and "packet_queue_enqueued_bytes = 0" in api,
              "snapshot API exposes current/peak/enqueue fields and reset path"),
        check("packet_queue_packets_peak =\n            session->passwall_diag.packet_queue_packets_current" in api and
              "packet_queue_bytes_peak =\n            session->passwall_diag.packet_queue_bytes_current" in api,
              "snapshot reset rebases peaks to current occupancy"),
    ]
    if not all(checks):
        return 1

    helpers = "\n\n".join(c_function(helpers_template, n) for n in (
        "_libssh2_diag_packet_enqueued",
        "_libssh2_diag_packet_bytes_consumed",
        "_libssh2_diag_packet_dequeued",
    ))
    if not compile_and_run(helpers):
        return 1
    if not compile_and_run_lifecycle(helpers, api):
        return 1

    if len(sys.argv) == 3:
        root = Path(sys.argv[2])
        project = Path(__file__).resolve().parent.parent
        try:
            packet = (root / "src/packet.c").read_text()
            channel = (root / "src/channel.c").read_text()
            session = (root / "src/session.c").read_text()
            private = (root / "src/libssh2_priv.h").read_text()
            public_header = (project / "libssh2_diag.h").read_text()
        except OSError as exc:
            print("FAIL: cannot read generated libssh2/project source: " + str(exc), file=sys.stderr)
            return 1
        actual = [
            check(re.search(r"_libssh2_diag_packet_enqueued\s*\(\s*session\s*,\s*packetp->data_len\s*-\s*packetp->data_head\s*\)", packet) is not None,
                  "generated packet.c enqueue hook is payload-based"),
            check("_libssh2_diag_packet_bytes_consumed(session, bytes_want);" in channel,
                  "generated channel.c partial read hook is present"),
            check("_libssh2_diag_packet_dequeued(session, 0);" in channel,
                  "generated channel.c full read avoids double subtraction"),
            check("_libssh2_diag_packet_dequeued" in channel and "packet->data_len - packet->data_head" in channel,
                  "generated channel.c flush removes remaining payload"),
            check("_libssh2_diag_packet_dequeued" in packet and "packet->data_len - packet->data_head" in packet,
                  "generated packet.c packet_ask removes remaining payload"),
            check("(unsigned long long)(packet->data_len - packet->data_head)" in session,
                  "generated session.c enable baseline is payload-based"),
            check(api.strip() in session,
                  "generated session.c contains the exact enable/snapshot API exercised by native tests"),
            check("_libssh2_diag_packet_enqueued" in private and "_libssh2_diag_packet_dequeued" in private,
                  "generated private header contains accounting helpers"),
            check(all(name in public_header for name in (
                    "packet_queue_packets_current", "packet_queue_bytes_current",
                    "packet_queue_packets_peak", "packet_queue_bytes_peak",
                    "packet_queue_enqueued_packets", "packet_queue_enqueued_bytes")),
                  "application public snapshot exposes all packet-queue fields"),
        ]
        if not all(actual):
            return 1
    print("PASS: R68 packet queue lifecycle and snapshot/reset regression checks completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
