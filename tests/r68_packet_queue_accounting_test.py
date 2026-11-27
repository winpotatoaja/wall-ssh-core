#!/usr/bin/env python3
"""Verify R68 libssh2 packet-queue payload accounting and patched call sites."""
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
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "replace_once" and len(n.args) >= 4:
            try:
                if ast.literal_eval(n.args[3]) == label:
                    return ast.literal_eval(n.args[2])
            except Exception:
                pass
    raise RuntimeError("missing patch template: " + label)


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


def main():
    if len(sys.argv) not in (2, 3):
        print("usage: r68_packet_queue_accounting_test.py PATCH_SCRIPT [PATCHED_LIBSSH2_SOURCE_DIR]", file=sys.stderr)
        return 2
    patch = Path(sys.argv[1]).read_text()
    tree = ast.parse(patch)
    enqueue = replacement(tree, "packet enqueue accounting")
    ask = replacement(tree, "packet ask dequeue accounting")
    flush = replacement(tree, "channel flush dequeue accounting")
    consume = replacement(tree, "account partially consumed packet bytes")
    read_unlink = replacement(tree, "channel read queue dequeue accounting")
    helpers_template = replacement(tree, "diagnostic timing and packet queue helpers")

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

    if len(sys.argv) == 3:
        root = Path(sys.argv[2])
        try:
            packet = (root / "src/packet.c").read_text()
            channel = (root / "src/channel.c").read_text()
            session = (root / "src/session.c").read_text()
            private = (root / "src/libssh2_priv.h").read_text()
        except OSError as exc:
            print("FAIL: cannot read generated libssh2 source: " + str(exc), file=sys.stderr)
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
            check("_libssh2_diag_packet_enqueued" in private and "_libssh2_diag_packet_dequeued" in private,
                  "generated private header contains accounting helpers"),
        ]
        if not all(actual):
            return 1
    print("PASS: R68 packet queue accounting regression checks completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
