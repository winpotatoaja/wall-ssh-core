#!/usr/bin/env python3
"""Source invariants for R61's per-channel receive-window backpressure."""
from pathlib import Path
import re
import sys

def check(condition: bool, label: str) -> bool:
    print(("PASS: " if condition else "FAIL: ") + label)
    return condition

def extract_function(source: str, signature: str) -> str:
    start = source.find(signature)
    if start < 0 or source.find(signature, start + 1) >= 0:
        raise RuntimeError("expected exactly one function: " + signature)
    brace = source.find("{", start)
    if brace < 0:
        raise RuntimeError("function body missing: " + signature)
    depth = 0
    quote = None
    line_comment = False
    block_comment = False
    i = brace
    while i < len(source):
        c = source[i]
        n = source[i + 1] if i + 1 < len(source) else ""
        if line_comment:
            if c == "\n":
                line_comment = False
        elif block_comment:
            if c == "*" and n == "/":
                block_comment = False
                i += 2
                continue
        elif quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = None
        elif c == "/" and n == "/":
            line_comment = True
            i += 2
            continue
        elif c == "/" and n == "*":
            block_comment = True
            i += 2
            continue
        elif c in ("'", '"'):
            quote = c
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return source[start:i + 1]
        i += 1
    raise RuntimeError("unterminated C function")

def main() -> int:
    if len(sys.argv) != 3:
        print("usage: r61_window_backpressure_test.py LIBSSH2_SOURCE_DIR SSH_CORE_C",
              file=sys.stderr)
        return 2
    root = Path(sys.argv[1])
    core = Path(sys.argv[2]).read_text()
    channel = (root / "src/channel.c").read_text()
    header = (root / "include/libssh2.h").read_text()
    transport = (root / "src/transport.c").read_text()
    priv = (root / "src/libssh2_priv.h").read_text()
    packet = (root / "src/packet.c").read_text()

    direct = extract_function(channel, "static LIBSSH2_CHANNEL *\nchannel_direct_tcpip(")
    stream = extract_function(channel, "static LIBSSH2_CHANNEL *\nchannel_direct_streamlocal(")
    channel_read = extract_function(channel, "ssize_t _libssh2_channel_read(")

    checks = [
        check((root / ".passwall-r60-worker-hotpath-cleanup-patched").is_file() and
              (root / ".passwall-r61-window-backpressure-patched").is_file(),
              "R60 prerequisite and R61 patch markers are present"),
        check("#define PASSWALL_DIRECT_TCPIP_WINDOW_SIZE (524288U)" in channel and
              "PASSWALL_DIRECT_TCPIP_WINDOW_SIZE" in direct and
              "LIBSSH2_CHANNEL_WINDOW_DEFAULT" not in direct,
              "direct-tcpip advertises exactly 512 KiB instead of the 2 MiB default"),
        check("LIBSSH2_CHANNEL_WINDOW_DEFAULT" in stream and
              "LIBSSH2_CHANNEL_PACKET_DEFAULT" in direct and
              "LIBSSH2_CHANNEL_PACKET_DEFAULT" in stream,
              "other channel types and the 32 KiB channel packet size are unchanged"),
        check(re.search(r"#define\s+LIBSSH2_CHANNEL_WINDOW_DEFAULT\s+\(2\s*\*\s*1024\s*\*\s*1024\)", header) is not None and
              re.search(r"#define\s+LIBSSH2_CHANNEL_PACKET_DEFAULT\s+32768\b", header) is not None,
              "upstream defaults remain 2 MiB window and 32 KiB packet"),
        check("_libssh2_channel_receive_window_adjust(channel, adjustment," in channel_read and
              "channel->remote.window_size_initial / 4 * 3 + buflen" in channel_read and
              "do {\n        rc = _libssh2_transport_read(session);\n    } while(rc > 0);" in channel_read,
              "channel reads keep normal WINDOW_ADJUST and transport packet processing"),
        check("memmove(p->buf, &p->buf[p->readidx], remainbuf);" in transport and
              "PACKETBUFSIZE - remainbuf" in transport and
              "#define PACKETBUFSIZE MAX_SSH_PACKET_LEN" in priv,
              "transport refill, buffer compaction and PACKETBUFSIZE are unchanged"),
        check("case SSH_MSG_CHANNEL_WINDOW_ADJUST:" in packet and
              "case SSH_MSG_CHANNEL_EOF:" in packet and
              "case SSH_MSG_CHANNEL_CLOSE:" in packet and
              "msg == SSH_MSG_KEXINIT" in packet,
              "WINDOW_ADJUST, EOF, CLOSE and rekey packet handlers remain present"),
        check("#define S2C_RELAY_BUF_SIZE     262144" in core and
              "#define S2C_SSH_READ_WINDOW_SIZE (512U * 1024U)" in core and
              "libssh2_channel_window_read_ex(" in core and
              '"[S2C WINDOW] client=%llu initial=%lu ring=%u"' in core,
              "SSH Owner records actual initial receive window against the 256 KiB S2C ring"),
        check("rb_free_space(&c->s2c) > 0" in core and
              "channel_read_with_rx_flush(" in core,
              "S2C channel reads remain gated by available ring space"),
        check("PACKETBUFSIZE" not in core and "SSL_read(" not in core,
              "R61 does not change the transport packet buffer or add TLS I/O to the SSH Owner"),
    ]
    if not all(checks):
        return 1
    print("PASS: R61 per-channel receive-window source invariants")
    return 0

if __name__ == "__main__":
    sys.exit(main())
