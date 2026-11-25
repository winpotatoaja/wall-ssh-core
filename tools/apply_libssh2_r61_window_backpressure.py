#!/usr/bin/env python3
"""Passwall r61: reduce the advertised direct-tcpip receive window."""
from pathlib import Path
import sys

WINDOW_BYTES = 512 * 1024
MARKER = ".passwall-r61-window-backpressure-patched"
VERSION_MARKER = '#define LIBSSH2_VERSION "1.11.1"'
DIRECT_SIG = "static LIBSSH2_CHANNEL *\nchannel_direct_tcpip("
STREAMLOCAL_SIG = "static LIBSSH2_CHANNEL *\nchannel_direct_streamlocal("

def replace_once(source: str, old: str, new: str, label: str) -> str:
    count = source.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one anchor, found {count}")
    return source.replace(old, new, 1)

def matching_brace(source: str, brace: int) -> int:
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
                return i + 1
        i += 1
    raise RuntimeError("unterminated C function")

def extract_function(source: str, signature: str) -> str:
    start = source.find(signature)
    if start < 0 or source.find(signature, start + 1) >= 0:
        raise RuntimeError("expected exactly one function: " + signature)
    brace = source.find("{", start)
    if brace < 0:
        raise RuntimeError("function body missing: " + signature)
    return source[start:matching_brace(source, brace)]

def patch(root: Path) -> None:
    if not (root / ".passwall-r60-worker-hotpath-cleanup-patched").is_file():
        raise RuntimeError("r61 requires the completed r60 libssh2 patch")
    header = (root / "include/libssh2.h").read_text()
    if VERSION_MARKER not in header:
        raise RuntimeError("r61 patch is pinned to libssh2 1.11.1")
    if "#define LIBSSH2_CHANNEL_WINDOW_DEFAULT  (2*1024*1024)" not in header:
        raise RuntimeError("unexpected libssh2 default channel receive window")
    if "#define LIBSSH2_CHANNEL_PACKET_DEFAULT  32768" not in header:
        raise RuntimeError("unexpected libssh2 default channel packet size")

    path = root / "src/channel.c"
    source = path.read_text()
    if (root / MARKER).exists():
        raise RuntimeError("r61 direct-tcpip receive-window patch is already present")

    # Keep the adjustment local to direct-tcpip. Other channel types retain
    # libssh2's upstream receive-window default.
    define = f"#define PASSWALL_DIRECT_TCPIP_WINDOW_SIZE ({WINDOW_BYTES}U)\n\n"
    source = replace_once(source, DIRECT_SIG, define + DIRECT_SIG,
                          "insert Passwall direct-tcpip window constant")
    direct_old = (
        '    channel =\n'
        '        _libssh2_channel_open(session, "direct-tcpip",\n'
        '                              sizeof("direct-tcpip") - 1,\n'
        '                              LIBSSH2_CHANNEL_WINDOW_DEFAULT,\n'
        '                              LIBSSH2_CHANNEL_PACKET_DEFAULT,\n'
        '                              session->direct_message,\n'
        '                              session->direct_message_len);\n'
    )
    direct_new = direct_old.replace(
        "LIBSSH2_CHANNEL_WINDOW_DEFAULT,",
        "PASSWALL_DIRECT_TCPIP_WINDOW_SIZE,",
    )
    source = replace_once(source, direct_old, direct_new,
                          "set only the direct-tcpip receive window to 512 KiB")

    direct_function = extract_function(source, DIRECT_SIG)
    streamlocal_function = extract_function(source, STREAMLOCAL_SIG)
    if "PASSWALL_DIRECT_TCPIP_WINDOW_SIZE" not in direct_function:
        raise RuntimeError("direct-tcpip helper does not use the Passwall window")
    if "LIBSSH2_CHANNEL_WINDOW_DEFAULT" in direct_function:
        raise RuntimeError("direct-tcpip helper still uses the 2 MiB default")
    if "LIBSSH2_CHANNEL_WINDOW_DEFAULT" not in streamlocal_function:
        raise RuntimeError("other channel type no longer uses upstream default")
    if "LIBSSH2_CHANNEL_PACKET_DEFAULT" not in direct_function:
        raise RuntimeError("direct-tcpip packet size unexpectedly changed")
    if "LIBSSH2_CHANNEL_PACKET_DEFAULT" not in streamlocal_function:
        raise RuntimeError("streamlocal packet size unexpectedly changed")

    path.write_text(source)
    (root / MARKER).write_text(
        "libssh2 1.11.1 Passwall r61 direct-tcpip receive window 512 KiB\n"
    )
    print("PASS: r61 limits only direct-tcpip initial receive window to 512 KiB; "
          "other channel types and 32 KiB packet size keep upstream defaults")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: apply_libssh2_r61_window_backpressure.py LIBSSH2_SOURCE_DIR",
              file=sys.stderr)
        sys.exit(2)
    patch(Path(sys.argv[1]))
