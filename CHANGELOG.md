# R66 Final — Changelog

## 2026-11-27 — final crypto profile and OpenWrt package

- Created \`release/r66-final\` from the R65-B baseline commit \`dc0454d93a93afc94e8024f6346b54eb3ccd07d7\`.
- Set \`PKG_RELEASE:=66\`; package: \`passwall-ssh-core_1.0.0-r66_mipsel_24kc.ipk\`.
- R65-E Actions #918 (\`45942020408\`) passed SDK and MT7621 QEMU. In its 27-case MIPS AES-CTR matrix, in-place EVP + per-packet memcpy was faster in every configuration; with a 32 MiB working set, out-of-place was median 6.00% slower.
- Final selection: retain R64 in-place AES-128-CTR RX + copy and R65-B HMAC context reuse. R65-C out-of-place is not applied. R65-D/E diagnostics/benchmark patchers are not part of the final workflow.
- Keep R65-A performance diagnostics behind the existing diagnostics flag.
- Added \`tests/r66_final_profile_source_test.py\` to assert the final transport path, HMAC reuse, absence of R65-C/D/E patch markers, and R66 package/artifact metadata.
- **R66 final validation PASS:** Actions #919, run \`45944954879\`, source commit \`41b101378ebda17e211d03be7ea7e7709f04f0ab\`. SDK and VM jobs both SUCCESS.
- SDK built \`passwall-ssh-core_1.0.0-r66_mipsel_24kc.ipk\`; package control metadata verified as \`1.0.0-r66\`.
- IPK SHA-256: \`3b67a40af48c532d3bd61394a843ec90504fb5123379a89254a1f78e956e3d9f\`.
- SDK artifact ID \`15174341956\`; MT7621 QEMU results artifact ID \`15174981023\`.
- R66 source gate passed: R64 in-place AES-CTR + copy and R65-B HMAC reuse are present; R65-C/D/E patch markers absent.
- MIPS AES-CTR helper passed 72 differential cases. HMAC-SHA256 helper passed 2 directions × 2,048 messages.
- AES-CTR non-ETM and ETM transport tests both passed checksum, both negotiated directions, bulk-only counters and HMAC reuse counter checks.
- Default SSH ChaCha20-Poly1305 and TLS 1.3 ChaCha20-Poly1305 negotiation remained intact. Four concurrent SOCKS clients transferred 4 × 32 MiB through one SSH session with matching SHA-256; aggregate QEMU throughput 12.675 MiB/s.
- TCP full-duplex, half-close, RST reconnect, TLS/SNI and related QEMU guest tests passed.
