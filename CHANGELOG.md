# R66 Final — Changelog

## 2026-11-27 — final crypto profile and OpenWrt package

- Created release/r66-final from the R65-B baseline commit dc0454d93a93afc94e8024f6346b54eb3ccd07d7.
- Set PKG_RELEASE:=66; expected package: passwall-ssh-core_1.0.0-r66_mipsel_24kc.ipk.
- R65-E Actions #918 (45942020408) passed SDK and MT7621 QEMU. In its 27-case MIPS AES-CTR matrix, in-place EVP + per-packet memcpy was faster in every configuration; with a 32 MiB working set, out-of-place was median 6.00% slower.
- Final selection: retain R64 in-place AES-128-CTR RX + copy and R65-B HMAC context reuse. R65-C out-of-place is not applied. R65-D/E diagnostics/benchmark patchers are not part of the final workflow.
- Keep R65-A performance diagnostics behind the existing diagnostics flag.
- Added tests/r66_final_profile_source_test.py to assert the final transport path, HMAC reuse, absence of R65-C/D/E patch markers, and R66 package/artifact metadata.
- Native, OpenWrt SDK/IPK and same-run MT7621 QEMU validation for R66: pending.
