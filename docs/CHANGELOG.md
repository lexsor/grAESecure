# Changelog
All notable changes to this project will be documented here.

## [0.2.1] - 2025-08-24
### Added
- **Test harness v0.6**: probe-safe (no blind map indexing), no raw-binary printing, GreyScript-friendly (no `elseif`/`and`/`or`), negative tests for sealed CBC (`short`, `non-multiple`, tamper).
- **Function arity introspection** (`FUNC_arity`) so the harness can *inspect* callable params without trial calls.
- **Safe map helpers** (`MAP_has`, `MAP_get`) used across tests to avoid `Key Not Found` errors.
- **Local PKCS#7 fallback** in harness (pads/unpads without requiring `AESLIB.PKCS7` to be exported).

### Changed
- **BYTES conversions hardened**: single-char strings map via a prebuilt `charmap` (no accidental `"0" → 0`), `_safe_char` clamps to 0..255 and never throws; `str_to_bytes` does pure char→code mapping.
- **Harness behavior**: CBC/CTR/Sealed tests compare **byte arrays** (or hex), never print raw ciphertext; optional features are cleanly **skipped** rather than probed.
- **Sealed-CBC entrypoints** standardized in tests to `seal_cbc_hmac_md5` / `open_cbc_hmac_md5` (aliases tolerated).

### Fixed
- Eliminated crashes:
  - `char: invalid char code` from unsafe `bytes_to_str`.
  - `Key Not Found` from direct `map["missing"]` reads.
  - Index errors from inclusive loop bounds.
  - “Too Many Arguments” by removing trial calls and using arity-aware/skip logic.
- CBC round-trip and sealed-CBC open now pass consistently; negative cases reject as expected.

### Removed
- Brittle library shims that read unknown keys (caused `Key Not Found`); tests handle compatibility instead.

### Known
- **CTR API surface is unstable** (runtime didn’t expose arity; harness skips CTR by default). Plan: add a small writer-only wrapper to guarantee `ctr_encrypt/decrypt(data, key32, nonce16)` in the next release.
- **`expand_key` not exported** → block-level encrypt/decrypt test is skipped (functional coverage provided by CBC/Sealed).
- **Packaging** (`AES1|CBC|salt_hex|iv_hex|ct_hex|tag_hex`) not yet implemented; coming in v0.3 alongside KDF/MAC notes.
- KDF & MAC remain minimal; stronger defaults targeted for v0.4.

---

## [0.2.0] - 2025-08-23
### Added
- Single-file AES-256 lib with CBC/CTR, S-box runtime gen, test harness

### Fixed
- GreyScript-safe control flow; import_code global export pattern

### Known
- KDF & MAC minimal; no file CLI yet

---

## [0.1.0] - 2025-08-20
### Added
- Initial prototype (non-compiling drafts)
