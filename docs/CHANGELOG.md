# Changelog
All notable changes to this project will be documented here.

# Changelog
All notable changes to this project will be documented here.

## [0.2.1] - 2025-08-25
### grAESecure (library)
**Theme:** GreyScript compatibility & cleanup

#### Changed
- Swept all code to single statement per line (no semicolons, no chained assignments).
- Rewrote all `if/else` blocks to multiline form; removed `and`/`or` usage.
- Ensured every `return` sits on its own line.
- Removed `_maybe_hex_to_bytes`; inlined safe hex/text handling inside text APIs.

#### BYTES utilities
- Hardened `bytes_to_str`, `from_hex`, `to_hex`, and `str_to_bytes`.
- Added `_safe_char`, `_build_charmap`, and `map_numeric_bytes_to_list` for robust map→list normalization.
- Added `random_bytes`, `key32_from_password` (iterated MD5 expansion), and `bytes_eq`.
- Added `append_all` / `append_slice` helpers.

#### HASH / HMAC
- Implemented `HASH.md5_bytes`: bytes → string → md5 → hex → bytes, with optional debug tracing.
- Implemented `BYTES.hmac_md5(key, msg)` (MD5/HMAC, block size 64).
- Debug flags: `DEBUG_HASH`, `DEBUG_HMAC`.

#### AES-256 core
- Runtime S-box/InvS-box builder; GF ops (`xtime`, `gmul`) without hex literals.
- AES-256 key schedule (`key_expansion_256`), block encrypt/decrypt.
- Rewrote `shift_rows`/`mix_columns` (and inverses) to single-operation lines.

#### Modes (CBC & CTR)
- CBC `pkcs7_pad`/`unpad` hardened; CBC encrypt/decrypt stable.

**Sealed CBC + HMAC-MD5**
- `seal_cbc_hmac_md5(pt, key_enc, key_mac, ivOpt, tagLenOpt)` → `iv||ct||tag`.
- `open_cbc_hmac_md5(sealed, key_enc, key_mac, tagLenOpt)` with constant-time-ish tag compare.
- Min tag length = 10; debug flags: `DEBUG_SEAL`, `DEBUG_OPEN`.
- Aliases: `seal_cbc_auth` / `open_cbc_auth`.

**CTR**
- Fixed `ctr_xcrypt(bytes, key32, nonce16)` (counter big-endian at `block[12..15]`).
- Explicit 3-arg wrappers: `ctr_encrypt(data, key, nonce)` and `ctr_decrypt(data, key, nonce)` (no aliasing).

**Sealed CTR**
- `seal_ctr(pt, key32, nonceOpt)` → `nonce||ct`.
- `open_ctr(sealed, key32)` → `pt`.
- Text helpers: `encrypt_text_ctr_sealed(text, pwd, asHexOpt)` / `decrypt_text_ctr_sealed(sealed, pwd)`.

#### KEYS helpers
- `load_or_create_mac_key()` and `rotate_mac_key(backupOpt)` fixed for in-game FS API (`.content`/`.get_content` fallback, `touch` arity, safe path handling).

#### Text APIs
- `encrypt_text_cbc`, `decrypt_text_cbc`, `encrypt_text_ctr`, `decrypt_text_ctr` now perform safe hex-or-text handling inline.

#### Export
- Primary namespace is `AESLIB`.
- Keeps alias `AES256_LIB = AESLIB` for compatibility.

#### Notes / caveats
- RNG uses `rnd` (not cryptographically strong).
- Password→key uses repeated MD5 (not a modern KDF).
- HMAC uses MD5 for tag (chosen for engine availability).

---

## [0.1.5] - 2025-08-25
### grAESecure_test (harness)
#### Changed
- Standardized on `AESLIB` (library also exports `AES256_LIB` alias).
- All control flow rewritten to single-statement lines; no semicolons, no `and`/`or`.
- Final marker: `[DONE] grAESecure tests finished.`

#### Added
- Helpers: `BYTES_eq`, `copy_list`, local `PKCS7_pad`/`unpad`.

#### Tests
- Text round-trips: CBC and CTR (hex path), CTR (sealed text), and CTR bytes-input.
- Byte/codec: BYTES round-trip (text) and raw `0..255` round-trip.
- AES core: S-box inverse, single-block enc/dec, GF sanity.
- Modes: CBC enc/dec, CTR sealed enc/dec (`seal_ctr`/`open_ctr`).

**Sealed CBC + HMAC-MD5 keyed test**
- Resolves `seal_cbc_hmac_md5`/`open_cbc_hmac_md5` (or `*_auth` aliases).
- Full-arity call with random MAC key; validates `iv||ct||tag` and plaintext recovery.
- Temporary debug section: local toggles for `DEBUG_SEAL`/`DEBUG_OPEN`/`DEBUG_HASH`/`DEBUG_HMAC` around keyed test, restored after.
---
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
