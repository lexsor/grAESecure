# Architecture

> Status: reflects **v0.2.1 (2025-08-25)**

## Overview
Single-file GreyScript library exposing the primary namespace **`AESLIB`** (compat alias: **`AES256_LIB = AESLIB`**).  
All modules live under `AESLIB.*` and are written in GS-safe style: one statement per line, expanded `if … end if`, no `and`/`or`, no semicolons.

## Module Layout
- **`AESLIB.AES256`** — AES-256 core
  - Finite field ops: `xtime`, `gmul` (no hex literals; bitwise only)
  - Runtime S-box / InvS-box generation: `init_sboxes`
  - Round transforms: `sub_bytes`, `shift_rows`, `mix_columns`, `add_round_key`
  - Key schedule: `key_expansion_256`
  - Block ops: `encrypt_block`, `decrypt_block`
- **`AESLIB.MODES`** — Modes & padding
  - CBC: `cbc_encrypt`, `cbc_decrypt`, `pkcs7_pad`, `pkcs7_unpad` (hardened)
  - CTR: `ctr_xcrypt(bytes, key32, nonce16)` (counter big-endian at `block[12..15]`)
  - Sealed helpers:
    - **CBC + HMAC-MD5:** `seal_cbc_hmac_md5(pt, key_enc, key_mac, ivOpt, tagLenOpt)` → `iv||ct||tag`  
      `open_cbc_hmac_md5(sealed, key_enc, key_mac, tagLenOpt)` (verify-then-decrypt, constant-time-ish tag compare)  
      Aliases: `seal_cbc_auth` / `open_cbc_auth`
    - **CTR (sealed):** `seal_ctr(pt, key32, nonceOpt)` → `nonce||ct`, `open_ctr(sealed, key32)` → `pt`
  - Thin wrappers: `ctr_encrypt(data, key, nonce)`, `ctr_decrypt(data, key, nonce)`
- **`AESLIB.BYTES`** — Byte/codec utilities
  - Conversions: `str_to_bytes`, `bytes_to_str`, `from_hex`, `to_hex`
  - Normalization & helpers: `_safe_char`, `_build_charmap`, `map_numeric_bytes_to_list`, `append_all`, `append_slice`
  - Equality & RNG: `bytes_eq(a, b)`, `random_bytes(n)` (engine `rnd`, not CSPRNG)
  - HMAC: `hmac_md5(key, msg)` (MD5, block size 64)
- **`AESLIB.HASH`** — Hash helpers
  - `md5_bytes(b)` → bytes (pipeline: bytes → string → md5 → hex → bytes); optional debug tracing
- **`AESLIB.KEYS`** — Key & key-file helpers
  - Derivation (compat): `key32_from_password(password)` (iterated MD5 expansion)
  - MAC key files: `load_or_create_mac_key()`, `rotate_mac_key(backupOpt)`  
    (handles `.content`/`.get_content` fallback, `touch` arity, safe paths)
- **`AESLIB.PATHS`** — Default locations for key material
  - `base`, `mac_key_name`, `mac_key_path`, `mac_key_backup`

## Text APIs
Text helpers perform **inline hex-or-text detection** (no `_maybe_hex_to_bytes`):
- CBC: `encrypt_text_cbc(text, keyOrPwd)`, `decrypt_text_cbc(ctOrHex, keyOrPwd)`
- CTR: `encrypt_text_ctr(text, keyOrPwd)`, `decrypt_text_ctr(ctOrHex, keyOrPwd)`
- Sealed CTR (password path): `encrypt_text_ctr_sealed(text, pwd, asHexOpt)`, `decrypt_text_ctr_sealed(sealed, pwd)`

## Data Flows
- **Bytes (CBC):** `pt_bytes → pkcs7_pad → CBC.encrypt → ct_bytes`
- **Bytes (CTR):** `data_bytes → CTR.xcrypt(nonce,key) → ct_bytes`
- **Sealed CBC + HMAC:** `pt → CBC.encrypt(key_enc, iv) → ct → HMAC_MD5(key_mac, iv||ct) → iv||ct||tag`
- **Sealed CTR:** `pt → CTR.xcrypt(key, nonce) → ct → nonce||ct`
- **Text paths:** `text ↔ BYTES.str_to_bytes/bytes_to_str`, with hex detection handled inside the text APIs

## Debug Flags
Toggleable for targeted troubleshooting (reset by harness):
- `DEBUG_SEAL`, `DEBUG_OPEN`, `DEBUG_HASH`, `DEBUG_HMAC`

## Design Choices
- **No hex literals** in core math; use decimal + bitwise ops.
- **Runtime S-box** generation to avoid large static tables.
- **GS-safe style:** expanded control flow, one statement per line, no chained assignments.
- **CTR counter endianness:** big-endian in `block[12..15]` (fixed in v0.2.1).

## Formats (current)
- **Sealed CBC + HMAC-MD5:** raw bytes `iv||ct||tag` (min tag length 10; default configurable via API)
- **Sealed CTR:** raw bytes `nonce||ct`
> Note: headerized, versioned payloads are planned for v0.3.

## Security Notes
- RNG uses `rnd` → **not** cryptographically secure.
- Password→key uses **iterated MD5** (compatibility); modern salted/iterated KDF planned.
- Authentication uses **HMAC-MD5** (engine availability); SHA-256 upgrade planned when feasible.
