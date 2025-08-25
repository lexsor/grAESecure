# grAESecure for Grey Hack (GreyScript)

**Grey Hack AES-256 Encryption Library**

**grAESecure** (Grey + AES + Secure) is a single-file GreyScript library that brings modern AES-256 encryption into the Grey Hack universe.  
Primary namespace: **`AESLIB`** (compat alias: **`AES256_LIB = AESLIB`**). Written in GS-safe style (one statement per line, expanded `if … end if`, no `and`/`or`, no semicolons).

---

## Features
- **AES-256 core:** runtime S-box/InvS-box, GF ops (`xtime`, `gmul`), key schedule (`key_expansion_256`), block `encrypt_block`/`decrypt_block`.
- **Modes:** CBC (PKCS#7) and CTR (fixed big-endian counter at `block[12..15]`).
- **Sealed modes:**
  - **CBC + HMAC-MD5 (authenticated):** `seal_cbc_hmac_md5` / `open_cbc_hmac_md5` (aliases: `seal_cbc_auth` / `open_cbc_auth`), `iv||ct||tag` with min tag len `10`.
  - **CTR (sealed):** `seal_ctr` / `open_ctr` (`nonce||ct`), plus text helpers for password workflows.
- **Text helpers:** `encrypt_text_cbc` / `decrypt_text_cbc`, `encrypt_text_ctr` / `decrypt_text_ctr`, and
  `encrypt_text_ctr_sealed` / `decrypt_text_ctr_sealed` with **inline hex-or-text detection**.
- **Utilities:** robust `BYTES` conversions (`str↔bytes`, `hex`), `_safe_char` / `_build_charmap`, `append_all` / `append_slice`, `bytes_eq`, `random_bytes`.
- **HASH / HMAC:** `HASH.md5_bytes`, `BYTES.hmac_md5`.
- **KEYS helpers:** `key32_from_password` (iterated MD5), `load_or_create_mac_key`, `rotate_mac_key` (filesystem-safe behavior).
- **Debug flags:** `DEBUG_SEAL`, `DEBUG_OPEN`, `DEBUG_HASH`, `DEBUG_HMAC`.

---

## Quickstart

### 1) Import
```ts
// Import the library (single file)
import_code("grAESecure.src")

// Primary namespace
lib = AESLIB  // alias AES256_LIB also exported
```
### 2) Sealed CTR with password (text path)
```ts
sealed_hex = lib.encrypt_text_ctr_sealed("hello world", "hunter2", true)  // hex output
pt = lib.decrypt_text_ctr_sealed(sealed_hex, "hunter2")
print(pt)  // -> "hello world"
```
### 3) CBC + HMAC-MD5 (authenticated bytes path)
```ts
pt_bytes = lib.BYTES.str_to_bytes("secret message")

enc_key = lib.KEYS.key32_from_password("encpw")
mac_key = lib.KEYS.key32_from_password("macpw")

sealed = lib.MODES.seal_cbc_hmac_md5(pt_bytes, enc_key, mac_key, null, 16)  // iv||ct||tag
pt2    = lib.MODES.open_cbc_hmac_md5(sealed, enc_key, mac_key, 16)
print(lib.BYTES.bytes_to_str(pt2))
```
### 4) Plain CTR (bytes)
```ts
nonce16 = lib.BYTES.random_bytes(16)
data = lib.BYTES.str_to_bytes("data")
key32 = lib.KEYS.key32_from_password("k")

ct = lib.MODES.ctr_xcrypt(data, key32, nonce16)
rt = lib.MODES.ctr_xcrypt(ct,   key32, nonce16)  // symmetric
print(lib.BYTES.bytes_to_str(rt))  // -> "data"
```
---
## What’s New (v0.2.1 — 2025-08-25)

- **Sealed CTR** helpers (`seal_ctr` / `open_ctr`) and password text helpers.
- **CBC + HMAC-MD5 (authenticated)**: `seal_cbc_hmac_md5` / `open_cbc_hmac_md5` (+ aliases).
- **BYTES / HASH / HMAC hardening**: `_safe_char`, `_build_charmap`, `bytes_eq`, `random_bytes`.
- **KEYS helpers** fixed for in-game FS API quirks.
- **Consistent GS-style cleanup** across the codebase.

See full details in the **Changelog**.

> **Tip:** If you keep `CHANGELOG.md` at repo root instead of `docs/`, update the link accordingly.

---

## Security Notes (important)

- **RNG:** uses `rnd` → *not* cryptographically secure.
- **KDF:** `key32_from_password` uses iterated **MD5** (compat path).
- **MAC:** HMAC uses **MD5** due to engine availability.
- **Planned upgrades:** headerized sealed formats, salted/iterated KDF metadata, and stronger hash (see **Roadmap**).
---
## Tests
Run the harness to validate core, modes, and sealed paths:
```ts
import_code("grAESecure_test.src")
// Running the script prints [OK] markers and a final "[DONE] grAESecure tests finished."
```

