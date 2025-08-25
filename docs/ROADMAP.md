# Roadmap

> This roadmap reflects progress through **v0.2.1 (2025-08-25)** and what’s next.

## Recently completed (v0.2.1)
- [x] **Sealed CTR**: `seal_ctr(pt, key32, nonceOpt) → nonce||ct`, `open_ctr(sealed, key32)`
- [x] **CBC auth tag (HMAC-MD5)**: `seal_cbc_hmac_md5` / `open_cbc_hmac_md5` (+ aliases `*_auth`)
- [x] **Random bytes**: `random_bytes(n)` (engine RNG `rnd`)
- [x] **Password → key**: `key32_from_password` (iterated MD5 expansion)
- [x] **Core hardening**: BYTES helpers, CBC PKCS#7 pad/unpad, CTR counter (big-endian), single-statement style
- [x] **Debug flags**: `DEBUG_SEAL`, `DEBUG_OPEN`, `DEBUG_HASH`, `DEBUG_HMAC`

---

## v0.3 – Packaging & Auth
- [ ] **Unified sealed payload format** for interchange (headerized):
      - CBC (auth): `AES1|CBC|kdf=md5|iter=<N>|salt=<hex>|iv=<hex>|ct=<hex>|tag=<hex>`
      - CTR (sealed): `AES1|CTR|kdf=md5|iter=<N>|salt=<hex>|nonce=<hex>|ct=<hex>`
      - Add strict parser/encoder and version checks.
- [ ] **Verify-then-decrypt** enforcement in `open_*_auth` (+ tests for truncated/tampered fields).
- [ ] **Tag length policy**: default `tagLen=16`, minimum `>=10`, configurable via API.
- [ ] **Salt plumbing**: carry `salt` in format and thread through text/file helpers.
- [ ] **Harness coverage**: negative tests for bad header, wrong mode, wrong KDF/meta.

## v0.4 – Usability
- [ ] **File CLI scripts**: `aes_file_encrypt.src` / `aes_file_decrypt.src`
      - Flags for mode (CBC-auth / CTR), input/output as hex or base64.
- [ ] **Round-key caching context**: `make_ctx(passwordOrKey)` returning expanded keys; wire into CTR/CBC paths.
- [ ] **Base64 helpers** for friendlier I/O in CLIs (optional vs hex).
- [ ] **Errors & guardrails**: consistent null/[] returns, error codes/messages for parse/KDF/auth failures.

## v0.5 – KDF, Verification & Benchmarks
- [ ] **KDF upgrade (salted/iterated)**: `key_from_password(password, salt, iters)` (MD5 today), keep `key32_from_password` for compat and deprecate later.
- [ ] **Embed/extract KDF meta**: ensure sealed headers round-trip `salt` and `iter`.
- [ ] **Known-answer tests**: AES-256 ECB vectors (adapted to GreyScript arrays).
- [ ] **Micro-benchmarks** + perf tips (buffer reuse, context reuse).

## Backlog / Nice-to-haves
- [ ] **MAC upgrade path**: switch to **HMAC-SHA-256** if/when the environment exposes SHA-256 (keep MD5 behind a flag).
- [ ] Streaming CTR API (chunked xcrypt).
- [ ] GitHub Actions CI (if a runner is available).
- [ ] Optional helpers: Base16/Base64 autodetect in text APIs, small “how-to” docs for payload format.

> Security notes: RNG is `rnd` (not CSPRNG). Current MAC/KDF use MD5 due to engine availability; plan to migrate to SHA-256 when feasible.
