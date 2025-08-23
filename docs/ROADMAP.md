# Roadmap

## v0.3 – Packaging & Safety
- [ ] Add `seal_cbc` / `open_cbc` format: `AES1|CBC|salt_hex|iv_hex|ct_hex|tag_hex`
- [ ] Add `seal_ctr` / `open_ctr` with nonce instead of IV
- [ ] Random `iv`/`nonce` generator (`random_bytes(n)`) with fallback
- [ ] Stronger KDF: md5 + salt + iterations (configurable)
- [ ] MAC: MD5-based tag for now (verify-before-decrypt)

## v0.4 – Usability
- [ ] File CLI scripts: `aes_file_encrypt.src` / `aes_file_decrypt.src`
- [ ] Round-key caching context (`make_ctx(password)`)
- [ ] Error messages & returns (null vs []), guard rails for inputs

## v0.5 – Verification & Benchmarks
- [ ] Known-answer tests (AES-256 ECB vectors adapted to GS arrays)
- [ ] Quick micro-benchmark script; document performance tips

## Backlog / Nice-to-haves
- [ ] Switch MAC to HMAC-SHA1 if environment provides SHA1
- [ ] Base64 helpers (optional)
- [ ] GitHub Actions (if you add CI with a runner)
