# Contributing

## Local dev
- Game path: place `aes256.src` where `import_code` can load it.
- Run: `aes_test.src` to verify changes.
- Style: GreyScript-safe (no single-line conditionals).

## Commits (Conventional Commits)
- `feat: add seal_cbc/open_cbc`
- `fix: sbox init guard`
- `perf: cache round keys`
- `test: add CTR vectors`
- `docs: architecture diagram`

## Branching & Releases
- Branch per feature; PR into `main`.
- Tag releases `vX.Y.Z`; update `CHANGELOG.md`.
