# Architecture

## Modules (single file export: `AES256_LIB`)
- `AES256` – core AES:
  - `xtime`, `gmul`, `init_sboxes`, `sub/shift/mix`, `add_round_key`
  - `key_expansion_256`, `encrypt_block`, `decrypt_block`
- `MODES` – CBC/CTR, PKCS#7
- `BYTES` – str↔bytes, hex, simple password→key

## Data flow
text → BYTES.str_to_bytes → MODE(CBC/CTR) → AES256.encrypt_block → hex

## Design choices
- No hex literals (decimal + `bitwise` ops)
- GS-safe style (expanded `if`…`end if`)
- S-box generated at runtime to avoid giant tables
