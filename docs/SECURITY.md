# Security Notes

- **KDF**: current password→key uses repeated MD5; add salt + iterations.
- **Integrity**: add MAC (verify-before-decrypt) in v0.3.
- **IV/Nonce**: must be unique per message; never reuse with the same key.
- **Modes**: CBC (files), CTR (streams). ECB is intentionally not provided.
- **Threat model**: local attackers reading files; passive network observers.
- **Reporting**: open a GitHub issue with "security" label; avoid posting secrets.
