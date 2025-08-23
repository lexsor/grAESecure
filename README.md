# grAESecure for Grey Hack (GreyScript)

**Grey Hack AES-256 Encryption Library**

grAESecure (Grey + AES + Secure) is a single-file GreyScript library that brings
modern AES-256 encryption into the Grey Hack universe.  

Features:
- AES-256 block cipher with 14 rounds
- CBC with PKCS#7 padding; CTR mode (streaming)
- String/byte helpers, hex encoding
- Simple password-to-key derivation
- Built-in self-tests for correctness

## StatStatus
- ✅ Compiles and passes self-tests (aes_test.src)
- ⚠️ KDF and MAC are minimal (see Roadmap)

## Docs
- [Roadmap](docs/ROADMAP.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Security](docs/SECURITY.md)
- [Changelog](docs/CHANGELOG.md)