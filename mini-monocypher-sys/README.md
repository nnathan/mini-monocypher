# mini-monocypher-sys

[![Crates.io](https://img.shields.io/crates/v/mini-monocypher-sys.svg)](https://crates.io/crates/mini-monocypher-sys)
[![Docs.rs](https://docs.rs/mini-monocypher-sys/badge.svg)](https://docs.rs/mini-monocypher-sys)

mini-monocypher-sys provides bindgen generated C bindings to [Monocypher](https://monocypher.org/) C library. It is the raw layer used by the mini-monocypher crate.

## Status

Bindings are generated for the full public API of Monocypher 4.0.3, including
the optional SHA-512 and Ed25519 functions.

## Supported functions

### Constant time comparison

  - `crypto_verify16`
  - `crypto_verify32`
  - `crypto_verify64`

### Memory wipe

  - `crypto_wipe`

### Authenticated encryption

  - `crypto_aead_lock`
  - `crypto_aead_unlock`
  - `crypto_aead_init_x`
  - `crypto_aead_init_djb`
  - `crypto_aead_init_ietf`
  - `crypto_aead_write`
  - `crypto_aead_read`

### BLAKE2b

  - `crypto_blake2b`
  - `crypto_blake2b_keyed`
  - `crypto_blake2b_init`
  - `crypto_blake2b_keyed_init`
  - `crypto_blake2b_update`
  - `crypto_blake2b_final`

### Argon2

  - `crypto_argon2`

### X25519

  - `crypto_x25519_public_key`
  - `crypto_x25519`
  - `crypto_x25519_to_eddsa`
  - `crypto_x25519_inverse`
  - `crypto_x25519_dirty_small`
  - `crypto_x25519_dirty_fast`

### EdDSA

  - `crypto_eddsa_key_pair`
  - `crypto_eddsa_sign`
  - `crypto_eddsa_check`
  - `crypto_eddsa_to_x25519`

### EdDSA building blocks

  - `crypto_eddsa_trim_scalar`
  - `crypto_eddsa_reduce`
  - `crypto_eddsa_mul_add`
  - `crypto_eddsa_scalarbase`
  - `crypto_eddsa_check_equation`

### ChaCha20

  - `crypto_chacha20_h`
  - `crypto_chacha20_djb`
  - `crypto_chacha20_ietf`
  - `crypto_chacha20_x`

### Poly1305

  - `crypto_poly1305`
  - `crypto_poly1305_init`
  - `crypto_poly1305_update`
  - `crypto_poly1305_final`

### Elligator

  - `crypto_elligator_map`
  - `crypto_elligator_rev`
  - `crypto_elligator_key_pair`

### SHA-512

  - `crypto_sha512`
  - `crypto_sha512_init`
  - `crypto_sha512_update`
  - `crypto_sha512_final`

### HMAC-SHA-512

  - `crypto_sha512_hmac`
  - `crypto_sha512_hmac_init`
  - `crypto_sha512_hmac_update`
  - `crypto_sha512_hmac_final`

### HKDF-SHA-512

  - `crypto_sha512_hkdf`
  - `crypto_sha512_hkdf_expand`

### Ed25519

  - `crypto_ed25519_key_pair`
  - `crypto_ed25519_sign`
  - `crypto_ed25519_check`
  - `crypto_ed25519_ph_sign`
  - `crypto_ed25519_ph_check`
