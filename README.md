# mini-monocypher

mini-monocypher provides API bindings to [Monocypher](https://monocypher.org/) via the raw FFI bindings provided by mini-monocypher-sys.

## Status

mini-monocypher binds the full public API of Monocypher 4.0.3, including the
optional SHA-512 and Ed25519 functions. Functions keep their C names and
argument order, so the [Monocypher manual](https://monocypher.org/manual/)
applies directly.

The bindings differ from C in these ways:

  - Fixed-size parameters such as `key[32]` are arrays such as `&[u8; 32]`.
  - A pointer and its size are a single slice.
  - `Option` is used where a NULL pointer is meaningful or the parameter is
    optional, such as additional data.
  - Functions returning an `int` status return a `Result`.
  - Invalid buffer sizes and parameter limits panic instead of being undefined
    behaviour. Rules that cannot be checked, such as never reusing a nonce, are
    still the caller's responsibility.
  - Contexts are opaque, are created with a `*_ctx_new` function, and are wiped
    when they go out of scope.
  - The Argon2 algorithm is an enum, usable by the same names as in C.
  - The low-level EdDSA building blocks are in the `hazmat` module.

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

### EdDSA building blocks (in the `hazmat` module)

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

## History

Before Claude there had been one version of this release, 0.1.0, where mini-monocypher was hand written in the era where LLMs and code generation had not taken over. The plan was always to get to fidelity with the Monocypher API, but it would have been a time consuming task.

In the era of Claude Code and high quality models it made sense to use one here. The quality of the code would be great for a small project like this because incrementally supporting the Monocypher API is very much a mechanical process, and Monocypher itself is incredibly LLM friendly. So I unleashed the LLM on this repository, but because it is cryptography related I reviewed all of the code that was generated.

I stayed in the loop to decide which Rust safety features to use while keeping fidelity with the C API and avoiding idiomatic Rust abstraction which would make the API too foreign for someone that has used Monocypher before.

I can attest that Claude has done a better job than I could ever do and at breakneck speed.

Thanks to Claude, as of version 0.3.0 we have fidelity with Monocypher 4.0.3.

## Known limitations

Monocypher allows the input and output of some functions, such as encryption
and decryption, to be the same or overlapping buffers. Rust does not allow a
buffer to be borrowed both mutably and immutably, so these bindings require
separate buffers.
