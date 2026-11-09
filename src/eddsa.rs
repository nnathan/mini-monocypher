use crate::ErrorKind;

/// Computes an EdDSA key pair from a random `seed`.
///
/// The `seed` must be freshly generated and only used once, and is wiped by
/// this function. `secret_key` is made up of the seed and the public key, and
/// should be treated as a unit.
///
/// See [`crypto_eddsa_sign`] for a full example of signing and checking.
pub fn crypto_eddsa_key_pair(
    secret_key: &mut [u8; 64],
    public_key: &mut [u8; 32],
    seed: &mut [u8; 32],
) {
    let secret_key_buf = secret_key.as_mut_ptr();
    let public_key_buf = public_key.as_mut_ptr();
    let seed_buf = seed.as_mut_ptr();

    unsafe { mini_monocypher_sys::crypto_eddsa_key_pair(secret_key_buf, public_key_buf, seed_buf) }
}

/// Signs `message` with `secret_key`. The output can be checked by
/// [`crypto_eddsa_check`].
///
/// This uses BLAKE2b as the underlying hash, so it is not compatible with
/// Ed25519.
///
/// Unlike Monocypher, `signature` and `message` cannot overlap, as Rust does
/// not allow a buffer to be borrowed both mutably and immutably.
///
/// It is recommended to read the [`Monocypher` manual] before using this
/// function.
///
/// # Examples
///
/// ```
/// use rand_core::{OsRng, RngCore};
/// use mini_monocypher::{crypto_eddsa_check, crypto_eddsa_key_pair, crypto_eddsa_sign};
///
/// let mut seed = [0u8; 32];
/// let mut secret_key = [0u8; 64];
/// let mut public_key = [0u8; 32];
/// let mut signature = [0u8; 64];
///
/// OsRng.fill_bytes(&mut seed);
/// crypto_eddsa_key_pair(&mut secret_key, &mut public_key, &mut seed);
///
/// crypto_eddsa_sign(&mut signature, &secret_key, b"Lorem ipsum");
/// crypto_eddsa_check(&signature, &public_key, b"Lorem ipsum")
///     .expect("signature should be valid");
/// ```
///
/// [`Monocypher` manual]: https://monocypher.org/manual/eddsa
pub fn crypto_eddsa_sign(signature: &mut [u8; 64], secret_key: &[u8; 64], message: &[u8]) {
    let signature_buf = signature.as_mut_ptr();
    let secret_key_buf = secret_key.as_ptr();
    let message_buf = message.as_ptr();

    unsafe {
        mini_monocypher_sys::crypto_eddsa_sign(
            signature_buf,
            secret_key_buf,
            message_buf,
            message.len(),
        );
    }
}

/// Checks that `signature` is genuine for `public_key` and `message`.
/// Returns `()` if it is, or [`ErrorKind::InvalidSignature`] if it is not.
///
/// This does not run in constant time. See [`crypto_eddsa_sign`] for a full
/// example of signing and checking.
pub fn crypto_eddsa_check(
    signature: &[u8; 64],
    public_key: &[u8; 32],
    message: &[u8],
) -> Result<(), ErrorKind> {
    let signature_buf = signature.as_ptr();
    let public_key_buf = public_key.as_ptr();
    let message_buf = message.as_ptr();

    let result = unsafe {
        mini_monocypher_sys::crypto_eddsa_check(
            signature_buf,
            public_key_buf,
            message_buf,
            message.len(),
        )
    };

    if result != 0 {
        return Err(ErrorKind::InvalidSignature);
    }

    Ok(())
}

/// Converts an EdDSA public key to an X25519 public key.
///
/// This ignores the sign of the x coordinate of `eddsa`. The inverse operation
/// is [`crypto_x25519_to_eddsa`].
///
/// [`crypto_x25519_to_eddsa`]: crate::crypto_x25519_to_eddsa
pub fn crypto_eddsa_to_x25519(x25519: &mut [u8; 32], eddsa: &[u8; 32]) {
    let x25519_buf = x25519.as_mut_ptr();
    let eddsa_buf = eddsa.as_ptr();

    unsafe { mini_monocypher_sys::crypto_eddsa_to_x25519(x25519_buf, eddsa_buf) }
}
