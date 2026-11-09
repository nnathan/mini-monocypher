use crate::ErrorKind;

/// Computes an Ed25519 key pair from a random `seed`.
///
/// The `seed` must be freshly generated and only used once, and is wiped by
/// this function. `secret_key` is made up of the seed and the public key, and
/// should be treated as a unit.
///
/// See [`crypto_ed25519_sign`] for a full example of signing and checking.
pub fn crypto_ed25519_key_pair(
    secret_key: &mut [u8; 64],
    public_key: &mut [u8; 32],
    seed: &mut [u8; 32],
) {
    let secret_key_buf = secret_key.as_mut_ptr();
    let public_key_buf = public_key.as_mut_ptr();
    let seed_buf = seed.as_mut_ptr();

    unsafe {
        mini_monocypher_sys::crypto_ed25519_key_pair(secret_key_buf, public_key_buf, seed_buf)
    }
}

/// Signs `message` with `secret_key` as described in RFC 8032. The output can
/// be checked by [`crypto_ed25519_check`].
///
/// This is provided for compatibility with Ed25519. Otherwise, consider
/// [`crypto_eddsa_sign`].
///
/// It is recommended to read the [`Monocypher` manual] before using this
/// function.
///
/// # Examples
///
/// ```
/// use rand_core::{OsRng, RngCore};
/// use mini_monocypher::{crypto_ed25519_check, crypto_ed25519_key_pair, crypto_ed25519_sign};
///
/// let mut seed = [0u8; 32];
/// let mut secret_key = [0u8; 64];
/// let mut public_key = [0u8; 32];
/// let mut signature = [0u8; 64];
///
/// OsRng.fill_bytes(&mut seed);
/// crypto_ed25519_key_pair(&mut secret_key, &mut public_key, &mut seed);
///
/// crypto_ed25519_sign(&mut signature, &secret_key, b"Lorem ipsum");
/// crypto_ed25519_check(&signature, &public_key, b"Lorem ipsum")
///     .expect("signature should be valid");
/// ```
///
/// [`Monocypher` manual]: https://monocypher.org/manual/ed25519
/// [`crypto_eddsa_sign`]: crate::crypto_eddsa_sign
pub fn crypto_ed25519_sign(signature: &mut [u8; 64], secret_key: &[u8; 64], message: &[u8]) {
    let signature_buf = signature.as_mut_ptr();
    let secret_key_buf = secret_key.as_ptr();
    let message_buf = message.as_ptr();

    unsafe {
        mini_monocypher_sys::crypto_ed25519_sign(
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
/// See [`crypto_ed25519_sign`] for a full example of signing and checking.
pub fn crypto_ed25519_check(
    signature: &[u8; 64],
    public_key: &[u8; 32],
    message: &[u8],
) -> Result<(), ErrorKind> {
    let signature_buf = signature.as_ptr();
    let public_key_buf = public_key.as_ptr();
    let message_buf = message.as_ptr();

    let result = unsafe {
        mini_monocypher_sys::crypto_ed25519_check(
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

/// Signs the [`crypto_sha512`] hash of a message, implementing Ed25519ph.
///
/// # Examples
///
/// ```
/// use rand_core::{OsRng, RngCore};
/// use mini_monocypher::{
///   crypto_ed25519_key_pair,
///   crypto_ed25519_ph_check,
///   crypto_ed25519_ph_sign,
///   crypto_sha512,
/// };
///
/// let mut seed = [0u8; 32];
/// let mut secret_key = [0u8; 64];
/// let mut public_key = [0u8; 32];
/// let mut message_hash = [0u8; 64];
/// let mut signature = [0u8; 64];
///
/// OsRng.fill_bytes(&mut seed);
/// crypto_ed25519_key_pair(&mut secret_key, &mut public_key, &mut seed);
/// crypto_sha512(&mut message_hash, b"Lorem ipsum");
///
/// crypto_ed25519_ph_sign(&mut signature, &secret_key, &message_hash);
/// crypto_ed25519_ph_check(&signature, &public_key, &message_hash)
///     .expect("signature should be valid");
/// ```
///
/// [`crypto_sha512`]: crate::crypto_sha512
pub fn crypto_ed25519_ph_sign(
    signature: &mut [u8; 64],
    secret_key: &[u8; 64],
    message_hash: &[u8; 64],
) {
    let signature_buf = signature.as_mut_ptr();
    let secret_key_buf = secret_key.as_ptr();
    let message_hash_buf = message_hash.as_ptr();

    unsafe {
        mini_monocypher_sys::crypto_ed25519_ph_sign(
            signature_buf,
            secret_key_buf,
            message_hash_buf,
        );
    }
}

/// Checks an Ed25519ph signature made by [`crypto_ed25519_ph_sign`]. Returns
/// `()` if it is genuine, or [`ErrorKind::InvalidSignature`] if it is not.
///
/// See [`crypto_ed25519_ph_sign`] for a full example.
pub fn crypto_ed25519_ph_check(
    signature: &[u8; 64],
    public_key: &[u8; 32],
    message_hash: &[u8; 64],
) -> Result<(), ErrorKind> {
    let signature_buf = signature.as_ptr();
    let public_key_buf = public_key.as_ptr();
    let message_hash_buf = message_hash.as_ptr();

    let result = unsafe {
        mini_monocypher_sys::crypto_ed25519_ph_check(
            signature_buf,
            public_key_buf,
            message_hash_buf,
        )
    };

    if result != 0 {
        return Err(ErrorKind::InvalidSignature);
    }

    Ok(())
}
