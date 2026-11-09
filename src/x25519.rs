/// Generate an X25519 public key from a secret key.
///
/// # Examples
///
/// ```
/// use rand_core::{OsRng, RngCore};
/// use mini_monocypher::crypto_x25519_public_key;
///
/// let mut secret_key = [0u8; 32];
/// let mut public_key = [0u8; 32];
///
/// OsRng.fill_bytes(&mut secret_key);
/// crypto_x25519_public_key(&mut public_key, &secret_key);
/// ```
pub fn crypto_x25519_public_key(public_key: &mut [u8; 32], secret_key: &[u8; 32]) {
    let pub_buf = public_key.as_mut_ptr();
    let secret_buf = secret_key.as_ptr();

    unsafe { mini_monocypher_sys::crypto_x25519_public_key(pub_buf, secret_buf) }
}

/// Perform an X25519 key exchange between `your_secret_key` and `their_public_key`.
///
/// It is recommended to read the [`Monocypher` manual] before using this
/// function.
///
/// # Examples
///
/// ```
/// use rand_core::{OsRng, RngCore};
/// use mini_monocypher::{crypto_x25519, crypto_x25519_public_key};
///
/// let mut your_secret_key = [0u8; 32];
/// OsRng.fill_bytes(&mut your_secret_key);
///
/// // generate other party's public key
/// let mut their_secret_key = [0u8; 32]; // assume you don't know this
/// let mut their_public_key = [0u8; 32];
/// OsRng.fill_bytes(&mut their_secret_key);
/// crypto_x25519_public_key(&mut their_public_key, &their_secret_key);
///
/// // assume you only have: your_secret_key and their_public_key
/// let mut shared_secret = [0u8; 32];
/// crypto_x25519(&mut shared_secret, &your_secret_key, &their_public_key);
///
/// // to use shared_secret, use a crypto_blake2b as a KDF
/// // or crypto_blake2b_keyed with key=shared_secret to derive
/// // multiple keys
/// ```
///
/// [`Monocypher` manual]: https://monocypher.org/manual/x25519
pub fn crypto_x25519(
    raw_shared_secret: &mut [u8; 32],
    your_secret_key: &[u8; 32],
    their_public_key: &[u8; 32],
) {
    let raw_buf = raw_shared_secret.as_mut_ptr();
    let secret_buf = your_secret_key.as_ptr();
    let pub_buf = their_public_key.as_ptr();

    unsafe { mini_monocypher_sys::crypto_x25519(raw_buf, secret_buf, pub_buf) }
}

/// Converts an X25519 public key to an EdDSA public key.
///
/// This only converts public keys, not secret keys.
///
/// # Examples
///
/// ```
/// use rand_core::{OsRng, RngCore};
/// use mini_monocypher::{crypto_x25519_public_key, crypto_x25519_to_eddsa};
///
/// let mut secret_key = [0u8; 32];
/// let mut public_key = [0u8; 32];
/// let mut eddsa = [0u8; 32];
///
/// OsRng.fill_bytes(&mut secret_key);
/// crypto_x25519_public_key(&mut public_key, &secret_key);
/// crypto_x25519_to_eddsa(&mut eddsa, &public_key);
/// ```
pub fn crypto_x25519_to_eddsa(eddsa: &mut [u8; 32], x25519: &[u8; 32]) {
    let eddsa_buf = eddsa.as_mut_ptr();
    let x25519_buf = x25519.as_ptr();

    unsafe { mini_monocypher_sys::crypto_x25519_to_eddsa(eddsa_buf, x25519_buf) }
}

/// Performs the inverse of [`crypto_x25519`], writing the original point to
/// `blind_salt`. This is used for blinding in protocols such as OPRF.
///
/// Be aware that exponential blinding is less secure than Diffie-Hellman key
/// exchange.
///
/// # Examples
///
/// ```
/// use rand_core::{OsRng, RngCore};
/// use mini_monocypher::{
///   crypto_x25519,
///   crypto_x25519_inverse,
///   crypto_x25519_public_key,
/// };
///
/// let mut b = [0u8; 32];
/// let mut private_key = [0u8; 32];
/// let mut base = [0u8; 32];
/// let mut curve_point = [0u8; 32];
/// let mut blind_salt = [0u8; 32];
///
/// OsRng.fill_bytes(&mut b);
/// OsRng.fill_bytes(&mut private_key);
///
/// crypto_x25519_public_key(&mut base, &b);
/// crypto_x25519(&mut curve_point, &private_key, &base);
/// crypto_x25519_inverse(&mut blind_salt, &private_key, &curve_point);
///
/// assert_eq!(blind_salt, base);
/// ```
pub fn crypto_x25519_inverse(
    blind_salt: &mut [u8; 32],
    private_key: &[u8; 32],
    curve_point: &[u8; 32],
) {
    let blind_salt_buf = blind_salt.as_mut_ptr();
    let private_key_buf = private_key.as_ptr();
    let curve_point_buf = curve_point.as_ptr();

    unsafe {
        mini_monocypher_sys::crypto_x25519_inverse(
            blind_salt_buf,
            private_key_buf,
            curve_point_buf,
        )
    }
}

/// Generates an X25519 public key for use with Elligator, with smaller code.
///
/// The public key is compatible with [`crypto_x25519`], but this function
/// leaks 3 bits of the secret key. Only use it for ephemeral keys that will be
/// hidden with Elligator, otherwise use [`crypto_x25519_public_key`].
///
/// # Examples
///
/// ```
/// use rand_core::{OsRng, RngCore};
/// use mini_monocypher::crypto_x25519_dirty_small;
///
/// let mut sk = [0u8; 32];
/// let mut pk = [0u8; 32];
///
/// OsRng.fill_bytes(&mut sk);
/// crypto_x25519_dirty_small(&mut pk, &sk);
/// ```
pub fn crypto_x25519_dirty_small(pk: &mut [u8; 32], sk: &[u8; 32]) {
    let pk_buf = pk.as_mut_ptr();
    let sk_buf = sk.as_ptr();

    unsafe { mini_monocypher_sys::crypto_x25519_dirty_small(pk_buf, sk_buf) }
}

/// Generates an X25519 public key for use with Elligator, optimised for speed.
///
/// The public key is compatible with [`crypto_x25519`], but this function
/// leaks 3 bits of the secret key. Only use it for ephemeral keys that will be
/// hidden with Elligator, otherwise use [`crypto_x25519_public_key`].
///
/// # Examples
///
/// ```
/// use rand_core::{OsRng, RngCore};
/// use mini_monocypher::crypto_x25519_dirty_fast;
///
/// let mut sk = [0u8; 32];
/// let mut pk = [0u8; 32];
///
/// OsRng.fill_bytes(&mut sk);
/// crypto_x25519_dirty_fast(&mut pk, &sk);
/// ```
pub fn crypto_x25519_dirty_fast(pk: &mut [u8; 32], sk: &[u8; 32]) {
    let pk_buf = pk.as_mut_ptr();
    let sk_buf = sk.as_ptr();

    unsafe { mini_monocypher_sys::crypto_x25519_dirty_fast(pk_buf, sk_buf) }
}
