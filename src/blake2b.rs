/// Computes a BLAKE2b hash for a message.
///
/// The output hash is written to `hash` which must have a length
/// between 1 and 64. Anything below 32 is discouraged when using
/// BLAKE2b as a general purpose hash function.
///
/// It is recommended to read the [`Monocypher` manual] before using this
/// function.
///
/// # Examples
///
/// ```
/// use mini_monocypher::crypto_blake2b;
///
/// let mut hash = [0u8; 32];
/// let message = b"Lorem ipsum";
/// crypto_blake2b(&mut hash, message);
/// ```
///
/// # Panics
///
/// This function can panic if `hash.len()` is not between 1 and 64.
///
/// [`Monocypher` manual]: https://monocypher.org/manual/blake2b
pub fn crypto_blake2b(hash: &mut [u8], message: &[u8]) {
    assert!(hash.len() > 0 && hash.len() <= 64);

    let hash_buf = hash.as_mut_ptr();
    let message_buf = message.as_ptr();

    unsafe {
        mini_monocypher_sys::crypto_blake2b(hash_buf, hash.len(), message_buf, message.len());
    }
}

/// Computes a BLAKE2b Message Authentication Code (MAC) for a message.
///
/// The output MAC is written to `hash` which must have a length
/// between 1 and 64. The input key material `key` must have a length
/// between 0 and 64.
///
/// # Examples
///
/// In this example we will derive a receive and transmit key from input key
/// material.
///
/// ```
/// use mini_monocypher::crypto_blake2b_keyed;
///
/// use rand_core::{OsRng, RngCore};
/// let mut input_key = [0u8; 32];
/// let mut rx_key = [0u8; 32];
/// let mut tx_key = [0u8; 32];
///
/// // usually key material comes from somewhere but for this example
/// // we will just fill with cryptographic random bytes
/// OsRng.fill_bytes(&mut input_key);
///
/// crypto_blake2b_keyed(&mut rx_key, &input_key, b"receive");
/// crypto_blake2b_keyed(&mut tx_key, &input_key, b"transmit");
/// ```
///
/// # Panics
///
/// This function can panic if `hash.len()` is not between 1 and 64,
/// or if `key.len()` is >64.
pub fn crypto_blake2b_keyed(hash: &mut [u8], key: &[u8], message: &[u8]) {
    assert!(hash.len() > 0 && hash.len() <= 64);
    assert!(key.len() <= 64);

    let hash_buf = hash.as_mut_ptr();
    let key_buf = key.as_ptr();
    let message_buf = message.as_ptr();

    unsafe {
        mini_monocypher_sys::crypto_blake2b_keyed(
            hash_buf,
            hash.len(),
            key_buf,
            key.len(),
            message_buf,
            message.len(),
        );
    }
}

/// BLAKE2b context for use with incremental interface.
///
/// The contents are private as Monocypher trusts them when writing to memory.
///
/// As added safety over Monocypher, the context is also wiped when it goes out
/// of scope, which covers a context abandoned before [`crypto_blake2b_final`].
/// Copies left behind when the context was moved are not affected.
#[repr(transparent)]
pub struct crypto_blake2b_ctx(mini_monocypher_sys::crypto_blake2b_ctx);

impl Drop for crypto_blake2b_ctx {
    fn drop(&mut self) {
        let ctx_ptr = &mut self.0 as *mut mini_monocypher_sys::crypto_blake2b_ctx;

        unsafe {
            mini_monocypher_sys::crypto_wipe(
                ctx_ptr.cast(),
                std::mem::size_of::<mini_monocypher_sys::crypto_blake2b_ctx>(),
            );
        }
    }
}

/// Returns a BLAKE2b context for use with the incremental interface.
/// Needs to be initialised with [`crypto_blake2b_init`].
pub fn crypto_blake2b_ctx_new() -> crypto_blake2b_ctx {
    crypto_blake2b_ctx(mini_monocypher_sys::crypto_blake2b_ctx {
        hash: [0u64; 8],
        input_offset: [0u64; 2],
        input: [0u64; 16],
        input_idx: 0,
        hash_size: 0,
    })
}

/// Initialises a BLAKE2B context for use with the incremental interface.
///
/// `hash_size` specifies the output hash length and must be between 1 and 64.
///
/// Use this interface if you don't want handle streams of data or large files
/// without using too much memory.
///
/// # Examples
///
/// This example demonstrates using the incremental interface.
///
/// ```
/// use mini_monocypher::{
///   crypto_blake2b_ctx_new,
///   crypto_blake2b_init,
///   crypto_blake2b_update,
///   crypto_blake2b_final,
/// };
///
/// let mut hash = [0u8; 32];
/// let mut ctx = crypto_blake2b_ctx_new();
///
/// crypto_blake2b_init(&mut ctx, hash.len());
/// crypto_blake2b_update(&mut ctx, b"Lorem");
/// crypto_blake2b_update(&mut ctx, b" ");
/// crypto_blake2b_update(&mut ctx, b"ipsum");
/// crypto_blake2b_final(&mut ctx, &mut hash);
/// ```
///
/// # Panics
///
/// The function will panic if `hash_size` is not between 1 and 64.
pub fn crypto_blake2b_init(ctx: &mut crypto_blake2b_ctx, hash_size: usize) {
    assert!(hash_size > 0 && hash_size <= 64);

    let ctx_ptr = &mut ctx.0 as *mut mini_monocypher_sys::crypto_blake2b_ctx;

    unsafe {
        mini_monocypher_sys::crypto_blake2b_init(ctx_ptr, hash_size);
    }
}

/// Initialises a BLAKE2b context for computing a Message Authentication Code
/// (MAC) with the incremental interface.
///
/// `hash_size` specifies the output hash length and must be between 1 and 64.
/// The input key material `key` must have a length between 0 and 64. An empty
/// `key` is equivalent to using [`crypto_blake2b_init`].
///
/// # Examples
///
/// This example computes a MAC over a message supplied in pieces.
///
/// ```
/// use mini_monocypher::{
///   crypto_blake2b_ctx_new,
///   crypto_blake2b_keyed_init,
///   crypto_blake2b_update,
///   crypto_blake2b_final,
/// };
///
/// let mut mac = [0u8; 32];
/// let key = [0x42u8; 32];
/// let mut ctx = crypto_blake2b_ctx_new();
///
/// crypto_blake2b_keyed_init(&mut ctx, mac.len(), &key);
/// crypto_blake2b_update(&mut ctx, b"Lorem");
/// crypto_blake2b_update(&mut ctx, b" ");
/// crypto_blake2b_update(&mut ctx, b"ipsum");
/// crypto_blake2b_final(&mut ctx, &mut mac);
/// ```
///
/// # Panics
///
/// This function can panic if `hash_size` is not between 1 and 64,
/// or if `key.len()` is >64.
pub fn crypto_blake2b_keyed_init(ctx: &mut crypto_blake2b_ctx, hash_size: usize, key: &[u8]) {
    assert!(hash_size > 0 && hash_size <= 64);
    assert!(key.len() <= 64);

    let ctx_ptr = &mut ctx.0 as *mut mini_monocypher_sys::crypto_blake2b_ctx;
    let key_buf = key.as_ptr();

    unsafe {
        mini_monocypher_sys::crypto_blake2b_keyed_init(ctx_ptr, hash_size, key_buf, key.len());
    }
}

/// Incrementally computes a BLAKE2b hash based on `ctx` and a message.
///
/// See [`crypto_blake2b_init`] for a full example of using the incremental
/// interface.
pub fn crypto_blake2b_update(ctx: &mut crypto_blake2b_ctx, message: &[u8]) {
    let ctx_ptr = &mut ctx.0 as *mut mini_monocypher_sys::crypto_blake2b_ctx;
    let message_buf = message.as_ptr();

    unsafe {
        mini_monocypher_sys::crypto_blake2b_update(ctx_ptr, message_buf, message.len());
    }
}

/// Computes the final BLAKE2b hash based on `ctx`. The output of the hash
/// will reside in `hash`.
///
/// `hash.len()` must be at least the size specified as
/// `hash_size` in [`crypto_blake2b_init`] and cannot be greater than 64.
///
/// See [`crypto_blake2b_init`] for a full example of using the incremental
/// interface.
///
/// # Panics
///
/// This function will panic if `hash.len()` is >64 or is less than the
/// `hash_size` specified in [`crypto_blake2b_init`].
pub fn crypto_blake2b_final(ctx: &mut crypto_blake2b_ctx, hash: &mut [u8]) {
    assert!(hash.len() > 0 && hash.len() <= 64);
    assert!(hash.len() >= ctx.0.hash_size);
    let ctx_ptr = &mut ctx.0 as *mut mini_monocypher_sys::crypto_blake2b_ctx;
    let hash_buf = hash.as_mut_ptr();

    unsafe {
        mini_monocypher_sys::crypto_blake2b_final(ctx_ptr, hash_buf);
    }
}
