/// Computes a SHA-512 hash of a message.
///
/// This is provided for compatibility with other systems. It is generally
/// recommended to use [`crypto_blake2b`] instead. SHA-512 is vulnerable to
/// length extension attacks, so it cannot be used directly as a message
/// authentication code, and it is not suitable for hashing passwords.
///
/// It is recommended to read the [`Monocypher` manual] before using this
/// function.
///
/// # Examples
///
/// ```
/// use mini_monocypher::crypto_sha512;
///
/// let mut hash = [0u8; 64];
/// crypto_sha512(&mut hash, b"Lorem ipsum");
/// ```
///
/// [`Monocypher` manual]: https://monocypher.org/manual/sha512
/// [`crypto_blake2b`]: crate::crypto_blake2b
pub fn crypto_sha512(hash: &mut [u8; 64], message: &[u8]) {
    let hash_buf = hash.as_mut_ptr();
    let message_buf = message.as_ptr();

    unsafe {
        mini_monocypher_sys::crypto_sha512(hash_buf, message_buf, message.len());
    }
}

/// SHA-512 context for use with incremental interface.
///
/// The contents are private as Monocypher trusts them when writing to memory.
///
/// As added safety over Monocypher, the context is also wiped when it goes out
/// of scope, which covers a context abandoned before [`crypto_sha512_final`].
/// Copies left behind when the context was moved are not affected.
#[repr(transparent)]
pub struct crypto_sha512_ctx(mini_monocypher_sys::crypto_sha512_ctx);

impl Drop for crypto_sha512_ctx {
    fn drop(&mut self) {
        let ctx_ptr = &mut self.0 as *mut mini_monocypher_sys::crypto_sha512_ctx;

        unsafe {
            mini_monocypher_sys::crypto_wipe(
                ctx_ptr.cast(),
                std::mem::size_of::<mini_monocypher_sys::crypto_sha512_ctx>(),
            );
        }
    }
}

/// Returns a SHA-512 context for use with the incremental interface.
/// Needs to be initialised with [`crypto_sha512_init`].
pub fn crypto_sha512_ctx_new() -> crypto_sha512_ctx {
    crypto_sha512_ctx(mini_monocypher_sys::crypto_sha512_ctx {
        hash: [0u64; 8],
        input: [0u64; 16],
        input_size: [0u64; 2],
        input_idx: 0,
    })
}

/// Initialises a SHA-512 context for use with the incremental interface.
///
/// # Examples
///
/// ```
/// use mini_monocypher::{
///   crypto_sha512_ctx_new,
///   crypto_sha512_init,
///   crypto_sha512_update,
///   crypto_sha512_final,
/// };
///
/// let mut hash = [0u8; 64];
/// let mut ctx = crypto_sha512_ctx_new();
///
/// crypto_sha512_init(&mut ctx);
/// crypto_sha512_update(&mut ctx, b"Lorem");
/// crypto_sha512_update(&mut ctx, b" ipsum");
/// crypto_sha512_final(&mut ctx, &mut hash);
/// ```
pub fn crypto_sha512_init(ctx: &mut crypto_sha512_ctx) {
    let ctx_ptr = &mut ctx.0 as *mut mini_monocypher_sys::crypto_sha512_ctx;

    unsafe {
        mini_monocypher_sys::crypto_sha512_init(ctx_ptr);
    }
}

/// Incrementally computes a SHA-512 hash based on `ctx` and a message.
///
/// See [`crypto_sha512_init`] for a full example of using the incremental
/// interface.
pub fn crypto_sha512_update(ctx: &mut crypto_sha512_ctx, message: &[u8]) {
    let ctx_ptr = &mut ctx.0 as *mut mini_monocypher_sys::crypto_sha512_ctx;
    let message_buf = message.as_ptr();

    unsafe {
        mini_monocypher_sys::crypto_sha512_update(ctx_ptr, message_buf, message.len());
    }
}

/// Computes the final SHA-512 hash based on `ctx`. The output of the hash
/// will reside in `hash`.
///
/// See [`crypto_sha512_init`] for a full example of using the incremental
/// interface.
pub fn crypto_sha512_final(ctx: &mut crypto_sha512_ctx, hash: &mut [u8; 64]) {
    let ctx_ptr = &mut ctx.0 as *mut mini_monocypher_sys::crypto_sha512_ctx;
    let hash_buf = hash.as_mut_ptr();

    unsafe {
        mini_monocypher_sys::crypto_sha512_final(ctx_ptr, hash_buf);
    }
}

/// Computes an HMAC-SHA-512 Message Authentication Code (MAC) for a message.
///
/// This is provided for compatibility with other systems. It is generally
/// recommended to use [`crypto_blake2b_keyed`] instead. The MAC can safely be
/// truncated down to 16 bytes, and should be compared with [`crypto_verify16`],
/// [`crypto_verify32`], or [`crypto_verify64`].
///
/// # Examples
///
/// ```
/// use mini_monocypher::crypto_sha512_hmac;
///
/// let key = [1u8; 32];
/// let mut hmac = [0u8; 64];
///
/// crypto_sha512_hmac(&mut hmac, &key, b"Lorem ipsum");
/// ```
///
/// [`crypto_blake2b_keyed`]: crate::crypto_blake2b_keyed
/// [`crypto_verify16`]: crate::crypto_verify16
/// [`crypto_verify32`]: crate::crypto_verify32
/// [`crypto_verify64`]: crate::crypto_verify64
pub fn crypto_sha512_hmac(hmac: &mut [u8; 64], key: &[u8], message: &[u8]) {
    let hmac_buf = hmac.as_mut_ptr();
    let key_buf = key.as_ptr();
    let message_buf = message.as_ptr();

    unsafe {
        mini_monocypher_sys::crypto_sha512_hmac(
            hmac_buf,
            key_buf,
            key.len(),
            message_buf,
            message.len(),
        );
    }
}

/// HMAC-SHA-512 context for use with incremental interface.
///
/// The contents are private as Monocypher trusts them when writing to memory.
///
/// As added safety over Monocypher, the context is also wiped when it goes out
/// of scope, which covers a context abandoned before
/// [`crypto_sha512_hmac_final`]. Copies left behind when the context was moved
/// are not affected.
#[repr(transparent)]
pub struct crypto_sha512_hmac_ctx(mini_monocypher_sys::crypto_sha512_hmac_ctx);

impl Drop for crypto_sha512_hmac_ctx {
    fn drop(&mut self) {
        let ctx_ptr = &mut self.0 as *mut mini_monocypher_sys::crypto_sha512_hmac_ctx;

        unsafe {
            mini_monocypher_sys::crypto_wipe(
                ctx_ptr.cast(),
                std::mem::size_of::<mini_monocypher_sys::crypto_sha512_hmac_ctx>(),
            );
        }
    }
}

/// Returns an HMAC-SHA-512 context for use with the incremental interface.
/// Needs to be initialised with [`crypto_sha512_hmac_init`].
pub fn crypto_sha512_hmac_ctx_new() -> crypto_sha512_hmac_ctx {
    crypto_sha512_hmac_ctx(mini_monocypher_sys::crypto_sha512_hmac_ctx {
        key: [0u8; 128],
        ctx: mini_monocypher_sys::crypto_sha512_ctx {
            hash: [0u64; 8],
            input: [0u64; 16],
            input_size: [0u64; 2],
            input_idx: 0,
        },
    })
}

/// Initialises an HMAC-SHA-512 context for use with the incremental interface.
///
/// # Examples
///
/// ```
/// use mini_monocypher::{
///   crypto_sha512_hmac_ctx_new,
///   crypto_sha512_hmac_init,
///   crypto_sha512_hmac_update,
///   crypto_sha512_hmac_final,
/// };
///
/// let key = [1u8; 32];
/// let mut hmac = [0u8; 64];
/// let mut ctx = crypto_sha512_hmac_ctx_new();
///
/// crypto_sha512_hmac_init(&mut ctx, &key);
/// crypto_sha512_hmac_update(&mut ctx, b"Lorem");
/// crypto_sha512_hmac_update(&mut ctx, b" ipsum");
/// crypto_sha512_hmac_final(&mut ctx, &mut hmac);
/// ```
pub fn crypto_sha512_hmac_init(ctx: &mut crypto_sha512_hmac_ctx, key: &[u8]) {
    let ctx_ptr = &mut ctx.0 as *mut mini_monocypher_sys::crypto_sha512_hmac_ctx;
    let key_buf = key.as_ptr();

    unsafe {
        mini_monocypher_sys::crypto_sha512_hmac_init(ctx_ptr, key_buf, key.len());
    }
}

/// Incrementally computes an HMAC-SHA-512 based on `ctx` and a message.
///
/// See [`crypto_sha512_hmac_init`] for a full example of using the incremental
/// interface.
pub fn crypto_sha512_hmac_update(ctx: &mut crypto_sha512_hmac_ctx, message: &[u8]) {
    let ctx_ptr = &mut ctx.0 as *mut mini_monocypher_sys::crypto_sha512_hmac_ctx;
    let message_buf = message.as_ptr();

    unsafe {
        mini_monocypher_sys::crypto_sha512_hmac_update(ctx_ptr, message_buf, message.len());
    }
}

/// Computes the final HMAC-SHA-512 based on `ctx`. The output will reside in
/// `hmac`.
///
/// See [`crypto_sha512_hmac_init`] for a full example of using the incremental
/// interface.
pub fn crypto_sha512_hmac_final(ctx: &mut crypto_sha512_hmac_ctx, hmac: &mut [u8; 64]) {
    let ctx_ptr = &mut ctx.0 as *mut mini_monocypher_sys::crypto_sha512_hmac_ctx;
    let hmac_buf = hmac.as_mut_ptr();

    unsafe {
        mini_monocypher_sys::crypto_sha512_hmac_final(ctx_ptr, hmac_buf);
    }
}

/// Expands a uniformly random pseudo-random key `prk` into `okm` using the
/// expand phase of HKDF-SHA-512.
///
/// `prk` should be at least 32 bytes long. `info` is an optional domain
/// separation string.
///
/// # Examples
///
/// ```
/// use mini_monocypher::crypto_sha512_hkdf_expand;
///
/// let prk = [1u8; 64];
/// let mut okm = [0u8; 80];
///
/// crypto_sha512_hkdf_expand(&mut okm, &prk, Some(b"domain"));
/// ```
///
/// # Panics
///
/// This function panics if `okm.len()` is >16320.
pub fn crypto_sha512_hkdf_expand(okm: &mut [u8], prk: &[u8], info: Option<&[u8]>) {
    assert!(okm.len() <= 16320);

    let okm_buf = okm.as_mut_ptr();
    let prk_buf = prk.as_ptr();
    let (info_buf, info_len) = match info {
        None => (std::ptr::null(), 0),
        Some(x) => (x.as_ptr(), x.len()),
    };

    unsafe {
        mini_monocypher_sys::crypto_sha512_hkdf_expand(
            okm_buf,
            okm.len(),
            prk_buf,
            prk.len(),
            info_buf,
            info_len,
        );
    }
}

/// Derives output key material `okm` from input key material `ikm` using
/// HKDF-SHA-512.
///
/// `salt` is an optional random salt which should contain at least 16 bytes
/// when used. `info` is an optional domain separation string.
///
/// # Examples
///
/// ```
/// use mini_monocypher::crypto_sha512_hkdf;
///
/// let ikm = [1u8; 32];
/// let salt = [2u8; 16];
/// let mut okm = [0u8; 32];
///
/// crypto_sha512_hkdf(&mut okm, &ikm, Some(&salt), Some(b"domain"));
/// ```
///
/// # Panics
///
/// This function panics if `okm.len()` is >16320.
pub fn crypto_sha512_hkdf(
    okm: &mut [u8],
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: Option<&[u8]>,
) {
    assert!(okm.len() <= 16320);

    let okm_buf = okm.as_mut_ptr();
    let ikm_buf = ikm.as_ptr();
    let (salt_buf, salt_len) = match salt {
        None => (std::ptr::null(), 0),
        Some(x) => (x.as_ptr(), x.len()),
    };
    let (info_buf, info_len) = match info {
        None => (std::ptr::null(), 0),
        Some(x) => (x.as_ptr(), x.len()),
    };

    unsafe {
        mini_monocypher_sys::crypto_sha512_hkdf(
            okm_buf,
            okm.len(),
            ikm_buf,
            ikm.len(),
            salt_buf,
            salt_len,
            info_buf,
            info_len,
        );
    }
}
