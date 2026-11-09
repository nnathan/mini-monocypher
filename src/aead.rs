use crate::ErrorKind;

/// Encrypts and authenticates a plaintext. The output can then be decrypted
/// by [`crypto_aead_unlock`].
///
/// Given a 32-byte cryptographic quality `key`, and a 24-byte unique or
/// random `nonce`, (optional) additional data `ad`, encrypts `plain_text` into
/// `cipher_text` and `mac`.
///
/// `cipher_text.len()` must be >= `plain_text.len()`.
///
/// Unlike Monocypher, `cipher_text` and `plain_text` cannot be the same buffer
/// for in-place encryption, as Rust does not allow a buffer to be borrowed
/// both mutably and immutably. Separate buffers must be used.
///
/// It is recommended to read the AEAD section of the [`Monocypher` manual]
/// for the full intricacies on using the `crypto_aead_{lock,unlock}` interface.
///
/// # Examples
///
/// This example is a full end to end example of encryption and decryption:
///
/// ```
/// use rand_core::{OsRng, RngCore};
/// use mini_monocypher::{crypto_aead_lock, crypto_aead_unlock};
///
/// let mut key = [0u8; 32];
/// let mut nonce = [0u8; 24];
/// let ad = b"authentication data";
/// let plaintext = b"hello world";
/// let mut aead_ciphertext = [0u8; 11+16]; // plaintext.len() + MAC
///
/// OsRng.fill_bytes(&mut key);
/// OsRng.fill_bytes(&mut nonce);
///
/// // encrypt
///
/// // note: the aead_ciphertext is the ciphertext (size is plaintext.len())
/// // concatenated with the MAC. If using random nonce, you would also want
/// // to include nonce as part of the aead_ciphertext as well.
/// let (ciphertext_detached, mac) = aead_ciphertext.split_at_mut(plaintext.len());
///
/// crypto_aead_lock(
///     ciphertext_detached,
///     mac.try_into().unwrap(),
///     &key,
///     &nonce,
///     Some(ad),
///     plaintext,
/// );
///
/// // decrypt
///
/// let mut plaintext = [0u8; 11];
///
/// crypto_aead_unlock(
///     &mut plaintext,
///     aead_ciphertext[(aead_ciphertext.len() - 16)..].try_into().unwrap(),
///     &key,
///     &nonce,
///     Some(ad),
///     &aead_ciphertext[..aead_ciphertext.len() - 16]
/// ).expect("decryption should succeed");
/// ```
///
/// # Panics
///
/// This function panics if `cipher_text.len() < plain_text.len()`.
///
/// [`Monocypher` manual]: https://monocypher.org/manual/aead
pub fn crypto_aead_lock(
    cipher_text: &mut [u8],
    mac: &mut [u8; 16],
    key: &[u8; 32],
    nonce: &[u8; 24],
    ad: Option<&[u8]>,
    plain_text: &[u8],
) {
    assert!(cipher_text.len() >= plain_text.len());

    let cipher_text_buf = cipher_text.as_mut_ptr();
    let mac_buf = mac.as_mut_ptr();
    let key_buf = key.as_ptr();
    let nonce_buf = nonce.as_ptr();
    let (ad_buf, ad_len) = match ad {
        None => (std::ptr::null(), 0),
        Some(x) => (x.as_ptr(), x.len()),
    };
    let plain_text_buf = plain_text.as_ptr();

    unsafe {
        mini_monocypher_sys::crypto_aead_lock(
            cipher_text_buf,
            mac_buf,
            key_buf,
            nonce_buf,
            ad_buf,
            ad_len,
            plain_text_buf,
            plain_text.len(),
        );
    }
}

/// Decrypts an authenticated ciphertext. Returns `()` if successful,
/// or [`ErrorKind`] if there is a decryption failure.
///
/// Given a 32-byte cryptographic quality `key`, a 24-byte `nonce`,
/// (optional) additional data `ad`, decrypt `cipher_text` and 16-byte `mac` into
/// `plain_text`.
///
/// `plain_text.len()` must be >= `cipher_text.len()`.
///
/// Unlike Monocypher, `plain_text` and `cipher_text` cannot be the same buffer
/// for in-place decryption, as Rust does not allow a buffer to be borrowed
/// both mutably and immutably. Separate buffers must be used.
///
/// See [`crypto_aead_lock`] for a full round trip example of performing
/// a lock (encrypt) and unlock (decrypt).
///
/// It crypto_aead_lockis recommended to read the AEAD section of the [`Monocypher` manual]
/// for the full intricacies on using the `crypto_aead_{lock,unlock}` interface.
///
/// # Panics
///
/// This function panics if `plain_text.len() < cipher_text.len()`.
///
/// [`Monocypher` manual]: https://monocypher.org/manual/aead
pub fn crypto_aead_unlock(
    plain_text: &mut [u8],
    mac: &[u8; 16],
    key: &[u8; 32],
    nonce: &[u8; 24],
    ad: Option<&[u8]>,
    cipher_text: &[u8],
) -> Result<(), ErrorKind> {
    assert!(plain_text.len() >= cipher_text.len());

    let plain_text_buf = plain_text.as_mut_ptr();
    let mac_buf = mac.as_ptr();
    let key_buf = key.as_ptr();
    let nonce_buf = nonce.as_ptr();
    let (ad_buf, ad_len) = match ad {
        None => (std::ptr::null(), 0),
        Some(x) => (x.as_ptr(), x.len()),
    };
    let cipher_text_buf = cipher_text.as_ptr();

    unsafe {
        let result = mini_monocypher_sys::crypto_aead_unlock(
            plain_text_buf,
            mac_buf,
            key_buf,
            nonce_buf,
            ad_buf,
            ad_len,
            cipher_text_buf,
            cipher_text.len(),
        );

        if result != 0 {
            return Err(ErrorKind::AuthenticationFailure);
        }
    }

    Ok(())
}

/// AEAD context for use with the incremental interface.
///
/// The contents are private as they include key material, and the context
/// cannot be copied as that would reuse the same key stream.
///
/// Monocypher says to wipe the context with `crypto_wipe` once the last chunk
/// has been processed. As added safety, this is done automatically when the
/// context goes out of scope. Copies left behind when the context was moved
/// are not affected.
#[repr(transparent)]
pub struct crypto_aead_ctx(mini_monocypher_sys::crypto_aead_ctx);

impl Drop for crypto_aead_ctx {
    fn drop(&mut self) {
        let ctx_ptr = &mut self.0 as *mut mini_monocypher_sys::crypto_aead_ctx;

        unsafe {
            mini_monocypher_sys::crypto_wipe(
                ctx_ptr.cast(),
                std::mem::size_of::<mini_monocypher_sys::crypto_aead_ctx>(),
            );
        }
    }
}

/// Returns an AEAD context for use with the incremental interface.
///
/// The context must be initialised with [`crypto_aead_init_x`],
/// [`crypto_aead_init_djb`], or [`crypto_aead_init_ietf`].
///
/// **Warning:** as with Monocypher, this is not checked. Skipping
/// initialisation silently encrypts with an all-zero key, so anyone can
/// decrypt the result.
pub fn crypto_aead_ctx_new() -> crypto_aead_ctx {
    crypto_aead_ctx(mini_monocypher_sys::crypto_aead_ctx {
        counter: 0,
        key: [0u8; 32],
        nonce: [0u8; 8],
    })
}

/// Initialises an AEAD context for use with the incremental interface, using
/// a 24-byte `nonce` that can be selected at random.
///
/// A `nonce` must never be reused with the same `key`.
///
/// See [`crypto_aead_write`] for a full example of using the incremental
/// interface.
pub fn crypto_aead_init_x(ctx: &mut crypto_aead_ctx, key: &[u8; 32], nonce: &[u8; 24]) {
    let ctx_ptr = &mut ctx.0 as *mut mini_monocypher_sys::crypto_aead_ctx;
    let key_buf = key.as_ptr();
    let nonce_buf = nonce.as_ptr();

    unsafe {
        mini_monocypher_sys::crypto_aead_init_x(ctx_ptr, key_buf, nonce_buf);
    }
}

/// Initialises an AEAD context for use with the incremental interface, using
/// an 8-byte `nonce` that is too small to be selected at random.
///
/// A `nonce` must never be reused with the same `key`.
///
/// See [`crypto_aead_write`] for a full example of using the incremental
/// interface.
pub fn crypto_aead_init_djb(ctx: &mut crypto_aead_ctx, key: &[u8; 32], nonce: &[u8; 8]) {
    let ctx_ptr = &mut ctx.0 as *mut mini_monocypher_sys::crypto_aead_ctx;
    let key_buf = key.as_ptr();
    let nonce_buf = nonce.as_ptr();

    unsafe {
        mini_monocypher_sys::crypto_aead_init_djb(ctx_ptr, key_buf, nonce_buf);
    }
}

/// Initialises an AEAD context for use with the incremental interface, using
/// a 12-byte `nonce` that is too small to be selected at random.
/// Each chunk is limited to 2^38 - 64 bytes.
///
/// A `nonce` must never be reused with the same `key`.
///
/// See [`crypto_aead_write`] for a full example of using the incremental
/// interface.
pub fn crypto_aead_init_ietf(ctx: &mut crypto_aead_ctx, key: &[u8; 32], nonce: &[u8; 12]) {
    let ctx_ptr = &mut ctx.0 as *mut mini_monocypher_sys::crypto_aead_ctx;
    let key_buf = key.as_ptr();
    let nonce_buf = nonce.as_ptr();

    unsafe {
        mini_monocypher_sys::crypto_aead_init_ietf(ctx_ptr, key_buf, nonce_buf);
    }
}

/// Encrypts and authenticates one chunk of a stream. The output can then be
/// decrypted by [`crypto_aead_read`], with chunks read in the order written.
///
/// Reordered chunks are detected, but truncation is not: the last chunk must
/// be marked by the caller, for example by using `ad` to mark it differently.
///
/// Only the first `plain_text.len()` bytes of `cipher_text` are written, any
/// remaining bytes are left untouched.
///
/// Unlike Monocypher, `cipher_text` and `plain_text` cannot be the same buffer
/// for in-place encryption, as Rust does not allow a buffer to be borrowed
/// both mutably and immutably. Separate buffers must be used.
///
/// It is recommended to read the AEAD section of the [`Monocypher` manual]
/// for the full intricacies on using the incremental interface.
///
/// # Examples
///
/// This example encrypts and decrypts a stream of two chunks.
///
/// ```
/// use rand_core::{OsRng, RngCore};
/// use mini_monocypher::{
///   crypto_aead_ctx_new,
///   crypto_aead_init_x,
///   crypto_aead_write,
///   crypto_aead_read,
/// };
///
/// let mut key = [0u8; 32];
/// let mut nonce = [0u8; 24];
///
/// OsRng.fill_bytes(&mut key);
/// OsRng.fill_bytes(&mut nonce);
///
/// let mut cipher_text = [[0u8; 5]; 2];
/// let mut mac = [[0u8; 16]; 2];
///
/// let mut ctx = crypto_aead_ctx_new();
/// crypto_aead_init_x(&mut ctx, &key, &nonce);
/// crypto_aead_write(&mut ctx, &mut cipher_text[0], &mut mac[0], None, b"Lorem");
/// crypto_aead_write(&mut ctx, &mut cipher_text[1], &mut mac[1], None, b"ipsum");
///
/// let mut plain_text = [0u8; 5];
///
/// let mut ctx = crypto_aead_ctx_new();
/// crypto_aead_init_x(&mut ctx, &key, &nonce);
/// crypto_aead_read(&mut ctx, &mut plain_text, &mac[0], None, &cipher_text[0])
///     .expect("decryption should succeed");
/// assert_eq!(&plain_text, b"Lorem");
/// crypto_aead_read(&mut ctx, &mut plain_text, &mac[1], None, &cipher_text[1])
///     .expect("decryption should succeed");
/// assert_eq!(&plain_text, b"ipsum");
/// ```
///
/// # Panics
///
/// This function panics if `cipher_text.len() < plain_text.len()`.
///
/// [`Monocypher` manual]: https://monocypher.org/manual/aead
pub fn crypto_aead_write(
    ctx: &mut crypto_aead_ctx,
    cipher_text: &mut [u8],
    mac: &mut [u8; 16],
    ad: Option<&[u8]>,
    plain_text: &[u8],
) {
    assert!(cipher_text.len() >= plain_text.len());

    let ctx_ptr = &mut ctx.0 as *mut mini_monocypher_sys::crypto_aead_ctx;
    let cipher_text_buf = cipher_text.as_mut_ptr();
    let mac_buf = mac.as_mut_ptr();
    let (ad_buf, ad_len) = match ad {
        None => (std::ptr::null(), 0),
        Some(x) => (x.as_ptr(), x.len()),
    };
    let plain_text_buf = plain_text.as_ptr();

    unsafe {
        mini_monocypher_sys::crypto_aead_write(
            ctx_ptr,
            cipher_text_buf,
            mac_buf,
            ad_buf,
            ad_len,
            plain_text_buf,
            plain_text.len(),
        );
    }
}

/// Decrypts one authenticated chunk of a stream. Returns `()` if successful,
/// or [`ErrorKind::AuthenticationFailure`] if there is a decryption failure.
///
/// On failure nothing is written to `plain_text` and `ctx` is unchanged.
///
/// Only the first `cipher_text.len()` bytes of `plain_text` are written, any
/// remaining bytes are left untouched.
///
/// Unlike Monocypher, `plain_text` and `cipher_text` cannot be the same buffer
/// for in-place decryption, as Rust does not allow a buffer to be borrowed
/// both mutably and immutably. Separate buffers must be used.
///
/// See [`crypto_aead_write`] for a full example of using the incremental
/// interface.
///
/// # Panics
///
/// This function panics if `plain_text.len() < cipher_text.len()`.
pub fn crypto_aead_read(
    ctx: &mut crypto_aead_ctx,
    plain_text: &mut [u8],
    mac: &[u8; 16],
    ad: Option<&[u8]>,
    cipher_text: &[u8],
) -> Result<(), ErrorKind> {
    assert!(plain_text.len() >= cipher_text.len());

    let ctx_ptr = &mut ctx.0 as *mut mini_monocypher_sys::crypto_aead_ctx;
    let plain_text_buf = plain_text.as_mut_ptr();
    let mac_buf = mac.as_ptr();
    let (ad_buf, ad_len) = match ad {
        None => (std::ptr::null(), 0),
        Some(x) => (x.as_ptr(), x.len()),
    };
    let cipher_text_buf = cipher_text.as_ptr();

    let result = unsafe {
        mini_monocypher_sys::crypto_aead_read(
            ctx_ptr,
            plain_text_buf,
            mac_buf,
            ad_buf,
            ad_len,
            cipher_text_buf,
            cipher_text.len(),
        )
    };

    if result != 0 {
        return Err(ErrorKind::AuthenticationFailure);
    }

    Ok(())
}
