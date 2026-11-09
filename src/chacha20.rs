/// Derives a 32-byte value `out` from a 32-byte `key` and 16-byte `input`.
///
/// This is the HChaCha20 function, used to hash X25519 shared secrets and to
/// build the extended nonce of [`crypto_chacha20_x`].
///
/// # Examples
///
/// ```
/// use mini_monocypher::crypto_chacha20_h;
///
/// let key = [1u8; 32];
/// let input = [2u8; 16];
/// let mut out = [0u8; 32];
///
/// crypto_chacha20_h(&mut out, &key, &input);
/// ```
pub fn crypto_chacha20_h(out: &mut [u8; 32], key: &[u8; 32], input: &[u8; 16]) {
    let out_buf = out.as_mut_ptr();
    let key_buf = key.as_ptr();
    let input_buf = input.as_ptr();

    unsafe { mini_monocypher_sys::crypto_chacha20_h(out_buf, key_buf, input_buf) }
}

/// Encrypts `plain_text` into `cipher_text` using an 8-byte `nonce`, or decrypts as
/// decryption is the same operation.
///
/// An 8-byte nonce is too small to be selected at random. Prefer
/// [`crypto_chacha20_x`] unless compatibility requires otherwise.
///
/// Returns the counter to pass as `ctr` to continue from where this call
/// stopped. See [`crypto_chacha20_x`] for details of the other arguments.
///
/// # Examples
///
/// ```
/// use mini_monocypher::crypto_chacha20_djb;
///
/// let key = [1u8; 32];
/// let nonce = [2u8; 8];
/// let plain_text = b"Lorem ipsum";
/// let mut cipher_text = [0u8; 11];
///
/// crypto_chacha20_djb(&mut cipher_text, Some(plain_text), &key, &nonce, 0);
/// ```
///
/// # Panics
///
/// This function panics if `plain_text` is longer than `cipher_text`.
pub fn crypto_chacha20_djb(
    cipher_text: &mut [u8],
    plain_text: Option<&[u8]>,
    key: &[u8; 32],
    nonce: &[u8; 8],
    ctr: u64,
) -> u64 {
    let (plain_text_buf, text_size) = match plain_text {
        None => (std::ptr::null(), cipher_text.len()),
        Some(x) => {
            assert!(cipher_text.len() >= x.len());
            (x.as_ptr(), x.len())
        }
    };
    let cipher_text_buf = cipher_text.as_mut_ptr();
    let key_buf = key.as_ptr();
    let nonce_buf = nonce.as_ptr();

    unsafe {
        mini_monocypher_sys::crypto_chacha20_djb(
            cipher_text_buf,
            plain_text_buf,
            text_size,
            key_buf,
            nonce_buf,
            ctr,
        )
    }
}

/// Encrypts `plain_text` into `cipher_text` using a 12-byte `nonce` as described in RFC 8439, or decrypts as
/// decryption is the same operation.
///
/// A 12-byte nonce is too small to be selected at random. Prefer
/// [`crypto_chacha20_x`] unless compatibility requires otherwise.
///
/// Returns the counter to pass as `ctr` to continue from where this call
/// stopped. See [`crypto_chacha20_x`] for details of the other arguments.
///
/// # Examples
///
/// ```
/// use mini_monocypher::crypto_chacha20_ietf;
///
/// let key = [1u8; 32];
/// let nonce = [2u8; 12];
/// let plain_text = b"Lorem ipsum";
/// let mut cipher_text = [0u8; 11];
///
/// crypto_chacha20_ietf(&mut cipher_text, Some(plain_text), &key, &nonce, 0);
/// ```
///
/// # Panics
///
/// This function panics if `plain_text` is longer than `cipher_text`.
pub fn crypto_chacha20_ietf(
    cipher_text: &mut [u8],
    plain_text: Option<&[u8]>,
    key: &[u8; 32],
    nonce: &[u8; 12],
    ctr: u32,
) -> u32 {
    let (plain_text_buf, text_size) = match plain_text {
        None => (std::ptr::null(), cipher_text.len()),
        Some(x) => {
            assert!(cipher_text.len() >= x.len());
            (x.as_ptr(), x.len())
        }
    };
    let cipher_text_buf = cipher_text.as_mut_ptr();
    let key_buf = key.as_ptr();
    let nonce_buf = nonce.as_ptr();

    unsafe {
        mini_monocypher_sys::crypto_chacha20_ietf(
            cipher_text_buf,
            plain_text_buf,
            text_size,
            key_buf,
            nonce_buf,
            ctr,
        )
    }
}

/// Encrypts `plain_text` into `cipher_text` using a 24-byte `nonce`, or decrypts as
/// decryption is the same operation.
///
/// This is a low-level primitive with no authentication, so prefer
/// [`crypto_aead_lock`] for general use. A `nonce` must never be reused with
/// the same `key`. A 24-byte nonce is large enough to be selected at random.
///
/// Only the first `plain_text.len()` bytes of `cipher_text` are written, any
/// remaining bytes are left untouched. If `plain_text` is [`None`], all of
/// `cipher_text` is filled with the raw ChaCha20 stream.
///
/// `ctr` is the number of 64-byte blocks to skip from the start of the stream
/// and should normally be 0.
///
/// Unlike Monocypher, `cipher_text` and `plain_text` cannot be the same buffer
/// for in-place encryption, as Rust does not allow a buffer to be borrowed
/// both mutably and immutably. Separate buffers must be used.
///
/// Returns the counter to pass as `ctr` to continue from where this call
/// stopped.
///
/// It is recommended to read the [`Monocypher` manual] before using this
/// function.
///
/// # Examples
///
/// ```
/// use mini_monocypher::crypto_chacha20_x;
///
/// let key = [1u8; 32];
/// let nonce = [2u8; 24];
/// let plain_text = b"Lorem ipsum";
/// let mut cipher_text = [0u8; 11];
///
/// crypto_chacha20_x(&mut cipher_text, Some(plain_text), &key, &nonce, 0);
/// ```
///
/// # Panics
///
/// This function panics if `plain_text` is longer than `cipher_text`.
///
/// [`Monocypher` manual]: https://monocypher.org/manual/chacha20
/// [`crypto_aead_lock`]: crate::crypto_aead_lock
pub fn crypto_chacha20_x(
    cipher_text: &mut [u8],
    plain_text: Option<&[u8]>,
    key: &[u8; 32],
    nonce: &[u8; 24],
    ctr: u64,
) -> u64 {
    let (plain_text_buf, text_size) = match plain_text {
        None => (std::ptr::null(), cipher_text.len()),
        Some(x) => {
            assert!(cipher_text.len() >= x.len());
            (x.as_ptr(), x.len())
        }
    };
    let cipher_text_buf = cipher_text.as_mut_ptr();
    let key_buf = key.as_ptr();
    let nonce_buf = nonce.as_ptr();

    unsafe {
        mini_monocypher_sys::crypto_chacha20_x(
            cipher_text_buf,
            plain_text_buf,
            text_size,
            key_buf,
            nonce_buf,
            ctr,
        )
    }
}
