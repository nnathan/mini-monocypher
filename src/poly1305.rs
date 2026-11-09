/// Computes a Poly1305 Message Authentication Code (MAC) for a message.
///
/// Poly1305 is a one-time authenticator: a `key` must only ever be used for
/// a single message, and must be random and secret. For general use prefer
/// [`crypto_aead_lock`] or [`crypto_blake2b_keyed`].
///
/// It is recommended to read the Poly1305 section of the [`Monocypher` manual]
/// before using this function.
///
/// # Examples
///
/// ```
/// use rand_core::{OsRng, RngCore};
/// use mini_monocypher::crypto_poly1305;
///
/// let mut key = [0u8; 32];
/// let mut mac = [0u8; 16];
///
/// OsRng.fill_bytes(&mut key);
/// crypto_poly1305(&mut mac, b"Lorem ipsum", &key);
/// ```
///
/// [`Monocypher` manual]: https://monocypher.org/manual/poly1305
/// [`crypto_aead_lock`]: crate::crypto_aead_lock
/// [`crypto_blake2b_keyed`]: crate::crypto_blake2b_keyed
pub fn crypto_poly1305(mac: &mut [u8; 16], message: &[u8], key: &[u8; 32]) {
    let mac_buf = mac.as_mut_ptr();
    let message_buf = message.as_ptr();
    let key_buf = key.as_ptr();

    unsafe {
        mini_monocypher_sys::crypto_poly1305(mac_buf, message_buf, message.len(), key_buf);
    }
}

/// Poly1305 context for use with incremental interface.
///
/// The contents are private as Monocypher trusts them when writing to memory.
///
/// As added safety over Monocypher, the context is also wiped when it goes out
/// of scope, which covers a context abandoned before [`crypto_poly1305_final`].
/// Copies left behind when the context was moved are not affected.
#[repr(transparent)]
pub struct crypto_poly1305_ctx(mini_monocypher_sys::crypto_poly1305_ctx);

impl Drop for crypto_poly1305_ctx {
    fn drop(&mut self) {
        let ctx_ptr = &mut self.0 as *mut mini_monocypher_sys::crypto_poly1305_ctx;

        unsafe {
            mini_monocypher_sys::crypto_wipe(
                ctx_ptr.cast(),
                std::mem::size_of::<mini_monocypher_sys::crypto_poly1305_ctx>(),
            );
        }
    }
}

/// Returns a Poly1305 context for use with the incremental interface.
///
/// The context must be initialised with [`crypto_poly1305_init`]. As with
/// Monocypher, this is not checked: skipping it silently produces an
/// all-zero MAC.
pub fn crypto_poly1305_ctx_new() -> crypto_poly1305_ctx {
    crypto_poly1305_ctx(mini_monocypher_sys::crypto_poly1305_ctx {
        c: [0u8; 16],
        c_idx: 0,
        r: [0u32; 4],
        pad: [0u32; 4],
        h: [0u32; 5],
    })
}

/// Initialises a Poly1305 context for use with the incremental interface.
///
/// See [`crypto_poly1305`] for the restrictions on `key`.
///
/// # Examples
///
/// This example demonstrates using the incremental interface.
///
/// ```
/// use rand_core::{OsRng, RngCore};
/// use mini_monocypher::{
///   crypto_poly1305_ctx_new,
///   crypto_poly1305_init,
///   crypto_poly1305_update,
///   crypto_poly1305_final,
/// };
///
/// let mut key = [0u8; 32];
/// let mut mac = [0u8; 16];
/// let mut ctx = crypto_poly1305_ctx_new();
///
/// OsRng.fill_bytes(&mut key);
///
/// crypto_poly1305_init(&mut ctx, &key);
/// crypto_poly1305_update(&mut ctx, b"Lorem");
/// crypto_poly1305_update(&mut ctx, b" ");
/// crypto_poly1305_update(&mut ctx, b"ipsum");
/// crypto_poly1305_final(&mut ctx, &mut mac);
/// ```
pub fn crypto_poly1305_init(ctx: &mut crypto_poly1305_ctx, key: &[u8; 32]) {
    let ctx_ptr = &mut ctx.0 as *mut mini_monocypher_sys::crypto_poly1305_ctx;
    let key_buf = key.as_ptr();

    unsafe {
        mini_monocypher_sys::crypto_poly1305_init(ctx_ptr, key_buf);
    }
}

/// Incrementally computes a Poly1305 MAC based on `ctx` and a message.
///
/// See [`crypto_poly1305_init`] for a full example of using the incremental
/// interface.
pub fn crypto_poly1305_update(ctx: &mut crypto_poly1305_ctx, message: &[u8]) {
    let ctx_ptr = &mut ctx.0 as *mut mini_monocypher_sys::crypto_poly1305_ctx;
    let message_buf = message.as_ptr();

    unsafe {
        mini_monocypher_sys::crypto_poly1305_update(ctx_ptr, message_buf, message.len());
    }
}

/// Computes the final Poly1305 MAC based on `ctx`. The output will reside
/// in `mac`.
///
/// `ctx` is wiped afterwards, and must be initialised again before reuse.
///
/// See [`crypto_poly1305_init`] for a full example of using the incremental
/// interface.
pub fn crypto_poly1305_final(ctx: &mut crypto_poly1305_ctx, mac: &mut [u8; 16]) {
    let ctx_ptr = &mut ctx.0 as *mut mini_monocypher_sys::crypto_poly1305_ctx;
    let mac_buf = mac.as_mut_ptr();

    unsafe {
        mini_monocypher_sys::crypto_poly1305_final(ctx_ptr, mac_buf);
    }
}
