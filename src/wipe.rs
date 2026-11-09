/// Erases `secret` by overwriting it with zeroes, in a way the compiler will
/// not optimise away.
///
/// This only erases the memory `secret` refers to. Copies of the data left
/// behind when a value was moved or copied are not affected.
///
/// It is recommended to read the [`Monocypher` manual] before using this
/// function.
///
/// # Examples
///
/// ```
/// use mini_monocypher::crypto_wipe;
///
/// let mut secret = [0x42u8; 32];
/// crypto_wipe(&mut secret);
/// assert_eq!(secret, [0u8; 32]);
/// ```
///
/// [`Monocypher` manual]: https://monocypher.org/manual/wipe
pub fn crypto_wipe(secret: &mut [u8]) {
    let secret_buf = secret.as_mut_ptr().cast();

    unsafe { mini_monocypher_sys::crypto_wipe(secret_buf, secret.len()) }
}
