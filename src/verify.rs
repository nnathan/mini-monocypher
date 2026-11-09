use crate::ErrorKind;

/// Compares two 16-byte buffers in constant time. Returns `()` if they are
/// equal, or [`ErrorKind::Mismatch`] if they are different.
///
/// Use this instead of `==` when comparing secrets such as MACs, as the time
/// taken by this function does not depend on the contents of the buffers.
///
/// It is recommended to read the [`Monocypher` manual] before using this
/// function.
///
/// # Examples
///
/// ```
/// use mini_monocypher::crypto_verify16;
///
/// let a = [1u8; 16];
/// let b = [1u8; 16];
/// let c = [2u8; 16];
///
/// assert!(crypto_verify16(&a, &b).is_ok());
/// assert!(crypto_verify16(&a, &c).is_err());
/// ```
///
/// [`Monocypher` manual]: https://monocypher.org/manual/verify
pub fn crypto_verify16(a: &[u8; 16], b: &[u8; 16]) -> Result<(), ErrorKind> {
    let a_buf = a.as_ptr();
    let b_buf = b.as_ptr();

    let result = unsafe { mini_monocypher_sys::crypto_verify16(a_buf, b_buf) };

    if result != 0 {
        return Err(ErrorKind::Mismatch);
    }

    Ok(())
}

/// Compares two 32-byte buffers in constant time. Returns `()` if they are
/// equal, or [`ErrorKind::Mismatch`] if they are different.
///
/// Use this instead of `==` when comparing secrets such as MACs, as the time
/// taken by this function does not depend on the contents of the buffers.
///
/// # Examples
///
/// ```
/// use mini_monocypher::crypto_verify32;
///
/// let a = [1u8; 32];
/// let b = [1u8; 32];
/// let c = [2u8; 32];
///
/// assert!(crypto_verify32(&a, &b).is_ok());
/// assert!(crypto_verify32(&a, &c).is_err());
/// ```
pub fn crypto_verify32(a: &[u8; 32], b: &[u8; 32]) -> Result<(), ErrorKind> {
    let a_buf = a.as_ptr();
    let b_buf = b.as_ptr();

    let result = unsafe { mini_monocypher_sys::crypto_verify32(a_buf, b_buf) };

    if result != 0 {
        return Err(ErrorKind::Mismatch);
    }

    Ok(())
}

/// Compares two 64-byte buffers in constant time. Returns `()` if they are
/// equal, or [`ErrorKind::Mismatch`] if they are different.
///
/// Use this instead of `==` when comparing secrets such as MACs, as the time
/// taken by this function does not depend on the contents of the buffers.
///
/// # Examples
///
/// ```
/// use mini_monocypher::crypto_verify64;
///
/// let a = [1u8; 64];
/// let b = [1u8; 64];
/// let c = [2u8; 64];
///
/// assert!(crypto_verify64(&a, &b).is_ok());
/// assert!(crypto_verify64(&a, &c).is_err());
/// ```
pub fn crypto_verify64(a: &[u8; 64], b: &[u8; 64]) -> Result<(), ErrorKind> {
    let a_buf = a.as_ptr();
    let b_buf = b.as_ptr();

    let result = unsafe { mini_monocypher_sys::crypto_verify64(a_buf, b_buf) };

    if result != 0 {
        return Err(ErrorKind::Mismatch);
    }

    Ok(())
}
