use super::ErrorKind;

/// Trims a 32-byte value `input` into a valid scalar `out`, by clearing and
/// setting the bits required by X25519 and EdDSA.
///
/// **Warning:** this is a dangerous low-level building block. Using it directly
/// allows many kinds of catastrophic misuse, including leaking the secret key.
/// Read the [`Monocypher` manual] and do not use this if you do not understand
/// it.
///
/// [`Monocypher` manual]: https://monocypher.org/manual/eddsa
pub fn crypto_eddsa_trim_scalar(out: &mut [u8; 32], input: &[u8; 32]) {
    let out_buf = out.as_mut_ptr();
    let input_buf = input.as_ptr();

    unsafe { mini_monocypher_sys::crypto_eddsa_trim_scalar(out_buf, input_buf) }
}

/// Reduces a 64-byte value `expanded` modulo the order of the curve, writing
/// the result to `reduced`.
///
/// **Warning:** this is a dangerous low-level building block. Using it directly
/// allows many kinds of catastrophic misuse, including leaking the secret key.
/// Read the [`Monocypher` manual] and do not use this if you do not understand
/// it.
///
/// [`Monocypher` manual]: https://monocypher.org/manual/eddsa
pub fn crypto_eddsa_reduce(reduced: &mut [u8; 32], expanded: &[u8; 64]) {
    let reduced_buf = reduced.as_mut_ptr();
    let expanded_buf = expanded.as_ptr();

    unsafe { mini_monocypher_sys::crypto_eddsa_reduce(reduced_buf, expanded_buf) }
}

/// Computes `r = a * b + c` modulo the order of the curve.
///
/// **Warning:** this is a dangerous low-level building block. Using it directly
/// allows many kinds of catastrophic misuse, including leaking the secret key.
/// Read the [`Monocypher` manual] and do not use this if you do not understand
/// it.
///
/// [`Monocypher` manual]: https://monocypher.org/manual/eddsa
pub fn crypto_eddsa_mul_add(r: &mut [u8; 32], a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) {
    let r_buf = r.as_mut_ptr();
    let a_buf = a.as_ptr();
    let b_buf = b.as_ptr();
    let c_buf = c.as_ptr();

    unsafe { mini_monocypher_sys::crypto_eddsa_mul_add(r_buf, a_buf, b_buf, c_buf) }
}

/// Multiplies the base point of the curve by `scalar`, writing the compressed
/// result to `point`.
///
/// **Warning:** this is a dangerous low-level building block. Using it directly
/// allows many kinds of catastrophic misuse, including leaking the secret key.
/// Read the [`Monocypher` manual] and do not use this if you do not understand
/// it.
///
/// [`Monocypher` manual]: https://monocypher.org/manual/eddsa
pub fn crypto_eddsa_scalarbase(point: &mut [u8; 32], scalar: &[u8; 32]) {
    let point_buf = point.as_mut_ptr();
    let scalar_buf = scalar.as_ptr();

    unsafe { mini_monocypher_sys::crypto_eddsa_scalarbase(point_buf, scalar_buf) }
}

/// Checks the EdDSA verification equation for `signature`, `public_key`, and
/// the reduced hash `h_ram`. Returns `()` if it holds, or
/// [`ErrorKind::InvalidSignature`] if it does not.
///
/// **Warning:** this is a dangerous low-level building block. Using it directly
/// allows many kinds of catastrophic misuse, including leaking the secret key.
/// Read the [`Monocypher` manual] and do not use this if you do not understand
/// it.
///
/// [`Monocypher` manual]: https://monocypher.org/manual/eddsa
pub fn crypto_eddsa_check_equation(
    signature: &[u8; 64],
    public_key: &[u8; 32],
    h_ram: &[u8; 32],
) -> Result<(), ErrorKind> {
    let signature_buf = signature.as_ptr();
    let public_key_buf = public_key.as_ptr();
    let h_ram_buf = h_ram.as_ptr();

    let result = unsafe {
        mini_monocypher_sys::crypto_eddsa_check_equation(
            signature_buf,
            public_key_buf,
            h_ram_buf,
        )
    };

    if result != 0 {
        return Err(ErrorKind::InvalidSignature);
    }

    Ok(())
}
