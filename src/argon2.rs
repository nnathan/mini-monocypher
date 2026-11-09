/// The variant of Argon2 to use in [`crypto_argon2_config`].
///
/// Monocypher uses integer constants for this. An enum means an invalid
/// variant cannot be expressed, and the variants are re-exported so that they
/// can be used by the same names as in C.
#[derive(Debug, Clone, Copy)]
#[repr(u32)]
pub enum crypto_argon2_algorithm {
    /// Argon2d.
    CRYPTO_ARGON2_D = mini_monocypher_sys::CRYPTO_ARGON2_D,
    /// Argon2i.
    CRYPTO_ARGON2_I = mini_monocypher_sys::CRYPTO_ARGON2_I,
    /// Argon2id.
    CRYPTO_ARGON2_ID = mini_monocypher_sys::CRYPTO_ARGON2_ID,
}

pub use crypto_argon2_algorithm::*;

/// Base parameters for an instance of [`crypto_argon2`].
#[derive(Debug, Clone, Copy)]
pub struct crypto_argon2_config {
    /// The variant of Argon2 to use.
    pub algorithm: crypto_argon2_algorithm,
    /// Memory hardness, the number of 1024-byte blocks for the work area.
    /// Must be at least `8 * nb_lanes`.
    pub nb_blocks: u32,
    /// CPU hardness. Must be at least 1, and 3 is strongly recommended for
    /// Argon2i.
    pub nb_passes: u32,
    /// Parallelism level. Must be at least 1. Monocypher is single threaded
    /// regardless, so 1 is strongly recommended.
    pub nb_lanes: u32,
}

/// Inputs for [`crypto_argon2`].
#[derive(Debug, Clone, Copy)]
pub struct crypto_argon2_inputs<'a> {
    /// The password to hash.
    pub pass: &'a [u8],
    /// Random bytes generated separately for each password. Must be at least
    /// 8 bytes, and 16 is recommended.
    pub salt: &'a [u8],
}

/// Optional extra inputs for [`crypto_argon2`], which are not commonly used.
#[derive(Debug, Clone, Copy)]
pub struct crypto_argon2_extras<'a> {
    /// A secret key to use in the hash, stored separately from the hashes.
    pub key: Option<&'a [u8]>,
    /// Additional data that goes into the hash.
    pub ad: Option<&'a [u8]>,
}

/// A [`crypto_argon2_extras`] with no key or additional data.
pub const crypto_argon2_no_extras: crypto_argon2_extras<'static> = crypto_argon2_extras {
    key: None,
    ad: None,
};

/// Computes an Argon2 hash of a password, for password storage or key
/// derivation. The output hash is written to `hash`, which should be 32 or 64
/// bytes for compatibility with [`crypto_verify32`] or [`crypto_verify64`].
///
/// `work_area` is temporary memory for the algorithm, and must have at least
/// `config.nb_blocks * 128` elements. It is a slice of `u64` so that it has
/// the alignment Monocypher requires, and is wiped by this function.
///
/// The password in `inputs` should be wiped with [`crypto_wipe`] after being
/// hashed. Use [`crypto_verify32`] or [`crypto_verify64`] to compare password
/// hashes.
///
/// It is recommended to read the [`Monocypher` manual] before using this
/// function.
///
/// # Examples
///
/// ```
/// use rand_core::{OsRng, RngCore};
/// use mini_monocypher::{
///   crypto_argon2,
///   crypto_argon2_config,
///   crypto_argon2_inputs,
///   crypto_argon2_no_extras,
///   CRYPTO_ARGON2_ID,
/// };
///
/// let config = crypto_argon2_config {
///     algorithm: CRYPTO_ARGON2_ID,
///     nb_blocks: 100000,
///     nb_passes: 3,
///     nb_lanes: 1,
/// };
///
/// let mut salt = [0u8; 16];
/// OsRng.fill_bytes(&mut salt);
///
/// let inputs = crypto_argon2_inputs {
///     pass: b"correct horse battery staple",
///     salt: &salt,
/// };
///
/// let mut hash = [0u8; 32];
/// let mut work_area = vec![0u64; config.nb_blocks as usize * 128];
///
/// crypto_argon2(&mut hash, &mut work_area, config, inputs, crypto_argon2_no_extras);
/// ```
///
/// # Panics
///
/// This function panics if `config.nb_lanes` or `config.nb_passes` is 0, if
/// `config.nb_blocks` is less than `8 * config.nb_lanes`, if `work_area` is
/// too small, if the salt is shorter than 8 bytes, or if the length of any
/// buffer does not fit in a `u32`.
///
/// [`Monocypher` manual]: https://monocypher.org/manual/argon2
/// [`crypto_verify32`]: crate::crypto_verify32
/// [`crypto_verify64`]: crate::crypto_verify64
/// [`crypto_wipe`]: crate::crypto_wipe
pub fn crypto_argon2(
    hash: &mut [u8],
    work_area: &mut [u64],
    config: crypto_argon2_config,
    inputs: crypto_argon2_inputs,
    extras: crypto_argon2_extras,
) {
    assert!(config.nb_lanes >= 1);
    assert!(config.nb_passes >= 1);
    assert!(config.nb_blocks as u64 >= 8 * config.nb_lanes as u64);
    assert!(work_area.len() as u64 >= config.nb_blocks as u64 * 128);
    assert!(inputs.salt.len() >= 8);

    let (key_buf, key_len) = match extras.key {
        None => (std::ptr::null(), 0),
        Some(x) => (x.as_ptr(), x.len()),
    };
    let (ad_buf, ad_len) = match extras.ad {
        None => (std::ptr::null(), 0),
        Some(x) => (x.as_ptr(), x.len()),
    };

    let u32_max = u32::MAX as usize;
    assert!(hash.len() <= u32_max);
    assert!(inputs.pass.len() <= u32_max);
    assert!(inputs.salt.len() <= u32_max);
    assert!(key_len <= u32_max);
    assert!(ad_len <= u32_max);

    let hash_buf = hash.as_mut_ptr();
    let work_area_buf = work_area.as_mut_ptr().cast();

    let config = mini_monocypher_sys::crypto_argon2_config {
        algorithm: config.algorithm as u32,
        nb_blocks: config.nb_blocks,
        nb_passes: config.nb_passes,
        nb_lanes: config.nb_lanes,
    };
    let inputs = mini_monocypher_sys::crypto_argon2_inputs {
        pass: inputs.pass.as_ptr(),
        salt: inputs.salt.as_ptr(),
        pass_size: inputs.pass.len() as u32,
        salt_size: inputs.salt.len() as u32,
    };
    let extras = mini_monocypher_sys::crypto_argon2_extras {
        key: key_buf,
        ad: ad_buf,
        key_size: key_len as u32,
        ad_size: ad_len as u32,
    };

    unsafe {
        mini_monocypher_sys::crypto_argon2(
            hash_buf,
            hash.len() as u32,
            work_area_buf,
            config,
            inputs,
            extras,
        );
    }
}
