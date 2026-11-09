//! # mini-monocypher
//!
//! A C-like Rust API for [`Monocypher`], with Rust safety where it makes sense.
//!
//! This release has full coverage of the API for [Monocypher 4.0.3].
//!
//! This documentation covers the usage of Monocypher through these bindings,
//! but for the intricacies regarding cryptographic usage and security hygiene
//! it is recommended to refer to the [`Monocypher` manual].
//!
//! [`Monocypher`]: https://monocypher.org/
//! [`Monocypher` manual]: https://monocypher.org/manual/
//! [Monocypher 4.0.3]: https://github.com/LoupVaillant/Monocypher/releases/tag/4.0.3

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![deny(missing_docs)]

mod aead;
mod argon2;
mod blake2b;
mod chacha20;
mod ed25519;
mod eddsa;
mod elligator;
mod error;
mod poly1305;
mod sha512;
mod verify;
mod wipe;
mod x25519;

/// Dangerous low-level building blocks ("hazardous materials").
///
/// These are memory safe, but using them directly allows many kinds of
/// catastrophic misuse. Most users want [`crypto_eddsa_sign`] and
/// [`crypto_eddsa_check`] instead.
pub mod hazmat;

pub use aead::*;
pub use argon2::*;
pub use blake2b::*;
pub use chacha20::*;
pub use ed25519::*;
pub use eddsa::*;
pub use elligator::*;
pub use error::ErrorKind;
pub use poly1305::*;
pub use sha512::*;
pub use verify::*;
pub use wipe::*;
pub use x25519::*;
