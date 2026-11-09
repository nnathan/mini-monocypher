use std::error::Error;
use std::fmt;

/// Errors returned by Monocypher
#[derive(Debug)]
#[non_exhaustive]
pub enum ErrorKind {
    /// Decryption failed due to incorrect nonce, integrity failure
    /// in ciphertext, or incorrect MAC.
    AuthenticationFailure,
    /// A constant time comparison found the inputs are different.
    Mismatch,
    /// A signature is not valid for the given public key and message.
    InvalidSignature,
    /// A public key cannot be hidden by [`crypto_elligator_rev`].
    ///
    /// [`crypto_elligator_rev`]: crate::crypto_elligator_rev
    UnsuitableForHiding,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ErrorKind::AuthenticationFailure => {
                write!(f, "authentication failure trying to decrypt ciphertext")
            }
            ErrorKind::Mismatch => write!(f, "inputs to constant time comparison are different"),
            ErrorKind::InvalidSignature => write!(f, "invalid signature"),
            ErrorKind::UnsuitableForHiding => write!(f, "public key is unsuitable for hiding"),
        }
    }
}

impl Error for ErrorKind {}
