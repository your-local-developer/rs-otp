use crate::algorithm::Algorithm;
use data_encoding::{DecodeError, BASE32, BASE32_NOPAD};
use std::io::Error;

pub(crate) trait Otp {
    /// Returns an instance taking the unencoded secret as vector of bytes.
    fn new(secret: Vec<u8>, algorithm: Algorithm, digits: u8) -> Self;

    /// Returns an instance taking the Base32 encoded secret as string.
    fn from_base32_string(
        secret: &str,
        algorithm: Algorithm,
        digits: u8,
    ) -> Result<Self, DecodeError>
    where
        Self: Sized;

    /// Returns an instance taking the unencoded secret as string.
    fn from_string(secret: &str, algorithm: Algorithm, digits: u8) -> Self;

    /// Validates a Base32 encoded secret while ignoring any spaces.
    fn validate(secret: &str) -> bool {
        Self::decode_secret(secret).is_ok()
    }

    /// Validates a Base32 encoded secret including its unencoded length while ignoring any spaces.
    /// Returns `false` if the length is smaller than 128 Bit.
    fn validate_len(secret: &str) -> bool {
        if let Ok(decoded_secret) = Self::decode_secret(secret) {
            decoded_secret.len() >= 16
        } else {
            false
        }
    }

    /// Decodes a Base32 encoded secret while removing any spaces.
    fn decode_secret(secret: &str) -> Result<Vec<u8>, DecodeError> {
        let secret = secret.replace(' ', "").to_uppercase();
        if secret.contains('=') {
            BASE32.decode(secret.as_bytes())
        } else {
            BASE32_NOPAD.decode(secret.as_bytes())
        }
    }

    /// Calculates the Otp value taking the given counter.
    fn calculate(&self, counter: u64) -> Result<u32, Error>;

    /// Calculates the Otp value taking the given counter and offset.
    fn calculate_with_offset(&self, counter: u64, offset: u8) -> Result<u32, Error>;
}
