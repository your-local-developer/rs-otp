use crate::algorithm::Algorithm;
use data_encoding::{DecodeError, BASE32, BASE32_NOPAD};
use std::io::Error;

pub trait Otp {
    /// Validates a Base32 encoded secret while ignoring any spaces.
    fn validate_secret(secret: &str) -> bool {
        Self::decode_secret(secret).is_ok()
    }

    /// Validates a Base32 encoded secret including its unencoded length while ignoring any spaces.
    /// Returns `false` if the length is smaller than 128 Bit and therefore not compliant to [RFC 4226 section 4 R6](https://www.rfc-editor.org/rfc/rfc4226#section-4).
    /// This is not included in `validate_secret` function, because Google Authanticator used to produce secrets, which did not confirm to the RFC.`
    fn validate_secret_len(secret: &str) -> bool {
        if let Ok(decoded_secret) = Self::decode_secret(secret) {
            decoded_secret.len() >= 16
        } else {
            false
        }
    }

    /// Decodes a Base32 encoded secret while removing any spaces.
    /// It accepts padded and non-padded secrets.
    fn decode_secret(secret: &str) -> Result<Vec<u8>, DecodeError> {
        let secret = secret.replace(' ', "").to_uppercase();
        if secret.contains('=') {
            BASE32.decode(secret.as_bytes())
        } else {
            BASE32_NOPAD.decode(secret.as_bytes())
        }
    }

    /// Calculates the u32 Otp code taking a counter or time based value as moving factor.
    /// It uses dynamic truncation to calculate an offset.
    /// Attention: this method does not increase any internal counters!
    fn generate_at(&self, moving_factor: u64) -> Result<u32, Error>;

    /// Calculates the current u32 Otp code.
    /// It uses dynamic truncation to calculate an offset.
    /// This is the preferred method.
    fn generate(&mut self) -> Result<u32, Error>;

    /// Validates the given otp code.
    fn validate(&mut self, code: u32) -> bool;

    /// Validates the given otp code against the moving factor.
    /// Attention: this method does not increase the any internal counters!
    fn validate_at(&self, code: u32, moving_factor: u64) -> bool;
}

pub trait OtpBuilder<T> {
    /// Returns a OtpBuilder taking the unencoded secret as bytes.
    /// The default algorithm is SHA-1.
    /// To be RFC compliant, the number od digits should be between 6 and 10.
    /// Numbers higher than 10 will receive leading zeros.
    /// Numbers smaller than 6 will lead to an error during build.
    fn new(secret: &[u8]) -> Self;

    /// Returns a OtpBuilder taking the Base32 encoded secret as string.
    /// The default algorithm is SHA-1.
    /// To be RFC compliant, the number od digits should be between 6 and 10.
    /// Numbers higher than 10 will receive leading zeros.
    /// Numbers smaller than 6 will lead to an error during build.
    fn with_base32_str(secret: &str) -> Result<Self, DecodeError>
    where
        Self: Sized;

    /// Returns a OtpBuilder taking the unencoded secret as string.
    /// The default algorithm is SHA-1.
    /// To be RFC compliant, the number od digits should be between 6 and 10.
    /// Numbers higher than 10 will receive leading zeros.
    /// Numbers smaller than 6 will lead to an error during build.
    fn with_str(secret: &str) -> Self;

    /// Builds the Otp instance and returns an error is the provided data does not conform to the RFC.
    fn build(&mut self) -> Result<T, Error>;

    /// Builds the Otp instance.
    /// It does not check the build for it's correctness.
    fn unchecked_build(&mut self) -> T;

    /// Sets the amount of digits for the Otp.
    fn digits(&mut self, digits: u8) -> &mut Self;

    /// Sets the algorithm for the Otp.
    fn algorithm(&mut self, algorithm: Algorithm) -> &mut Self;

    /// Sets the validation window for the Otp.
    fn validation_window(&mut self, validation_window: u8) -> &mut Self;
}
