use crate::algorithm::Algorithm;
use data_encoding::{DecodeError, BASE32, BASE32_NOPAD};
use std::io::Error;

pub trait Otp {
    /// Returns a OtpBuilder taking the unencoded secret as vector of bytes.
    /// The default algorithm is SHA-1.
    /// To be RFC compliant, the number od digits should be between 6 and 10.
    /// Numbers higher than 10 will receive leading zeros.
    fn new(secret: Vec<u8>) -> Box<dyn OtpBuilder<Self>>;

    /// Returns a OtpBuilder taking the Base32 encoded secret as string.
    /// The default algorithm is SHA-1.
    /// To be RFC compliant, the number od digits should be between 6 and 10.
    /// Numbers higher than 10 will receive leading zeros.
    fn new_base32(secret: &str) -> Result<Box<dyn OtpBuilder<Self>>, DecodeError>;

    /// Returns a OtpBuilder taking the unencoded secret as string.
    /// The default algorithm is SHA-1.
    /// To be RFC compliant, the number od digits should be between 6 and 10.
    /// Numbers higher than 10 will receive leading zeros.
    fn new_str(secret: &str) -> Box<dyn OtpBuilder<Self>>;

    /// Validates a Base32 encoded secret while ignoring any spaces.
    fn validate_secret(secret: &str) -> bool {
        Self::decode_secret(secret).is_ok()
    }

    /// Validates a Base32 encoded secret including its unencoded length while ignoring any spaces.
    /// Returns `false` if the length is smaller than 128 Bit and therefore not compliant to [RFC 4226 section 4 R6](https://www.rfc-editor.org/rfc/rfc4226#section-4).
    /// This is not included in `validate_secret` function, because Google Authenticator used to produce secrets, which did not confirm to the RFC.`
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
    /// This is the preferred method.
    fn generate_at(&self, moving_factor: u64) -> Result<u32, Error>;

    /// Calculates the current u32 Otp code.
    /// It uses dynamic truncation to calculate an offset.
    /// This is the preferred method.
    fn generate(&mut self) -> Result<u32, Error>;

    /// Validates the given otp code.
    fn validate(&mut self, code: u32) -> bool;

    /// Validates the given otp code against the moving factor.
    fn validate_at(&self, code: u32, moving_factor: u64) -> bool;
}

pub trait OtpBuilder<T> {
    /// Builds the Otp instance and returns an error is the provided data does not conform to the RFC.
    fn build(&mut self) -> Result<T, Error>;
    
    /// Builds the Otp instance.
    fn unchecked_build(&mut self) -> T;

    /// Sets the digits of the OtpBuilder.
    fn digits(&mut self, digits: u8) -> &mut dyn OtpBuilder<T>;
    
    /// Sets the algorithm of the OtpBuilder.
    fn algorithm(&mut self, algorithm: Algorithm) -> &mut dyn OtpBuilder<T>;
    
    /// Sets the validation window of the OtpBuilder.
    fn validation_window(&mut self, validation_window: u8) -> &mut dyn OtpBuilder<T>;
}
