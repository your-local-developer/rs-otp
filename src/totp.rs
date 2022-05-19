use crate::hotp::{Hotp, DEFAULT_DIGITS as HOTP_DEFAULT_DIGITS};
use crate::otp::Otp;

pub static DEFAULT_DIGITS: u8 = HOTP_DEFAULT_DIGITS;

pub struct Totp {
    hotp: Hotp,
}

impl Otp for Totp {
    fn new(secret: Vec<u8>, algorithm: crate::algorithm::Algorithm, digits: u8) -> Self {
        let hotp = Otp::new(secret, algorithm, digits);
        Totp { hotp }
    }

    fn from_base32_string(
        secret: &str,
        algorithm: crate::algorithm::Algorithm,
        digits: u8,
    ) -> Result<Self, data_encoding::DecodeError> {
        let hotp = Otp::from_base32_string(secret, algorithm, digits)?;
        Ok(Totp { hotp })
    }

    fn from_string(secret: &str, algorithm: crate::algorithm::Algorithm, digits: u8) -> Self {
        let hotp = Otp::from_string(secret, algorithm, digits);
        Totp { hotp }
    }

    fn calculate(&self, counter: u64) -> Result<u32, std::io::Error> {
        todo!()
    }

    fn calculate_with_offset(&self, counter: u64, offset: u8) -> Result<u32, std::io::Error> {
        todo!()
    }
}

impl Totp {
    fn validate_with_window(code: u32, moving_factor: u64, window: u8) -> bool{
        todo!()
    }
}