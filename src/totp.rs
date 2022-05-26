use std::io::{Error, ErrorKind};
use std::time::{self, SystemTime};

use crate::algorithm::Algorithm;
use crate::hotp::{Hotp, DEFAULT_DIGITS as HOTP_DEFAULT_DIGITS};
use crate::otp::Otp;

pub const DEFAULT_DIGITS: u8 = HOTP_DEFAULT_DIGITS;

/// Default step size as proposed in [RFC 6238 Section 5.2](https://www.rfc-editor.org/rfc/rfc6238#section-5.2)
const DEFAULT_STEP_SIZE: u8 = 30;

pub struct Totp {
    hotp: Hotp,
    step_size: u8,
}

impl Otp for Totp {
    fn new(secret: Vec<u8>, algorithm: Algorithm, digits: u8) -> Self {
        let hotp = Otp::new(secret, algorithm, digits);
        Totp {
            hotp,
            step_size: DEFAULT_STEP_SIZE,
        }
    }

    fn from_base32_string(
        secret: &str,
        algorithm: Algorithm,
        digits: u8,
    ) -> Result<Self, data_encoding::DecodeError> {
        let hotp = Otp::from_base32_string(secret, algorithm, digits)?;
        Ok(Totp {
            hotp,
            step_size: DEFAULT_STEP_SIZE,
        })
    }

    fn from_string(secret: &str, algorithm: Algorithm, digits: u8) -> Self {
        let hotp = Otp::from_string(secret, algorithm, digits);
        Totp {
            hotp,
            step_size: DEFAULT_STEP_SIZE,
        }
    }

    fn generate_at(&self, time_in_seconds: u64) -> Result<u32, Error> {
        self.calculate(time_in_seconds)
    }

    fn generate(&mut self) -> Result<u32, Error> {
        let system_time = match SystemTime::now().duration_since(time::UNIX_EPOCH) {
            Ok(x) => x.as_secs(),
            Err(e) => return Err(Error::new(ErrorKind::InvalidData, e)),
        };
        self.calculate(system_time)
    }
}

impl Totp {
    fn calculate(&self, time_in_seconds: u64) -> Result<u32, Error> {
        let moving_factor = time_in_seconds / self.step_size as u64;
        self.hotp.generate_at(moving_factor)
    }
}

#[cfg(test)]
mod test {
    use crate::algorithm::Algorithm;
    use crate::otp::Otp;
    use crate::totp::Totp;

    /// Test vectors taken from [RFC-6238 Appendix B](https://www.rfc-editor.org/rfc/rfc6238#appendix-B).
    const RFC_TIME_STAMPS: [u64; 6] = [
        59,
        1111111109,
        1111111111,
        1234567890,
        2000000000,
        20000000000,
    ];

    /// Test vectors taken from [RFC-6238 Appendix B](https://www.rfc-editor.org/rfc/rfc6238#appendix-B).
    const RFC_SHA1_CODES: [u32; 6] = [94287082, 07081804, 14050471, 89005924, 69279037, 65353130];

    /// Test vectors taken from [RFC-6238 Appendix B](https://www.rfc-editor.org/rfc/rfc6238#appendix-B).
    const RFC_SHA256_CODES: [u32; 6] = [46119246, 68084774, 67062674, 91819424, 90698825, 77737706];

    /// Test vectors taken from [RFC-6238 Appendix B](https://www.rfc-editor.org/rfc/rfc6238#appendix-B).
    const RFC_SHA512_CODES: [u32; 6] = [90693936, 25091201, 99943326, 93441116, 38618901, 47863826];

    #[test]
    /// Test vectors for SHA1 taken from [RFC-6238 Appendix B](https://www.rfc-editor.org/rfc/rfc6238#appendix-B).
    fn validate_sha1_against_rfc() {
        for (index, time) in RFC_TIME_STAMPS.iter().enumerate() {
            let htop_code = Totp::from_string("12345678901234567890", Algorithm::SHA1, 8)
                .generate_at(*time)
                .unwrap();
            let expected_code = RFC_SHA1_CODES[index];
            assert_eq!(htop_code, expected_code);
        }
    }

    #[test]
    /// Test vectors for SHA256 taken from [RFC-6238 Appendix B](https://www.rfc-editor.org/rfc/rfc6238#appendix-B).
    fn validate_sha256_against_rfc() {
        for (index, time) in RFC_TIME_STAMPS.iter().enumerate() {
            let htop_code =
                Totp::from_string("12345678901234567890123456789012", Algorithm::SHA256, 8)
                    .generate_at(*time)
                    .unwrap();
            let expected_code = RFC_SHA256_CODES[index];
            assert_eq!(htop_code, expected_code);
        }
    }

    #[test]
    /// Test vectors for SHA512 taken from [RFC-6238 Appendix B](https://www.rfc-editor.org/rfc/rfc6238#appendix-B).
    fn validate_sha512_against_rfc() {
        for (index, time) in RFC_TIME_STAMPS.iter().enumerate() {
            let htop_code = Totp::from_string(
                "1234567890123456789012345678901234567890123456789012345678901234",
                Algorithm::SHA512,
                8,
            )
            .generate_at(*time)
            .unwrap();
            let expected_code = RFC_SHA512_CODES[index];
            assert_eq!(htop_code, expected_code);
        }
    }
}
