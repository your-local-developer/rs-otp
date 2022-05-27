use std::io::{Error, ErrorKind};
use std::time::{self, SystemTime};

use crate::algorithm::Algorithm;
use crate::hotp::{Hotp, DEFAULT_DIGITS as HOTP_DEFAULT_DIGITS};
use crate::otp::Otp;

pub const DEFAULT_DIGITS: u8 = HOTP_DEFAULT_DIGITS;

pub const DEFAULT_VALIDATION_WINDOW_SIZE: u8 = 1;

/// Default step size as proposed in [RFC 6238 Section 5.2](https://www.rfc-editor.org/rfc/rfc6238#section-5.2)
pub const DEFAULT_STEP_SIZE: u8 = 30;

#[derive(Clone, Debug)]
pub struct Totp {
    hotp: Hotp,
    step_size: u8,
    last_validated_code: Option<u32>,
}

impl AsMut<Totp> for Totp {
    fn as_mut(&mut self) -> &mut Totp {
        self
    }
}

impl AsRef<Totp> for Totp {
    fn as_ref(&self) -> &Totp {
        self
    }
}

impl Otp for Totp {
    fn new(secret: Vec<u8>, algorithm: Algorithm, digits: u8) -> Self {
        let mut hotp: Hotp = Otp::new(secret, algorithm, digits);
        hotp.look_ahead_window = DEFAULT_VALIDATION_WINDOW_SIZE;
        Totp {
            hotp,
            step_size: DEFAULT_STEP_SIZE,
            last_validated_code: None,
        }
    }

    fn from_base32_string(
        secret: &str,
        algorithm: Algorithm,
        digits: u8,
    ) -> Result<Self, data_encoding::DecodeError> {
        let mut hotp: Hotp = Otp::from_base32_string(secret, algorithm, digits)?;
        hotp.look_ahead_window = DEFAULT_VALIDATION_WINDOW_SIZE;
        Ok(Totp {
            hotp,
            step_size: DEFAULT_STEP_SIZE,
            last_validated_code: None,
        })
    }

    fn from_string(secret: &str, algorithm: Algorithm, digits: u8) -> Self {
        let mut hotp: Hotp = Otp::from_string(secret, algorithm, digits);
        hotp.look_ahead_window = DEFAULT_VALIDATION_WINDOW_SIZE;
        Totp {
            hotp,
            step_size: DEFAULT_STEP_SIZE,
            last_validated_code: None,
        }
    }

    fn generate_at(&self, time_in_seconds: u64) -> Result<u32, Error> {
        self.calculate(time_in_seconds)
    }

    fn generate(&mut self) -> Result<u32, Error> {
        let system_time = Self::system_time()?;
        self.calculate(system_time)
    }

    /// Validate the given code against the current timestamp.
    /// Only accept the code if it is not already validated. [RFC 6238 section 5.2](https://www.rfc-editor.org/rfc/rfc6238#section-5.2)
    fn validate(&mut self, code: u32) -> bool {
        if self.last_validated_code != Some(code) {
            match Self::system_time() {
                Ok(x) => {
                    let validation_result = self.validate_at(code, x);
                    if validation_result {
                        self.last_validated_code = Some(code);
                    }
                    validation_result
                }
                Err(_) => false,
            }
        } else {
            false
        }
    }

    fn validate_at(&self, code: u32, time_in_sec: u64) -> bool {
        let mut validation_result = false;
        // Validate against window to prevent network delay
        for attempt in
            -(self.hotp.look_ahead_window as i128)..self.hotp.look_ahead_window as i128 + 1
        {
            // Calculate time with offset based on the attempt and step size
            let calculated_time = time_in_sec as i128 + attempt * self.step_size as i128;
            validation_result = match self.generate_at(calculated_time as u64) {
                Ok(x) => x == code,
                Err(_) => false,
            };
            // If successful exit the loop
            if validation_result {
                break;
            }
        }
        validation_result
    }
}

impl Totp {
    /// Calculate moving factor as described in [RFC 6238 section 4.2](https://www.rfc-editor.org/rfc/rfc6238#section-4.2)
    /// and generate the token.
    fn calculate(&self, time_in_seconds: u64) -> Result<u32, Error> {
        let moving_factor = time_in_seconds / self.step_size as u64;
        self.hotp.generate_at(moving_factor)
    }

    fn system_time() -> Result<u64, Error> {
        match SystemTime::now().duration_since(time::UNIX_EPOCH) {
            Ok(x) => Ok(x.as_secs()),
            Err(e) => Err(Error::new(ErrorKind::InvalidData, e)),
        }
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

    #[test]
    /// Checks validation window.
    fn validate_sha1_against_window() {
        let totp = Totp::from_string("12345678901234567890", Algorithm::SHA1, 8);
        assert!(totp.validate_at(07081804, 1111111109 + 30));
        assert!(!totp.validate_at(07081804, 1111111109 + 31));
        // 1111111109 is at the end of a 30 second window
        assert!(totp.validate_at(07081804, 1111111109 - 59));
        assert!(!totp.validate_at(07081804, 1111111109 - 60));
    }

    #[test]
    /// Checks if the current code can be created and can be validated.
    fn validate_now() {
        let mut totp = Totp::from_string("12345678901234567890", Algorithm::SHA1, 8);
        let expected_code = totp.generate().unwrap();
        assert!(totp.validate(expected_code));
        assert_eq!(totp.last_validated_code.unwrap(), expected_code);
        // Should be false because the code is already validated.
        assert!(!totp.validate(expected_code));
    }
}
