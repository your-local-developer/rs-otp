#[cfg(feature = "serialization")]
use serde::{Deserialize, Serialize};

use std::io::{Error, ErrorKind};
use std::time::{self, SystemTime};

use crate::algorithm::Algorithm;
use crate::hotp::{Hotp, HotpBuilder, DEFAULT_DIGITS as HOTP_DEFAULT_DIGITS};
use crate::otp::{Otp, OtpBuilder};

pub const DEFAULT_DIGITS: u8 = HOTP_DEFAULT_DIGITS;

pub const DEFAULT_VALIDATION_WINDOW_SIZE: u8 = 1;

/// Default step size as proposed in [RFC 6238 Section 5.2](https://www.rfc-editor.org/rfc/rfc6238#section-5.2)
pub const DEFAULT_STEP_SIZE: u8 = 30;

#[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TotpBuilder {
    hotp_builder: HotpBuilder,
    step_size: Option<u8>,
    last_validated_code: Option<u32>,
}

impl OtpBuilder<Totp> for TotpBuilder {
    fn new(secret: &[u8]) -> Self {
        TotpBuilder {
            hotp_builder: HotpBuilder::new(secret),
            step_size: None,
            last_validated_code: None,
        }
    }

    fn with_base32_str(secret: &str) -> Result<Self, data_encoding::DecodeError>
    where
        Self: Sized,
    {
        match HotpBuilder::with_base32_str(secret) {
            Ok(hotp_builder) => Ok(TotpBuilder {
                hotp_builder,
                step_size: None,
                last_validated_code: None,
            }),
            Err(e) => Err(e),
        }
    }

    fn with_str(secret: &str) -> Self {
        TotpBuilder {
            hotp_builder: HotpBuilder::with_str(secret),
            step_size: None,
            last_validated_code: None,
        }
    }

    fn build(&mut self) -> Result<Totp, Error> {
        let default_unchecked_totp = Self::unchecked_build(self);
        match Self::verify(&default_unchecked_totp) {
            Ok(_) => Ok(default_unchecked_totp),
            Err(msg) => Err(Error::new(ErrorKind::InvalidInput, msg)),
        }
    }

    fn unchecked_build(&mut self) -> Totp {
        let default_unchecked_totp = Self::apply_defaults(self);
        Totp {
            hotp: default_unchecked_totp.hotp,
            last_validated_code: default_unchecked_totp.last_validated_code,
            step_size: default_unchecked_totp.step_size,
        }
    }

    fn digits(&mut self, digits: u8) -> &mut Self {
        self.hotp_builder.digits(digits);
        self
    }

    fn algorithm(&mut self, algorithm: Algorithm) -> &mut Self {
        self.hotp_builder.algorithm(algorithm);
        self
    }

    fn validation_window(&mut self, validation_window: u8) -> &mut Self {
        self.hotp_builder.validation_window(validation_window);
        self
    }
}

impl AsMut<TotpBuilder> for TotpBuilder {
    fn as_mut(&mut self) -> &mut TotpBuilder {
        self
    }
}

impl AsRef<TotpBuilder> for TotpBuilder {
    fn as_ref(&self) -> &TotpBuilder {
        self
    }
}

impl From<Totp> for TotpBuilder {
    fn from(totp: Totp) -> Self {
        TotpBuilder {
            hotp_builder: HotpBuilder::from(totp.hotp),
            step_size: Some(totp.step_size),
            last_validated_code: totp.last_validated_code,
        }
    }
}

impl TotpBuilder {
    /// Sets the step size of the time-step in seconds.
    pub fn step_size(&mut self, step_size: u8) -> &mut Self {
        self.step_size = Some(step_size);
        self
    }

    /// Sets the last validated totp code.
    pub fn last_validated_code(&mut self, last_validated_code: u32) -> &mut Self {
        self.last_validated_code = Some(last_validated_code);
        self
    }

    /// Applies default values to the Totp instance.
    fn apply_defaults(&mut self) -> Totp {
        let hotp = self
            .hotp_builder
            .validation_window(DEFAULT_VALIDATION_WINDOW_SIZE)
            .unchecked_build();
        Totp {
            hotp,
            step_size: self.step_size.unwrap_or(DEFAULT_STEP_SIZE),
            last_validated_code: self.last_validated_code,
        }
    }

    /// Verifies a Totp instance for it's correctness.
    fn verify(totp: &Totp) -> Result<(), &'static str> {
        HotpBuilder::verify(&totp.hotp)
    }
}

#[cfg_attr(feature = "serialization", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
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
    use crate::otp::{Otp, OtpBuilder};
    #[cfg(feature = "serialization")]
    use crate::totp::Totp;
    use crate::totp::TotpBuilder;

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
            let htop_code = TotpBuilder::with_str("12345678901234567890")
                .digits(8)
                .build()
                .unwrap()
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
            let htop_code = TotpBuilder::with_str("12345678901234567890123456789012")
                .algorithm(Algorithm::SHA256)
                .digits(8)
                .build()
                .unwrap()
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
            let htop_code = TotpBuilder::with_str(
                "1234567890123456789012345678901234567890123456789012345678901234",
            )
            .algorithm(Algorithm::SHA512)
            .digits(8)
            .build()
            .unwrap()
            .generate_at(*time)
            .unwrap();
            let expected_code = RFC_SHA512_CODES[index];
            assert_eq!(htop_code, expected_code);
        }
    }

    #[test]
    /// Checks validation window.
    fn validate_sha1_against_window() {
        let totp = TotpBuilder::with_str("12345678901234567890")
            .digits(8)
            .build()
            .unwrap();
        assert!(totp.validate_at(07081804, 1111111109 + 30));
        assert!(!totp.validate_at(07081804, 1111111109 + 31));
        // 1111111109 is at the end of a 30 second window
        assert!(totp.validate_at(07081804, 1111111109 - 59));
        assert!(!totp.validate_at(07081804, 1111111109 - 60));
    }

    #[test]
    /// Checks if the current code can be created and can be validated.
    fn validate_now() {
        let mut totp = TotpBuilder::with_str("12345678901234567890")
            .digits(8)
            .build()
            .unwrap();
        let expected_code = totp.generate().unwrap();
        assert!(totp.validate(expected_code));
        assert_eq!(totp.last_validated_code.unwrap(), expected_code);
        // Should be false because the code is already validated.
        assert!(!totp.validate(expected_code));
    }

    #[test]
    #[cfg(feature = "serialization")]
    fn serialization() {
        let totp = TotpBuilder::with_str("12345678901234567890")
            .build()
            .unwrap();
        let serialized_totp = serde_json::to_string(&totp).unwrap();
        assert_eq!(
            serialized_totp,
            r#"{"hotp":{"secret":[49,50,51,52,53,54,55,56,57,48,49,50,51,52,53,54,55,56,57,48],"algorithm":"SHA1","digits":6,"counter":0,"look_ahead_window":1},"step_size":30,"last_validated_code":null}"#
        );
        let deserialized_totp: Totp = serde_json::from_str(&serialized_totp).unwrap();
        assert_eq!(deserialized_totp, totp);
    }
}
