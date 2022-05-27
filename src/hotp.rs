use std::io::{Error, ErrorKind};

use data_encoding::DecodeError;
use ring::hmac;

use crate::algorithm::Algorithm;
use crate::otp::{Otp, OtpBuilder};

pub const DEFAULT_DIGITS: u8 = 6;

const INITIAL_COUNTER: u64 = 0;

const DEFAULT_VALIDATION_WINDOW_SIZE: u8 = 10;
#[derive(Clone, Debug)]
pub struct HotpBuilder {
    secret: Vec<u8>,
    algorithm: Option<Algorithm>,
    digits: Option<u8>,
    counter: Option<u64>, // not in OtpBuilder
    look_ahead_window: Option<u8>,
}

impl OtpBuilder<Hotp> for HotpBuilder {
    fn build(&mut self) -> Result<Hotp, Error> {
        let algorithm = self.algorithm.unwrap_or(Algorithm::SHA1);
        let digits = self.digits.unwrap_or(DEFAULT_DIGITS);
        let counter = self.counter.unwrap_or(INITIAL_COUNTER);
        let look_ahead_window = self
            .look_ahead_window
            .unwrap_or(DEFAULT_VALIDATION_WINDOW_SIZE);
        let secret = self.secret.to_owned();

        if digits >= 6 {
            Ok(Hotp {
                secret,
                algorithm,
                counter,
                digits,
                look_ahead_window,
            })
        } else {
            Err(Error::new(
                ErrorKind::InvalidInput,
                "Digits must be equal or greater than 6.",
            ))
        }
    }

    fn digits(&mut self, digits: u8) -> &mut dyn OtpBuilder<Hotp> {
        self.digits = Some(digits);
        self
    }

    fn algorithm(&mut self, algorithm: Algorithm) -> &mut dyn OtpBuilder<Hotp> {
        self.algorithm = Some(algorithm);
        self
    }

    fn validation_window(&mut self, validation_window: u8) -> &mut dyn OtpBuilder<Hotp> {
        self.look_ahead_window = Some(validation_window);
        self
    }

    fn unchecked_build(&mut self) -> Hotp {
        let algorithm = self.algorithm.unwrap_or(Algorithm::SHA1);
        let digits = self.digits.unwrap_or(DEFAULT_DIGITS);
        let counter = self.counter.unwrap_or(INITIAL_COUNTER);
        let look_ahead_window = self
            .look_ahead_window
            .unwrap_or(DEFAULT_VALIDATION_WINDOW_SIZE);
        let secret = self.secret.to_owned();

        Hotp {
            secret,
            algorithm,
            counter,
            digits,
            look_ahead_window,
        }
    }
}

impl HotpBuilder {
    pub fn counter(&mut self, counter: u64) -> &mut Self {
        self.counter = Some(counter);
        self
    }
}

impl From<Hotp> for HotpBuilder {
    fn from(hotp: Hotp) -> Self {
        HotpBuilder {
            secret: hotp.secret,
            algorithm: Some(hotp.algorithm),
            digits: Some(hotp.digits),
            counter: Some(hotp.counter),
            look_ahead_window: Some(hotp.look_ahead_window),
        }
    }
}

impl From<Box<dyn OtpBuilder<Hotp>>> for HotpBuilder {
    fn from(mut value: Box<dyn OtpBuilder<Hotp>>) -> Self {
        let hotp = value.unchecked_build();
        HotpBuilder {
            secret: hotp.secret,
            algorithm: Some(hotp.algorithm),
            digits: Some(hotp.digits),
            look_ahead_window: Some(hotp.look_ahead_window),
            counter: Some(hotp.counter),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Hotp {
    secret: Vec<u8>,
    algorithm: Algorithm,
    digits: u8,
    counter: u64,
    pub(crate) look_ahead_window: u8,
}

impl AsMut<Hotp> for Hotp {
    fn as_mut(&mut self) -> &mut Hotp {
        self
    }
}

impl AsRef<Hotp> for Hotp {
    fn as_ref(&self) -> &Hotp {
        self
    }
}

impl Otp for Hotp {
    /// Initializes a new Hotp instance taking the unencoded secret as u8 vector.
    fn new(secret: Vec<u8>) -> Box<dyn OtpBuilder<Hotp>> {
        Box::new(HotpBuilder {
            secret,
            algorithm: None,
            digits: None,
            counter: None,
            look_ahead_window: None,
        })
    }

    /// Initializes a new Hotp instance taking the Base32 encoded secret as string.
    fn new_base32(secret: &str) -> Result<Box<dyn OtpBuilder<Hotp>>, DecodeError> {
        let decoded_secret = Self::decode_secret(secret)?;
        Ok(Box::new(HotpBuilder {
            secret: decoded_secret,
            algorithm: None,
            digits: None,
            counter: None,
            look_ahead_window: None,
        }))
    }
    /// Initializes a new Hotp instance taking the unencoded secret as string.
    fn new_str(secret: &str) -> Box<dyn OtpBuilder<Hotp>> {
        Box::new(HotpBuilder {
            secret: secret.as_bytes().to_vec(),
            algorithm: None,
            digits: None,
            counter: None,
            look_ahead_window: None,
        })
    }

    /// Calculates the HOTP code as with the given counter.
    fn generate_at(&self, counter: u64) -> Result<u32, Error> {
        self.generate_with_offset(counter, None)
    }

    /// Calculates the current HOTP code and increments the internal counter.
    fn generate(&mut self) -> Result<u32, Error> {
        match self.generate_with_offset(self.counter, None) {
            Ok(x) => {
                // Increment counter when generation was successful
                self.counter += 1;
                Ok(x)
            }
            Err(e) => Err(e),
        }
    }

    /// Validates the given code against the internal counter and increments it on success.
    fn validate(&mut self, code: u32) -> bool {
        if self.validate_at(code, self.counter) {
            self.counter += 1;
            true
        } else {
            false
        }
    }

    /// Validates the given code against the counter.
    /// Attention: this method does not increase the internal counter!
    fn validate_at(&self, code: u32, counter: u64) -> bool {
        let mut validation_result = false;
        // Validate against window to prevent network delay
        for attempt in 0..self.look_ahead_window as u64 {
            // Calculate time with offset based on the attempt and step size
            let calculated_counter = counter + attempt;
            validation_result = match self.generate_at(calculated_counter) {
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

impl Hotp {
    /// Calculates the u32 Hotp code taking a counter as moving factor.
    /// It uses a custom offset to extract 4 bytes from the HMAC-SHA Digest.
    /// Keep in mind that the max value of the offset is the last index of the resulting digest minus four bytes.
    /// Therefore, the offset has to be between (inclusive) 0 and 15 for SHA1, 27 for SHA256 and 59 for SHA512.
    /// Attention: this method does not increase the internal counter.
    pub fn generate_with_offset(&self, counter: u64, offset: Option<u8>) -> Result<u32, Error> {
        let full_code = Self::encode_digest(
            Self::calc_hmac_digest(self.secret.to_vec(), counter, self.algorithm)
                .as_ref()
                .to_vec(),
            offset,
        )?;
        let out_of_range_err = Error::new(
            ErrorKind::InvalidData,
            "Number of digits should be between 0 and 10.",
        );

        // 32 bit can only lead to a 10 digit code
        if self.digits < 10 {
            // Shorten the code to the desired length
            if let Some(modulus) = 10_u32.checked_pow(self.digits.into()) {
                if let Some(code) = (full_code).checked_rem(modulus) {
                    Ok(code)
                } else {
                    Err(out_of_range_err)
                }
            } else {
                Err(out_of_range_err)
            }
        } else {
            // Return full 10 digit code.
            Ok(full_code)
        }
    }

    /// Calculates the HMAC digest for the given combination of secret and counter and algorithm.
    pub(crate) fn calc_hmac_digest(
        decoded_secret: Vec<u8>,
        counter: u64,
        algorithm: Algorithm,
    ) -> hmac::Tag {
        let sha_algorithm = algorithm.into();
        let key = hmac::Key::new(sha_algorithm, &decoded_secret);
        hmac::sign(&key, &counter.to_be_bytes())
    }

    /// Encodes the HMAC digest into a n-digit integer.
    /// The max offset has to be the length of the digest minus five.
    /// For SHA1 this is 15, 27 for SHA256 and 59 for SHA512.
    pub(crate) fn encode_digest(digest: Vec<u8>, offset: Option<u8>) -> Result<u32, Error> {
        let offset = match offset {
            // Use provided offset.
            Some(x) => x,
            // Calculate offset from last byte.
            // Max offset can be 16 bytes (value of 15), because the calculated digest has a min length of 20 bytes.
            None => match digest.last() {
                Some(y) => *y & 0xf,
                None => return Err(Error::new(ErrorKind::InvalidData, "Digest not valid!")),
            },
        } as usize;

        // Extract 4 bytes from calculated HMAC-SHA digest.
        let code_bytes: [u8; 4] = match digest[offset..offset + 4].try_into() {
            Ok(x) => x,
            Err(e) => return Err(Error::new(ErrorKind::InvalidData, e)),
        };
        let code = u32::from_be_bytes(code_bytes);

        // Shorten code to 31 bit.
        Ok(code & 0x7fffffff)
    }
}

#[cfg(test)]
mod test {
    use crate::hotp::{Hotp, HotpBuilder};
    use crate::otp::{Otp, OtpBuilder};
    use data_encoding::BASE32;

    #[test]
    /// HOTP test values taken from RFC 4226 appendix D https://www.rfc-editor.org/rfc/rfc4226#appendix-D
    fn test_rfc_compliance() {
        const RFC_CODES: [u32; 10] = [
            755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489,
        ];
        const RFC_SECRET: &str = "12345678901234567890";
        let rfc_secret_vec: Vec<u8> = RFC_SECRET.as_bytes().to_vec();
        let rfc_base32_secret = BASE32.encode(RFC_SECRET.as_bytes());
        for index in 0..9 {
            let expected_code = RFC_CODES.get(index).unwrap().to_owned();
            assert_eq!(
                Hotp::new_str(RFC_SECRET)
                    .build()
                    .unwrap()
                    .generate_at(index.try_into().unwrap())
                    .unwrap(),
                expected_code
            );
            assert_eq!(
                Hotp::new_base32(&rfc_base32_secret)
                    .unwrap()
                    .build()
                    .unwrap()
                    .generate_at(index.try_into().unwrap())
                    .unwrap(),
                expected_code
            );
            assert_eq!(
                Hotp::new(rfc_secret_vec.to_owned())
                    .build()
                    .unwrap()
                    .generate_at(index.try_into().unwrap())
                    .unwrap(),
                expected_code
            );
        }
    }

    #[test]
    /// Checks validation and if the counter increases on successful validation and generation.
    fn validate_code() {
        let unencoded_secret = "12345678901234567890";
        let mut hotp: Hotp = Otp::new(unencoded_secret.as_bytes().to_vec())
            .build()
            .unwrap();
        let code = hotp.generate().unwrap();
        assert_eq!(hotp.counter, 1);
        // Reset counter
        hotp.counter = 0;
        assert!(hotp.validate(code));
        assert_eq!(hotp.counter, 1);
        // Only increment when validation was successful
        assert!(!hotp.validate(code + 1));
        assert_eq!(hotp.counter, 1);
    }

    #[test]
    /// Checks if the server accepts a counter drift from the client.
    fn validate_code_with_drift() {
        let unencoded_secret = "12345678901234567890";
        let mut hotp_server = Hotp::new(unencoded_secret.as_bytes().to_vec())
            .build()
            .unwrap();
        let mut hotp_client = Hotp::new(unencoded_secret.as_bytes().to_vec())
            .build()
            .unwrap();
        hotp_client.counter = 5;
        assert!(hotp_server.validate(hotp_client.generate().unwrap()));
        hotp_client.counter = 11;
        assert!(!hotp_server.validate(hotp_client.generate().unwrap()));
    }

    #[test]
    /// Make hotp specific changes via the HotpBuilder
    fn hotp_specific_changes() {
        let hotp = HotpBuilder::from(Otp::new_str("12345678901234567890"))
            .counter(3)
            .build()
            .unwrap()
            .generate()
            .unwrap();
        assert_eq!(hotp, 969429)
    }
}
