use std::io::{Error, ErrorKind};

use data_encoding::DecodeError;
use ring::hmac;

use crate::algorithm::Algorithm;
use crate::otp::Otp;

pub static DEFAULT_DIGITS: u8 = 6;

pub struct Hotp {
    pub(crate) secret: Vec<u8>,
    pub(crate) algorithm: Algorithm,
    pub(crate) digits: u8,
}

impl Otp for Hotp {
    /// Initializes a new Hotp instance taking the unencoded secret as u8 vector.
    fn new(secret: Vec<u8>, algorithm: Algorithm, digits: u8) -> Self {
        Hotp {
            secret,
            algorithm,
            digits,
        }
    }

    /// Initializes a new Hotp instance taking the Base32 encoded secret as string.
    fn from_base32_string(
        secret: &str,
        algorithm: Algorithm,
        digits: u8,
    ) -> Result<Self, DecodeError> {
        let decoded_secret = Self::decode_secret(secret)?;
        Ok(Hotp {
            secret: decoded_secret,
            algorithm,
            digits,
        })
    }

    /// Initializes a new Hotp instance taking the unencoded secret as string.
    fn from_string(secret: &str, algorithm: Algorithm, digits: u8) -> Self {
        Hotp {
            secret: secret.as_bytes().to_vec(),
            algorithm,
            digits,
        }
    }

    /// Calculates the HOTP code as u32.
    fn calculate(&self, counter: u64) -> Result<u32, Error> {
        self.calculate_with_offset(counter, None)
    }
}

impl Hotp {
    /// Calculates the u32 Hotp code taking a counter as moving factor.
    /// It uses a custom offset to extract 4 bytes from the HMAC-SHA Digest.
    /// Keep in mind that the max value of the offset is the last index of the resulting digest minus four bytes.
    /// Therefore, the offset has to be between (inclusive) 0 and 15.
    pub fn calculate_with_offset(&self, counter: u64, offset: Option<u8>) -> Result<u32, Error> {
        let full_code = Self::encode_digest(
            Self::calc_hmac_digest(&self.secret, counter, self.algorithm).as_ref(),
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
        decoded_secret: &[u8],
        counter: u64,
        algorithm: Algorithm,
    ) -> hmac::Tag {
        let key = hmac::Key::new(algorithm.into(), decoded_secret);
        hmac::sign(&key, &counter.to_be_bytes())
    }

    /// Encodes the HMAC digest into a n-digit integer.
    pub(crate) fn encode_digest(digest: &[u8], offset: Option<u8>) -> Result<u32, Error> {
        // Calculate offset from last byte.
        // Max offset can be 16 bytes (value of 15), because the calculated digest has a max length of 20 bytes.
        let offset = match offset {
            Some(x) => x,
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
    use crate::{
        algorithm::Algorithm,
        hotp::{Hotp, DEFAULT_DIGITS},
        otp::Otp,
    };
    use data_encoding::BASE32;

    #[test]
    // HOTP test values taken from RFC 4226 appendix D https://www.rfc-editor.org/rfc/rfc4226#appendix-D
    fn test_hmac_rfc_compliance() {
        let unencoded_secret = "12345678901234567890";
        let base32_secret = BASE32.encode(unencoded_secret.as_bytes());

        let hotp_0 = Hotp::new(
            unencoded_secret.as_bytes().to_vec(),
            Algorithm::SHA1,
            DEFAULT_DIGITS,
        )
        .calculate(0)
        .unwrap();
        assert_eq!(hotp_0, 755224);

        let hotp_1 = Hotp::from_string(unencoded_secret, Algorithm::SHA1, DEFAULT_DIGITS)
            .calculate(1)
            .unwrap();
        assert_eq!(hotp_1, 287082);

        let hotp_2 = Hotp::from_base32_string(&base32_secret, Algorithm::SHA1, DEFAULT_DIGITS)
            .unwrap()
            .calculate(2)
            .unwrap();
        assert_eq!(hotp_2, 359152);

        let hotp_3 = Hotp::from_base32_string(&base32_secret, Algorithm::SHA1, DEFAULT_DIGITS)
            .unwrap()
            .calculate(3)
            .unwrap();
        assert_eq!(hotp_3, 969429);

        let hotp_4 = Hotp::from_base32_string(&base32_secret, Algorithm::SHA1, DEFAULT_DIGITS)
            .unwrap()
            .calculate(4)
            .unwrap();
        assert_eq!(hotp_4, 338314);

        let hotp_5 = Hotp::from_base32_string(&base32_secret, Algorithm::SHA1, DEFAULT_DIGITS)
            .unwrap()
            .calculate(5)
            .unwrap();
        assert_eq!(hotp_5, 254676);

        let hotp_6 = Hotp::from_base32_string(&base32_secret, Algorithm::SHA1, DEFAULT_DIGITS)
            .unwrap()
            .calculate(6)
            .unwrap();
        assert_eq!(hotp_6, 287922);

        let hotp_7 = Hotp::from_base32_string(&base32_secret, Algorithm::SHA1, DEFAULT_DIGITS)
            .unwrap()
            .calculate(7)
            .unwrap();
        assert_eq!(hotp_7, 162583);

        let hotp_8 = Hotp::from_base32_string(&base32_secret, Algorithm::SHA1, DEFAULT_DIGITS)
            .unwrap()
            .calculate(8)
            .unwrap();
        assert_eq!(hotp_8, 399871);

        let hotp_9 = Hotp::from_base32_string(&base32_secret, Algorithm::SHA1, DEFAULT_DIGITS)
            .unwrap()
            .calculate(9)
            .unwrap();
        assert_eq!(hotp_9, 520489);
    }
}
