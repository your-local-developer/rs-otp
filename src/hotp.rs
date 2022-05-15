use std::io::{Error, ErrorKind};

use data_encoding::DecodeError;
use ring::hmac;

use crate::algorithm::Algorithm;
use crate::otp::Otp;

pub static DEFAULT_DIGITS: u8 = 6;

struct Hotp {
    secret: Vec<u8>,
    algorithm: Algorithm,
    digits: u8,
}

impl Otp for Hotp {
    fn new(secret: Vec<u8>, algorithm: Algorithm, digits: u8) -> Self {
        Hotp {
            secret,
            algorithm,
            digits,
        }
    }

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

    fn from_string(secret: &str, algorithm: Algorithm, digits: u8) -> Self {
        Hotp {
            secret: secret.as_bytes().to_vec(),
            algorithm,
            digits,
        }
    }

    fn calculate(&self, counter: u64) -> Result<u32, Error> {
        let full_code = Self::encode_digest(
            Self::calc_hmac_digest(&self.secret, counter, self.algorithm).as_ref(),
        )?;

        if let Some(modulus) = 10_u32.checked_pow(self.digits.into()) {
            if let Some(code) = full_code.checked_rem(modulus) {
                Ok(code)
            } else {
                Err(Error::new(
                    ErrorKind::InvalidData,
                    "Number of digits to big for this operation.",
                ))
            }
        } else {
            Err(Error::new(
                ErrorKind::InvalidData,
                "Number of digits to big for this operation.",
            ))
        }
    }

    fn calculate_with_offset(&self, _counter: u64, _offset: u8) -> Result<u32, Error> {
        todo!()
    }
}

impl Hotp {
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
    pub(crate) fn encode_digest(digest: &[u8]) -> Result<u32, Error> {
        let invalid_digest_err = Error::new(ErrorKind::InvalidData, "Digest not valid!");
        let offset = match digest.last() {
            Some(x) => *x & 0xf,
            None => return Err(invalid_digest_err),
        } as usize;

        // TODO: Add possibility to set a custom offset
        let code_bytes: [u8; 4] = match digest[offset..offset + 4].try_into() {
            Ok(x) => x,
            Err(_) => return Err(invalid_digest_err),
        };
        let code = u32::from_be_bytes(code_bytes);
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
