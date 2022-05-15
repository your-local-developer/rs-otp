use ring::hmac::{
    Algorithm as HmacAlgorithm, HMAC_SHA1_FOR_LEGACY_USE_ONLY, HMAC_SHA256, HMAC_SHA512,
};

#[derive(Debug, Clone, Copy)]
pub enum Algorithm {
    SHA1,
    SHA256,
    SHA512,
}

impl Default for Algorithm {
    fn default() -> Self {
        Algorithm::SHA1
    }
}

impl From<Algorithm> for HmacAlgorithm {
    fn from(algorithm: Algorithm) -> Self {
        match algorithm {
            Algorithm::SHA1 => HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            Algorithm::SHA256 => HMAC_SHA256,
            Algorithm::SHA512 => HMAC_SHA512,
        }
    }
}
