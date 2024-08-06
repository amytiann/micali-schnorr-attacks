//! An implementation of the Micali-Schnorr pseudorandom generator (MS PRG).

use std::fmt;

use num_traits::One;
use rand::distributions::{Distribution, Uniform};
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey};

/// The version of the MS PRG.
#[derive(Clone, Copy, Debug)]
pub enum Version {
    Ms91,
    Iso,
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Version::Ms91 => "MS91",
                Version::Iso => "ISO",
            }
        )
    }
}

/// The state of the MS PRG.
#[derive(Debug)]
pub struct State {
    rsa_key: RsaPublicKey,
    n: usize,
    k: usize,
    version: Version,
    s: BigUint,
}

impl State {
    /// Creates a new MS PRG state.
    pub fn new(n: usize, e: &BigUint, k: usize, version: Version) -> Self {
        let mut rng = rand::thread_rng();
        let rsa_key = RsaPublicKey::from(
            &RsaPrivateKey::new_with_exp(&mut rng, n, e).expect("unable to create RSA key"),
        );
        State {
            s: Uniform::new_inclusive(BigUint::one(), rsa_key.n() >> k).sample(&mut rng),
            rsa_key,
            n,
            k,
            version,
        }
    }

    /// Returns the RSA modulus for the MS PRG.
    pub fn modulus(&self) -> &BigUint {
        self.rsa_key.n()
    }
}

impl Iterator for State {
    type Item = BigUint;

    /// Generates the output for the next iteration of the MS PRG.
    fn next(&mut self) -> Option<Self::Item> {
        let z = self.s.modpow(self.rsa_key.e(), self.rsa_key.n());
        self.s = match self.version {
            Version::Ms91 => (&z >> self.k) + 1u32,
            Version::Iso => &z >> self.k,
        };
        Some(z & ((BigUint::one() << self.k) - 1u32))
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "(N, e): ({}, {})\n(n, k, r): ({}, {}, {})\nVersion: {}\nState: {}",
            self.rsa_key.n(),
            self.rsa_key.e(),
            self.n,
            self.k,
            self.n - self.k,
            self.version,
            self.s,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_ms91() {
        let mut msprg = State {
            rsa_key: RsaPublicKey::new(BigUint::from(11u32 * 23), BigUint::from(3u32))
                .expect("unable to create RSA key"),
            n: 8,
            k: 3,
            version: Version::Ms91,
            s: BigUint::from(24u32),
        };

        assert_eq!(msprg.next(), Some(BigUint::from(2u32)));
        assert_eq!(msprg.next(), Some(BigUint::from(1u32)));
    }

    #[test]
    fn next_iso() {
        let mut msprg = State {
            rsa_key: RsaPublicKey::new(BigUint::from(11u32 * 23), BigUint::from(3u32))
                .expect("unable to create RSA key"),
            n: 8,
            k: 3,
            version: Version::Iso,
            s: BigUint::from(24u32),
        };

        assert_eq!(msprg.next(), Some(BigUint::from(2u32)));
        assert_eq!(msprg.next(), Some(BigUint::from(5u32)));
    }

    #[test]
    fn modulus() {
        let msprg = State {
            rsa_key: RsaPublicKey::new(BigUint::from(11u32 * 23), BigUint::from(3u32))
                .expect("unable to create RSA key"),
            n: 8,
            k: 3,
            version: Version::Iso,
            s: BigUint::from(24u32),
        };

        assert_eq!(msprg.modulus(), &BigUint::from(11u32 * 23));
    }
}
