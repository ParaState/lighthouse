use base64::prelude::*;
use secp256k1::rand::thread_rng;
use secp256k1::{generate_keypair, Secp256k1};
use serde::{de, ser, Deserialize, Serialize};
use std::array::TryFromSliceError;
use std::convert::{TryFrom, TryInto};
use std::fmt;

pub type CryptoError = secp256k1::Error;

/// Represents a hash digest (32 bytes).
#[derive(Hash, PartialEq, Default, Eq, Clone, Deserialize, Serialize, Ord, PartialOrd)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn size(&self) -> usize {
        self.0.len()
    }
}

impl From<&[u8; 32]> for Digest {
    fn from(value: &[u8; 32]) -> Self {
        Digest(value.clone())
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<&[u8]> for Digest {
    type Error = TryFromSliceError;
    fn try_from(item: &[u8]) -> Result<Self, Self::Error> {
        Ok(Digest(item.try_into()?))
    }
}

/// This trait is implemented by all messages that can be hashed.
pub trait Hash {
    fn digest(&self) -> Digest;
}

/// Represents a public key (in bytes).
#[derive(Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct PublicKey(pub [u8; 33]);

impl Default for PublicKey {
    fn default() -> Self {
        PublicKey([0; 33])
    }
}

impl PublicKey {
    pub fn base64(&self) -> String {
        BASE64_STANDARD.encode(&self.0[..])
    }

    pub fn from_base64(s: &str) -> Result<Self, base64::DecodeError> {
        let bytes = BASE64_STANDARD.decode(s)?;
        let array: [u8; 33] = bytes[..33]
            .try_into()
            .map_err(|_| base64::DecodeError::InvalidLength(bytes.len()))?;
        Ok(Self(array))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.base64())
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "{}", self.base64())
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_str(&self.base64())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let value = Self::from_base64(&s).map_err(|e| de::Error::custom(e.to_string()))?;
        Ok(value)
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Represents a secret key (in bytes).
#[derive(Clone, PartialEq, Debug)]
pub struct SecretKey(pub [u8; 32]);

impl SecretKey {
    pub fn encode_base64(&self) -> String {
        BASE64_STANDARD.encode(&self.0[..])
    }

    pub fn decode_base64(s: &str) -> Result<Self, base64::DecodeError> {
        let bytes = BASE64_STANDARD.decode(s)?;
        let array = bytes[..32]
            .try_into()
            .map_err(|_| base64::DecodeError::InvalidLength(bytes.len()))?;
        Ok(Self(array))
    }
}

impl Serialize for SecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_str(&self.encode_base64())
    }
}

impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let value = Self::decode_base64(&s).map_err(|e| de::Error::custom(e.to_string()))?;
        Ok(value)
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.iter_mut().for_each(|x| *x = 0);
    }
}

pub fn generate_production_keypair() -> (PublicKey, SecretKey) {
    generate_secp256k_keypair()
}

pub fn generate_secp256k_keypair() -> (PublicKey, SecretKey) {
    let (secret_key, public_key) = generate_keypair(&mut thread_rng());
    // let keypair = dalek::Keypair::generate(csprng);
    let public = PublicKey(public_key.serialize());
    let secret = SecretKey(secret_key.secret_bytes());
    (public, secret)
}

/// Represents an ed25519 signature.
#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct Signature {
    part1: [u8; 32],
    part2: [u8; 32],
}

impl Signature {
    pub fn new(digest: &Digest, secret: &SecretKey) -> Result<Self, CryptoError> {
        let secret_key = secp256k1::SecretKey::from_slice(&secret.0)?;
        let message = secp256k1::Message::from_digest(digest.0);
        let sig = secret_key.sign_ecdsa(message).serialize_compact();
        let part1 = sig[..32].try_into().unwrap();
        let part2 = sig[32..64].try_into().unwrap();
        Ok(Signature { part1, part2 })
    }

    pub fn flatten(&self) -> [u8; 64] {
        [self.part1, self.part2].concat().try_into().unwrap()
    }

    pub fn from_bytes(sig: &[u8]) -> Result<Self, CryptoError> {
        if sig.len() != 64 {
            return Err(CryptoError::InvalidSignature);
        }
        let part1 = sig[..32].try_into().unwrap();
        let part2 = sig[32..64].try_into().unwrap();
        Ok(Signature { part1, part2 })
    }

    pub fn verify(&self, digest: &Digest, public_key: &PublicKey) -> Result<(), CryptoError> {
        let signature = secp256k1::ecdsa::Signature::from_compact(&self.flatten())?;
        let message = secp256k1::Message::from_digest(digest.0);
        let key = secp256k1::PublicKey::from_slice(&public_key.0)?;
        let secp = Secp256k1::verification_only();
        secp.verify_ecdsa(&message, &signature, &key)
    }

    pub fn verify_batch<'a, I>(digest: &Digest, votes: I) -> Result<(), CryptoError>
    where
        I: IntoIterator<Item = &'a (PublicKey, Signature)>,
    {
        let message = secp256k1::Message::from_digest(digest.0);
        let secp = Secp256k1::verification_only();
        for (key, sig) in votes.into_iter() {
            let signature = secp256k1::ecdsa::Signature::from_compact(&sig.flatten())?;
            let pub_key = secp256k1::PublicKey::from_slice(&key.0)?;
            secp.verify_ecdsa(&message, &signature, &pub_key)?;
        }
        Ok(())
    }
}
