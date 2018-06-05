#![allow(missing_docs)]

use priv_prelude::*;
use maidsafe_utilities::serialisation;
use rust_sodium::crypto::{box_, sealedbox, sign};

pub trait PublicId: 'static
        + Send
        + fmt::Debug
        + PartialEq
        + Eq
        + PartialOrd
        + Ord
        + Clone
        + Serialize
        + DeserializeOwned
        + Hash
{
    type Signature: 'static
        + Send
        + fmt::Debug
        + PartialEq
        + Eq
        + PartialOrd
        + Ord
        + Hash
        + Clone
        + Serialize
        + DeserializeOwned;
    
    fn encrypt_anonymous<T>(&self, plaintext: &T) -> Vec<u8>
    where T:
        Serialize;
    
    fn encrypt_anonymous_bytes(&self, plaintext: &[u8]) -> Vec<u8>;

    fn verify_detached(&self, signature: &Self::Signature, data: &[u8]) -> bool;
}

pub trait SecretId: 'static
        + Send
        + fmt::Debug
        + Clone
{
    type Public: PublicId;
    type SharedSecret: SharedSecretKey;
    
    fn new() -> Self;
    fn public_id(&self) -> &Self::Public;
    fn decrypt_anonymous<T>(&self, cyphertext: &[u8]) -> Result<T, DecryptError>
    where
        T: Serialize + DeserializeOwned;
    fn decrypt_anonymous_bytes(&self, cyphertext: &[u8]) -> Result<Vec<u8>, DecryptBytesError>;
    
    fn sign_detached(&self, data: &[u8]) -> <Self::Public as PublicId>::Signature;
    fn precompute(&self, their_pk: &Self::Public) -> Self::SharedSecret;
}

pub trait SharedSecretKey: 'static
        + Send
        + fmt::Debug
        + Clone
{
    fn encrypt_bytes(&self, plaintext: &[u8]) -> Vec<u8>;
    fn encrypt<T>(&self, plaintext: &T) -> Vec<u8>
    where
        T: Serialize;
    fn decrypt_bytes(&self, cyphertext: &[u8]) -> Result<Vec<u8>, DecryptBytesError>;
    fn decrypt<T>(&self, cyphertext: &[u8]) -> Result<T, DecryptError>
    where
        T: Serialize + DeserializeOwned;
}

quick_error! {
    #[derive(Debug)]
    pub enum DecryptError {
        DecryptVerify {
            description("error decrypting/verifying message")
        }
        Deserialization(e: serialisation::SerialisationError) {
            description("error deserializing decrypted message")
            display("error deserializing decrypted message: {}", e)
            cause(e)
        }
    }
}

quick_error! {
    #[derive(Clone, Debug)]
    pub enum DecryptBytesError {
        DecryptVerify {
            description("error decrypting/verifying message")
        }
    }
}

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Clone)]
pub struct P2pPublicId {
    sign: sign::PublicKey,
    encrypt: box_::PublicKey,
}

impl PublicId for P2pPublicId {
    type Signature = sign::Signature;

    fn encrypt_anonymous<T>(&self, plaintext: &T) -> Vec<u8>
    where T:
        Serialize
    {
        let bytes = unwrap!(serialisation::serialise(plaintext));
        self.encrypt_anonymous_bytes(&bytes)
    }

    fn encrypt_anonymous_bytes(&self, plaintext: &[u8]) -> Vec<u8> {
        sealedbox::seal(plaintext, &self.encrypt)
    }

    fn verify_detached(&self, signature: &sign::Signature, data: &[u8]) -> bool {
        sign::verify_detached(signature, data, &self.sign)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct P2pSecretId {
    sign: sign::SecretKey,
    encrypt: box_::SecretKey,
    public: P2pPublicId,
}

impl SecretId for P2pSecretId {
    type Public = P2pPublicId;
    type SharedSecret = P2pSharedSecretKey;

    fn new() -> P2pSecretId {
        let (sign_pk, sign_sk) = sign::gen_keypair();
        let (encrypt_pk, encrypt_sk) = box_::gen_keypair();
        let public = P2pPublicId {
            sign: sign_pk,
            encrypt: encrypt_pk,
        };
        P2pSecretId {
            public: public,
            sign: sign_sk,
            encrypt: encrypt_sk,
        }
    }

    fn public_id(&self) -> &P2pPublicId {
        &self.public
    }

    fn decrypt_anonymous<T>(&self, cyphertext: &[u8]) -> Result<T, DecryptError>
    where
        T: Serialize + DeserializeOwned
    {
        let bytes = self
            .decrypt_anonymous_bytes(cyphertext)
            .map_err(|DecryptBytesError::DecryptVerify| DecryptError::DecryptVerify)?;
        serialisation::deserialise(&bytes)
            .map_err(|e| DecryptError::Deserialization(e))
    }

    fn decrypt_anonymous_bytes(&self, cyphertext: &[u8]) -> Result<Vec<u8>, DecryptBytesError> {
        sealedbox::open(cyphertext, &self.public.encrypt, &self.encrypt)
            .map_err(|()| DecryptBytesError::DecryptVerify)
    }
    
    fn sign_detached(&self, data: &[u8]) -> sign::Signature {
        sign::sign_detached(data, &self.sign)
    }

    fn precompute(&self, their_pk: &P2pPublicId) -> P2pSharedSecretKey {
        let precomputed = box_::precompute(&their_pk.encrypt, &self.encrypt);
        P2pSharedSecretKey {
            precomputed,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct P2pSharedSecretKey {
    precomputed: box_::PrecomputedKey,
}

impl SharedSecretKey for P2pSharedSecretKey {
    fn encrypt_bytes(&self, plaintext: &[u8]) -> Vec<u8> {
        let nonce = unwrap!(box_::Nonce::from_slice(&[0u8; 24][..]));
        box_::seal_precomputed(plaintext, &nonce, &self.precomputed)
    }

    fn encrypt<T>(&self, plaintext: &T) -> Vec<u8>
    where
        T: Serialize
    {
        let bytes = unwrap!(serialisation::serialise(plaintext));
        self.encrypt_bytes(&bytes)
    }

    fn decrypt_bytes(&self, cyphertext: &[u8]) -> Result<Vec<u8>, DecryptBytesError> {
        let nonce = unwrap!(box_::Nonce::from_slice(&[0u8; 24][..]));
        box_::open_precomputed(cyphertext, &nonce, &self.precomputed)
            .map_err(|()| DecryptBytesError::DecryptVerify)
    }

    fn decrypt<T>(&self, cyphertext: &[u8]) -> Result<T, DecryptError>
    where
        T: Serialize + DeserializeOwned
    {
        let bytes = self
            .decrypt_bytes(cyphertext)
            .map_err(|DecryptBytesError::DecryptVerify| DecryptError::DecryptVerify)?;
        serialisation::deserialise(&bytes)
            .map_err(|e| DecryptError::Deserialization(e))
    }
}


