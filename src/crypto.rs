#![allow(missing_docs)]

use maidsafe_utilities::serialisation;
use priv_prelude::*;
use rust_sodium::crypto::{box_, sealedbox};

pub trait PublicId:
    'static
    + Send
    + Sync
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
    fn encrypt_anonymous<T>(&self, plaintext: &T) -> Vec<u8>
    where
        T: Serialize;

    fn encrypt_anonymous_bytes(&self, plaintext: &[u8]) -> Vec<u8>;
}

pub trait SecretId: 'static + Send + Sync + fmt::Debug + Clone {
    type Public: PublicId;
    type SharedSecret: SharedSecretKey;

    fn new() -> Self;
    fn public_id(&self) -> &Self::Public;
    fn decrypt_anonymous<T>(&self, cyphertext: &[u8]) -> Result<T, DecryptError>
    where
        T: Serialize + DeserializeOwned;
    fn decrypt_anonymous_bytes(&self, cyphertext: &[u8]) -> Result<Vec<u8>, DecryptBytesError>;
    fn shared_key(&self, their_pk: &Self::Public) -> Self::SharedSecret;
}

pub trait SharedSecretKey: 'static + Send + Sync + fmt::Debug + Clone {
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
    encrypt_pk: box_::PublicKey,
}

impl PublicId for P2pPublicId {
    fn encrypt_anonymous<T>(&self, plaintext: &T) -> Vec<u8>
    where
        T: Serialize,
    {
        let bytes = unwrap!(serialisation::serialise(plaintext));
        self.encrypt_anonymous_bytes(&bytes)
    }

    fn encrypt_anonymous_bytes(&self, plaintext: &[u8]) -> Vec<u8> {
        sealedbox::seal(plaintext, &self.encrypt_pk)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct P2pSecretId {
    encrypt_sk: Arc<box_::SecretKey>,
    public: P2pPublicId,
}

impl SecretId for P2pSecretId {
    type Public = P2pPublicId;
    type SharedSecret = P2pSharedSecretKey;

    fn new() -> P2pSecretId {
        let (encrypt_pk, encrypt_sk) = box_::gen_keypair();
        let public = P2pPublicId {
            encrypt_pk,
        };
        P2pSecretId {
            public,
            encrypt_sk: Arc::new(encrypt_sk),
        }
    }

    fn public_id(&self) -> &P2pPublicId {
        &self.public
    }

    fn decrypt_anonymous<T>(&self, cyphertext: &[u8]) -> Result<T, DecryptError>
    where
        T: Serialize + DeserializeOwned,
    {
        let bytes = self
            .decrypt_anonymous_bytes(cyphertext)
            .map_err(|DecryptBytesError::DecryptVerify| DecryptError::DecryptVerify)?;
        serialisation::deserialise(&bytes).map_err(DecryptError::Deserialization)
    }

    fn decrypt_anonymous_bytes(&self, cyphertext: &[u8]) -> Result<Vec<u8>, DecryptBytesError> {
        sealedbox::open(cyphertext, &self.public.encrypt_pk, &self.encrypt_sk)
            .map_err(|()| DecryptBytesError::DecryptVerify)
    }

    fn shared_key(&self, their_pk: &P2pPublicId) -> P2pSharedSecretKey {
        let precomputed = box_::precompute(&their_pk.encrypt_pk, &self.encrypt_sk);
        P2pSharedSecretKey { precomputed }
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
        T: Serialize,
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
        T: Serialize + DeserializeOwned,
    {
        let bytes = self
            .decrypt_bytes(cyphertext)
            .map_err(|DecryptBytesError::DecryptVerify| DecryptError::DecryptVerify)?;
        serialisation::deserialise(&bytes).map_err(DecryptError::Deserialization)
    }
}
