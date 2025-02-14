use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};
use ring::aead::{NonceSequence, UnboundKey};

pub fn new_key() -> UnboundKey {
    let algorithm = &ring::aead::AES_256_GCM;
    let key_bytes = &[0; 32];
    UnboundKey::new(algorithm, key_bytes).unwrap()
}
