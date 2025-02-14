use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};
use ring::aead::{NonceSequence, UnboundKey};

pub struct RandNonce(pub ChaCha20Rng);
impl RandNonce {
    pub fn new() -> Self {
        let rng = ChaCha20Rng::from_os_rng();
        RandNonce(rng)
    }
}

impl NonceSequence for RandNonce {
    fn advance(&mut self) -> Result<ring::aead::Nonce, ring::error::Unspecified> {
        let mut nonce = [0; 12];
        self.0.fill_bytes(&mut nonce);
        Ok(ring::aead::Nonce::assume_unique_for_key(nonce))
    }
}

pub fn new_key() -> UnboundKey {
    let algorithm = &ring::aead::AES_256_GCM;
    let key_bytes = &[0; 32];
    UnboundKey::new(algorithm, key_bytes).unwrap()
}
