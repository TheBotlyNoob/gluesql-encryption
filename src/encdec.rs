use gluesql_core::{data::Value, store::DataRow};
use ring::aead::{Aad, LessSafeKey, Nonce, NonceSequence};

pub fn encrypt_value_in_place<N: NonceSequence>(
    key: &LessSafeKey,
    nonce_sequence: &mut N,
    value: &mut Value,
) -> Result<(), crate::Error> {
    let nonce = nonce_sequence.advance()?;

    tracing::info!(nonce = ?nonce.as_ref(), "encrypting val with nonce");

    let mut encrypted = Vec::with_capacity(
        key.algorithm().nonce_len() + std::mem::size_of::<Value>() + key.algorithm().tag_len(),
    );

    encrypted.extend_from_slice(nonce.as_ref());

    let mut encrypted = postcard::to_extend(value, encrypted)?;

    let aad = Aad::from(*nonce.as_ref());

    let tag =
        key.seal_in_place_separate_tag(nonce, aad, &mut encrypted[key.algorithm().nonce_len()..])?;

    encrypted.extend_from_slice(tag.as_ref());

    *value = Value::Bytea(encrypted);

    Ok(())
}

pub fn encrypt_row_in_place<N: NonceSequence>(
    key: &LessSafeKey,
    nonce_sequence: &mut N,
    row: &mut DataRow,
) -> Result<(), crate::Error> {
    match row {
        DataRow::Vec(ref mut values) => {
            for value in values {
                encrypt_value_in_place(key, nonce_sequence, value)?;
            }
        }
        DataRow::Map(ref mut values) => {
            for value in values.values_mut() {
                encrypt_value_in_place(key, nonce_sequence, value)?;
            }
        }
    }

    Ok(())
}

pub fn decrypt_value_in_place(key: &LessSafeKey, value: &mut Value) -> Result<bool, crate::Error> {
    tracing::info!("decrypting");
    match value {
        Value::Bytea(encrypted) => {
            let mut decrypted = encrypted.clone();

            let (nonce, ciphertext) = decrypted.split_at_mut(key.algorithm().nonce_len());

            tracing::info!(nonce = ?nonce, "decrypting val with nonce");

            let nonce = Nonce::try_assume_unique_for_key(nonce)?;
            let aad = Aad::from(*nonce.as_ref());

            key.open_in_place(nonce, aad, ciphertext)?;

            *value = postcard::from_bytes(ciphertext)?;

            Ok(true)
        }
        _ => {
            // value is most likely a default column value

            Ok(false)
        }
    }
}

pub fn decrypt_row_in_place(key: &LessSafeKey, row: &mut DataRow) -> Result<(), crate::Error> {
    match row {
        DataRow::Vec(ref mut values) => {
            for value in values {
                decrypt_value_in_place(key, value)?;
            }
        }
        DataRow::Map(ref mut values) => {
            for value in values.values_mut() {
                decrypt_value_in_place(key, value)?;
            }
        }
    }

    Ok(())
}
