use {
    async_trait::async_trait,
    gluesql_core::{
        data::Value,
        prelude::{Glue, Payload},
    },
    gluesql_encryption::EncryptedStore,
    gluesql_memory_storage::MemoryStorage,
    gluesql_test_suite::*,
    ring::aead::UnboundKey,
    std::vec,
    test_utils::RandNonce,
};

#[path = "../src/test_utils.rs"]
mod test_utils;

struct EncryptedTester {
    glue: Glue<EncryptedStore<MemoryStorage, RandNonce>>,
}

#[async_trait(?Send)]
impl Tester<EncryptedStore<MemoryStorage, RandNonce>> for EncryptedTester {
    async fn new(_: &str) -> Self {
        let storage = MemoryStorage::default();

        let glue = Glue::new(EncryptedStore::new_unchecked(
            storage,
            test_utils::new_key(),
            RandNonce::new(),
        ));

        EncryptedTester { glue }
    }

    fn get_glue(&mut self) -> &mut Glue<EncryptedStore<MemoryStorage, RandNonce>> {
        &mut self.glue
    }
}

generate_store_tests!(tokio::test, EncryptedTester);

generate_alter_table_tests!(tokio::test, EncryptedTester);

generate_metadata_table_tests!(tokio::test, EncryptedTester);

generate_custom_function_tests!(tokio::test, EncryptedTester);

macro_rules! exec {
    ($glue: ident $sql: literal) => {
        $glue.execute($sql).await.unwrap();
    };
}

macro_rules! test {
    ($glue: ident $sql: expr, $result: expr) => {
        assert_eq!($glue.execute($sql).await, $result);
    };
}

#[tokio::test]
async fn encrypted_storage_checks_key() {
    use gluesql_core::prelude::Glue;

    let storage = EncryptedStore::new(
        MemoryStorage::default(),
        test_utils::new_key(),
        RandNonce::new(),
    )
    .await
    .unwrap();

    let mut glue = Glue::new(storage);

    exec!(glue "CREATE TABLE TxTest (id INTEGER);");

    exec!(glue "INSERT INTO TxTest (id) VALUES (1);");

    glue.storage = glue
        .storage
        .change_key(UnboundKey::new(&ring::aead::AES_256_GCM, &[1; 32]).unwrap())
        .await
        .unwrap();

    test!(
        glue
        "SELECT * FROM TxTest;",
        Ok(vec![Payload::Select {
            rows: vec![vec![Value::I64(1)]],
            labels: vec!["id".to_owned()],
        }])
    );

    let storage = EncryptedStore::new(
        glue.storage.into_inner(),
        UnboundKey::new(&ring::aead::AES_256_GCM, &[1; 32]).unwrap(),
        RandNonce::new(),
    )
    .await
    .unwrap();

    assert_eq!(
        EncryptedStore::new(
            storage.into_inner(),
            UnboundKey::new(&ring::aead::AES_256_GCM, &[2; 32]).unwrap(),
            RandNonce::new(),
        )
        .await
        .unwrap_err(),
        gluesql_encryption::Error::InvalidKey
    );
}

#[tokio::test]
async fn encrypted_storage_change_key() {
    use gluesql_core::prelude::{Glue, Payload};

    let storage = EncryptedStore::new(
        MemoryStorage::default(),
        test_utils::new_key(),
        RandNonce::new(),
    )
    .await
    .unwrap();
    let mut glue = Glue::new(storage);

    exec!(glue "CREATE TABLE TxTest (id INTEGER);");

    exec!(glue "INSERT INTO TxTest (id) VALUES (1);");

    glue.storage = glue
        .storage
        .change_key(UnboundKey::new(&ring::aead::AES_256_GCM, &[1; 32]).unwrap())
        .await
        .unwrap();

    test!(
        glue
        "SELECT * FROM TxTest;",
        Ok(vec![Payload::Select {
            rows: vec![vec![Value::I64(1)]],
            labels: vec!["id".to_owned()],
        }])
    );

    assert_eq!(
        EncryptedStore::new(
            glue.storage.into_inner(),
            UnboundKey::new(&ring::aead::AES_256_GCM, &[2; 32]).unwrap(),
            RandNonce::new(),
        )
        .await
        .unwrap_err(),
        gluesql_encryption::Error::InvalidKey
    )
}
