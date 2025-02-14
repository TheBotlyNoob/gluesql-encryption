use {
    async_trait::async_trait, futures::stream::TryStreamExt, gluesql_core::prelude::Glue,
    gluesql_encryption::EncryptedStore, gluesql_memory_storage::MemoryStorage,
    gluesql_test_suite::*, ring::aead::UnboundKey, test_utils::RandNonce,
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

        let glue = Glue::new(EncryptedStore::new(
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
async fn memory_storage_index() {
    use gluesql_core::{
        prelude::{Error, Glue},
        store::{Index, Store},
    };

    let storage = EncryptedStore::new(
        MemoryStorage::default(),
        test_utils::new_key(),
        RandNonce::new(),
    );

    assert_eq!(
        Store::scan_data(&storage, "Idx")
            .await
            .unwrap()
            .try_collect::<Vec<_>>()
            .await
            .as_ref()
            .map(Vec::len),
        Ok(0),
    );

    assert_eq!(
        storage
            .scan_indexed_data("Idx", "hello", None, None)
            .await
            .map(|_| ()),
        Err(Error::StorageMsg(
            "[MemoryStorage] index is not supported".to_owned()
        ))
    );

    let mut glue = Glue::new(storage);

    exec!(glue "CREATE TABLE Idx (id INTEGER);");
    test!(
        glue "CREATE INDEX idx_id ON Idx (id);",
        Err(Error::StorageMsg("[MemoryStorage] index is not supported".to_owned()))
    );
    test!(
        glue "DROP INDEX Idx.idx_id;",
        Err(Error::StorageMsg("[MemoryStorage] index is not supported".to_owned()))
    );
}

#[tokio::test]
async fn memory_storage_transaction() {
    use gluesql_core::prelude::{Error, Glue, Payload};

    let storage = EncryptedStore::new(
        MemoryStorage::default(),
        test_utils::new_key(),
        RandNonce::new(),
    );
    let mut glue = Glue::new(storage);

    exec!(glue "CREATE TABLE TxTest (id INTEGER);");
    test!(glue "BEGIN", Err(Error::StorageMsg("[MemoryStorage] transaction is not supported".to_owned())));
    test!(glue "COMMIT", Ok(vec![Payload::Commit]));
    test!(glue "ROLLBACK", Ok(vec![Payload::Rollback]));

    exec!(glue "INSERT INTO TxTest (id) VALUES (1);");
    glue.storage = glue
        .storage
        .change_key(UnboundKey::new(&ring::aead::AES_256_GCM, &[1; 32]).unwrap())
        .await
        .unwrap();

    tracing::info!(a = ?glue.execute("SELECT * FROM TxTest;").await.unwrap());
}
