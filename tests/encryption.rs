use {
    async_trait::async_trait,
    futures::stream::TryStreamExt,
    gluesql_core::{prelude::Glue, store::RowIter},
    gluesql_encryption::EncryptedStore,
    gluesql_memory_storage::MemoryStorage,
    gluesql_test_suite::*,
    ring::aead::{Nonce, NonceSequence, UnboundKey},
};

struct CounterNonce(u64);

impl CounterNonce {
    fn new() -> Self {
        let _ = tracing_subscriber::fmt::try_init();

        CounterNonce(0)
    }
}

impl Default for CounterNonce {
    fn default() -> Self {
        Self::new()
    }
}

impl NonceSequence for CounterNonce {
    fn advance(&mut self) -> Result<Nonce, ring::error::Unspecified> {
        self.0 += 1;
        let mut buf = [0; 12];
        buf[..8].copy_from_slice(&self.0.to_le_bytes());
        Ok(Nonce::assume_unique_for_key(buf))
    }
}

fn new_key() -> UnboundKey {
    let algorithm = &ring::aead::AES_256_GCM;
    let key_bytes = &[0; 32];
    UnboundKey::new(algorithm, key_bytes).unwrap()
}

struct EncryptedTester {
    glue: Glue<EncryptedStore<MemoryStorage, CounterNonce>>,
}

#[async_trait(?Send)]
impl Tester<EncryptedStore<MemoryStorage, CounterNonce>> for EncryptedTester {
    async fn new(_: &str) -> Self {
        let storage = MemoryStorage::default();

        let glue = Glue::new(EncryptedStore::new(storage, new_key(), CounterNonce::new()));

        EncryptedTester { glue }
    }

    fn get_glue(&mut self) -> &mut Glue<EncryptedStore<MemoryStorage, CounterNonce>> {
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

    let storage = MemoryStorage::default();

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

    let storage = MemoryStorage::default();
    let mut glue = Glue::new(storage);

    exec!(glue "CREATE TABLE TxTest (id INTEGER);");
    test!(glue "BEGIN", Err(Error::StorageMsg("[MemoryStorage] transaction is not supported".to_owned())));
    test!(glue "COMMIT", Ok(vec![Payload::Commit]));
    test!(glue "ROLLBACK", Ok(vec![Payload::Rollback]));
}
