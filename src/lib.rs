use std::{fmt::Debug, sync::Mutex};

use async_trait::async_trait;
use futures::StreamExt;
use gluesql_core::{
    ast::{ColumnDef, IndexOperator, OrderByExpr},
    data::{CustomFunction as StructCustomFunction, Key, Schema, Value},
    error::{Error as GluesqlError, Result},
    executor::Referencing,
    store::{
        AlterTable, CustomFunction, CustomFunctionMut, DataRow, Index, IndexMut, MetaIter,
        Metadata, RowIter, Store, StoreMut, Transaction,
    },
};
use ring::aead::{Aad, LessSafeKey, Nonce, NonceSequence, UnboundKey};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("[GlueqlEncryption] serialization error: {0}")]
    SerializationError(#[from] postcard::Error),
    #[error("[GluesqlEncryption] encryption error")]
    EncryptionError,
    #[error("[GluesqlEncryption] invalid value")]
    InvalidValue,
}

impl From<ring::error::Unspecified> for Error {
    fn from(_: ring::error::Unspecified) -> Self {
        Error::EncryptionError
    }
}

impl From<Error> for GluesqlError {
    fn from(error: Error) -> Self {
        GluesqlError::StorageMsg(error.to_string())
    }
}
pub struct EncryptedStore<S, NonceSeq: NonceSequence> {
    key: LessSafeKey,
    nonce_sequence: Mutex<NonceSeq>,
    store: S,
}

impl<S: Debug, NonceSeq: NonceSequence> Debug for EncryptedStore<S, NonceSeq> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedStore")
            .field("store", &self.store)
            .finish_non_exhaustive()
    }
}

impl<S, NonceSeq: NonceSequence> EncryptedStore<S, NonceSeq> {
    pub fn new(store: S, key: UnboundKey, nonce_sequence: NonceSeq) -> Self {
        Self {
            key: LessSafeKey::new(key),
            nonce_sequence: Mutex::new(nonce_sequence),
            store,
        }
    }

    pub fn encrypt_value_in_place(&self, value: &mut Value) -> Result<(), Error> {
        let nonce = self.nonce_sequence.lock().unwrap().advance()?;

        tracing::info!(nonce = ?nonce.as_ref(), "encrypting val with nonce");

        let mut encrypted = Vec::with_capacity(
            self.key.algorithm().nonce_len()
                + std::mem::size_of::<Value>()
                + self.key.algorithm().tag_len(),
        );

        encrypted.extend_from_slice(nonce.as_ref());

        let mut encrypted = postcard::to_extend(value, encrypted)?;

        let aad = Aad::from(*nonce.as_ref());

        let tag = self.key.seal_in_place_separate_tag(
            nonce,
            aad,
            &mut encrypted[self.key.algorithm().nonce_len()..],
        )?;

        encrypted.extend_from_slice(tag.as_ref());

        *value = Value::Bytea(encrypted);

        Ok(())
    }

    pub fn encrypt_row_in_place(&self, row: &mut DataRow) -> Result<(), Error> {
        match row {
            DataRow::Vec(ref mut values) => {
                for value in values {
                    self.encrypt_value_in_place(value)?;
                }
            }
            DataRow::Map(ref mut values) => {
                for value in values.values_mut() {
                    self.encrypt_value_in_place(value)?
                }
            }
        }

        Ok(())
    }

    pub fn decrypt_value_in_place(&self, value: &mut Value) -> Result<(), Error> {
        tracing::info!("decrypting");
        match value {
            Value::Bytea(encrypted) => {
                let mut decrypted = encrypted.clone();

                let (nonce, ciphertext) = decrypted.split_at_mut(self.key.algorithm().nonce_len());

                tracing::info!(nonce = ?nonce, "decrypting val with nonce");

                let nonce = Nonce::try_assume_unique_for_key(nonce)?;
                let aad = Aad::from(*nonce.as_ref());

                self.key.open_in_place(nonce, aad, ciphertext)?;

                *value = postcard::from_bytes(ciphertext)?;

                Ok(())
            }
            v => {
                tracing::warn!(?v, "invalid value");

                Ok(())
            }
        }
    }

    pub fn decrypt_row_in_place(&self, row: &mut DataRow) -> Result<(), Error> {
        match row {
            DataRow::Vec(ref mut values) => {
                for value in values {
                    self.decrypt_value_in_place(value)?;
                }
            }
            DataRow::Map(ref mut values) => {
                for value in values.values_mut() {
                    self.decrypt_value_in_place(value)?
                }
            }
        }

        Ok(())
    }

    pub fn handle_column(&self, column: &mut ColumnDef) -> Result<ColumnDef> {
        //TODO: handle default column values
        todo!()
    }
}

#[async_trait(?Send)]
impl<S: Store, NonceSeq: NonceSequence> Store for EncryptedStore<S, NonceSeq> {
    async fn fetch_schema(&self, table_name: &str) -> Result<Option<Schema>> {
        self.store.fetch_schema(table_name).await
    }

    async fn fetch_all_schemas(&self) -> Result<Vec<Schema>> {
        self.store.fetch_all_schemas().await
    }

    async fn fetch_data(&self, table_name: &str, key: &Key) -> Result<Option<DataRow>> {
        let data = self.store.fetch_data(table_name, key).await?;

        match data {
            Some(mut data) => {
                tracing::info!(?data);
                self.decrypt_row_in_place(&mut data)
                    .map_err(GluesqlError::from)?;
                Ok(Some(data))
            }
            None => Ok(None),
        }
    }

    async fn scan_data(&self, table_name: &str) -> Result<RowIter<'_>> {
        match self.store.scan_data(table_name).await {
            Ok(rows) => Ok(Box::pin(rows.map(|row| match row {
                Ok((key, mut row)) => {
                    self.decrypt_row_in_place(&mut row)
                        .map_err(GluesqlError::from)?;
                    Ok((key, row))
                }
                Err(e) => Err(e),
            }))),
            Err(e) => Err(e),
        }
    }

    async fn fetch_referencings(&self, table_name: &str) -> Result<Vec<Referencing>> {
        self.store.fetch_referencings(table_name).await
    }
}

#[async_trait(?Send)]
impl<S: StoreMut, NonceSeq: NonceSequence> StoreMut for EncryptedStore<S, NonceSeq> {
    async fn insert_schema(&mut self, schema: &Schema) -> Result<()> {
        self.store.insert_schema(schema).await
    }

    async fn delete_schema(&mut self, table_name: &str) -> Result<()> {
        self.store.delete_schema(table_name).await
    }

    async fn append_data(&mut self, table_name: &str, mut rows: Vec<DataRow>) -> Result<()> {
        tracing::info!("appending");

        for row in rows.iter_mut() {
            self.encrypt_row_in_place(row).map_err(GluesqlError::from)?;
        }

        tracing::info!(?rows);

        self.store.append_data(table_name, rows).await
    }

    async fn insert_data(&mut self, table_name: &str, mut rows: Vec<(Key, DataRow)>) -> Result<()> {
        tracing::info!(?rows, %table_name, "inserting");

        for (_, ref mut row) in rows.iter_mut() {
            self.encrypt_row_in_place(row).map_err(GluesqlError::from)?;
        }

        self.store.insert_data(table_name, rows).await
    }

    async fn delete_data(&mut self, table_name: &str, keys: Vec<Key>) -> Result<()> {
        self.store.delete_data(table_name, keys).await
    }
}

#[async_trait(?Send)]
impl<S: AlterTable, NonceSeq: NonceSequence> AlterTable for EncryptedStore<S, NonceSeq> {
    async fn rename_schema(&mut self, table_name: &str, new_table_name: &str) -> Result<()> {
        self.store.rename_schema(table_name, new_table_name).await
    }

    async fn rename_column(
        &mut self,
        table_name: &str,
        column_name: &str,
        new_column_name: &str,
    ) -> Result<()> {
        self.store
            .rename_column(table_name, column_name, new_column_name)
            .await
    }

    async fn add_column(&mut self, table_name: &str, column_def: &ColumnDef) -> Result<()> {
        self.store.add_column(table_name, column_def).await
    }

    async fn drop_column(
        &mut self,
        table_name: &str,
        column_name: &str,
        if_exists: bool,
    ) -> Result<()> {
        self.store
            .drop_column(table_name, column_name, if_exists)
            .await
    }
}

#[async_trait(?Send)]
impl<S: Index, NonceSeq: NonceSequence> Index for EncryptedStore<S, NonceSeq> {
    async fn scan_indexed_data(
        &self,
        table_name: &str,
        index_name: &str,
        asc: Option<bool>,
        cmp_value: Option<(&IndexOperator, Value)>,
    ) -> Result<RowIter<'_>> {
        self.store
            .scan_indexed_data(table_name, index_name, asc, cmp_value)
            .await
    }
}

#[async_trait(?Send)]
impl<S: IndexMut, NonceSeq: NonceSequence> IndexMut for EncryptedStore<S, NonceSeq> {
    async fn create_index(
        &mut self,
        table_name: &str,
        index_name: &str,
        column: &OrderByExpr,
    ) -> Result<()> {
        self.store
            .create_index(table_name, index_name, column)
            .await
    }

    async fn drop_index(&mut self, table_name: &str, index_name: &str) -> Result<()> {
        self.store.drop_index(table_name, index_name).await
    }
}

#[async_trait(?Send)]
impl<S: Metadata, NonceSeq: NonceSequence> Metadata for EncryptedStore<S, NonceSeq> {
    async fn scan_table_meta(&self) -> Result<MetaIter> {
        self.store.scan_table_meta().await
    }
}

#[async_trait(?Send)]
impl<S: Transaction, NonceSeq: NonceSequence> Transaction for EncryptedStore<S, NonceSeq> {
    async fn begin(&mut self, autocommit: bool) -> Result<bool> {
        self.store.begin(autocommit).await
    }

    async fn commit(&mut self) -> Result<()> {
        self.store.commit().await
    }

    async fn rollback(&mut self) -> Result<()> {
        self.store.rollback().await
    }
}

#[async_trait(?Send)]
impl<S: CustomFunction, NonceSeq: NonceSequence> CustomFunction for EncryptedStore<S, NonceSeq> {
    async fn fetch_function(&self, func_name: &str) -> Result<Option<&StructCustomFunction>> {
        self.store.fetch_function(func_name).await
    }

    async fn fetch_all_functions(&self) -> Result<Vec<&StructCustomFunction>> {
        self.store.fetch_all_functions().await
    }
}

#[async_trait(?Send)]
impl<S: CustomFunctionMut, NonceSeq: NonceSequence> CustomFunctionMut
    for EncryptedStore<S, NonceSeq>
{
    async fn insert_function(&mut self, func: StructCustomFunction) -> Result<()> {
        self.store.insert_function(func).await
    }

    async fn delete_function(&mut self, func_name: &str) -> Result<()> {
        self.store.delete_function(func_name).await
    }
}
