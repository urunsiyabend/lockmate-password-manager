use crate::domain::models::vault_item::{NewVaultItemRecord, VaultItemRecord};
use crate::infrastructure::data::db_context::surrealdb_context::DB;
use surrealdb::Error;
use surrealdb::err::Error::Thrown;

pub struct VaultItemRepository {
    table: String,
}

impl VaultItemRepository {
    pub fn new() -> Self {
        Self {
            table: String::from("vault_items"),
        }
    }

    pub async fn list_by_user(&self, user_id: &str) -> Result<Vec<VaultItemRecord>, Error> {
        let mut response = DB
            .query("SELECT * FROM type::table($table) WHERE user_id = $user_id")
            .bind(("table", self.table.clone()))
            .bind(("user_id", user_id.to_owned()))
            .await?;

        let items = response.take::<Vec<VaultItemRecord>>(0)?;
        Ok(items)
    }

    pub async fn list_by_folder(
        &self,
        user_id: &str,
        folder_id: &str,
    ) -> Result<Vec<VaultItemRecord>, Error> {
        let mut response = DB
            .query(
                "SELECT * FROM type::table($table) \
                WHERE folder_id = $folder_id AND user_id = $user_id",
            )
            .bind(("table", self.table.clone()))
            .bind(("user_id", user_id.to_owned()))
            .bind(("folder_id", folder_id.to_owned()))
            .await?;

        let items = response.take::<Vec<VaultItemRecord>>(0)?;
        Ok(items)
    }

    pub async fn get_by_id_for_user(
        &self,
        user_id: &str,
        id: &str,
    ) -> Result<VaultItemRecord, Error> {
        let mut response = DB
            .query(
                "SELECT * FROM type::table($table) \
                WHERE id = type::thing($table, $id) AND user_id = $user_id",
            )
            .bind(("table", self.table.clone()))
            .bind(("id", id.to_owned()))
            .bind(("user_id", user_id.to_owned()))
            .await?;

        if let Some(item) = response.take::<Option<VaultItemRecord>>(0)? {
            return Ok(item);
        }

        let error = Error::Db(Thrown(format!("Vault item with id {} not found", id)));
        Err(error)
    }

    pub async fn create(&self, item: NewVaultItemRecord) -> Result<VaultItemRecord, Error> {
        let mut response = DB
            .query("CREATE type::table($table) CONTENT $content RETURN AFTER")
            .bind(("table", self.table.clone()))
            .bind(("content", item))
            .await?;

        if let Some(created) = response.take::<Option<VaultItemRecord>>(0)? {
            return Ok(created);
        }

        Err(Error::Db(Thrown("Failed to create vault item".into())))
    }

    pub async fn update_for_user(
        &self,
        id: &str,
        user_id: &str,
        folder_id: Option<String>,
        ciphertext: String,
        nonce: String,
        expected_updated_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Option<VaultItemRecord>, Error> {
        let mut response = DB
            .query(
                "UPDATE type::table($table) \
                SET folder_id = $folder_id, \
                    ciphertext = $ciphertext, \
                    nonce = $nonce, \
                    updated_at = time::now() \
                WHERE id = type::thing($table, $id) \
                  AND user_id = $user_id \
                  AND updated_at = $expected \
                RETURN AFTER",
            )
            .bind(("table", self.table.clone()))
            .bind(("id", id.to_owned()))
            .bind(("user_id", user_id.to_owned()))
            .bind(("folder_id", folder_id))
            .bind(("ciphertext", ciphertext))
            .bind(("nonce", nonce))
            .bind(("expected", expected_updated_at))
            .await?;

        let updated = response.take::<Option<VaultItemRecord>>(0)?;
        Ok(updated)
    }

    pub async fn delete_for_user(
        &self,
        id: &str,
        user_id: &str,
        expected_updated_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, Error> {
        let mut response = DB
            .query(
                "DELETE type::table($table) \
                WHERE id = type::thing($table, $id) \
                  AND user_id = $user_id \
                  AND updated_at = $expected \
                RETURN BEFORE",
            )
            .bind(("table", self.table.clone()))
            .bind(("id", id.to_owned()))
            .bind(("user_id", user_id.to_owned()))
            .bind(("expected", expected_updated_at))
            .await?;

        let deleted = response.take::<Option<VaultItemRecord>>(0)?.is_some();
        Ok(deleted)
    }
}
