use crate::domain::models::vault_item::VaultItem;
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

    pub async fn list_by_user(&self, user_id: &str) -> Result<Vec<VaultItem>, Error> {
        let mut response = DB
            .query("SELECT * FROM type::table($table) WHERE user_id = $user_id")
            .bind(("table", self.table.clone()))
            .bind(("user_id", user_id.to_owned()))
            .await?;

        let items = response.take::<Vec<VaultItem>>(0)?;
        Ok(items)
    }

    pub async fn list_by_folder(&self, folder_id: &str) -> Result<Vec<VaultItem>, Error> {
        let mut response = DB
            .query("SELECT * FROM type::table($table) WHERE folder_id = $folder_id ORDER BY title")
            .bind(("table", self.table.clone()))
            .bind(("folder_id", folder_id.to_owned()))
            .await?;

        let items = response.take::<Vec<VaultItem>>(0)?;
        Ok(items)
    }

    pub async fn get_by_id(&self, id: &str) -> Result<VaultItem, Error> {
        if let Some(item) = DB.select((&self.table, id)).await? {
            return Ok(item);
        }

        let error = Error::Db(Thrown(format!("Vault item with id {} not found", id)));
        Err(error)
    }

    pub async fn create(&self, item: VaultItem) -> Result<VaultItem, Error> {
        let mut response = DB
            .query("CREATE type::table($table) CONTENT $content RETURN AFTER")
            .bind(("table", self.table.clone()))
            .bind(("content", item))
            .await?;

        if let Some(created) = response.take::<Option<VaultItem>>(0)? {
            return Ok(created);
        }

        Err(Error::Db(Thrown("Failed to create vault item".into())))
    }
}
