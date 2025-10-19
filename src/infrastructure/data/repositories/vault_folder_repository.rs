use crate::domain::models::vault_folder::VaultFolder;
use crate::infrastructure::data::db_context::surrealdb_context::DB;
use surrealdb::Error;
use surrealdb::err::Error::Thrown;

pub struct VaultFolderRepository {
    table: String,
}

impl VaultFolderRepository {
    pub fn new() -> Self {
        Self {
            table: String::from("vault_folders"),
        }
    }

    pub async fn list_by_user(&self, user_id: &str) -> Result<Vec<VaultFolder>, Error> {
        let mut response = DB
            .query("SELECT * FROM type::table($table) WHERE user_id = $user_id")
            .bind(("table", self.table.clone()))
            .bind(("user_id", user_id.to_owned()))
            .await?;

        let folders = response.take::<Vec<VaultFolder>>(0)?;
        Ok(folders)
    }

    pub async fn get_by_id(&self, id: &str) -> Result<VaultFolder, Error> {
        if let Some(folder) = DB.select((&self.table, id)).await? {
            return Ok(folder);
        }

        let error = Error::Db(Thrown(format!("Vault folder with id {} not found", id)));
        Err(error)
    }

    pub async fn create(&self, folder: VaultFolder) -> Result<VaultFolder, Error> {
        let mut response = DB
            .query("CREATE type::table($table) CONTENT $content RETURN AFTER")
            .bind(("table", self.table.clone()))
            .bind(("content", folder))
            .await?;

        if let Some(created) = response.take::<Option<VaultFolder>>(0)? {
            return Ok(created);
        }

        Err(Error::Db(Thrown("Failed to create vault folder".into())))
    }
}
