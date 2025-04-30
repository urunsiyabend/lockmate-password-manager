use surrealdb::err::Error::Thrown;
use surrealdb::Error;
use crate::{infrastructure::data::db_context::surrealdb_context::DB};
use crate::domain::models::user::User;

pub struct UserRepository {
    table: String,
}

impl UserRepository {
    pub fn new() -> Self {
        UserRepository {
            table: String::from("users"),
        }
    }

    pub async fn get_all(&self) -> Result<Vec<User>, Error> {
        let records = DB.select(&self.table).await?;
        Ok(records)
    }

    pub async fn get_by_id(&self, id: String) -> Result<User, Error> {
        if let Some(record) = DB.select((&self.table, id.clone())).await? {
            return Ok(record);
        }

        let error = Error::Db(
            Thrown(
                format!("User with id {} not found", id)
            )
        );
        Err(error)
    }

    pub async fn add_user(&self, content: User) -> Result<Vec<User>, Error> {
        let opt_records = DB
            .create(&self.table)
            .content(content)
            .await?;
        match opt_records {
            Some(records) => Ok(records),
            None => Err(Error::Db(Thrown("Failed to insert user".into()))),
        }
    }

}
