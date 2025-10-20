use crate::domain::models::user::User;
use crate::infrastructure::data::db_context::surrealdb_context::DB;
use serde::{Deserialize, Serialize};
use surrealdb::Error;
use surrealdb::err::Error::Thrown;
use surrealdb::sql::Datetime;

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

        let error = Error::Db(Thrown(format!("User with id {} not found", id)));
        Err(error)
    }

    pub async fn add_user(&self, user: User) -> Result<Vec<User>, Error> {
        #[derive(Serialize)]
        struct DbUser {
            id: i32,
            username: String,
            email: String,
            password: String,
            encryption_public_key: String,
            signature_public_key: String,
            created_at: Datetime,
            updated_at: Datetime,
        }

        impl From<&User> for DbUser {
            fn from(user: &User) -> Self {
                Self {
                    id: user.id,
                    username: user.username.clone(),
                    email: user.email.clone(),
                    password: user.password.clone(),
                    encryption_public_key: user.encryption_public_key.clone(),
                    signature_public_key: user.signature_public_key.clone(),
                    created_at: user.created_at.into(),
                    updated_at: user.updated_at.into(),
                }
            }
        }

        let payload = DbUser::from(&user);
        let opt_records = DB.create(&self.table).content(payload).await?;
        match opt_records {
            Some(records) => Ok(records),
            None => Err(Error::Db(Thrown("Failed to insert user".into()))),
        }
    }

    pub async fn get_by_username(&self, username: &str) -> Result<User, Error> {
        let mut response = DB
            .query("SELECT * FROM type::table($table) WHERE username = $username LIMIT 1")
            .bind(("table", self.table.clone()))
            .bind(("username", username.to_owned()))
            .await?;

        if let Some(user) = response.take::<Option<User>>(0)? {
            return Ok(user);
        }

        let error = Error::Db(Thrown(format!("User with username {} not found", username)));
        Err(error)
    }

    pub async fn username_exists(&self, username: &str) -> Result<bool, Error> {
        self.exists_by_field("username", username).await
    }

    pub async fn email_exists(&self, email: &str) -> Result<bool, Error> {
        self.exists_by_field("email", email).await
    }

    pub async fn next_id(&self) -> Result<i32, Error> {
        let mut response = DB
            .query("SELECT math::max(id) AS max_id FROM type::table($table)")
            .bind(("table", self.table.clone()))
            .await?;

        #[derive(Deserialize)]
        struct MaxIdResult {
            max_id: Option<i32>,
        }

        let max_id = response
            .take::<Option<MaxIdResult>>(0)?
            .and_then(|record| record.max_id)
            .unwrap_or(0);

        Ok(max_id + 1)
    }

    async fn exists_by_field(&self, field: &str, value: &str) -> Result<bool, Error> {
        let mut response = DB
            .query(
                "SELECT count() AS count FROM type::table($table) WHERE type::field($field) = $value",
            )
            .bind(("table", self.table.clone()))
            .bind(("field", field.to_string()))
            .bind(("value", value.to_string()))
            .await?;

        #[derive(Deserialize)]
        struct ExistsResult {
            count: i64,
        }

        let count = response
            .take::<Option<ExistsResult>>(0)?
            .map(|record| record.count)
            .unwrap_or(0);

        Ok(count > 0)
    }
}
