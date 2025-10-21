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

    pub async fn add_user(&self, user: User) -> Result<User, Error> {
        #[derive(Serialize)]
        struct DbUser {
            user_id: i32,                                // ← note the name
            username: String,
            email: String,
            password: String,
            encryption_public_key: String,
            signature_public_key: String,
            created_at: Datetime,
            updated_at: Datetime,
        }

        impl From<&User> for DbUser {
            fn from(u: &User) -> Self {
                Self {
                    user_id: u.user_id,
                    username: u.username.clone(),
                    email: u.email.clone(),
                    password: u.password.clone(),
                    encryption_public_key: u.encryption_public_key.clone(),
                    signature_public_key: u.signature_public_key.clone(),
                    created_at: u.created_at.into(),
                    updated_at: u.updated_at.into(),
                }
            }
        }

        let payload = DbUser::from(&user);
        let record: Option<User> = DB.create(&self.table).content(payload).await?;
        record.ok_or_else(|| Error::Db(Thrown("Failed to insert user".into())))
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
        let mut res = DB
            .query("SELECT math::max(array::group(user_id)) AS max_id FROM type::table($table)")
            .bind(("table", self.table.clone()))
            .await?;

        #[derive(Deserialize)]
        struct Row { max_id: Option<i64> }

        let max_id = res.take::<Option<Row>>(0)?.and_then(|r| r.max_id).unwrap_or(0);
        Ok((max_id as i32) + 1)
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
