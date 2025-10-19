use crate::domain::models::audit_entry::{AuditEntry, NewAuditEntry};
use crate::infrastructure::data::db_context::surrealdb_context::DB;
use surrealdb::Error;
use surrealdb::err::Error::Thrown;

pub struct AuditEntryRepository {
    table: String,
}

impl AuditEntryRepository {
    pub fn new() -> Self {
        Self {
            table: String::from("audit_entries"),
        }
    }

    pub async fn log(&self, entry: NewAuditEntry) -> Result<AuditEntry, Error> {
        let mut response = DB
            .query("CREATE type::table($table) CONTENT $content RETURN AFTER")
            .bind(("table", self.table.clone()))
            .bind(("content", entry))
            .await?;

        if let Some(created) = response.take::<Option<AuditEntry>>(0)? {
            return Ok(created);
        }

        Err(Error::Db(Thrown("Failed to create audit entry".into())))
    }

    pub async fn list_recent_for_user(
        &self,
        user_id: &str,
        limit: usize,
    ) -> Result<Vec<AuditEntry>, Error> {
        let mut response = DB
            .query(
                "SELECT * FROM type::table($table) WHERE user_id = $user_id ORDER BY occurred_at DESC LIMIT $limit",
            )
            .bind(("table", self.table.clone()))
            .bind(("user_id", user_id.to_owned()))
            .bind(("limit", limit as i64))
            .await?;

        let entries = response.take::<Vec<AuditEntry>>(0)?;
        Ok(entries)
    }

    pub async fn query_logs(
        &self,
        user_id: Option<&str>,
        action: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AuditEntry>, Error> {
        let mut query = String::from("SELECT * FROM type::table($table)");
        let mut clauses = Vec::new();

        if user_id.is_some() {
            clauses.push("user_id = $user_id");
        }

        if action.is_some() {
            clauses.push("action = $action");
        }

        if !clauses.is_empty() {
            query.push_str(" WHERE ");
            query.push_str(&clauses.join(" AND "));
        }

        query.push_str(" ORDER BY occurred_at DESC LIMIT $limit");

        let mut statement = DB
            .query(query)
            .bind(("table", self.table.clone()))
            .bind(("limit", limit as i64));

        if let Some(user_id) = user_id {
            statement = statement.bind(("user_id", user_id.to_owned()));
        }

        if let Some(action) = action {
            statement = statement.bind(("action", action.to_owned()));
        }

        let mut response = statement.await?;
        let entries = response.take::<Vec<AuditEntry>>(0)?;
        Ok(entries)
    }
}
