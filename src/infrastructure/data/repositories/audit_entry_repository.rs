use crate::domain::models::audit_entry::AuditEntry;
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

    pub async fn log(&self, entry: AuditEntry) -> Result<AuditEntry, Error> {
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
}
