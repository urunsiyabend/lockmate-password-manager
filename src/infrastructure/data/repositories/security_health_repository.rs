use crate::domain::models::security_health::{
    NewSecurityHealthFindingRecord, SecurityHealthFindingRecord,
};
use crate::infrastructure::data::db_context::surrealdb_context::DB;
use surrealdb::Error;

pub struct SecurityHealthFindingRepository {
    table: String,
}

impl SecurityHealthFindingRepository {
    pub fn new() -> Self {
        Self {
            table: String::from("security_health_findings"),
        }
    }

    pub async fn list_by_user(
        &self,
        user_id: &str,
    ) -> Result<Vec<SecurityHealthFindingRecord>, Error> {
        let mut response = DB
            .query(
                "SELECT * FROM type::table($table) \
                WHERE user_id = $user_id ORDER BY created_at DESC",
            )
            .bind(("table", self.table.clone()))
            .bind(("user_id", user_id.to_owned()))
            .await?;

        let findings = response.take::<Vec<SecurityHealthFindingRecord>>(0)?;
        Ok(findings)
    }

    pub async fn clear_for_user(&self, user_id: &str) -> Result<(), Error> {
        DB.query("DELETE type::table($table) WHERE user_id = $user_id")
            .bind(("table", self.table.clone()))
            .bind(("user_id", user_id.to_owned()))
            .await?;

        Ok(())
    }

    pub async fn replace_for_user(
        &self,
        user_id: &str,
        findings: &[NewSecurityHealthFindingRecord],
    ) -> Result<Vec<SecurityHealthFindingRecord>, Error> {
        self.clear_for_user(user_id).await?;

        let mut stored = Vec::with_capacity(findings.len());
        for finding in findings {
            let mut response = DB
                .query("CREATE type::table($table) CONTENT $content RETURN AFTER")
                .bind(("table", self.table.clone()))
                .bind(("content", finding.clone()))
                .await?;

            if let Some(record) = response.take::<Option<SecurityHealthFindingRecord>>(0)? {
                stored.push(record);
            }
        }

        Ok(stored)
    }
}
