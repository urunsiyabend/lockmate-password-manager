use chrono::{DateTime, Utc};
use surrealdb::{Error, RecordId};

use crate::{
    domain::models::mfa::MfaDevice, infrastructure::data::db_context::surrealdb_context::DB,
};

pub struct MfaRepository {
    table: String,
}

impl MfaRepository {
    pub fn new() -> Self {
        Self {
            table: String::from("mfa_devices"),
        }
    }

    fn record_id(&self, id: &str) -> RecordId {
        RecordId::from((self.table.as_str(), id))
    }

    pub async fn upsert(&self, device: &MfaDevice) -> Result<MfaDevice, Error> {
        let mut payload = device.clone();
        payload.mark_updated();

        let record: Option<MfaDevice> = DB
            .update((self.table.as_str(), payload.id.clone()))
            .content(payload)
            .await?;

        record.ok_or_else(|| {
            Error::Db(surrealdb::err::Error::Thrown(
                "Failed to persist MFA device".into(),
            ))
        })
    }

    pub async fn create(&self, device: &MfaDevice) -> Result<MfaDevice, Error> {
        let record: Option<MfaDevice> = DB
            .create((self.table.as_str(), device.id.clone()))
            .content(device.clone())
            .await?;

        record.ok_or_else(|| {
            Error::Db(surrealdb::err::Error::Thrown(
                "Failed to create MFA device".into(),
            ))
        })
    }

    pub async fn get_by_id(&self, id: &str) -> Result<MfaDevice, Error> {
        let record: Option<MfaDevice> = DB.select(self.record_id(id)).await?;
        record.ok_or_else(|| {
            Error::Db(surrealdb::err::Error::Thrown(format!(
                "MFA device with id {id} not found"
            )))
        })
    }

    pub async fn get_active_by_user(&self, user_id: i32) -> Result<Option<MfaDevice>, Error> {
        let mut response = DB
            .query(
                "SELECT * FROM type::table($table) WHERE user_id = $user_id AND enabled = true LIMIT 1",
            )
            .bind(("table", self.table.clone()))
            .bind(("user_id", user_id))
            .await?;

        response.take::<Option<MfaDevice>>(0)
    }

    pub async fn get_pending_by_user(&self, user_id: i32) -> Result<Option<MfaDevice>, Error> {
        let mut response = DB
            .query(
                "SELECT * FROM type::table($table) WHERE user_id = $user_id AND enabled = false LIMIT 1",
            )
            .bind(("table", self.table.clone()))
            .bind(("user_id", user_id))
            .await?;

        response.take::<Option<MfaDevice>>(0)
    }

    pub async fn delete(&self, id: &str) -> Result<(), Error> {
        let _: Option<MfaDevice> = DB.delete(self.record_id(id)).await?;
        Ok(())
    }

    pub async fn touch_last_used(&self, id: &str, step: i64) -> Result<(), Error> {
        let now = Utc::now();
        let _: Option<MfaDevice> = DB
            .query("UPDATE type::thing($table, $id) SET last_used_step = $step, updated_at = $now")
            .bind(("table", self.table.clone()))
            .bind(("id", id.to_string()))
            .bind(("step", step))
            .bind(("now", now))
            .await?
            .take(0)?;
        Ok(())
    }

    pub async fn reset_rate_limiter(&self, id: &str) -> Result<(), Error> {
        let now = Utc::now();
        let _: Option<MfaDevice> = DB
            .query(
                "UPDATE type::thing($table, $id) SET failed_attempts = 0, lockout_until = NONE, updated_at = $now",
            )
            .bind(("table", self.table.clone()))
            .bind(("id", id.to_string()))
            .bind(("now", now))
            .await?
            .take(0)?;
        Ok(())
    }

    pub async fn increment_failed_attempts(
        &self,
        id: &str,
        failed_attempts: i32,
        lockout_until: Option<DateTime<Utc>>,
    ) -> Result<(), Error> {
        let now = Utc::now();
        let _: Option<MfaDevice> = DB
            .query(
                "UPDATE type::thing($table, $id) SET failed_attempts = $failed, lockout_until = $lockout, updated_at = $now",
            )
            .bind(("table", self.table.clone()))
            .bind(("id", id.to_string()))
            .bind(("failed", failed_attempts))
            .bind(("lockout", lockout_until))
            .bind(("now", now))
            .await?
            .take(0)?;
        Ok(())
    }
}
