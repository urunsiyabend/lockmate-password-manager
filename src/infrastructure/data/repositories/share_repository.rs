use chrono::{DateTime, Utc};
use serde_json::json;
use surrealdb::{Error, err::Error::Thrown};

use crate::domain::models::share::{
    NewShareInvitationRecord, NewShareRecord, ShareInvitationRecord, ShareInvitationStatus,
    ShareRecord,
};
use crate::infrastructure::data::db_context::surrealdb_context::DB;

pub struct ShareRepository {
    share_table: String,
    invitation_table: String,
}

impl ShareRepository {
    pub fn new() -> Self {
        Self {
            share_table: String::from("shares"),
            invitation_table: String::from("share_invitations"),
        }
    }

    pub async fn find_active_share(
        &self,
        owner_id: &str,
        item_id: &str,
    ) -> Result<Option<ShareRecord>, Error> {
        let mut response = DB
            .query(
                "SELECT * FROM type::table($table) \
                 WHERE owner_id = $owner_id AND item_id = $item_id AND revoked_at = NONE LIMIT 1",
            )
            .bind(("table", self.share_table.clone()))
            .bind(("owner_id", owner_id.to_owned()))
            .bind(("item_id", item_id.to_owned()))
            .await?;

        Ok(response.take::<Option<ShareRecord>>(0)?)
    }

    pub async fn get_share_by_id(&self, share_id: &str) -> Result<ShareRecord, Error> {
        let mut response = DB
            .query("SELECT * FROM type::table($table) WHERE id = type::thing($table, $id) LIMIT 1")
            .bind(("table", self.share_table.clone()))
            .bind(("id", share_id.to_owned()))
            .await?;

        if let Some(share) = response.take::<Option<ShareRecord>>(0)? {
            return Ok(share);
        }

        Err(Error::Db(Thrown(format!(
            "Share with id {} not found",
            share_id
        ))))
    }

    pub async fn create_share(&self, share: NewShareRecord) -> Result<ShareRecord, Error> {
        let mut response = DB
            .query("CREATE type::table($table) CONTENT $content RETURN AFTER")
            .bind(("table", self.share_table.clone()))
            .bind(("content", share))
            .await?;

        if let Some(record) = response.take::<Option<ShareRecord>>(0)? {
            return Ok(record);
        }

        Err(Error::Db(Thrown("Failed to create share".into())))
    }

    pub async fn create_invitation(
        &self,
        invitation: NewShareInvitationRecord,
    ) -> Result<ShareInvitationRecord, Error> {
        let mut response = DB
            .query("CREATE type::table($table) CONTENT $content RETURN AFTER")
            .bind(("table", self.invitation_table.clone()))
            .bind(("content", invitation))
            .await?;

        if let Some(record) = response.take::<Option<ShareInvitationRecord>>(0)? {
            return Ok(record);
        }

        Err(Error::Db(Thrown(
            "Failed to create share invitation".into(),
        )))
    }

    pub async fn list_invitations_for_share(
        &self,
        share_id: &str,
    ) -> Result<Vec<ShareInvitationRecord>, Error> {
        let mut response = DB
            .query("SELECT * FROM type::table($table) WHERE share_id = $share_id")
            .bind(("table", self.invitation_table.clone()))
            .bind(("share_id", share_id.to_owned()))
            .await?;

        Ok(response.take::<Vec<ShareInvitationRecord>>(0)?)
    }

    pub async fn list_pending_for_recipient(
        &self,
        recipient_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Vec<ShareInvitationRecord>, Error> {
        let mut response = DB
            .query(
                "SELECT * FROM type::table($table) \
                 WHERE recipient_id = $recipient_id \
                   AND status = 'pending' \
                   AND expires_at > $now",
            )
            .bind(("table", self.invitation_table.clone()))
            .bind(("recipient_id", recipient_id.to_owned()))
            .bind(("now", now))
            .await?;

        Ok(response.take::<Vec<ShareInvitationRecord>>(0)?)
    }

    pub async fn list_active_for_recipient(
        &self,
        recipient_id: &str,
    ) -> Result<Vec<ShareInvitationRecord>, Error> {
        let mut response = DB
            .query(
                "SELECT * FROM type::table($table) \
                 WHERE recipient_id = $recipient_id \
                   AND status = 'accepted' \
                   AND revoked_at = NONE",
            )
            .bind(("table", self.invitation_table.clone()))
            .bind(("recipient_id", recipient_id.to_owned()))
            .await?;

        Ok(response.take::<Vec<ShareInvitationRecord>>(0)?)
    }

    pub async fn get_invitation_by_id(
        &self,
        invitation_id: &str,
    ) -> Result<ShareInvitationRecord, Error> {
        let mut response = DB
            .query("SELECT * FROM type::table($table) WHERE id = type::thing($table, $id) LIMIT 1")
            .bind(("table", self.invitation_table.clone()))
            .bind(("id", invitation_id.to_owned()))
            .await?;

        if let Some(record) = response.take::<Option<ShareInvitationRecord>>(0)? {
            return Ok(record);
        }

        Err(Error::Db(Thrown(format!(
            "Share invitation with id {} not found",
            invitation_id
        ))))
    }

    pub async fn find_existing_invitation(
        &self,
        share_id: &str,
        recipient_id: &str,
    ) -> Result<Option<ShareInvitationRecord>, Error> {
        let mut response = DB
            .query(
                "SELECT * FROM type::table($table) \
                 WHERE share_id = $share_id \
                   AND recipient_id = $recipient_id \
                   AND status != 'declined' \
                   AND status != 'revoked' \
                   AND status != 'expired' \
                 LIMIT 1",
            )
            .bind(("table", self.invitation_table.clone()))
            .bind(("share_id", share_id.to_owned()))
            .bind(("recipient_id", recipient_id.to_owned()))
            .await?;

        Ok(response.take::<Option<ShareInvitationRecord>>(0)?)
    }

    pub async fn update_invitation_status(
        &self,
        invitation_id: &str,
        status: ShareInvitationStatus,
        responded_at: Option<DateTime<Utc>>,
        revoked_at: Option<DateTime<Utc>>,
    ) -> Result<ShareInvitationRecord, Error> {
        let mut response = DB
            .query(
                "UPDATE type::table($table) \
                 SET status = $status, \
                     responded_at = $responded_at, \
                     revoked_at = $revoked_at, \
                     updated_at = time::now() \
                 WHERE id = type::thing($table, $id) \
                RETURN AFTER",
            )
            .bind(("table", self.invitation_table.clone()))
            .bind(("id", invitation_id.to_owned()))
            .bind(("status", String::from(&status)))
            .bind(("responded_at", responded_at))
            .bind(("revoked_at", revoked_at))
            .await?;

        if let Some(record) = response.take::<Option<ShareInvitationRecord>>(0)? {
            return Ok(record);
        }

        Err(Error::Db(Thrown(
            "Failed to update share invitation".into(),
        )))
    }

    pub async fn revoke_recipient(
        &self,
        share_id: &str,
        recipient_id: &str,
    ) -> Result<Vec<ShareInvitationRecord>, Error> {
        let mut response = DB
            .query(
                "UPDATE type::table($table) \
                 SET status = 'revoked', \
                     revoked_at = time::now(), \
                     updated_at = time::now() \
                 WHERE share_id = $share_id \
                   AND recipient_id = $recipient_id \
                   AND status != 'revoked' \
                RETURN AFTER",
            )
            .bind(("table", self.invitation_table.clone()))
            .bind(("share_id", share_id.to_owned()))
            .bind(("recipient_id", recipient_id.to_owned()))
            .await?;

        Ok(response.take::<Vec<ShareInvitationRecord>>(0)?)
    }

    pub async fn revoke_all_for_share(
        &self,
        share_id: &str,
    ) -> Result<Vec<ShareInvitationRecord>, Error> {
        let mut response = DB
            .query(
                "UPDATE type::table($table) \
                 SET status = 'revoked', \
                     revoked_at = time::now(), \
                     updated_at = time::now() \
                 WHERE share_id = $share_id AND status != 'revoked' \
                RETURN AFTER",
            )
            .bind(("table", self.invitation_table.clone()))
            .bind(("share_id", share_id.to_owned()))
            .await?;

        Ok(response.take::<Vec<ShareInvitationRecord>>(0)?)
    }

    pub async fn expire_pending_invitations(&self, now: DateTime<Utc>) -> Result<(), Error> {
        DB.query(
            "UPDATE type::table($table) \
                 SET status = 'expired', \
                     responded_at = time::now(), \
                     updated_at = time::now() \
                 WHERE status = 'pending' AND expires_at <= $now",
        )
        .bind(("table", self.invitation_table.clone()))
        .bind(("now", now))
        .await?;

        Ok(())
    }

    pub async fn mark_share_revoked(&self, share_id: &str) -> Result<ShareRecord, Error> {
        let mut response = DB
            .query(
                "UPDATE type::table($table) \
                 SET revoked_at = time::now() \
                 WHERE id = type::thing($table, $id) \
                RETURN AFTER",
            )
            .bind(("table", self.share_table.clone()))
            .bind(("id", share_id.to_owned()))
            .await?;

        if let Some(record) = response.take::<Option<ShareRecord>>(0)? {
            return Ok(record);
        }

        Err(Error::Db(Thrown("Failed to revoke share".into())))
    }

    pub async fn list_shares_for_ids(
        &self,
        share_ids: &[String],
    ) -> Result<Vec<ShareRecord>, Error> {
        if share_ids.is_empty() {
            return Ok(Vec::new());
        }

        let mut response = DB
            .query("SELECT * FROM type::table($table) WHERE id INSIDE $ids")
            .bind(("table", self.share_table.clone()))
            .bind(("ids", json!(share_ids)))
            .await?;

        Ok(response.take::<Vec<ShareRecord>>(0)?)
    }
}
