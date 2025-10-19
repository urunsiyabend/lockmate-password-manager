use crate::infrastructure::data::db_context::surrealdb_context::DB;
use surrealdb::Error;

const DEFINE_USERS: &str = r#"
DEFINE TABLE users SCHEMAFULL;
DEFINE FIELD username ON TABLE users TYPE string;
DEFINE FIELD email ON TABLE users TYPE string;
DEFINE FIELD password ON TABLE users TYPE string;
DEFINE FIELD encryption_public_key ON TABLE users TYPE string;
DEFINE FIELD signature_public_key ON TABLE users TYPE string;
DEFINE FIELD created_at ON TABLE users TYPE datetime;
DEFINE FIELD updated_at ON TABLE users TYPE datetime;
"#;

const DEFINE_VAULT_FOLDERS: &str = r#"
DEFINE TABLE vault_folders SCHEMAFULL;
DEFINE FIELD user_id ON TABLE vault_folders TYPE string;
DEFINE FIELD name ON TABLE vault_folders TYPE string;
DEFINE FIELD description ON TABLE vault_folders TYPE option<string>;
DEFINE FIELD created_at ON TABLE vault_folders TYPE datetime;
DEFINE FIELD updated_at ON TABLE vault_folders TYPE datetime;
"#;

const DEFINE_VAULT_ITEMS: &str = r#"
DEFINE TABLE vault_items SCHEMAFULL;
DEFINE FIELD user_id ON TABLE vault_items TYPE string;
DEFINE FIELD folder_id ON TABLE vault_items TYPE option<string>;
DEFINE FIELD ciphertext ON TABLE vault_items TYPE string;
DEFINE FIELD nonce ON TABLE vault_items TYPE string;
DEFINE FIELD created_at ON TABLE vault_items TYPE datetime;
DEFINE FIELD updated_at ON TABLE vault_items TYPE datetime;
"#;

const DEFINE_AUDIT_ENTRIES: &str = r#"
DEFINE TABLE audit_entries SCHEMAFULL PERMISSIONS
    FOR select FULL,
    FOR create FULL,
    FOR update NONE,
    FOR delete NONE;
DEFINE FIELD user_id ON TABLE audit_entries TYPE string;
DEFINE FIELD vault_item_id ON TABLE audit_entries TYPE option<string>;
DEFINE FIELD action ON TABLE audit_entries TYPE string;
DEFINE FIELD ip_address ON TABLE audit_entries TYPE option<string>;
DEFINE FIELD metadata ON TABLE audit_entries TYPE option<object>;
DEFINE FIELD occurred_at ON TABLE audit_entries TYPE datetime;
"#;

const DEFINE_SHARES: &str = r#"
DEFINE TABLE shares SCHEMAFULL;
DEFINE FIELD owner_id ON TABLE shares TYPE string;
DEFINE FIELD item_id ON TABLE shares TYPE string;
DEFINE FIELD created_at ON TABLE shares TYPE datetime;
DEFINE FIELD revoked_at ON TABLE shares TYPE option<datetime>;
"#;

const DEFINE_SHARE_INVITATIONS: &str = r#"
DEFINE TABLE share_invitations SCHEMAFULL;
DEFINE FIELD share_id ON TABLE share_invitations TYPE string;
DEFINE FIELD recipient_id ON TABLE share_invitations TYPE string;
DEFINE FIELD status ON TABLE share_invitations TYPE string;
DEFINE FIELD key_payload ON TABLE share_invitations TYPE object;
DEFINE FIELD created_at ON TABLE share_invitations TYPE datetime;
DEFINE FIELD updated_at ON TABLE share_invitations TYPE datetime;
DEFINE FIELD expires_at ON TABLE share_invitations TYPE datetime;
DEFINE FIELD responded_at ON TABLE share_invitations TYPE option<datetime>;
DEFINE FIELD revoked_at ON TABLE share_invitations TYPE option<datetime>;
"#;

pub async fn ensure_schema() -> Result<(), Error> {
    DB.query(DEFINE_USERS).await?;
    DB.query(DEFINE_VAULT_FOLDERS).await?;
    DB.query(DEFINE_VAULT_ITEMS).await?;
    DB.query(DEFINE_AUDIT_ENTRIES).await?;
    DB.query(DEFINE_SHARES).await?;
    DB.query(DEFINE_SHARE_INVITATIONS).await?;
    Ok(())
}
