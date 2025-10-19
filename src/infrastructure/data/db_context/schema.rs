use crate::infrastructure::data::db_context::surrealdb_context::DB;
use surrealdb::Error;

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
DEFINE FIELD title ON TABLE vault_items TYPE string;
DEFINE FIELD username ON TABLE vault_items TYPE option<string>;
DEFINE FIELD password ON TABLE vault_items TYPE option<string>;
DEFINE FIELD url ON TABLE vault_items TYPE option<string>;
DEFINE FIELD notes ON TABLE vault_items TYPE option<string>;
DEFINE FIELD created_at ON TABLE vault_items TYPE datetime;
DEFINE FIELD updated_at ON TABLE vault_items TYPE datetime;
"#;

const DEFINE_AUDIT_ENTRIES: &str = r#"
DEFINE TABLE audit_entries SCHEMAFULL;
DEFINE FIELD user_id ON TABLE audit_entries TYPE string;
DEFINE FIELD vault_item_id ON TABLE audit_entries TYPE option<string>;
DEFINE FIELD action ON TABLE audit_entries TYPE string;
DEFINE FIELD ip_address ON TABLE audit_entries TYPE option<string>;
DEFINE FIELD metadata ON TABLE audit_entries TYPE option<object>;
DEFINE FIELD occurred_at ON TABLE audit_entries TYPE datetime;
"#;

pub async fn ensure_schema() -> Result<(), Error> {
    DB.query(DEFINE_VAULT_FOLDERS).await?;
    DB.query(DEFINE_VAULT_ITEMS).await?;
    DB.query(DEFINE_AUDIT_ENTRIES).await?;
    Ok(())
}
