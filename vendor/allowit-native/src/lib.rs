pub mod client;
pub mod crypto;
pub mod error;
pub mod journal;
pub mod lifecycle;
pub mod native;
pub mod paysh;
pub mod policy;
pub mod rpc;
pub mod transaction;
use serde::Deserialize;
use std::{collections::BTreeMap, sync::OnceLock};
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Release {
    pub contract_revision: String,
    pub source_bundle: String,
    pub artifacts: Vec<Artifact>,
    pub sources: BTreeMap<String, String>,
}
#[derive(Deserialize)]
pub struct Artifact {
    pub name: String,
    pub bytes: u64,
    pub sha256: String,
}
pub fn release() -> &'static Release {
    static RELEASE: OnceLock<Release> = OnceLock::new();
    RELEASE.get_or_init(|| {
        serde_json::from_str(include_str!("release.json"))
            .expect("checked-in native release manifest")
    })
}
