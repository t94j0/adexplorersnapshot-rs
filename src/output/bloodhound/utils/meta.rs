use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Meta {
    pub methods: u64,
    pub r#type: String,
    pub count: u64,
    pub version: u8,
}
