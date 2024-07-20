use super::common::{get_aces, is_acl_protected, ldap2domain};
use super::utils::{Aces, Meta};
use crate::parser::{ADExplorerSnapshot, AttributeValue, Object, ObjectType};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct GPOsOutput {
    meta: Meta,
    #[serde(rename = "data")]
    gpos: Vec<GPO>,
}

impl GPOsOutput {
    pub fn new(snapshot: &ADExplorerSnapshot) -> Self {
        let gpos: Vec<GPO> = snapshot
            .snapshot
            .objects
            .iter()
            .filter(|v| v.get_type() == ObjectType::GPO)
            .map(|obj| GPO::new(obj, snapshot))
            .collect();

        Self {
            meta: Meta {
                methods: 46067,
                r#type: "gpos".to_string(),
                count: gpos.len() as u64,
                version: 6,
            },
            gpos,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GPO {
    #[serde(rename = "Properties")]
    pub properties: GPOProperties,

    #[serde(rename = "Aces")]
    aces: Vec<Aces>,

    #[serde(rename = "ObjectIdentifier")]
    object_identifier: String,

    #[serde(rename = "IsDeleted")]
    is_deleted: bool,

    #[serde(rename = "IsACLProtected")]
    is_acl_protected: bool,
}

impl GPO {
    pub fn new(obj: &Object, snapshot: &ADExplorerSnapshot) -> Self {
        GPO {
            properties: GPOProperties::new(obj, snapshot),
            aces: get_aces(obj, snapshot),
            object_identifier: obj
                .get_first("objectGUID")
                .and_then(AttributeValue::as_guid)
                .map(|v| v.to_string())
                .unwrap_or_default(),
            is_deleted: false, // Assuming this information is not available in the snapshot
            is_acl_protected: is_acl_protected(obj),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GPOProperties {
    pub domain: String,
    pub name: String,
    pub distinguishedname: String,
    pub domainsid: String,
    pub whencreated: i64,
    pub gpcpath: String,
}

impl GPOProperties {
    pub fn new(obj: &Object, snapshot: &ADExplorerSnapshot) -> Self {
        let distinguished_name = obj
            .get_first("distinguishedName")
            .and_then(AttributeValue::as_string)
            .map(|v| v.clone())
            .unwrap_or_default();
        let domain = ldap2domain(&distinguished_name);
        let name = obj
            .get_first("displayName")
            .and_then(AttributeValue::as_string)
            .map(|v| v.clone())
            .unwrap_or_default();

        GPOProperties {
            domain: domain.clone(),
            name: format!("{}@{}", name.to_uppercase(), domain.to_uppercase()),
            distinguishedname: distinguished_name,
            domainsid: snapshot.caches.domain_sid.as_ref().unwrap().to_string(),
            whencreated: obj
                .get_first("whenCreated")
                .and_then(AttributeValue::as_unix_timestamp)
                .unwrap_or(0),
            gpcpath: obj
                .get_first("gPCFileSysPath")
                .and_then(AttributeValue::as_string)
                .map(|v| v.to_string())
                .unwrap_or_default(),
        }
    }
}
