use super::common::{get_aces, is_acl_protected, ldap2domain};
use super::utils::{Aces, Meta};
use crate::parser::{ADExplorerSnapshot, AttributeValue, Object, ObjectType};
use serde::{Deserialize, Serialize};
#[derive(Debug, Serialize, Deserialize)]
pub struct ContainersOutput {
    meta: Meta,
    #[serde(rename = "data")]
    containers: Vec<Container>,
}

impl ContainersOutput {
    pub fn new(snapshot: &ADExplorerSnapshot) -> Self {
        let containers: Vec<Container> = snapshot
            .snapshot
            .objects
            .iter()
            .filter(|obj| obj.get_type() == ObjectType::Container)
            .map(|obj| Container::new(obj, snapshot))
            .collect();

        Self {
            meta: Meta {
                methods: 46067,
                r#type: "containers".to_string(),
                count: containers.len() as u64,
                version: 5,
            },
            containers,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Container {
    #[serde(rename = "Properties")]
    pub properties: ContainerProperties,

    #[serde(rename = "ChildObjects")]
    pub child_objects: Vec<ChildObject>,

    #[serde(rename = "Aces")]
    aces: Vec<Aces>,

    #[serde(rename = "ObjectIdentifier")]
    object_identifier: String,

    #[serde(rename = "IsDeleted")]
    is_deleted: bool,

    #[serde(rename = "IsACLProtected")]
    is_acl_protected: bool,
}

impl Container {
    pub fn new(obj: &Object, snapshot: &ADExplorerSnapshot) -> Self {
        Container {
            properties: ContainerProperties::new(obj, snapshot),
            // TODO: How do you get child objects of a container?
            child_objects: Vec::new(),
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
pub struct ContainerProperties {
    pub domain: String,
    pub name: String,
    pub distinguishedname: String,
    pub domainsid: String,
}

impl ContainerProperties {
    pub fn new(obj: &Object, snapshot: &ADExplorerSnapshot) -> Self {
        let distinguished_name = obj
            .get_first("distinguishedName")
            .and_then(AttributeValue::as_string)
            .map(|v| v.clone())
            .unwrap_or_default();
        let domain = ldap2domain(&distinguished_name);
        let name = obj
            .get_first("name")
            .and_then(AttributeValue::as_string)
            .map(|v| v.clone())
            .unwrap_or_default();

        ContainerProperties {
            domain: domain.clone(),
            name: format!("{}@{}", name, domain),
            distinguishedname: distinguished_name,
            domainsid: snapshot.caches.domain_sid.as_ref().unwrap().to_string(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChildObject {
    #[serde(rename = "ObjectIdentifier")]
    pub object_identifier: String,
    #[serde(rename = "ObjectType")]
    pub object_type: String,
}
