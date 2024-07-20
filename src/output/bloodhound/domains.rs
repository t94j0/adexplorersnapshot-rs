use crate::parser::{ADExplorerSnapshot, AttributeValue, Object};
use crate::security_descriptor::ControlFlag;
use serde::{Deserialize, Serialize};

use super::common::get_aces;
use super::utils::Aces;

#[derive(Debug, Serialize, Deserialize)]
pub struct DomainsOutput {
    meta: Meta,
    #[serde(rename = "data")]
    domains: Vec<Domain>,
}

impl DomainsOutput {
    pub fn new(snapshot: &ADExplorerSnapshot) -> Self {
        Self {
            meta: Meta {
                methods: 46067,
                r#type: "domains".to_string(),
                count: 5,
            },
            domains: snapshot
                .get_root_domain()
                .map(|root| Domain::new(root, snapshot))
                .into_iter()
                .collect(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Meta {
    methods: u64,
    r#type: String,
    count: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Domain {
    #[serde(rename = "Properties")]
    pub properties: DomainProperties,

    #[serde(rename = "ChildObjects")]
    pub child_objects: Vec<ChildObject>,

    #[serde(rename = "Trusts")]
    pub trusts: Vec<Trust>,

    #[serde(rename = "Links")]
    links: Vec<Links>,

    #[serde(rename = "Aces")]
    aces: Vec<Aces>,

    #[serde(rename = "ObjectIdentifier")]
    object_identifier: String,

    #[serde(rename = "IsDeleted")]
    is_deleted: bool,

    #[serde(rename = "IsACLProtected")]
    is_acl_protected: bool,
}

impl Domain {
    pub fn new(obj: &Object, snapshot: &ADExplorerSnapshot) -> Self {
        // TODO: Error checking
        // TODO: Make get_guid a method on Object
        let guid = obj
            .get_first("objectGUID")
            .and_then(AttributeValue::as_guid)
            .unwrap();

        let sddls = obj
            .get_first("nTSecurityDescriptor")
            .and_then(AttributeValue::as_nt_security_descriptor);

        let is_acl_protected = sddls
            .iter()
            .any(|sd| sd.control_flags.is_set(ControlFlag::DP));

        Domain {
            properties: DomainProperties::new(obj, snapshot),
            child_objects: Vec::new(),
            trusts: process_trusts(snapshot),
            links: Vec::new(),
            aces: get_aces(obj, snapshot),
            object_identifier: guid.to_string(),
            is_deleted: false,
            is_acl_protected,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Links {
    #[serde(rename = "IsEnforced")]
    is_enforced: bool,

    #[serde(rename = "GUID")]
    guid: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChildObject {
    #[serde(rename = "ObjectIdentifier")]
    object_identifier: String,

    #[serde(rename = "ObjectType")]
    object_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DomainProperties {
    pub name: String,
    pub domain: String,
    pub distinguishedname: String,
    pub domainsid: String,
    pub description: Option<String>,
    pub functionallevel: String,
    pub whencreated: i64,
    pub highvalue: bool,
}

impl DomainProperties {
    pub fn new(obj: &Object, _snapshot: &ADExplorerSnapshot) -> Self {
        DomainProperties {
            name: obj
                .get_first("name")
                .and_then(AttributeValue::as_string)
                .unwrap()
                .clone(),
            domain: obj
                .get_first("name")
                .and_then(AttributeValue::as_string)
                .unwrap()
                .to_uppercase(),
            distinguishedname: obj
                .get_first("distinguishedName")
                .and_then(AttributeValue::as_string)
                .unwrap()
                .to_string(),
            domainsid: Self::get_domain_sid(obj),
            description: obj
                .get_first("description")
                .and_then(AttributeValue::as_string)
                .map(String::to_string),
            functionallevel: Self::get_functional_level(obj),
            whencreated: Self::get_when_created(obj),
            highvalue: true,
        }
    }

    pub fn get_domain_sid(obj: &Object) -> String {
        obj.get_object_identifier()
            .unwrap_or("ERR_UNKNOWN".to_string())
    }

    pub fn get_functional_level(obj: &Object) -> String {
        obj.get_first("msDS-Behavior-Version")
            .and_then(AttributeValue::as_integer)
            .map(|level| match level {
                0 => "2000 Mixed/Native",
                1 => "2003 Interim",
                2 => "2003",
                3 => "2008",
                4 => "2008 R2",
                5 => "2012",
                6 => "2012 R2",
                7 => "2016",
                _ => "Unknown",
            })
            .unwrap_or("Unknown")
            .to_string()
    }

    pub fn get_when_created(obj: &Object) -> i64 {
        obj.get_first("creationTime")
            .and_then(AttributeValue::as_large_integer)
            .unwrap_or(0)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Trust {
    #[serde(rename = "TargetDomainSid")]
    target_domain_sid: String,

    #[serde(rename = "TargetDomainName")]
    target_domain_name: String,

    #[serde(rename = "IsTransitive")]
    is_transitive: bool,

    #[serde(rename = "SidFilteringEnabled")]
    sid_filtering_enabled: bool,

    #[serde(rename = "TrustDirection")]
    trust_direction: String,

    #[serde(rename = "TrustType")]
    trust_type: String,
}

pub fn process_trusts(snapshot: &ADExplorerSnapshot) -> Vec<Trust> {
    snapshot
        .snapshot
        .objects
        .iter()
        .filter_map(|obj| process_trust(obj))
        .collect()
}

fn process_trust(obj: &Object) -> Option<Trust> {
    // Check if 'trustedDomain' is in the object classes
    if !obj
        .get_attribute_classes()?
        .iter()
        .any(|class| class == "trustedDomain")
    {
        return None;
    }

    Some(Trust {
        target_domain_sid: obj
            .get_first("securityIdentifier")
            .and_then(AttributeValue::as_sid)
            .map(|s| s.to_string())
            .unwrap_or("Unknown".to_string()),
        target_domain_name: obj
            .get_first("name")
            .and_then(AttributeValue::as_string)
            .map(String::to_string)
            .unwrap(),
        is_transitive: obj
            .get_first("trustTransitive")
            .and_then(AttributeValue::as_boolean)
            .unwrap_or_default(),
        sid_filtering_enabled: (obj
            .get_first("trustAttributes")
            .and_then(AttributeValue::as_integer)
            .unwrap_or_default()
            & 0x00000040)
            != 0,
        trust_direction: match obj
            .get_first("trustDirection")
            .and_then(AttributeValue::as_integer)
            .unwrap_or_default()
        {
            0 => "Disabled".to_string(),
            1 => "Inbound".to_string(),
            2 => "Outbound".to_string(),
            3 => "Bidirectional".to_string(),
            _ => "Unknown".to_string(),
        },
        trust_type: match obj
            .get_first("trustType")
            .and_then(AttributeValue::as_integer)
            .unwrap_or_default()
        {
            1 => "WINDOWS_NON_ACTIVE_DIRECTORY".to_string(),
            2 => "WINDOWS_ACTIVE_DIRECTORY".to_string(),
            3 => "MIT".to_string(),
            _ => "Unknown".to_string(),
        },
    })
}
