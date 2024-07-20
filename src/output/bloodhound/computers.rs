use super::common::{get_aces, get_sid, is_acl_protected, ldap2domain};
use super::utils::{Aces, Meta};
use crate::output::bloodhound::common::type_string;
use crate::parser::{ADExplorerSnapshot, AttributeValue, Object};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ComputersOutput {
    meta: Meta,
    #[serde(rename = "data")]
    computers: Vec<Computer>,
}

impl ComputersOutput {
    pub fn new(snapshot: &ADExplorerSnapshot) -> Self {
        let computers: Vec<Computer> = snapshot
            .snapshot
            .objects
            .iter()
            .filter(|obj| {
                obj.get_first("sAMAccountType")
                    .and_then(AttributeValue::as_integer)
                    .map(|account_type| account_type == 805306369)
                    .unwrap_or(false)
            })
            .map(|obj| Computer::new(obj, snapshot))
            .collect();

        Self {
            meta: Meta {
                methods: 46067,
                r#type: "computers".to_string(),
                count: computers.len() as u64,
                version: 5,
            },
            computers,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Computer {
    #[serde(rename = "Properties")]
    pub properties: ComputerProperties,

    #[serde(rename = "AllowedToDelegate")]
    pub allowed_to_delegate: Vec<DelegationTarget>,

    #[serde(rename = "AllowedToAct")]
    pub allowed_to_act: Vec<DelegationTarget>,

    #[serde(rename = "PrimaryGroupSID")]
    pub primary_group_sid: String,

    #[serde(rename = "HasSIDHistory")]
    pub has_sid_history: Vec<SIDHistoryItem>,

    #[serde(rename = "Sessions")]
    pub sessions: SessionsInfo,

    #[serde(rename = "PrivilegedSessions")]
    pub privileged_sessions: SessionsInfo,

    #[serde(rename = "RegistrySessions")]
    pub registry_sessions: SessionsInfo,

    #[serde(rename = "LocalGroups")]
    pub local_groups: Vec<LocalGroup>,

    #[serde(rename = "Aces")]
    aces: Vec<Aces>,

    #[serde(rename = "ObjectIdentifier")]
    object_identifier: String,

    #[serde(rename = "IsDeleted")]
    is_deleted: bool,

    #[serde(rename = "IsACLProtected")]
    is_acl_protected: bool,
}

impl Computer {
    pub fn new(obj: &Object, snapshot: &ADExplorerSnapshot) -> Self {
        Computer {
            properties: ComputerProperties::new(obj, snapshot),
            allowed_to_delegate: process_allowed_to_delegate(obj, snapshot),
            allowed_to_act: process_allowed_to_act(obj),
            primary_group_sid: get_primary_group_sid(obj, snapshot),
            has_sid_history: process_sid_history(obj),
            sessions: SessionsInfo::default(),
            privileged_sessions: SessionsInfo::default(),
            registry_sessions: SessionsInfo::default(),
            local_groups: Vec::new(), // This would need to be populated if the data is available
            aces: get_aces(obj, snapshot),
            object_identifier: get_sid(obj),
            is_deleted: false, // Assuming this information is not available in the snapshot
            is_acl_protected: is_acl_protected(obj),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ComputerProperties {
    pub domain: String,
    pub name: String,
    pub distinguishedname: String,
    pub domainsid: String,
    pub haslaps: bool,
    pub description: Option<String>,
    pub whencreated: i64,
    pub enabled: bool,
    pub unconstraineddelegation: bool,
    pub trustedtoauth: bool,
    pub lastlogon: i64,
    pub lastlogontimestamp: i64,
    pub pwdlastset: i64,
    pub serviceprincipalnames: Vec<String>,
    pub operatingsystem: Option<String>,
    pub sidhistory: Vec<String>,
    pub samaccountname: Option<String>,
}

impl ComputerProperties {
    pub fn new(obj: &Object, snapshot: &ADExplorerSnapshot) -> Self {
        let distinguished_name = obj
            .get_first("distinguishedName")
            .and_then(AttributeValue::as_string)
            .map(|v| v.clone())
            .unwrap_or_default();

        let domain = ldap2domain(&distinguished_name).to_uppercase();
        let name = obj
            .get_first("name")
            .and_then(AttributeValue::as_string)
            .map(|v| v.clone())
            .unwrap_or_default();

        let uac = obj
            .get_first("userAccountControl")
            .and_then(AttributeValue::as_integer)
            .unwrap_or(0);

        ComputerProperties {
            domain: domain.clone(),
            name: format!("{}@{}", name.to_uppercase(), domain),
            distinguishedname: distinguished_name,
            domainsid: snapshot.caches.domain_sid.as_ref().unwrap().to_string(),
            haslaps: obj
                .get_first("ms-mcs-admpwdexpirationtime")
                .and_then(AttributeValue::as_integer)
                .map(|v| v != 0)
                .unwrap_or(false),
            description: obj
                .get_first("description")
                .and_then(AttributeValue::as_string)
                .map(|v| v.clone()),
            whencreated: obj
                .get_first("whenCreated")
                .and_then(AttributeValue::as_unix_timestamp)
                .unwrap_or(0),
            enabled: uac & 2 == 0,
            unconstraineddelegation: uac & 0x00080000 == 0x00080000,
            trustedtoauth: uac & 0x01000000 == 0x01000000,
            lastlogon: obj
                .get_first("lastLogon")
                .and_then(AttributeValue::as_unix_timestamp)
                .unwrap_or(0),
            lastlogontimestamp: obj
                .get_first("lastLogonTimestamp")
                .and_then(AttributeValue::as_unix_timestamp)
                .unwrap_or(-1),
            pwdlastset: obj
                .get_first("pwdLastSet")
                .and_then(AttributeValue::as_unix_timestamp)
                .unwrap_or(0),
            serviceprincipalnames: obj
                .get("servicePrincipalName")
                .map(|values| {
                    values
                        .iter()
                        .filter_map(AttributeValue::as_string)
                        .cloned()
                        .collect()
                })
                .unwrap_or_default(),
            operatingsystem: obj
                .get_first("operatingSystem")
                .and_then(AttributeValue::as_string)
                .map(|os| {
                    obj.get_first("operatingSystemServicePack")
                        .and_then(AttributeValue::as_string)
                        .map(|sp| format!("{} {}", os, sp))
                        .unwrap_or_else(|| os.to_string())
                }),
            sidhistory: obj
                .get("sIDHistory")
                .map(|values| {
                    values
                        .iter()
                        .filter_map(AttributeValue::as_sid)
                        .map(|sid| sid.to_string())
                        .collect()
                })
                .unwrap_or_default(),
            samaccountname: obj
                .get_first("sAMAccountName")
                .and_then(AttributeValue::as_string)
                .map(|v| v.clone()),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DelegationTarget {
    #[serde(rename = "ObjectIdentifier")]
    pub object_identifier: String,
    #[serde(rename = "ObjectType")]
    pub object_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SIDHistoryItem {
    #[serde(rename = "ObjectIdentifier")]
    pub object_identifier: String,
    #[serde(rename = "ObjectType")]
    pub object_type: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct SessionsInfo {
    pub results: Vec<SessionResult>,
    pub collected: bool,
    pub failure_reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionResult {
    #[serde(rename = "UserSID")]
    pub user_sid: String,
    #[serde(rename = "ComputerSID")]
    pub computer_sid: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LocalGroup {
    pub collected: bool,
    pub failure_reason: String,
    pub results: Vec<LocalGroupMember>,
    #[serde(rename = "LocalName")]
    pub local_name: Vec<String>,
    pub name: String,
    #[serde(rename = "ObjectIdentifier")]
    pub object_identifier: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LocalGroupMember {
    #[serde(rename = "ObjectIdentifier")]
    pub object_identifier: String,
    #[serde(rename = "ObjectType")]
    pub object_type: String,
}

fn process_allowed_to_delegate(
    obj: &Object,
    snapshot: &ADExplorerSnapshot,
) -> Vec<DelegationTarget> {
    obj.get("msDS-AllowedToDelegateTo")
        .map(|values| {
            values
                .iter()
                .filter_map(AttributeValue::as_string)
                .flat_map(|host| {
                    let target = host.split('/').nth(1).unwrap_or(host);
                    if let Some(target_obj) = snapshot.get_computer(target) {
                        vec![DelegationTarget {
                            object_identifier: target_obj
                                .get_object_identifier()
                                .unwrap_or("ERR_UNKNOWN".to_string()),
                            object_type: type_string(target_obj),
                        }]
                    } else if target.contains('.') {
                        vec![DelegationTarget {
                            object_identifier: target.to_uppercase(),
                            object_type: "Computer".to_string(),
                        }]
                    } else {
                        eprintln!("Invalid delegation target: {}", host);
                        vec![]
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

fn process_allowed_to_act(_obj: &Object) -> Vec<DelegationTarget> {
    // TODO: Property msDS-AllowedToActOnBehalfOfOtherIdentity?

    Vec::new()
}

fn get_primary_group_sid(obj: &Object, snapshot: &ADExplorerSnapshot) -> String {
    let group_id = obj
        .get_first("primaryGroupID")
        .and_then(AttributeValue::as_integer)
        .unwrap_or(513); // Default to 513 (Domain Users) if not found

    let domain_sid = snapshot.caches.domain_sid.as_ref().unwrap();

    format!("{}-{}", domain_sid.to_string(), group_id)
}

fn process_sid_history(obj: &Object) -> Vec<SIDHistoryItem> {
    obj.get("sIDHistory")
        .map(|values| {
            values
                .iter()
                .filter_map(AttributeValue::as_sid)
                .map(|sid| SIDHistoryItem {
                    object_identifier: sid.to_string(),
                    object_type: "Computer".to_string(),
                })
                .collect()
        })
        .unwrap_or_default()
}
