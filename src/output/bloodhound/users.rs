use super::common::{get_aces, get_sid, is_acl_protected, ldap2domain};
use super::utils::{Aces, Meta};
use crate::output::bloodhound::common::type_string;
use crate::parser::Cache;
use crate::parser::{ADExplorerSnapshot, AttributeValue, Object};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize)]
pub struct UsersOutput {
    meta: Meta,
    #[serde(rename = "data")]
    users: Vec<User>,
}

impl UsersOutput {
    pub fn new(snapshot: &ADExplorerSnapshot) -> Self {
        let snapshot = Arc::new(snapshot);
        let domain_sid = snapshot.caches.domain_sid.as_ref().unwrap().to_string();

        let users: Vec<User> = snapshot
            .snapshot
            .objects
            .iter()
            .filter(|obj| Self::is_valid_user(obj, &snapshot))
            .map(|obj| User::new(obj, &snapshot, &domain_sid))
            .collect();

        Self {
            meta: Meta {
                methods: 46067,
                r#type: "users".to_string(),
                count: users.len() as u64,
                version: 5,
            },
            users,
        }
    }

    fn is_valid_user(obj: &Object, snapshot: &ADExplorerSnapshot) -> bool {
        let classes = obj
            .get("objectClass")
            .map(|values| {
                values
                    .iter()
                    .filter_map(AttributeValue::as_string)
                    .map(|v| v.to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let category = Self::get_object_category(obj, snapshot).unwrap_or_default();

        let class_condition = (classes.contains(&"user".to_string()) && category == "person")
            || classes.contains(&"ms-DS-Group-Managed-Service-Account".to_string());

        let account_type_condition = obj
            .get_first("sAMAccountType")
            .and_then(AttributeValue::as_integer)
            .map(|account_type| account_type != 805306370)
            .unwrap_or(false);

        class_condition && account_type_condition
    }

    fn get_object_category(obj: &Object, snapshot: &ADExplorerSnapshot) -> Option<String> {
        obj.get_first("objectCategory")
            .and_then(AttributeValue::as_string)
            .and_then(|cat_dn| snapshot.caches.class_cache.get(cat_dn))
            .and_then(|cat_idx| snapshot.snapshot.classes.get(*cat_idx))
            .map(|cat_obj| cat_obj.class_name.clone())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    #[serde(rename = "Properties")]
    pub properties: UserProperties,

    #[serde(rename = "AllowedToDelegate")]
    pub allowed_to_delegate: Vec<DelegationTarget>,

    #[serde(rename = "PrimaryGroupSID")]
    pub primary_group_sid: String,

    #[serde(rename = "HasSIDHistory")]
    pub has_sid_history: Vec<SIDHistoryItem>,

    #[serde(rename = "SpnTargets")]
    pub spn_targets: Vec<SPNTarget>,

    #[serde(rename = "Aces")]
    aces: Vec<Aces>,

    #[serde(rename = "ObjectIdentifier")]
    object_identifier: String,

    #[serde(rename = "IsDeleted")]
    is_deleted: bool,

    #[serde(rename = "IsACLProtected")]
    is_acl_protected: bool,
}

impl User {
    pub fn new(obj: &Object, snapshot: &ADExplorerSnapshot, domain_sid: &str) -> Self {
        User {
            properties: UserProperties::new(obj, snapshot),
            allowed_to_delegate: process_allowed_to_delegate(obj, snapshot),
            primary_group_sid: get_primary_group_sid(obj, domain_sid),
            has_sid_history: process_sid_history(obj),
            spn_targets: process_spn_targets(obj, snapshot),
            aces: get_aces(obj, snapshot),
            object_identifier: get_sid(obj),
            is_deleted: false, // Assuming this information is not available in the snapshot
            is_acl_protected: is_acl_protected(obj),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserProperties {
    pub domain: String,
    pub name: String,
    pub distinguishedname: String,
    pub domainsid: String,
    pub description: Option<String>,
    pub whencreated: i64,
    pub sensitive: bool,
    pub dontreqpreauth: bool,
    pub passwordnotreqd: bool,
    pub unconstraineddelegation: bool,
    pub pwdneverexpires: bool,
    pub enabled: bool,
    pub trustedtoauth: bool,
    pub lastlogon: i64,
    pub lastlogontimestamp: i64,
    pub pwdlastset: i64,
    pub serviceprincipalnames: Vec<String>,
    pub hasspn: bool,
    pub displayname: Option<String>,
    pub admincount: bool,
    pub sidhistory: Vec<String>,
}

impl UserProperties {
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

        UserProperties {
            domain: domain.clone(),
            name: format!("{}@{}", name.to_uppercase(), domain),
            distinguishedname: distinguished_name,
            domainsid: snapshot.caches.domain_sid.as_ref().unwrap().to_string(),
            description: obj
                .get_first("description")
                .and_then(AttributeValue::as_string)
                .map(|v| v.clone()),
            whencreated: obj
                .get_first("whenCreated")
                .and_then(AttributeValue::as_unix_timestamp)
                .unwrap_or(0),
            sensitive: obj
                .get_first("isSensitiveAccount")
                .and_then(AttributeValue::as_boolean)
                .unwrap_or(false),
            dontreqpreauth: obj
                .get_first("doesNotRequirePreAuth")
                .and_then(AttributeValue::as_boolean)
                .unwrap_or(false),
            passwordnotreqd: obj
                .get_first("passwordNotRequired")
                .and_then(AttributeValue::as_boolean)
                .unwrap_or(false),
            unconstraineddelegation: obj
                .get_first("trustToDelegateComputer")
                .and_then(AttributeValue::as_boolean)
                .unwrap_or(false),
            pwdneverexpires: obj
                .get_first("passwordNeverExpires")
                .and_then(AttributeValue::as_boolean)
                .unwrap_or(false),
            enabled: !obj
                .get_first("accountDisabled")
                .and_then(AttributeValue::as_boolean)
                .unwrap_or(false),
            trustedtoauth: obj
                .get_first("trustedToAuthForDelegation")
                .and_then(AttributeValue::as_boolean)
                .unwrap_or(false),
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
            hasspn: !obj
                .get("servicePrincipalName")
                .map(|values| values.is_empty())
                .unwrap_or(true),
            displayname: obj
                .get_first("displayName")
                .and_then(AttributeValue::as_string)
                .map(|v| v.clone()),
            admincount: obj
                .get_first("adminCount")
                .and_then(AttributeValue::as_boolean)
                .unwrap_or(false),
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

#[derive(Debug, Serialize, Deserialize)]
pub struct SPNTarget {
    #[serde(rename = "ComputerSID")]
    pub computer_sid: String,
    pub port: u16,
    pub service: String,
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

                    if let Some(target_obj) = snapshot.get_computer(&target) {
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

fn get_primary_group_sid(obj: &Object, domain_sid: &str) -> String {
    let group_id = obj
        .get_first("primaryGroupID")
        .and_then(AttributeValue::as_integer)
        .unwrap_or(513); // Default to 513 (Domain Users) if not found

    format!("{}-{}", domain_sid, group_id)
}

fn process_sid_history(obj: &Object) -> Vec<SIDHistoryItem> {
    obj.get("sIDHistory")
        .map(|values| {
            values
                .iter()
                .filter_map(AttributeValue::as_sid)
                .map(|sid| SIDHistoryItem {
                    object_identifier: sid.to_string(),
                    object_type: "User".to_string(),
                })
                .collect()
        })
        .unwrap_or_default()
}

// https://github.com/BloodHoundAD/SharpHoundCommon/blob/ea6b097927c5bb795adb8589e9a843293d36ae37/src/CommonLib/Processors/SPNProcessors.cs#L19
pub fn process_spn_targets(obj: &Object, snapshot: &ADExplorerSnapshot) -> Vec<SPNTarget> {
    let computer_cache = &snapshot.caches.computer_cache;
    obj.get("servicePrincipalName")
        .map(|values| {
            values
                .iter()
                .filter_map(AttributeValue::as_string)
                .filter_map(|spn| {
                    // Skip SPNs containing '@'
                    if spn.contains('@') {
                        return None;
                    }

                    let parts: Vec<&str> = spn.split('/').collect();
                    if parts.len() >= 2 {
                        let service = parts[0].to_lowercase();
                        let target_with_port = parts[1];

                        // Extract hostname (remove port if present)
                        let target = target_with_port
                            .split(':')
                            .next()
                            .unwrap_or(target_with_port)
                            .to_string();

                        // Parse port, defaulting to 1433 if not specified or invalid
                        let port = parts
                            .get(2)
                            .and_then(|p| p.split(':').last())
                            .and_then(|p| p.parse().ok())
                            .or_else(|| {
                                target_with_port
                                    .split(':')
                                    .nth(1)
                                    .and_then(|p| p.parse().ok())
                            })
                            .unwrap_or(1433);

                        // Check if the service is MSSQL (case-insensitive)
                        if service.contains("MSSQLSvc") {
                            let computer_sid = if computer_cache.contains_key(&target) {
                                target.clone()
                            } else if target.contains('.') {
                                target.to_uppercase()
                            } else {
                                eprintln!("Invalid SPN target: {} - {}", spn, target);
                                return None;
                            };

                            Some(SPNTarget {
                                computer_sid,
                                port,
                                service: String::from("SQLAdmin"),
                            })
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}
