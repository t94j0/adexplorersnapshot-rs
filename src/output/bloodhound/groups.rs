use super::common::{get_aces, get_sid, is_acl_protected, ldap2domain, type_string};
use super::utils::{Aces, Meta};
use crate::parser::{ADExplorerSnapshot, AttributeValue, Object};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Serialize, Deserialize)]
pub struct GroupsOutput {
    meta: Meta,
    #[serde(rename = "data")]
    groups: Vec<Group>,
}

impl GroupsOutput {
    pub fn new(snapshot: &ADExplorerSnapshot) -> Self {
        let domain_sid = snapshot.caches.domain_sid.as_ref().unwrap().to_string();
        let highvalue_sids: HashSet<&str> = [
            "S-1-5-32-544",
            "S-1-5-32-550",
            "S-1-5-32-549",
            "S-1-5-32-551",
            "S-1-5-32-548",
        ]
        .iter()
        .cloned()
        .collect();

        let groups: Vec<Group> = snapshot
            .snapshot
            .objects
            .iter()
            .filter(|obj| {
                obj.get("objectClass")
                    .map(|values| {
                        values
                            .iter()
                            .any(|v| v.as_string() == Some(&"group".to_string()))
                    })
                    .unwrap_or(false)
            })
            .map(|obj| Group::new(obj, snapshot, &domain_sid, &highvalue_sids))
            .collect();

        Self {
            meta: Meta {
                methods: 46067,
                r#type: "groups".to_string(),
                count: groups.len() as u64,
                version: 5,
            },
            groups,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Group {
    #[serde(rename = "Properties")]
    pub properties: GroupProperties,

    #[serde(rename = "Members")]
    pub members: Vec<GroupMember>,

    #[serde(rename = "Aces")]
    aces: Vec<Aces>,

    #[serde(rename = "ObjectIdentifier")]
    object_identifier: String,

    #[serde(rename = "IsDeleted")]
    is_deleted: bool,

    #[serde(rename = "IsACLProtected")]
    is_acl_protected: bool,
}

impl Group {
    pub fn new(
        obj: &Object,
        snapshot: &ADExplorerSnapshot,
        domain_sid: &str,
        highvalue_sids: &HashSet<&str>,
    ) -> Self {
        let sid = get_sid(obj);
        let object_identifier = if WELLKNOWN_SIDS.contains(&sid.as_str()) {
            format!("{}-{}", domain_sid, sid)
        } else {
            sid.clone()
        };

        Group {
            properties: GroupProperties::new(obj, snapshot, &sid, highvalue_sids),
            members: process_members(obj, snapshot),
            aces: get_aces(obj, snapshot),
            object_identifier,
            is_deleted: obj
                .get_first("isDeleted")
                .and_then(AttributeValue::as_boolean)
                .unwrap_or(false),
            is_acl_protected: is_acl_protected(obj),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GroupProperties {
    pub domain: String,
    pub domainsid: String,
    pub highvalue: bool,
    pub name: String,
    pub distinguishedname: String,
    pub admincount: bool,
    pub description: Option<String>,
    pub whencreated: i64,
}

impl GroupProperties {
    pub fn new(
        obj: &Object,
        snapshot: &ADExplorerSnapshot,
        sid: &str,
        highvalue_sids: &HashSet<&str>,
    ) -> Self {
        let distinguished_name = obj
            .get_first("distinguishedName")
            .and_then(AttributeValue::as_string)
            .map(|s| s.to_string())
            .unwrap_or_default();
        let domain = ldap2domain(&distinguished_name).to_uppercase();
        let name = obj
            .get_first("name")
            .and_then(AttributeValue::as_string)
            .map(|s| s.to_string())
            .unwrap_or_default();

        GroupProperties {
            domain: domain.clone(),
            domainsid: snapshot.caches.domain_sid.as_ref().unwrap().to_string(),
            highvalue: is_highvalue(sid, highvalue_sids),
            name: format!("{}@{}", name.to_uppercase(), domain),
            distinguishedname: distinguished_name.to_string(),
            admincount: obj
                .get_first("adminCount")
                .and_then(AttributeValue::as_integer)
                .map(|count| count == 1)
                .unwrap_or(false),
            description: obj
                .get_first("description")
                .and_then(AttributeValue::as_string)
                .map(|v| v.to_string()),
            whencreated: obj
                .get_first("whenCreated")
                .and_then(AttributeValue::as_unix_timestamp)
                .unwrap_or(0),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GroupMember {
    #[serde(rename = "ObjectIdentifier")]
    pub object_identifier: String,
    #[serde(rename = "ObjectType")]
    pub object_type: String,
}

fn process_members(obj: &Object, snapshot: &ADExplorerSnapshot) -> Vec<GroupMember> {
    obj.get("member")
        .map(|values| {
            values
                .iter()
                .filter_map(AttributeValue::as_string)
                .filter_map(|member_dn| resolve_membership(member_dn, snapshot))
                .collect()
        })
        .unwrap_or_default()
}

fn resolve_membership(member_dn: &str, snapshot: &ADExplorerSnapshot) -> Option<GroupMember> {
    snapshot.get_dn(member_dn).map(|obj| GroupMember {
        object_identifier: get_sid(obj),
        object_type: type_string(obj),
    })
}

fn is_highvalue(sid: &str, highvalue_sids: &HashSet<&str>) -> bool {
    sid.ends_with("-512")
        || sid.ends_with("-516")
        || sid.ends_with("-519")
        || sid.ends_with("-520")
        || highvalue_sids.contains(sid)
}

const WELLKNOWN_SIDS: &[&str] = &[
    "S-1-0",
    "S-1-0-0",
    "S-1-1",
    "S-1-1-0",
    "S-1-2",
    "S-1-2-0",
    "S-1-2-1",
    "S-1-3",
    "S-1-3-0",
    "S-1-3-1",
    "S-1-3-2",
    "S-1-3-3",
    "S-1-3-4",
    "S-1-5-1",
    "S-1-5-2",
    "S-1-5-3",
    "S-1-5-4",
    "S-1-5-6",
    "S-1-5-7",
    "S-1-5-8",
    "S-1-5-9",
    "S-1-5-10",
    "S-1-5-11",
    "S-1-5-12",
    "S-1-5-13",
    "S-1-5-14",
    "S-1-5-15",
    "S-1-5-17",
    "S-1-5-18",
    "S-1-5-19",
    "S-1-5-20",
    "S-1-5-21-0-0-0-496",
    "S-1-5-21-0-0-0-497",
    "S-1-5-32-544",
    "S-1-5-32-545",
    "S-1-5-32-546",
    "S-1-5-32-547",
    "S-1-5-32-548",
    "S-1-5-32-549",
    "S-1-5-32-550",
    "S-1-5-32-551",
    "S-1-5-32-552",
    "S-1-5-32-554",
    "S-1-5-32-555",
    "S-1-5-32-556",
    "S-1-5-32-557",
    "S-1-5-32-558",
    "S-1-5-32-559",
    "S-1-5-32-560",
    "S-1-5-32-561",
    "S-1-5-32-562",
    "S-1-5-32-568",
    "S-1-5-32-569",
    "S-1-5-32-573",
    "S-1-5-32-574",
    "S-1-5-32-575",
    "S-1-5-32-576",
    "S-1-5-32-577",
    "S-1-5-32-578",
    "S-1-5-32-579",
    "S-1-5-32-580",
];
