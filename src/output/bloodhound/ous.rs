use super::common::{get_aces, is_acl_protected, ldap2domain, type_string};
use super::utils::{Aces, Meta};
use crate::parser::{ADExplorerSnapshot, AttributeValue, Object, ObjectType};
use nom::{
    branch::alt,
    bytes::complete::{is_not, tag},
    character::complete::char,
    combinator::{map, opt, value},
    multi::separated_list0,
    sequence::{delimited, preceded, tuple},
    IResult,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct OUsOutput {
    meta: Meta,
    #[serde(rename = "data")]
    ous: Vec<OU>,
}

impl OUsOutput {
    pub fn new(snapshot: &ADExplorerSnapshot) -> Self {
        let ous: Vec<OU> = snapshot
            .snapshot
            .objects
            .iter()
            .filter(|obj| obj.get_type() == ObjectType::OU)
            .map(|obj| OU::new(obj, snapshot))
            .collect();

        Self {
            meta: Meta {
                methods: 46067,
                r#type: "ous".to_string(),
                count: ous.len() as u64,
                version: 5,
            },
            ous,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OU {
    #[serde(rename = "Properties")]
    pub properties: OUProperties,

    #[serde(rename = "Links")]
    pub links: Vec<Link>,

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

impl OU {
    pub fn new(obj: &Object, snapshot: &ADExplorerSnapshot) -> Self {
        OU {
            properties: OUProperties::new(obj, snapshot),
            links: process_links(obj),
            child_objects: process_child_objects(obj, snapshot),
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

fn process_child_objects(obj: &Object, snapshot: &ADExplorerSnapshot) -> Vec<ChildObject> {
    let mut child_objects = Vec::new();

    let ou_dn = match obj
        .get_first("distinguishedName")
        .and_then(AttributeValue::as_string)
    {
        Some(dn) => dn,
        None => return child_objects,
    };

    let child_indexes = snapshot.caches.dn_cache.get_ou_children(ou_dn);

    for &index in &child_indexes {
        if let Some(child_obj) = snapshot.snapshot.objects.get(index) {
            child_objects.push(ChildObject {
                object_identifier: child_obj
                    .get_object_identifier()
                    .unwrap_or("ERR_UNKNOWN".to_string()),
                object_type: type_string(child_obj),
            });
        }
    }

    child_objects
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OUProperties {
    pub domain: String,
    pub name: String,
    pub distinguishedname: String,
    pub domainsid: String,
    pub description: Option<String>,
    pub whencreated: i64,
    pub blocksinheritance: bool,
}

impl OUProperties {
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
            .map(|v| v.clone().to_uppercase())
            .unwrap_or_default();

        OUProperties {
            domain: domain.clone(),
            name: format!("{}@{}", name, domain),
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
            blocksinheritance: obj
                .get_first("gPOptions")
                .and_then(AttributeValue::as_integer)
                .map(|v| v & 1 != 0)
                .unwrap_or(false),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Link {
    #[serde(rename = "IsEnforced")]
    pub is_enforced: bool,
    #[serde(rename = "GUID")]
    pub guid: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChildObject {
    #[serde(rename = "ObjectIdentifier")]
    pub object_identifier: String,
    #[serde(rename = "ObjectType")]
    pub object_type: String,
}

impl Link {
    fn parse_guid(input: &str) -> IResult<&str, String> {
        map(delimited(char('{'), is_not("}"), char('}')), |s: &str| {
            s.to_uppercase()
        })(input)
    }

    fn parse_gplink_entry(input: &str) -> IResult<&str, Link> {
        map(
            tuple((
                preceded(tag("LDAP://cn="), Self::parse_guid),
                alt((value(true, tag(";2")), value(false, opt(tag(";0"))))),
            )),
            |(guid, is_enforced)| Link { guid, is_enforced },
        )(input)
    }

    fn parse_gplink(input: &str) -> IResult<&str, Vec<Link>> {
        separated_list0(
            char(']'),
            delimited(char('['), Self::parse_gplink_entry, opt(char(']'))),
        )(input)
    }

    pub fn from_gplink(gplink: &str) -> Vec<Link> {
        match Self::parse_gplink(gplink) {
            Ok((_, links)) => links,
            Err(_) => Vec::new(),
        }
    }
}

fn process_links(obj: &Object) -> Vec<Link> {
    obj.get("gPLink")
        .and_then(|values| values.first())
        .and_then(AttributeValue::as_string)
        .map(|gplink| Link::from_gplink(gplink))
        .unwrap_or_default()
}
