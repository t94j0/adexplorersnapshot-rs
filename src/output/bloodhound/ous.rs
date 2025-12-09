use super::common::{get_aces, is_acl_protected, ldap2domain, type_string};
use super::utils::{Aces, Meta};
use crate::parser::{ADExplorerSnapshot, AttributeValue, Object, ObjectType};
use nom::{
    branch::alt,
    bytes::complete::{is_not, tag, tag_no_case},
    character::complete::char,
    combinator::{map, opt, value},
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
                preceded(tag_no_case("LDAP://cn="), Self::parse_guid),
                // Skip everything between the GUID and the semicolon (e.g., ",CN=Policies,CN=System,DC=lab,DC=local")
                preceded(
                    is_not(";"),
                    alt((value(true, tag(";2")), value(false, opt(tag(";0"))))),
                ),
            )),
            |(guid, is_enforced)| Link { guid, is_enforced },
        )(input)
    }

    fn parse_gplink(input: &str) -> IResult<&str, Vec<Link>> {
        nom::multi::many0(delimited(char('['), Self::parse_gplink_entry, char(']')))(input)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gplink_parsing_uppercase_cn() {
        // Real-world format with uppercase CN=
        let gplink = "[LDAP://CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=lab,DC=local;0]";
        let links = Link::from_gplink(gplink);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].guid, "31B2F340-016D-11D2-945F-00C04FB984F9");
        assert!(!links[0].is_enforced);
    }

    #[test]
    fn test_gplink_parsing_lowercase_cn() {
        // Format with lowercase cn=
        let gplink = "[LDAP://cn={31B2F340-016D-11D2-945F-00C04FB984F9},cn=Policies,cn=System,DC=lab,DC=local;0]";
        let links = Link::from_gplink(gplink);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].guid, "31B2F340-016D-11D2-945F-00C04FB984F9");
        assert!(!links[0].is_enforced);
    }

    #[test]
    fn test_gplink_parsing_enforced() {
        // Enforced GPO (;2)
        let gplink = "[LDAP://CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=lab,DC=local;2]";
        let links = Link::from_gplink(gplink);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].guid, "31B2F340-016D-11D2-945F-00C04FB984F9");
        assert!(links[0].is_enforced);
    }

    #[test]
    fn test_gplink_parsing_multiple_gpos() {
        // Multiple GPOs linked
        let gplink = "[LDAP://CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=lab,DC=local;0][LDAP://CN={6AC1786C-016F-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=lab,DC=local;2]";
        let links = Link::from_gplink(gplink);
        assert_eq!(links.len(), 2);
        assert_eq!(links[0].guid, "31B2F340-016D-11D2-945F-00C04FB984F9");
        assert!(!links[0].is_enforced);
        assert_eq!(links[1].guid, "6AC1786C-016F-11D2-945F-00C04FB984F9");
        assert!(links[1].is_enforced);
    }

    #[test]
    fn test_gplink_parsing_empty() {
        let gplink = "";
        let links = Link::from_gplink(gplink);
        assert!(links.is_empty());
    }

    #[test]
    fn test_gplink_guid_uppercase_conversion() {
        // Lowercase GUID should be converted to uppercase
        let gplink = "[LDAP://CN={31b2f340-016d-11d2-945f-00c04fb984f9},CN=Policies,CN=System,DC=lab,DC=local;0]";
        let links = Link::from_gplink(gplink);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].guid, "31B2F340-016D-11D2-945F-00C04FB984F9");
    }
}
