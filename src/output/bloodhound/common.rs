use super::utils::Aces;
use crate::parser::{ADExplorerSnapshot, ObjectType};
use crate::parser::{AttributeValue, Object};
use crate::security_descriptor::ControlFlag;

pub fn get_sid(obj: &Object) -> String {
    obj.get_object_identifier()
        .unwrap_or("ERR_UNKNOWN".to_string())
}

pub fn is_acl_protected(obj: &Object) -> bool {
    obj.get_first("nTSecurityDescriptor")
        .and_then(AttributeValue::as_nt_security_descriptor)
        .map(|sd| sd.control_flags.is_set(ControlFlag::DP))
        .unwrap_or(false)
}

pub fn get_aces(obj: &Object, snapshot: &ADExplorerSnapshot) -> Vec<Aces> {
    let has_laps = obj.get("ms-Mcs-AdmPwdExpirationTime").is_some();
    let object_type = obj.get_type();
    obj.get_first("nTSecurityDescriptor")
        .and_then(AttributeValue::as_nt_security_descriptor)
        .map(|sd| Aces::from_security_descriptor(&sd, snapshot, &object_type, has_laps))
        .unwrap_or_default()
}

pub fn ldap2domain(ldap: &str) -> String {
    ldap.split(',')
        .filter(|&part| part.to_lowercase().starts_with("dc="))
        .map(|part| &part[3..])
        .collect::<Vec<&str>>()
        .join(".")
}

pub fn type_string(obj: &Object) -> String {
    match obj.get_type() {
        ObjectType::Computer => "Computer".to_string(),
        ObjectType::Domain => "Domain".to_string(),
        ObjectType::Group => "Group".to_string(),
        ObjectType::User => "User".to_string(),
        ObjectType::UserDisabled => "User".to_string(),
        ObjectType::OU => "OU".to_string(),
        ObjectType::GPO => "GPO".to_string(),
        ObjectType::Container => "Container".to_string(),
        ObjectType::Unknown => "Unknown".to_string(),
    }
}
