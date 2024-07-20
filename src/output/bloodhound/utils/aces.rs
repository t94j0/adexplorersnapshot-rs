use crate::{
    output::bloodhound::common::type_string,
    parser::{ADExplorerSnapshot, ObjectType},
    security_descriptor::{ACEFlags, ACEGuid, AccessMask, ACE, SDDL},
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Serialize, Deserialize)]
pub struct Aces {
    #[serde(rename = "PrincipalSID")]
    pub principal_sid: String,

    #[serde(rename = "PrincipalType")]
    pub principal_type: String,

    #[serde(rename = "RightName")]
    pub right_name: String,

    #[serde(rename = "IsInherited")]
    pub is_inherited: bool,
}

impl Aces {
    pub fn from_security_descriptor(
        sd: &SDDL,
        snapshot: &ADExplorerSnapshot,
        object_type: &ObjectType,
        has_laps: bool,
    ) -> Vec<Self> {
        let mut aces = Vec::new();
        if let Some(owner) = &sd.owner_sid {
            if let Some(obj) = snapshot.get_sid(owner) {
                let ace = Aces {
                    principal_sid: owner.to_string(),
                    principal_type: type_string(obj),
                    right_name: "Owns".to_string(),
                    is_inherited: false,
                };
                aces.push(ace);
            } else {
                // eprintln!("Owner SID not found in snapshot: {}", owner.to_string());
            }
        }

        if let Some(dacl) = &sd.dacl {
            for ace in dacl
                .aces
                .iter()
                .filter(|ace| !matches!(ace, ACE::AccessDenied(_) | ACE::AccessDeniedObject(_)))
            {
                let rights = Self::rights(ace, object_type, has_laps);
                if let Some(target_obj) = snapshot.get_sid(&ace.sid()) {
                    for right in rights {
                        let ace = Aces {
                            principal_sid: ace.sid().to_string(),
                            principal_type: type_string(target_obj),
                            right_name: right,
                            is_inherited: Self::is_inherited(ace),
                        };
                        aces.push(ace);
                    }
                }
            }
        }

        aces
    }

    fn is_inherited(ace: &ACE) -> bool {
        ace.header().ace_flags.is_set(ACEFlags::INHERITED_ACE)
    }

    fn rights(ace: &ACE, object_type: &ObjectType, has_laps: bool) -> HashSet<String> {
        let mut rights = HashSet::new();
        let ace_mask = ace.mask();
        let ace_type = ace.object_type_s();

        // GenericAll
        if ace_mask.has_flag(AccessMask::GENERIC_ALL) {
            if ace_type.is_none() || ace_type == Some(ACEGuid::AllGuid) {
                rights.insert("GenericAll".to_string());
            }
            return rights; // Early return to avoid other checks
        }

        // WriteDACL and WriteOwner
        if ace_mask.has_flag(AccessMask::WRITE_DACL) {
            rights.insert("WriteDacl".to_string());
        }
        if ace_mask.has_flag(AccessMask::WRITE_OWNER) {
            rights.insert("WriteOwner".to_string());
        }

        // AddSelf
        if ace_mask.has_flag(AccessMask::ADS_RIGHT_DS_SELF)
            && !ace_mask.has_flag(AccessMask::ADS_RIGHT_DS_WRITE_PROP)
            && !ace_mask.has_flag(AccessMask::GENERIC_WRITE)
            && object_type == &ObjectType::Group
            && ace_type == Some(ACEGuid::WriteMember)
        {
            rights.insert("AddSelf".to_string());
        }

        // ExtendedRights
        if ace_mask.has_flag(AccessMask::ADS_RIGHT_DS_CONTROL_ACCESS) {
            match object_type {
                ObjectType::Domain => match ace_type {
                    Some(ACEGuid::DSReplicationGetChanges) => {
                        rights.insert("GetChanges".to_string());
                    }
                    Some(ACEGuid::DSReplicationGetChangesAll) => {
                        rights.insert("GetChangesAll".to_string());
                    }
                    Some(ACEGuid::DSReplicationGetChangesInFilteredSet) => {
                        rights.insert("GetChangesInFilteredSet".to_string());
                    }
                    Some(ACEGuid::AllGuid) | None => {
                        rights.insert("AllExtendedRights".to_string());
                    }
                    _ => {}
                },
                ObjectType::User => match ace_type {
                    Some(ACEGuid::UserForceChangePassword) => {
                        rights.insert("ForceChangePassword".to_string());
                    }
                    Some(ACEGuid::AllGuid) | None => {
                        rights.insert("AllExtendedRights".to_string());
                    }
                    _ => {}
                },
                ObjectType::Computer => {
                    if has_laps {
                        if ace_type.is_none() || ace_type == Some(ACEGuid::AllGuid) {
                            rights.insert("AllExtendedRights".to_string());
                        }
                    }
                }
                _ => {}
            }
        }

        // GenericWrite and WriteProperty
        if ace_mask.has_flag(AccessMask::GENERIC_WRITE)
            || ace_mask.has_flag(AccessMask::ADS_RIGHT_DS_WRITE_PROP)
        {
            match object_type {
                ObjectType::User | ObjectType::Group | ObjectType::Computer | ObjectType::GPO => {
                    if ace_type.is_none() || ace_type == Some(ACEGuid::AllGuid) {
                        rights.insert("GenericWrite".to_string());
                    }
                }
                _ => {}
            }

            match (object_type, ace_type) {
                (ObjectType::User, Some(ACEGuid::WriteSPN)) => {
                    rights.insert("WriteSPN".to_string());
                }
                (ObjectType::Computer, Some(ACEGuid::WriteAllowedToAct)) => {
                    rights.insert("AddAllowedToAct".to_string());
                }
                (ObjectType::Computer, Some(ACEGuid::UserAccountRestrictions)) => {
                    rights.insert("WriteAccountRestrictions".to_string());
                }
                (ObjectType::Group, Some(ACEGuid::WriteMember)) => {
                    rights.insert("AddMember".to_string());
                }
                (ObjectType::User | ObjectType::Computer, Some(ACEGuid::AddKeyPrincipal)) => {
                    rights.insert("AddKeyCredentialLink".to_string());
                }
                _ => {}
            }
        }

        rights
    }
}
