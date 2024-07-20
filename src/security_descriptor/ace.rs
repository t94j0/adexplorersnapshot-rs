use super::access_mask::{parse_access_mask, AccessMask};
use crate::guid::GUID;
use crate::sid::SID;
use nom::{
    bytes::complete::take,
    number::complete::{le_u16, le_u32, le_u8},
    sequence::tuple,
    IResult,
};
use serde::Serialize;

#[derive(Debug, PartialEq, Eq, Serialize, Clone)]
pub enum ACE {
    AccessAllowed(AccessAllowedAce),
    AccessAllowedObject(AccessAllowedObjectAce),
    AccessDenied(AccessDeniedAce),
    SystemAuditObject(SystemAuditObjectAce),
    AccessDeniedObject(AccessDeniedObjectAce),
}

impl ACE {
    pub fn header(&self) -> &ACEHeader {
        match self {
            ACE::AccessAllowed(ace) => &ace.header,
            ACE::AccessAllowedObject(ace) => &ace.header,
            ACE::AccessDenied(ace) => &ace.header,
            ACE::SystemAuditObject(ace) => &ace.header,
            ACE::AccessDeniedObject(ace) => &ace.header,
        }
    }

    pub fn sid(&self) -> &SID {
        match self {
            ACE::AccessAllowed(ace) => &ace.sid,
            ACE::AccessAllowedObject(ace) => &ace.sid,
            ACE::AccessDenied(ace) => &ace.sid,
            ACE::SystemAuditObject(ace) => &ace.sid,
            ACE::AccessDeniedObject(ace) => &ace.sid,
        }
    }

    pub fn mask(&self) -> AccessMask {
        match self {
            ACE::AccessAllowed(ace) => ace.mask,
            ACE::AccessAllowedObject(ace) => ace.mask,
            ACE::AccessDenied(ace) => ace.mask,
            ACE::SystemAuditObject(ace) => ace.mask,
            ACE::AccessDeniedObject(ace) => ace.mask,
        }
    }

    pub fn object_type(&self) -> Option<&GUID> {
        match self {
            ACE::AccessAllowedObject(ace) => ace.object_type.as_ref(),
            ACE::SystemAuditObject(ace) => ace.object_type.as_ref(),
            ACE::AccessDeniedObject(ace) => ace.object_type.as_ref(),
            _ => None,
        }
    }

    pub fn object_type_s(&self) -> Option<ACEGuid> {
        let ot = self.object_type()?;
        ACEGuid::from_guid(ot)
    }

    pub fn inherited_object_type(&self) -> Option<&GUID> {
        match self {
            ACE::AccessAllowedObject(ace) => ace.inherited_object_type.as_ref(),
            ACE::SystemAuditObject(ace) => ace.inherited_object_type.as_ref(),
            ACE::AccessDeniedObject(ace) => ace.inherited_object_type.as_ref(),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Clone)]
pub enum ACEGuid {
    DSReplicationGetChanges,
    DSReplicationGetChangesAll,
    DSReplicationGetChangesInFilteredSet,
    UserForceChangePassword,
    AllGuid,
    WriteMember,
    WriteAllowedToAct,
    WriteSPN,
    AddKeyPrincipal,
    UserAccountRestrictions,
    PKINameFlag,
    PKIEnrollmentFlag,
    Enroll,
    AutoEnroll,
}

impl ACEGuid {
    pub fn from_guid(guid: &GUID) -> Option<ACEGuid> {
        // https://github.com/BloodHoundAD/SharpHoundCommon/blob/ea6b097927c5bb795adb8589e9a843293d36ae37/src/CommonLib/Processors/ACEGuids.cs#L4
        match guid.to_string().as_str() {
            "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" => Some(ACEGuid::DSReplicationGetChanges),
            "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" => Some(ACEGuid::DSReplicationGetChangesAll),
            "89e95b76-444d-4c62-991a-0facbeda640c" => {
                Some(ACEGuid::DSReplicationGetChangesInFilteredSet)
            }
            "00299570-246d-11d0-a768-00aa006e0529" => Some(ACEGuid::UserForceChangePassword),
            "00000000-0000-0000-0000-000000000000" => Some(ACEGuid::AllGuid),
            "bf9679c0-0de6-11d0-a285-00aa003049e2" => Some(ACEGuid::WriteMember),
            "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79" => Some(ACEGuid::WriteAllowedToAct),
            "f3a64788-5306-11d1-a9c5-0000f80367c1" => Some(ACEGuid::WriteSPN),
            "5b47d60f-6090-40b2-9f37-2a4de88f3063" => Some(ACEGuid::AddKeyPrincipal),
            "4c164200-20c0-11d0-a768-00aa006e0529" => Some(ACEGuid::UserAccountRestrictions),
            "ea1dddc4-60ff-416e-8cc0-17cee534bce7" => Some(ACEGuid::PKINameFlag),
            "d15ef7d8-f226-46db-ae79-b34e560bd12c" => Some(ACEGuid::PKIEnrollmentFlag),
            "0e10c968-78fb-11d2-90d4-00c04f79dc55" => Some(ACEGuid::Enroll),
            "a05b8cc2-17bc-4802-a710-e7c15ab866a2" => Some(ACEGuid::AutoEnroll),
            _ => None,
        }
    }
}

pub fn parse_ace(input: &[u8]) -> IResult<&[u8], ACE> {
    let (input, header) = parse_ace_header(input)?;
    match header.ace_type {
        ACEType::AccessAllowed => {
            let (input, ace) = parse_access_allowed_ace(input, header)?;
            Ok((input, ACE::AccessAllowed(ace)))
        }
        ACEType::AccessAllowedObject => {
            let (input, ace) = parse_access_allowed_object_ace(input, header)?;
            Ok((input, ACE::AccessAllowedObject(ace)))
        }
        ACEType::AccessDenied => {
            let (input, ace) = parse_access_denied_ace(input, header)?;
            Ok((input, ACE::AccessDenied(ace)))
        }
        ACEType::SystemAuditObject => {
            let (input, ace) = parse_system_audit_object_ace(input, header)?;
            Ok((input, ACE::SystemAuditObject(ace)))
        }
        ACEType::AccessDeniedObject => {
            let (input, ace) = parse_access_denied_object_ace(input, header)?;
            Ok((input, ACE::AccessDeniedObject(ace)))
        }
        _ => unimplemented!("ACE type not implemented: {:?}", header.ace_type),
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Clone)]
pub struct AccessAllowedAce {
    pub header: ACEHeader,
    pub mask: AccessMask,
    pub sid: SID,
}

fn parse_access_allowed_ace(input: &[u8], header: ACEHeader) -> IResult<&[u8], AccessAllowedAce> {
    let (input, mask) = parse_access_mask(input)?;
    let (input, sid) = SID::from_next_bytes(input)?;

    Ok((input, AccessAllowedAce { header, mask, sid }))
}

#[derive(Debug, PartialEq, Eq, Serialize, Clone)]
pub struct AccessAllowedObjectAce {
    pub header: ACEHeader,
    pub mask: AccessMask,
    pub flags: u32,
    pub object_type: Option<GUID>,
    pub inherited_object_type: Option<GUID>,
    pub sid: SID,
}

fn parse_access_allowed_object_ace(
    input: &[u8],
    header: ACEHeader,
) -> IResult<&[u8], AccessAllowedObjectAce> {
    let (input, mask) = parse_access_mask(input)?;
    let (input, flags) = le_u32(input)?;
    let (input, mut object_type) = (input, None);
    let (mut input, mut inherited_object_type) = (input, None);

    if flags & 1 != 0 {
        let (inner_input, ot) = GUID::from_next_bytes(input)?;
        input = inner_input;
        object_type = Some(ot);
    }
    if flags & 2 != 0 {
        let (inner_input, iot) = GUID::from_next_bytes(input)?;
        input = inner_input;
        inherited_object_type = Some(iot);
    }
    let (input, sid) = SID::from_next_bytes(input)?;

    Ok((
        input,
        AccessAllowedObjectAce {
            header,
            mask,
            flags,
            object_type,
            inherited_object_type,
            sid,
        },
    ))
}

#[derive(Debug, PartialEq, Eq, Serialize, Clone)]
pub struct AccessDeniedAce {
    pub header: ACEHeader,
    pub mask: AccessMask,
    pub sid: SID,
}

fn parse_access_denied_ace(input: &[u8], header: ACEHeader) -> IResult<&[u8], AccessDeniedAce> {
    let (input, mask) = parse_access_mask(input)?;
    let (input, sid) = SID::from_next_bytes(input)?;

    Ok((input, AccessDeniedAce { header, mask, sid }))
}

#[derive(Debug, PartialEq, Eq, Serialize, Clone)]
pub struct SystemAuditObjectAce {
    pub header: ACEHeader,
    pub mask: AccessMask,
    pub flags: u32,
    pub object_type: Option<GUID>,
    pub inherited_object_type: Option<GUID>,
    pub sid: SID,
    pub application_data: Vec<u8>,
}

fn parse_system_audit_object_ace(
    input: &[u8],
    header: ACEHeader,
) -> IResult<&[u8], SystemAuditObjectAce> {
    let (input, mask) = parse_access_mask(input)?;
    let (input, flags) = le_u32(input)?;

    let (input, object_type) = if flags & 0x00000001 != 0 {
        let (input, guid) = GUID::from_next_bytes(input)?;
        (input, Some(guid))
    } else {
        (input, None)
    };

    let (input, inherited_object_type) = if flags & 0x00000002 != 0 {
        let (input, guid) = GUID::from_next_bytes(input)?;
        (input, Some(guid))
    } else {
        (input, None)
    };

    let (input, _) = take(8usize)(input)?;

    let (input, sid) = SID::from_next_bytes(input)?;

    // Calculate the size of application data
    let app_data_size = header.ace_size as usize;
    let (input, application_data) = take(app_data_size)(input)?;

    Ok((
        input,
        SystemAuditObjectAce {
            header,
            mask,
            flags,
            object_type,
            inherited_object_type,
            sid,
            application_data: application_data.to_vec(),
        },
    ))
}

#[derive(Debug, PartialEq, Eq, Serialize, Clone)]
pub struct AccessDeniedObjectAce {
    pub header: ACEHeader,
    pub mask: AccessMask,
    pub flags: u32,
    pub object_type: Option<GUID>,
    pub inherited_object_type: Option<GUID>,
    pub sid: SID,
}

// Constants for the flags
const ACE_OBJECT_TYPE_PRESENT: u32 = 0x00000001;
const ACE_INHERITED_OBJECT_TYPE_PRESENT: u32 = 0x00000002;

fn parse_access_denied_object_ace(
    input: &[u8],
    header: ACEHeader,
) -> IResult<&[u8], AccessDeniedObjectAce> {
    let (input, mask) = parse_access_mask(input)?;
    let (input, flags) = le_u32(input)?;
    let (input, mut object_type) = (input, None);
    let (mut input, mut inherited_object_type) = (input, None);

    if flags & ACE_OBJECT_TYPE_PRESENT != 0 {
        let (inner_input, ot) = GUID::from_next_bytes(input)?;
        input = inner_input;
        object_type = Some(ot);
    }
    if flags & ACE_INHERITED_OBJECT_TYPE_PRESENT != 0 {
        let (inner_input, iot) = GUID::from_next_bytes(input)?;
        input = inner_input;
        inherited_object_type = Some(iot);
    }
    let (input, sid) = SID::from_next_bytes(input)?;

    Ok((
        input,
        AccessDeniedObjectAce {
            header,
            mask,
            flags,
            object_type,
            inherited_object_type,
            sid,
        },
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ACEType {
    AccessAllowed = 0x00,
    AccessDenied = 0x01,
    SystemAudit = 0x02,
    SystemAlarm = 0x03,
    AccessAllowedCompound = 0x04,
    AccessAllowedObject = 0x05,
    AccessDeniedObject = 0x06,
    SystemAuditObject = 0x07,
    SystemAlarmObject = 0x08,
    AccessAllowedCallback = 0x09,
    AccessDeniedCallback = 0x0A,
    AccessAllowedCallbackObject = 0x0B,
    AccessDeniedCallbackObject = 0x0C,
    SystemAuditCallback = 0x0D,
    SystemAlarmCallback = 0x0E,
    SystemAuditCallbackObject = 0x0F,
    SystemAlarmCallbackObject = 0x10,
    SystemMandatoryLabel = 0x11,
    SystemResourceAttribute = 0x12,
    SystemScopedPolicyId = 0x13,
}

impl From<u8> for ACEType {
    fn from(value: u8) -> Self {
        match value {
            0x00 => ACEType::AccessAllowed,
            0x01 => ACEType::AccessDenied,
            0x02 => ACEType::SystemAudit,
            0x03 => ACEType::SystemAlarm,
            0x04 => ACEType::AccessAllowedCompound,
            0x05 => ACEType::AccessAllowedObject,
            0x06 => ACEType::AccessDeniedObject,
            0x07 => ACEType::SystemAuditObject,
            0x08 => ACEType::SystemAlarmObject,
            0x09 => ACEType::AccessAllowedCallback,
            0x0A => ACEType::AccessDeniedCallback,
            0x0B => ACEType::AccessAllowedCallbackObject,
            0x0C => ACEType::AccessDeniedCallbackObject,
            0x0D => ACEType::SystemAuditCallback,
            0x0E => ACEType::SystemAlarmCallback,
            0x0F => ACEType::SystemAuditCallbackObject,
            0x10 => ACEType::SystemAlarmCallbackObject,
            0x11 => ACEType::SystemMandatoryLabel,
            0x12 => ACEType::SystemResourceAttribute,
            0x13 => ACEType::SystemScopedPolicyId,
            _ => panic!("Invalid ACE type"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ACEFlags(u8);

impl ACEFlags {
    pub const CONTAINER_INHERIT_ACE: u8 = 0x02;
    pub const FAILED_ACCESS_ACE_FLAG: u8 = 0x80;
    pub const INHERIT_ONLY_ACE: u8 = 0x08;
    pub const INHERITED_ACE: u8 = 0x10;
    pub const NO_PROPAGATE_INHERIT_ACE: u8 = 0x04;
    pub const OBJECT_INHERIT_ACE: u8 = 0x01;
    pub const SUCCESSFUL_ACCESS_ACE_FLAG: u8 = 0x40;

    pub fn new(value: u8) -> Self {
        ACEFlags(value)
    }

    pub fn is_set(&self, flag: u8) -> bool {
        self.0 & flag != 0
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Clone)]
pub struct ACEHeader {
    pub ace_type: ACEType,
    pub ace_flags: ACEFlags,
    pub ace_size: u16,
}

pub fn parse_ace_header(input: &[u8]) -> IResult<&[u8], ACEHeader> {
    let (input, (ace_type, ace_flags, ace_size)) = tuple((le_u8, le_u8, le_u16))(input)?;

    Ok((
        input,
        ACEHeader {
            ace_type: ACEType::from(ace_type),
            ace_flags: ACEFlags::new(ace_flags),
            ace_size,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore]
    fn test_sddl_parsing() {
        let ace_bytes = vec![
            0, 1, 0, 0, 1, 0, 0, 0, 24, 126, 15, 62, 122, 44, 16, 76, 186, 130, 77, 146, 109, 185,
            154, 62, 1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 45, 65, 88, 115, 197, 187, 192, 93, 42,
            109, 38, 58, 10, 2, 0, 0, 5, 0, 56, 0, 0, 1, 0, 0, 1, 0, 0, 0, 170, 246, 49, 17, 7,
            156, 209, 17, 247, 159, 0, 192, 79, 194, 220, 210, 1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0,
            45, 65, 88, 115, 197, 187, 192, 93, 42, 109, 38, 58, 242, 1, 0, 0, 5, 0, 56, 0, 0, 1,
            0, 0, 1, 0, 0, 0, 173, 246, 49, 17, 7, 156, 209, 17, 247, 159, 0, 192, 79, 194, 220,
            210, 1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 45, 65, 88, 115, 197, 187, 192, 93, 42, 109,
            38, 58, 4, 2, 0, 0, 5, 2, 56, 0, 48, 0, 0, 0, 1, 0, 0, 0, 15, 214, 71, 91, 144, 96,
            178, 64, 159, 55, 42, 77, 232, 143, 48, 99, 1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 45,
            65, 88, 115, 197, 187, 192, 93, 42, 109, 38, 58, 14, 2, 0, 0, 5, 2, 56, 0, 48, 0, 0, 0,
            1, 0, 0, 0, 15, 214, 71, 91, 144, 96, 178, 64, 159, 55, 42, 77, 232, 143, 48, 99, 1, 5,
            0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 45, 65, 88, 115, 197, 187, 192, 93, 42, 109, 38, 58, 15,
            2, 0, 0, 5, 10, 56, 0, 8, 0, 0, 0, 3, 0, 0, 0, 166, 109, 2, 155, 60, 13, 92, 70, 139,
            238, 81, 153, 215, 22, 92, 186, 134, 122, 150, 191, 230, 13, 208, 17, 162, 133, 0, 170,
            0, 48, 73, 226, 1, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 5, 10, 56, 0, 8, 0, 0, 0, 3, 0, 0,
            0, 166, 109, 2, 155, 60, 13, 92, 70, 139, 238, 81, 153, 215, 22, 92, 186, 134, 122,
            150, 191, 230, 13, 208, 17, 162, 133, 0, 170, 0, 48, 73, 226, 1, 1, 0, 0, 0, 0, 0, 5,
            10, 0, 0, 0, 5, 10, 56, 0, 16, 0, 0, 0, 3, 0, 0, 0, 109, 158, 198, 183, 199, 44, 210,
            17, 133, 78, 0, 160, 201, 131, 246, 8, 134, 122, 150, 191, 230, 13, 208, 17, 162, 133,
            0, 170, 0, 48, 73, 226, 1, 1, 0, 0, 0, 0, 0, 5, 9, 0, 0, 0, 5, 10, 56, 0, 16, 0, 0, 0,
            3, 0, 0, 0, 109, 158, 198, 183, 199, 44, 210, 17, 133, 78, 0, 160, 201, 131, 246, 8,
            156, 122, 150, 191, 230, 13, 208, 17, 162, 133, 0, 170, 0, 48, 73, 226, 1, 1, 0, 0, 0,
            0, 0, 5, 9, 0, 0, 0, 5, 10, 56, 0, 16, 0, 0, 0, 3, 0, 0, 0, 109, 158, 198, 183, 199,
            44, 210, 17, 133, 78, 0, 160, 201, 131, 246, 8, 186, 122, 150, 191, 230, 13, 208, 17,
            162, 133, 0, 170, 0, 48, 73, 226, 1, 1, 0, 0, 0, 0, 0, 5, 9, 0, 0, 0, 5, 10, 56, 0, 32,
            0, 0, 0, 3, 0, 0, 0, 147, 123, 27, 234, 72, 94, 213, 70, 188, 108, 77, 244, 253, 167,
            138, 53, 134, 122, 150, 191, 230, 13, 208, 17, 162, 133, 0, 170, 0, 48, 73, 226, 1, 1,
            0, 0, 0, 0, 0, 5, 10, 0, 0, 0, 5, 0, 44, 0, 0, 1, 0, 0, 1, 0, 0, 0, 118, 91, 233, 137,
            77, 68, 98, 76, 153, 26, 15, 172, 190, 218, 100, 12, 1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0,
            0, 32, 2, 0, 0, 5, 0, 44, 0, 0, 1, 0, 0, 1, 0, 0, 0, 170, 246, 49, 17, 7, 156, 209, 17,
            247, 159, 0, 192, 79, 194, 220, 210, 1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0,
            5, 0, 44, 0, 0, 1, 0, 0, 1, 0, 0, 0, 171, 246, 49, 17, 7, 156, 209, 17, 247, 159, 0,
            192, 79, 194, 220, 210, 1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0, 5, 0, 44, 0,
            0, 1, 0, 0, 1, 0, 0, 0, 172, 246, 49, 17, 7, 156, 209, 17, 247, 159, 0, 192, 79, 194,
            220, 210, 1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0, 5, 0, 44, 0, 0, 1, 0, 0, 1,
            0, 0, 0, 173, 246, 49, 17, 7, 156, 209, 17, 247, 159, 0, 192, 79, 194, 220, 210, 1, 2,
            0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0, 5, 0, 44, 0, 0, 1, 0, 0, 1, 0, 0, 0, 174,
            246, 49, 17, 7, 156, 209, 17, 247, 159, 0, 192, 79, 194, 220, 210, 1, 2, 0, 0, 0, 0, 0,
            5, 32, 0, 0, 0, 32, 2, 0, 0, 5, 0, 44, 0, 0, 1, 0, 0, 1, 0, 0, 0, 201, 109, 163, 226,
            23, 174, 195, 71, 181, 139, 190, 52, 197, 91, 166, 51, 1, 2, 0, 0, 0, 0, 0, 5, 32, 0,
            0, 0, 45, 2, 0, 0, 5, 0, 44, 0, 16, 0, 0, 0, 1, 0, 0, 0, 96, 115, 64, 199, 191, 32,
            208, 17, 167, 104, 0, 170, 0, 110, 5, 41, 1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 42, 2,
            0, 0, 5, 0, 44, 0, 16, 0, 0, 0, 1, 0, 0, 0, 208, 159, 17, 184, 246, 4, 98, 71, 171,
            122, 73, 134, 199, 107, 63, 154, 1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 42, 2, 0, 0, 5,
            10, 44, 0, 148, 0, 2, 0, 2, 0, 0, 0, 20, 204, 40, 72, 55, 20, 188, 69, 155, 7, 173,
            111, 1, 94, 95, 40, 1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 42, 2, 0, 0, 5, 10, 44, 0,
            148, 0, 2, 0, 2, 0, 0, 0, 156, 122, 150, 191, 230, 13, 208, 17, 162, 133, 0, 170, 0,
            48, 73, 226, 1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 42, 2, 0, 0, 5, 10, 44, 0, 148, 0, 2,
            0, 2, 0, 0, 0, 186, 122, 150, 191, 230, 13, 208, 17, 162, 133, 0, 170, 0, 48, 73, 226,
            1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 42, 2, 0, 0, 5, 0, 40, 0, 0, 1, 0, 0, 1, 0, 0, 0,
            94, 76, 199, 5, 235, 77, 180, 67, 189, 159, 134, 102, 76, 42, 127, 213, 1, 1, 0, 0, 0,
            0, 0, 5, 11, 0, 0, 0, 5, 0, 40, 0, 0, 1, 0, 0, 1, 0, 0, 0, 118, 91, 233, 137, 77, 68,
            98, 76, 153, 26, 15, 172, 190, 218, 100, 12, 1, 1, 0, 0, 0, 0, 0, 5, 9, 0, 0, 0, 5, 0,
            40, 0, 0, 1, 0, 0, 1, 0, 0, 0, 125, 220, 194, 204, 173, 166, 122, 74, 136, 70, 192, 78,
            60, 197, 53, 1, 1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0, 5, 0, 40, 0, 0, 1, 0, 0, 1, 0, 0,
            0, 156, 54, 15, 40, 199, 103, 142, 67, 174, 152, 29, 70, 243, 198, 245, 65, 1, 1, 0, 0,
            0, 0, 0, 5, 11, 0, 0, 0, 5, 0, 40, 0, 0, 1, 0, 0, 1, 0, 0, 0, 170, 246, 49, 17, 7, 156,
            209, 17, 247, 159, 0, 192, 79, 194, 220, 210, 1, 1, 0, 0, 0, 0, 0, 5, 9, 0, 0, 0, 5, 0,
            40, 0, 0, 1, 0, 0, 1, 0, 0, 0, 171, 246, 49, 17, 7, 156, 209, 17, 247, 159, 0, 192, 79,
            194, 220, 210, 1, 1, 0, 0, 0, 0, 0, 5, 9, 0, 0, 0, 5, 0, 40, 0, 0, 1, 0, 0, 1, 0, 0, 0,
            172, 246, 49, 17, 7, 156, 209, 17, 247, 159, 0, 192, 79, 194, 220, 210, 1, 1, 0, 0, 0,
            0, 0, 5, 9, 0, 0, 0, 5, 0, 40, 0, 0, 1, 0, 0, 1, 0, 0, 0, 174, 246, 49, 17, 7, 156,
            209, 17, 247, 159, 0, 192, 79, 194, 220, 210, 1, 1, 0, 0, 0, 0, 0, 5, 9, 0, 0, 0, 5, 0,
            40, 0, 16, 0, 0, 0, 1, 0, 0, 0, 208, 159, 17, 184, 246, 4, 98, 71, 171, 122, 73, 134,
            199, 107, 63, 154, 1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0, 5, 3, 40, 0, 48, 0, 0, 0, 1, 0,
            0, 0, 229, 195, 120, 63, 154, 247, 189, 70, 160, 184, 157, 24, 17, 109, 220, 121, 1, 1,
            0, 0, 0, 0, 0, 5, 10, 0, 0, 0, 5, 10, 40, 0, 48, 1, 0, 0, 1, 0, 0, 0, 222, 71, 230,
            145, 111, 217, 112, 75, 149, 87, 214, 63, 244, 243, 204, 216, 1, 1, 0, 0, 0, 0, 0, 5,
            10, 0, 0, 0, 0, 0, 36, 0, 189, 1, 14, 0, 1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 45, 65,
            88, 115, 197, 187, 192, 93, 42, 109, 38, 58, 0, 2, 0, 0, 0, 2, 36, 0, 255, 1, 15, 0, 1,
            5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 45, 65, 88, 115, 197, 187, 192, 93, 42, 109, 38, 58,
            7, 2, 0, 0, 0, 0, 24, 0, 16, 0, 2, 0, 1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 42, 2, 0, 0,
            0, 2, 24, 0, 4, 0, 0, 0, 1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 42, 2, 0, 0, 0, 2, 24, 0,
            189, 1, 15, 0, 1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0, 0, 0, 20, 0, 16, 0, 0,
            0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 20, 0, 148, 0, 2, 0, 1, 1, 0, 0, 0, 0, 0,
            5, 9, 0, 0, 0, 0, 0, 20, 0, 148, 0, 2, 0, 1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0, 0, 0,
            20, 0, 255, 1, 15, 0, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0, 1, 2, 0, 0, 0, 0, 0, 5, 32,
            0, 0, 0, 32, 2, 0, 0, 1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0,
        ];
        let (input, _) = parse_ace(&ace_bytes).unwrap();

        if input.len() > 0 {
            println!("remaining: {:?}", input);
            assert!(false, "Failed to parse ACE");
        }
    }
}
