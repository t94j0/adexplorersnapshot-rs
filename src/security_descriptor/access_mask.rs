use nom::{number::complete::le_u32, IResult};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct AccessMask(u32);

impl AccessMask {
    // Generic rights
    pub const GENERIC_READ: u32 = 0x80000000;
    pub const GENERIC_WRITE: u32 = 0x40000000;
    pub const GENERIC_EXECUTE: u32 = 0x20000000;
    pub const GENERIC_ALL: u32 = 0x10000000;

    // Standard rights
    pub const MAXIMUM_ALLOWED: u32 = 0x02000000;
    pub const ACCESS_SYSTEM_SECURITY: u32 = 0x01000000;
    pub const SYNCHRONIZE: u32 = 0x00100000;
    pub const WRITE_OWNER: u32 = 0x00080000;
    pub const WRITE_DACL: u32 = 0x00040000;
    pub const READ_CONTROL: u32 = 0x00020000;
    pub const DELETE: u32 = 0x00010000;

    // AD rights
    pub const ADS_RIGHT_DS_CONTROL_ACCESS: u32 = 0x00000100;
    pub const ADS_RIGHT_DS_CREATE_CHILD: u32 = 0x00000001;
    pub const ADS_RIGHT_DS_DELETE_CHILD: u32 = 0x00000002;
    pub const ADS_RIGHT_DS_READ_PROP: u32 = 0x00000010;
    pub const ADS_RIGHT_DS_WRITE_PROP: u32 = 0x00000020;
    pub const ADS_RIGHT_DS_SELF: u32 = 0x00000008;

    // Object-specific rights are represented by the lower 16 bits (0-15)
    pub const OBJECT_SPECIFIC_RIGHTS_MASK: u32 = 0x0000FFFF;

    pub fn new(mask: u32) -> Self {
        AccessMask(mask)
    }

    pub fn as_u32(&self) -> u32 {
        self.0
    }

    pub fn has_flag(&self, flag: u32) -> bool {
        self.0 & flag == flag
    }

    pub fn set_flag(&mut self, flag: u32) {
        self.0 |= flag;
    }

    pub fn clear_flag(&mut self, flag: u32) {
        self.0 &= !flag;
    }

    pub fn get_rights_generic(&self) -> Vec<u32> {
        vec![
            AccessMask::GENERIC_READ,
            AccessMask::GENERIC_WRITE,
            AccessMask::GENERIC_EXECUTE,
            AccessMask::GENERIC_ALL,
            AccessMask::MAXIMUM_ALLOWED,
            AccessMask::ACCESS_SYSTEM_SECURITY,
            AccessMask::SYNCHRONIZE,
            AccessMask::WRITE_OWNER,
            AccessMask::WRITE_DACL,
            AccessMask::READ_CONTROL,
            AccessMask::DELETE,
        ]
        .into_iter()
        .filter(|&flag| self.has_flag(flag))
        .collect()
    }

    pub fn get_rights_ad(&self) -> Vec<u32> {
        vec![
            AccessMask::ADS_RIGHT_DS_CONTROL_ACCESS,
            AccessMask::ADS_RIGHT_DS_CREATE_CHILD,
            AccessMask::ADS_RIGHT_DS_DELETE_CHILD,
            AccessMask::ADS_RIGHT_DS_READ_PROP,
            AccessMask::ADS_RIGHT_DS_WRITE_PROP,
            AccessMask::ADS_RIGHT_DS_SELF,
            AccessMask::GENERIC_READ,
            AccessMask::GENERIC_WRITE,
            AccessMask::GENERIC_EXECUTE,
            AccessMask::GENERIC_ALL,
            AccessMask::MAXIMUM_ALLOWED,
            AccessMask::ACCESS_SYSTEM_SECURITY,
            AccessMask::SYNCHRONIZE,
            AccessMask::WRITE_OWNER,
            AccessMask::WRITE_DACL,
            AccessMask::READ_CONTROL,
            AccessMask::DELETE,
        ]
        .into_iter()
        .filter(|&flag| self.has_flag(flag))
        .collect()
    }
}

impl From<u32> for AccessMask {
    fn from(mask: u32) -> Self {
        AccessMask(mask)
    }
}

impl Into<u32> for AccessMask {
    fn into(self) -> u32 {
        self.0
    }
}

impl IntoIterator for AccessMask {
    type Item = u32;
    type IntoIter = AccessMaskIter;

    fn into_iter(self) -> Self::IntoIter {
        AccessMaskIter {
            mask: self.0,
            index: 0,
        }
    }
}

pub fn parse_access_mask(input: &[u8]) -> IResult<&[u8], AccessMask> {
    let (input, mask) = le_u32(input)?;
    Ok((input, AccessMask::new(mask)))
}

pub struct AccessMaskIter {
    mask: u32,
    index: usize,
}

impl Iterator for AccessMaskIter {
    type Item = u32;

    fn next(&mut self) -> Option<Self::Item> {
        const RIGHTS: [u32; 11] = [
            AccessMask::GENERIC_READ,
            AccessMask::GENERIC_WRITE,
            AccessMask::GENERIC_EXECUTE,
            AccessMask::GENERIC_ALL,
            AccessMask::MAXIMUM_ALLOWED,
            AccessMask::ACCESS_SYSTEM_SECURITY,
            AccessMask::SYNCHRONIZE,
            AccessMask::WRITE_OWNER,
            AccessMask::WRITE_DACL,
            AccessMask::READ_CONTROL,
            AccessMask::DELETE,
        ];

        while self.index < RIGHTS.len() {
            let right = RIGHTS[self.index];
            self.index += 1;
            if self.mask & right == right {
                return Some(right);
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_access_mask() {
        let mut mask = AccessMask::new(0);

        // Test setting and checking generic rights
        mask.set_flag(AccessMask::GENERIC_READ);
        assert!(mask.has_flag(AccessMask::GENERIC_READ));
        assert!(!mask.has_flag(AccessMask::GENERIC_WRITE));

        // Test setting and checking standard rights
        mask.set_flag(AccessMask::WRITE_DACL);
        assert!(mask.has_flag(AccessMask::WRITE_DACL));
        assert!(!mask.has_flag(AccessMask::WRITE_OWNER));

        // Test clearing flags
        mask.clear_flag(AccessMask::GENERIC_READ);
        assert!(!mask.has_flag(AccessMask::GENERIC_READ));

        // Test object-specific rights
        let object_rights = 0x1234;
        mask = AccessMask::new(object_rights);

        // Test conversion
        let mask_u32: u32 = mask.into();
        assert_eq!(mask_u32, object_rights);
    }
}
