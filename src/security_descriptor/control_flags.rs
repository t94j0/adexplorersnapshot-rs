use serde::{Deserialize, Serialize};

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7d4dac05-9cef-4563-a058-f108abecce1d
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlFlag {
    SR = 0x8000, // Self Relative
    RM = 0x4000, // RM Control Valid
    PS = 0x2000, // SACL Protected
    PD = 0x1000, // DACL Protected
    SI = 0x0800, // SACL Auto-Inherited
    DI = 0x0400, // DACL Auto-Inherited
    SC = 0x0200, // SACL Computed Inheritance Required
    DC = 0x0100, // DACL Computed Inheritance Required
    SS = 0x0080, // Server Security
    DT = 0x0040, // DACL Trusted
    SD = 0x0020, // SACL Defaulted
    SP = 0x0010, // SACL Present
    DD = 0x0008, // DACL Defaulted
    DP = 0x0004, // DACL Present
    GD = 0x0002, // Group Defaulted
    OD = 0x0001, // Owner Defaulted
}

impl std::ops::BitOr for ControlFlag {
    type Output = ControlFlags;

    fn bitor(self, rhs: ControlFlag) -> Self::Output {
        ControlFlags(self as u16 | rhs as u16)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ControlFlags(pub u16);

impl ControlFlags {
    pub fn new(value: u16) -> Self {
        ControlFlags(value)
    }

    pub fn is_set(&self, flag: ControlFlag) -> bool {
        self.0 & (flag as u16) != 0
    }

    pub fn as_u16(&self) -> u16 {
        self.0
    }

    pub fn get_flags(&self) -> Vec<ControlFlag> {
        vec![
            ControlFlag::SR,
            ControlFlag::RM,
            ControlFlag::PS,
            ControlFlag::PD,
            ControlFlag::SI,
            ControlFlag::DI,
            ControlFlag::SC,
            ControlFlag::DC,
            ControlFlag::SS,
            ControlFlag::DT,
            ControlFlag::SD,
            ControlFlag::SP,
            ControlFlag::DD,
            ControlFlag::DP,
            ControlFlag::GD,
            ControlFlag::OD,
        ]
        .into_iter()
        .filter(|&flag| self.is_set(flag))
        .collect()
    }
}
