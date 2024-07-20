use nom::{
    multi::count,
    number::complete::{le_u16, le_u8},
    sequence::tuple,
    IResult,
};
use serde::Serialize;

use super::ace::{parse_ace, ACE};

#[derive(Debug, PartialEq, Eq, Serialize, Clone)]
pub struct ACL {
    pub acl_revision: u8,
    pub sbz1: u8,
    pub acl_size: u16,
    pub ace_count: u16,
    pub sbz2: u16,
    pub aces: Vec<ACE>,
}

pub fn parse_acl(input: &[u8]) -> IResult<&[u8], ACL> {
    let (input, (acl_revision, sbz1, acl_size, ace_count, sbz2)) =
        tuple((le_u8, le_u8, le_u16, le_u16, le_u16))(input)?;

    // TODO: Handle these errors instead of panicking
    if acl_revision != 2 && acl_revision != 4 {
        panic!("ACL revision must be 2 or 4. Got: {}", acl_revision);
    }

    if sbz1 != 0 {
        panic!("sbz1 must be 0. Got: {}", sbz1);
    }

    if sbz2 != 0 {
        panic!("sbz2 must be 0. Got: {}", sbz2);
    }

    let (input, aces) = count(parse_ace, ace_count as usize)(input)?;

    Ok((
        input,
        ACL {
            acl_revision,
            sbz1,
            acl_size,
            ace_count,
            sbz2,
            aces: aces,
        },
    ))
}
