use core::hash::{Hash, Hasher};
use core::str::FromStr;
use nom::{
    bits::complete::take, error::Error, multi::count, number::complete::le_u32, sequence::tuple,
    IResult,
};
use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SID {
    revision: u8,
    sub_authority_count: u8,
    identifier_authority: [u8; 6],
    sub_authorities: [u32; 15], // Maximum 15 sub-authorities
}

impl SID {
    pub fn from_bytes(input: &[u8]) -> Result<Self, nom::Err<Error<&[u8]>>> {
        let (_, sid) = parse_sid(input)?;
        Ok(sid)
    }

    pub fn from_next_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        parse_sid(input)
    }

    pub fn to_string(&self) -> String {
        let auth = u64::from_be_bytes([
            0,
            0,
            self.identifier_authority[0],
            self.identifier_authority[1],
            self.identifier_authority[2],
            self.identifier_authority[3],
            self.identifier_authority[4],
            self.identifier_authority[5],
        ]);
        let sub_auths = self.sub_authorities[..self.sub_authority_count as usize]
            .iter()
            .map(|&x| x.to_string())
            .collect::<Vec<_>>()
            .join("-");
        format!("S-{}-{}-{}", self.revision, auth, sub_auths)
    }
}

fn parse_sid(input: &[u8]) -> IResult<&[u8], SID> {
    let (input, ((revision, sub_authority_count), identifier_authority)) = tuple((
        nom::bits::bits::<_, _, Error<(&[u8], usize)>, _, _>(tuple((take(8usize), take(8usize)))),
        nom::combinator::map(nom::bytes::complete::take(6usize), |slice: &[u8]| {
            let mut arr = [0u8; 6];
            arr.copy_from_slice(slice);
            arr
        }),
    ))(input)?;

    let (input, sub_authorities) = count(le_u32, sub_authority_count as usize)(input)?;

    let mut sid = SID {
        revision,
        sub_authority_count,
        identifier_authority,
        sub_authorities: [0; 15],
    };
    sid.sub_authorities[..sub_authority_count as usize].copy_from_slice(&sub_authorities);

    Ok((input, sid))
}

impl FromStr for SID {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() < 3 || parts[0] != "S" {
            return Err("Invalid SID format".to_string());
        }

        let revision = parts[1].parse::<u8>().map_err(|e| e.to_string())?;
        let auth = parts[2].parse::<u64>().map_err(|e| e.to_string())?;
        let identifier_authority = auth.to_be_bytes()[2..].try_into().unwrap();

        let sub_authorities: Vec<u32> = parts[3..]
            .iter()
            .map(|&s| s.parse::<u32>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;

        if sub_authorities.len() > 15 {
            return Err("Too many sub-authorities".to_string());
        }

        let mut sid = SID {
            revision,
            sub_authority_count: sub_authorities.len() as u8,
            identifier_authority,
            sub_authorities: [0; 15],
        };
        sid.sub_authorities[..sub_authorities.len()].copy_from_slice(&sub_authorities);

        Ok(sid)
    }
}

impl Hash for SID {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.revision.hash(state);
        self.sub_authority_count.hash(state);
        self.identifier_authority.hash(state);
        for &sub_auth in &self.sub_authorities[..self.sub_authority_count as usize] {
            sub_auth.hash(state);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    #[test]
    fn test_sid_creation_and_to_string() {
        let octet_string = vec![1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0];
        let sid = SID::from_bytes(&octet_string).unwrap();
        assert_eq!(sid.to_string(), "S-1-5-32-544");
    }

    #[test]
    fn test_sid_equality() {
        let octet_string1 = vec![
            1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 45, 65, 88, 115, 197, 187, 192, 93, 42, 109, 38,
            58, 80, 4, 0, 0,
        ];
        let octet_string2 = vec![
            1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 45, 65, 88, 115, 197, 187, 192, 93, 42, 109, 38,
            58, 80, 4, 0, 0,
        ];
        let sid1 = SID::from_bytes(&octet_string1).unwrap();
        let sid2 = SID::from_bytes(&octet_string2).unwrap();
        assert_eq!(sid1, sid2);
    }

    #[test]
    fn test_sid_hash() {
        let octet_string1 = vec![
            1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 45, 65, 88, 115, 197, 187, 192, 93, 42, 109, 38,
            58, 80, 4, 0, 0,
        ];
        let octet_string2 = vec![
            1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 45, 65, 88, 115, 197, 187, 192, 93, 42, 109, 38,
            58, 80, 4, 0, 0,
        ];
        let sid1 = SID::from_bytes(&octet_string1).unwrap();
        let sid2 = SID::from_bytes(&octet_string2).unwrap();

        let mut hasher1 = DefaultHasher::new();
        let mut hasher2 = DefaultHasher::new();
        sid1.hash(&mut hasher1);
        sid2.hash(&mut hasher2);

        assert_eq!(hasher1.finish(), hasher2.finish());
    }

    #[test]
    fn test_from_next_bytes() {
        let input = vec![
            // First SID
            1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0, // Second SID
            1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 45, 65, 88, 115, 197, 187, 192, 93, 42, 109, 38,
            58, 80, 4, 0, 0, // Additional data
            0xFF, 0xFF,
        ];

        let (remaining, sid1) = SID::from_next_bytes(&input).unwrap();
        assert_eq!(sid1.to_string(), "S-1-5-32-544");
        assert_eq!(remaining.len(), input.len() - 16);

        let (remaining, sid2) = SID::from_next_bytes(remaining).unwrap();
        assert_eq!(
            sid2.to_string(),
            "S-1-5-21-1935163693-1572912069-975596842-1104"
        );
        assert_eq!(remaining, &[0xFF, 0xFF]);
    }
}
