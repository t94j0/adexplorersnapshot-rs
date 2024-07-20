use nom::{
    bytes::complete::take,
    combinator::map,
    number::complete::{le_u16, le_u32},
    sequence::tuple,
    IResult,
};
use serde::Serialize;

#[derive(Debug, PartialEq, Eq, Serialize, Clone)]
pub struct GUID {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

impl GUID {
    pub fn from_bytes(input: &[u8]) -> Result<Self, nom::Err<nom::error::Error<&[u8]>>> {
        let (_, guid) = parse_guid(input)?;
        Ok(guid)
    }

    pub fn from_next_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        parse_guid(input)
    }

    pub fn to_string(&self) -> String {
        format!(
            "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            self.data1,
            self.data2,
            self.data3,
            self.data4[0],
            self.data4[1],
            self.data4[2],
            self.data4[3],
            self.data4[4],
            self.data4[5],
            self.data4[6],
            self.data4[7]
        )
    }
}

fn parse_guid(input: &[u8]) -> IResult<&[u8], GUID> {
    let (input, (data1, data2, data3, data4)) = tuple((
        le_u32,
        le_u16,
        le_u16,
        map(take(8usize), |slice: &[u8]| {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(slice);
            arr
        }),
    ))(input)?;

    Ok((
        input,
        GUID {
            data1,
            data2,
            data3,
            data4,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guid_parsing() {
        let bytes = [
            166, 109, 2, 155, 60, 13, 92, 70, 139, 238, 81, 153, 215, 22, 92, 186,
        ];
        let guid = GUID::from_bytes(&bytes).unwrap();
        assert_eq!(guid.to_string(), "9B026DA6-0D3C-465C-8BEE-5199D7165CBA");
    }

    #[test]
    fn test_from_next_bytes() {
        let bytes = [
            166, 109, 2, 155, 60, 13, 92, 70, 139, 238, 81, 153, 215, 22, 92, 186, 0xFF,
            0xFF, // Additional data
        ];
        let (remaining, guid) = GUID::from_next_bytes(&bytes).unwrap();
        assert_eq!(guid.to_string(), "9B026DA6-0D3C-465C-8BEE-5199D7165CBA");
        assert_eq!(remaining, &[0xFF, 0xFF]);
    }
}
