use crate::guid::GUID;
use crate::security_descriptor::SDDL;
use crate::sid::SID;
use byteorder::{LittleEndian, ReadBytesExt};
use chrono::{TimeZone, Utc};
use memmap2::Mmap;
use serde::Serialize;
use std::char;
use std::collections::HashMap;
use std::fs::File;
use std::io::Result;
use std::io::{Cursor, Error, ErrorKind, Read, Seek, SeekFrom};
use std::path::Path;

fn read_wstring_exact(reader: &mut impl Read, num_chars: usize) -> Result<String> {
    let mut buffer = vec![0u8; num_chars * 2];
    reader.read_exact(&mut buffer)?;

    let utf16_chars: Vec<u16> = buffer
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .take_while(|&c| c != 0)
        .collect();

    Ok(String::from_utf16_lossy(&utf16_chars))
}

fn read_next_wstring(file: &mut impl Read) -> Result<String> {
    let mut result = String::new();
    let mut word_buf = [0u8; 2];

    loop {
        file.read_exact(&mut word_buf)?;
        let word = u16::from_le_bytes(word_buf);

        if word == 0 {
            break;
        }

        if let Some(ch) = char::from_u32(word as u32) {
            result.push(ch);
        } else {
            result.push(char::REPLACEMENT_CHARACTER);
        }
    }

    Ok(result)
}

fn read_wstring<T: Read>(reader: &mut T) -> Result<String> {
    let len = reader.read_u32::<LittleEndian>()? as usize;
    let mut result = String::with_capacity(len / 2);
    let mut word_buf = [0u8; 2];

    for _ in 0..len / 2 {
        reader.read_exact(&mut word_buf)?;
        let word = u16::from_le_bytes(word_buf);

        if word == 0 {
            break;
        }

        if let Some(ch) = char::from_u32(word as u32) {
            result.push(ch);
        } else {
            result.push(char::REPLACEMENT_CHARACTER);
        }
    }

    Ok(result)
}

fn read_guid<T: Read>(reader: &mut T) -> Result<GUID> {
    let mut buffer = [0u8; 16];
    reader.read_exact(&mut buffer)?;
    GUID::from_bytes(&buffer).map_err(|e| {
        Error::new(
            ErrorKind::InvalidData,
            format!("Failed to parse GUID: {:?}", e),
        )
    })
}

#[derive(Debug, Serialize)]
pub struct Header {
    pub win_ad_sig: String,
    pub marker: i32,
    pub filetime: u64,
    pub optional_description: String,
    pub server: String,
    pub num_objects: u32,
    pub num_attributes: u32,
    pub fileoffset_low: u32,
    pub fileoffset_high: u32,
    pub fileoffset_end: u32,
    pub unk0x43a: i32,
}

impl Header {
    fn parse(reader: &mut impl Read) -> Result<Self> {
        let mut win_ad_sig = [0u8; 10];
        reader.read_exact(&mut win_ad_sig)?;

        Ok(Header {
            win_ad_sig: String::from_utf8_lossy(&win_ad_sig).to_string(),
            marker: reader.read_i32::<LittleEndian>()?,
            filetime: reader.read_u64::<LittleEndian>()?,
            optional_description: read_wstring_exact(reader, 260)?,
            server: read_wstring_exact(reader, 260)?,
            num_objects: reader.read_u32::<LittleEndian>()?,
            num_attributes: reader.read_u32::<LittleEndian>()?,
            fileoffset_low: reader.read_u32::<LittleEndian>()?,
            fileoffset_high: reader.read_u32::<LittleEndian>()?,
            fileoffset_end: reader.read_u32::<LittleEndian>()?,
            unk0x43a: reader.read_i32::<LittleEndian>()?,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct Property {
    pub prop_name: String,
    pub unk1: i32,
    pub ads_type: u32,
    pub dn: String,
    pub schema_id_guid: GUID,
    pub attribute_security_guid: GUID,
}

impl Property {
    pub fn parse<T: Read + Seek>(reader: &mut T) -> Result<Self> {
        let prop_name = read_wstring(reader)?;
        let unk1 = reader.read_i32::<LittleEndian>()?;
        let ads_type = reader.read_u32::<LittleEndian>()?;
        let dn = read_wstring(reader)?;
        let schema_id_guid = read_guid(reader)?;
        let attribute_security_guid = read_guid(reader)?;

        // Skip the blob (4 bytes)
        reader.seek(SeekFrom::Current(4))?;

        Ok(Property {
            prop_name,
            unk1,
            ads_type,
            dn,
            schema_id_guid,
            attribute_security_guid,
        })
    }
}

#[derive(Debug, Serialize)]
struct MappingEntry {
    attr_index: u32,
    attr_offset: i32,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub enum ObjectType {
    Computer,
    User,
    UserDisabled,
    Group,
    Domain,
    OU,
    Container,
    GPO,
    Unknown,
}

#[derive(Debug, Serialize)]
pub struct Object {
    pub obj_size: u32,
    pub table_size: u32,
    mapping_table: Vec<MappingEntry>,
    pub attributes: HashMap<String, Attribute>,
}

impl Object {
    fn parse(reader: &mut (impl Read + Seek), properties: &[Property]) -> Result<Self> {
        let start_pos = reader.stream_position()?;
        let obj_size = reader.read_u32::<LittleEndian>()?;
        let table_size = reader.read_u32::<LittleEndian>()?;

        let mapping_table = (0..table_size)
            .map(|_| {
                Ok(MappingEntry {
                    attr_index: reader.read_u32::<LittleEndian>()?,
                    attr_offset: reader.read_i32::<LittleEndian>()?,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let attributes = mapping_table
            .iter()
            .filter_map(|entry| {
                let property = properties.get(entry.attr_index as usize)?;
                let attr_pos = if entry.attr_offset >= 0 {
                    start_pos + entry.attr_offset as u64
                } else {
                    start_pos.checked_sub(entry.attr_offset.unsigned_abs() as u64)?
                };

                let current_pos = reader.stream_position().ok()?;
                reader.seek(SeekFrom::Start(attr_pos)).ok()?;
                let attribute = Attribute::parse(reader, property.ads_type).ok()?;
                reader.seek(SeekFrom::Start(current_pos)).ok()?;

                Some((property.prop_name.clone(), attribute))
            })
            .collect();

        reader.seek(SeekFrom::Start(start_pos + obj_size as u64))?;

        Ok(Object {
            obj_size,
            table_size,
            mapping_table,
            attributes,
        })
    }

    pub fn get_attribute_names(&self) -> Vec<String> {
        self.attributes.keys().cloned().collect()
    }

    pub fn get(&self, attr_name: &str) -> Option<&Vec<AttributeValue>> {
        self.attributes.get(attr_name).map(|attr| &attr.values)
    }

    pub fn get_first(&self, attr_name: &str) -> Option<&AttributeValue> {
        self.get(attr_name).and_then(|values| values.first())
    }

    pub fn get_attribute_classes(&self) -> Option<Vec<String>> {
        let values = self.get("objectClass")?;
        Some(
            values
                .iter()
                .filter_map(|v| AttributeValue::as_string(v).cloned())
                .collect(),
        )
    }

    pub fn has_attribute_class(&self, class: &str) -> bool {
        self.get_attribute_classes()
            .map(|classes| classes.iter().any(|c| c == class))
            .unwrap_or(false)
    }

    pub fn get_object_identifier(&self) -> Option<String> {
        match self.get_type() {
            ObjectType::Computer | ObjectType::User | ObjectType::Group => self
                .get_first("objectSid")
                .and_then(AttributeValue::as_sid)
                .map(|sid| sid.to_string()),
            ObjectType::OU | ObjectType::Container | ObjectType::GPO => self
                .get_first("objectGUID")
                .and_then(AttributeValue::as_guid)
                .map(|guid| guid.to_string()),
            _ => None,
        }
    }

    pub fn get_type(&self) -> ObjectType {
        // For some reason, some GPOs have gPCFileSysPath attribute but not in the objectClass of groupPolicyContainer
        if self.get_first("gPCFileSysPath").is_some() {
            return ObjectType::GPO;
        }

        if self.has_attribute_class("user") {
            if let Some(uac) = self
                .get_first("userAccountControl")
                .and_then(AttributeValue::as_integer)
            {
                return if uac & 0x00000002 != 0 {
                    ObjectType::UserDisabled
                } else {
                    ObjectType::User
                };
            }
        }

        if let Some(classes) = self.get_attribute_classes() {
            for class in classes.iter() {
                match class.as_str() {
                    "computer" => return ObjectType::Computer,
                    "user" => {
                        if let Some(uac) = self
                            .get_first("userAccountControl")
                            .and_then(AttributeValue::as_integer)
                        {
                            return if uac & 0x00000002 != 0 {
                                ObjectType::UserDisabled
                            } else {
                                ObjectType::User
                            };
                        }
                    }
                    "group" => return ObjectType::Group,
                    "domain" => return ObjectType::Domain,
                    "organizationalUnit" => return ObjectType::OU,
                    "container" => return ObjectType::Container,
                    "groupPolicyContainer" => return ObjectType::GPO,
                    _ => continue,
                }
            }
        }
        ObjectType::Unknown
    }
}

#[derive(Debug, Serialize)]
pub struct Attribute {
    pub num_values: u32,
    pub values: Vec<AttributeValue>,
}

impl Attribute {
    fn parse<T: Read + Seek>(reader: &mut T, ads_type: u32) -> Result<Self> {
        let attribute_start = reader.stream_position()?;
        let num_values = reader.read_u32::<LittleEndian>()?;

        let values = match ads_type {
            1 | 2 | 3 | 4 | 5 | 12 => {
                Self::parse_string_values(reader, num_values, attribute_start)?
            }
            8 => Self::parse_octet_string_values(reader, num_values)?,
            6 => {
                if num_values != 1 {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "Boolean attribute should have only one value",
                    ));
                }
                vec![AttributeValue::Boolean(
                    reader.read_u32::<LittleEndian>()? != 0,
                )]
            }
            7 => (0..num_values)
                .map(|_| Ok(AttributeValue::Integer(reader.read_u32::<LittleEndian>()?)))
                .collect::<Result<Vec<_>>>()?,
            10 => (0..num_values)
                .map(|_| {
                    Ok(AttributeValue::LargeInteger(
                        reader.read_i64::<LittleEndian>()?,
                    ))
                })
                .collect::<Result<Vec<_>>>()?,
            9 => Self::parse_utc_time_values(reader, num_values)?,
            25 => Self::parse_nt_security_descriptor(reader)?,
            _ => {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("Unhandled ADSTYPE: {}", ads_type),
                ))
            }
        };

        Ok(Attribute { num_values, values })
    }

    fn parse_string_values<T: Read + Seek>(
        reader: &mut T,
        num_values: u32,
        attribute_start: u64,
    ) -> Result<Vec<AttributeValue>> {
        let mut result = Vec::with_capacity(num_values as usize);
        let mut offset_buf = vec![0u32; num_values as usize];
        reader.read_u32_into::<LittleEndian>(&mut offset_buf)?;

        for &offset in &offset_buf {
            let current_pos = reader.stream_position()?;
            reader.seek(SeekFrom::Start(attribute_start + offset as u64))?;
            let value = AttributeValue::String(read_next_wstring(reader)?);
            reader.seek(SeekFrom::Start(current_pos))?;
            result.push(value);
        }

        Ok(result)
    }

    fn parse_octet_string_values<T: Read>(
        reader: &mut T,
        num_values: u32,
    ) -> Result<Vec<AttributeValue>> {
        let mut lengths = vec![0u32; num_values as usize];
        reader.read_u32_into::<LittleEndian>(&mut lengths)?;

        let mut result = Vec::with_capacity(num_values as usize);

        for &length in &lengths {
            let mut buffer = vec![0u8; length as usize];
            reader.read_exact(&mut buffer)?;
            result.push(AttributeValue::OctetString(buffer));
        }

        Ok(result)
    }

    fn parse_utc_time_values<T: Read>(
        reader: &mut T,
        num_values: u32,
    ) -> Result<Vec<AttributeValue>> {
        let mut time_values = Vec::with_capacity(num_values as usize);

        for _ in 0..num_values {
            let time = SystemTime {
                year: reader.read_u16::<LittleEndian>()?,
                month: reader.read_u16::<LittleEndian>()?,
                day_of_week: reader.read_u16::<LittleEndian>()?,
                day: reader.read_u16::<LittleEndian>()?,
                hour: reader.read_u16::<LittleEndian>()?,
                minute: reader.read_u16::<LittleEndian>()?,
                second: reader.read_u16::<LittleEndian>()?,
                milliseconds: reader.read_u16::<LittleEndian>()?,
            };

            time_values.push(AttributeValue::UTCTime(
                time.to_unix_timestamp()
                    .ok_or_else(|| Error::new(ErrorKind::InvalidData, "Invalid UTC time"))?,
            ))
        }

        Ok(time_values)
    }

    fn parse_nt_security_descriptor<T: Read>(reader: &mut T) -> Result<Vec<AttributeValue>> {
        let len_descriptor_bytes = reader.read_u32::<LittleEndian>()?;
        let mut buffer = vec![0u8; len_descriptor_bytes as usize];
        reader.read_exact(&mut buffer)?;
        Ok(vec![AttributeValue::NTSecurityDescriptor(buffer)])
    }
}

#[derive(Debug, Serialize, Clone)]
pub enum AttributeValue {
    String(String),
    OctetString(Vec<u8>),
    Boolean(bool),
    Integer(u32),
    LargeInteger(i64),
    UTCTime(i64),
    NTSecurityDescriptor(Vec<u8>),
}

impl AttributeValue {
    pub fn as_string(&self) -> Option<&String> {
        if let AttributeValue::String(s) = self {
            Some(s)
        } else {
            None
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        if let AttributeValue::String(s) = self {
            Some(s)
        } else {
            None
        }
    }

    pub fn as_integer(&self) -> Option<u32> {
        if let AttributeValue::Integer(i) = self {
            Some(*i)
        } else {
            None
        }
    }

    pub fn as_large_integer(&self) -> Option<i64> {
        if let AttributeValue::LargeInteger(i) = self {
            Some(*i)
        } else {
            None
        }
    }

    pub fn as_boolean(&self) -> Option<bool> {
        if let AttributeValue::Boolean(b) = self {
            Some(*b)
        } else {
            None
        }
    }

    pub fn as_octet_string(&self) -> Option<&Vec<u8>> {
        if let AttributeValue::OctetString(o) = self {
            Some(o)
        } else {
            None
        }
    }

    pub fn as_nt_security_descriptor(&self) -> Option<SDDL> {
        if let AttributeValue::NTSecurityDescriptor(o) = self {
            SDDL::from_bytes(&o).ok()
        } else {
            None
        }
    }

    pub fn as_sid(&self) -> Option<SID> {
        if let AttributeValue::OctetString(o) = self {
            SID::from_bytes(&o).ok()
        } else {
            None
        }
    }

    pub fn as_guid(&self) -> Option<GUID> {
        if let AttributeValue::OctetString(o) = self {
            GUID::from_bytes(&o).ok()
        } else {
            None
        }
    }

    pub fn as_unix_timestamp(&self) -> Option<i64> {
        match self {
            AttributeValue::LargeInteger(t) => {
                if *t == 0 {
                    return Some(0);
                }

                Some((*t - 116444736000000000) / 10000000)
            }
            AttributeValue::UTCTime(t) => Some(*t),
            _ => None,
        }
    }
}

#[derive(Debug, Serialize, Clone)]
pub struct SystemTime {
    year: u16,
    month: u16,
    day_of_week: u16,
    day: u16,
    hour: u16,
    minute: u16,
    second: u16,
    milliseconds: u16,
}

impl SystemTime {
    pub fn to_unix_timestamp(&self) -> Option<i64> {
        let datetime = Utc.with_ymd_and_hms(
            self.year as i32,
            self.month as u32,
            self.day as u32,
            self.hour as u32,
            self.minute as u32,
            self.second as u32,
        );

        datetime.single().map(|dt| dt.timestamp())
    }
}

#[derive(Debug, Serialize)]
struct SystemPossSuperior {
    system_poss_superior: String,
}

#[derive(Debug, Serialize)]
struct AuxiliaryClasses {
    auxiliary_class: String,
}

#[derive(Debug, Serialize)]
struct Block {
    unk1: u32,
    unk2: u32,
    unk3: Vec<u8>,
}

impl Block {
    pub fn parse<T: Read + Seek>(reader: &mut T) -> Result<Self> {
        let unk1 = reader.read_u32::<LittleEndian>()?;
        let unk2 = reader.read_u32::<LittleEndian>()?;
        let mut unk3 = vec![0u8; unk2 as usize];
        reader.read_exact(&mut unk3)?;
        Ok(Block { unk1, unk2, unk3 })
    }
}

#[derive(Debug, Serialize)]
pub struct Class {
    pub class_name: String,
    pub dn: String,
    pub common_class_name: String,
    pub sub_class_of: String,
    pub schema_id_guid: GUID,
    pub unk2: Vec<u8>,
    blocks: Vec<Block>,
    pub unknown: Vec<u8>,
    system_poss_superiors: Vec<SystemPossSuperior>,
    auxiliary_classes: Vec<AuxiliaryClasses>,
}

impl Class {
    pub fn parse<T: Read + Seek>(reader: &mut T) -> Result<Self> {
        Ok(Class {
            class_name: read_wstring(reader)?,
            dn: read_wstring(reader)?,
            common_class_name: read_wstring(reader)?,
            sub_class_of: read_wstring(reader)?,
            schema_id_guid: read_guid(reader)?,
            unk2: Self::parse_unk2(reader)?,
            blocks: Self::parse_blocks(reader)?,
            unknown: Self::parse_unknown(reader)?,
            system_poss_superiors: Self::parse_system_poss_superiors(reader)?,
            auxiliary_classes: Self::parse_auxiliary_classes(reader)?,
        })
    }

    fn parse_unk2<T: Read + Seek>(reader: &mut T) -> Result<Vec<u8>> {
        let offset_to_num_blocks = reader.read_u32::<LittleEndian>()?;
        let mut unk2 = vec![0u8; offset_to_num_blocks as usize];
        reader.read_exact(&mut unk2)?;
        Ok(unk2)
    }

    fn parse_blocks<T: Read + Seek>(reader: &mut T) -> Result<Vec<Block>> {
        let num_blocks = reader.read_u32::<LittleEndian>()?;
        (0..num_blocks).map(|_| Block::parse(reader)).collect()
    }

    fn parse_unknown<T: Read + Seek>(reader: &mut T) -> Result<Vec<u8>> {
        let num_unknown = reader.read_u32::<LittleEndian>()?;
        let mut unknown = vec![0u8; (num_unknown * 0x10) as usize];
        reader.read_exact(&mut unknown)?;
        Ok(unknown)
    }

    fn parse_system_poss_superiors<T: Read + Seek>(
        reader: &mut T,
    ) -> Result<Vec<SystemPossSuperior>> {
        let num_items = reader.read_u32::<LittleEndian>()?;
        (0..num_items)
            .map(|_| {
                Ok(SystemPossSuperior {
                    system_poss_superior: read_wstring(reader)?,
                })
            })
            .collect()
    }

    fn parse_auxiliary_classes<T: Read + Seek>(reader: &mut T) -> Result<Vec<AuxiliaryClasses>> {
        let num_items = reader.read_u32::<LittleEndian>()?;
        (0..num_items)
            .map(|_| {
                Ok(AuxiliaryClasses {
                    auxiliary_class: read_wstring(reader)?,
                })
            })
            .collect()
    }
}

pub fn parse_classes<T: Read + Seek>(reader: &mut T) -> Result<Vec<Class>> {
    let num_classes = reader.read_u32::<LittleEndian>()?;
    (0..num_classes).map(|_| Class::parse(reader)).collect()
}

#[derive(Debug, Serialize)]
struct Right {
    name: String,
    desc: String,
    blob: [u8; 20],
}

impl Right {
    pub fn parse<T: Read + Seek>(reader: &mut T) -> Result<Self> {
        Ok(Right {
            name: read_wstring(reader)?,
            desc: read_wstring(reader)?,
            blob: Self::read_blob(reader)?,
        })
    }

    fn read_blob<T: Read>(reader: &mut T) -> Result<[u8; 20]> {
        let mut blob = [0u8; 20];
        reader.read_exact(&mut blob)?;
        Ok(blob)
    }
}

fn parse_rights<T: Read + Seek>(reader: &mut T) -> Result<Vec<Right>> {
    let num_rights = reader.read_u32::<LittleEndian>()?;
    (0..num_rights).map(|_| Right::parse(reader)).collect()
}

#[derive(Debug, Serialize)]
pub struct Snapshot {
    pub header: Header,
    pub properties: Vec<Property>,
    pub objects: Vec<Object>,
    pub classes: Vec<Class>,
    rights: Vec<Right>,
}

impl Snapshot {
    pub fn snapshot_from_file<P: AsRef<Path>>(path: P) -> Result<Snapshot> {
        let file = File::open(path)?;
        let mmap = unsafe { Mmap::map(&file)? };
        Self::snapshot_from_memory(&mmap[..])
    }

    pub fn snapshot_from_memory(snapshot: impl AsRef<[u8]>) -> Result<Snapshot> {
        let mut cursor = Cursor::new(snapshot.as_ref());

        let header = Header::parse(&mut cursor)?;

        cursor.seek(SeekFrom::Start(
            (header.fileoffset_high as u64) << 32 | header.fileoffset_low as u64,
        ))?;

        let num_properties = cursor.read_u32::<LittleEndian>()?;

        let mut properties = Vec::new();
        for _ in 0..num_properties {
            properties.push(Property::parse(&mut cursor)?);
        }

        let offset_properties = cursor.position();

        cursor.seek(SeekFrom::Start(0x43e))?;

        let mut objects = Vec::new();
        for _ in 0..header.num_objects {
            objects.push(Object::parse(&mut cursor, &properties)?);
        }

        cursor.seek(SeekFrom::Start(offset_properties))?;

        let classes = parse_classes(&mut cursor)?;
        let rights = parse_rights(&mut cursor)?;

        let result = Snapshot {
            header,
            properties,
            objects,
            classes,
            rights,
        };

        Ok(result)
    }
}
