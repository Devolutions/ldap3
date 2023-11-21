use ldap3_proto::LdapPartialAttribute;
use serde::{de::Visitor, ser::SerializeStruct, Deserialize, Serialize};
use wasm_bindgen::{prelude::wasm_bindgen};

// ================================================================================================= Attribute Values
#[derive(Debug, Clone, PartialEq)]
pub enum DisplayableAttributesValues {
    String(Vec<String>),
    Integer(Vec<i32>),
    Boolean(Vec<bool>),
    Date(Vec<String>),
    Bytes(Vec<Vec<u8>>),
    Enum(Vec<u8>),
}

impl DisplayableAttributesValues {
    pub fn get_type(&self) -> DisplayableAttributesValueType {
        match self {
            DisplayableAttributesValues::String(_) => DisplayableAttributesValueType::String,
            DisplayableAttributesValues::Integer(_) => DisplayableAttributesValueType::Integer,
            DisplayableAttributesValues::Boolean(_) => DisplayableAttributesValueType::Boolean,
            DisplayableAttributesValues::Date(_) => DisplayableAttributesValueType::Date,
            DisplayableAttributesValues::Bytes(_) => DisplayableAttributesValueType::Bytes,
            DisplayableAttributesValues::Enum(_) => DisplayableAttributesValueType::Enum,
        }
    }
}
impl Serialize for DisplayableAttributesValues {
    fn serialize<S>(&self, serializer: S) -> std::prelude::v1::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut sv = serializer.serialize_struct("DisplayableAttributesValues", 2)?;
        sv.serialize_field("type", &self.get_type().into_i32())?;

        match self {
            DisplayableAttributesValues::String(value) => {
                sv.serialize_field("value", value)?;
            }
            DisplayableAttributesValues::Integer(value) => {
                sv.serialize_field("value", value)?;
            }
            DisplayableAttributesValues::Boolean(value) => {
                sv.serialize_field("value", value)?;
            }
            DisplayableAttributesValues::Date(value) => {
                sv.serialize_field("value", value)?;
            }
            DisplayableAttributesValues::Bytes(value) => {
                sv.serialize_field("value", value)?;
            }
            DisplayableAttributesValues::Enum(value) => {
                sv.serialize_field("value", value)?;
            }
        };

        sv.end()
    }
}

impl<'de> Deserialize<'de> for DisplayableAttributesValues {
    fn deserialize<D>(deserializer: D) -> std::prelude::v1::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(DisplayableAttributesValuesVisitor)
    }
}
struct DisplayableAttributesValuesVisitor;
impl<'de> Visitor<'de> for DisplayableAttributesValuesVisitor {
    type Value = DisplayableAttributesValues;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("DisplayableAttributesValues failed to deserialize")
    }

    fn visit_map<A>(self, mut map: A) -> std::prelude::v1::Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        let key: String = map.next_key()?.ok_or_else(|| {
            serde::de::Error::custom(
                "DisplayableAttributesValues failed to deserialize, the first key is missing",
            )
        })?;

        if key != "type" {
            return Err(serde::de::Error::custom(
                "DisplayableAttributesValues failed to deserialize, the first key is not type",
            ));
        }

        let value: i32 = map.next_value()?;

        let value_type = DisplayableAttributesValueType::try_from(value).map_err(|e| {
            serde::de::Error::custom(format!(
                "DisplayableAttributesValues failed to deserialize, the first key is not type {:?}",
                e
            ))
        })?;

        let key: String = map.next_key()?.ok_or_else(|| {
            serde::de::Error::custom(
                "DisplayableAttributesValues failed to deserialize, the second key is missing",
            )
        })?;

        if key != "value" {
            return Err(serde::de::Error::custom(
                "DisplayableAttributesValues failed to deserialize, the second key is not value",
            ));
        }
        match value_type {
            DisplayableAttributesValueType::String => {
                let value: Vec<String> = map.next_value()?;
                Ok(DisplayableAttributesValues::String(value))
            }
            DisplayableAttributesValueType::Integer => {
                let value: Vec<i32> = map.next_value()?;
                Ok(DisplayableAttributesValues::Integer(value))
            }
            DisplayableAttributesValueType::Boolean => {
                let value: Vec<bool> = map.next_value()?;
                Ok(DisplayableAttributesValues::Boolean(value))
            }
            DisplayableAttributesValueType::Date => {
                let value: Vec<String> = map.next_value()?;
                Ok(DisplayableAttributesValues::Date(value))
            }
            DisplayableAttributesValueType::Bytes => {
                let value: Vec<Vec<u8>> = map.next_value()?;
                Ok(DisplayableAttributesValues::Bytes(value))
            }
            DisplayableAttributesValueType::Enum => {
                let value: Vec<u8> = map.next_value()?;
                Ok(DisplayableAttributesValues::Enum(value))
            }
        }
    }
}

impl From<DisplayableAttributesValues> for Vec<Vec<u8>> {
    fn from(val: DisplayableAttributesValues) -> Self {
        match val {
            DisplayableAttributesValues::String(value) => {
                value.into_iter().map(|v| v.into_bytes()).collect()
            }
            DisplayableAttributesValues::Integer(ints) => {
                ints.into_iter().map(|v| v.to_be_bytes().to_vec()).collect()
            }
            DisplayableAttributesValues::Boolean(bools) => bools
                .into_iter()
                .map(|v| {
                    if v {
                        b"TRUE".to_vec()
                    } else {
                        b"FALSE".to_vec()
                    }
                })
                .collect(),
            DisplayableAttributesValues::Date(date) => {
                date.into_iter().map(|v| v.into_bytes()).collect()
            }
            DisplayableAttributesValues::Bytes(bytes) => bytes,
            DisplayableAttributesValues::Enum(enums) => {
                enums.into_iter().map(|v| vec![v]).collect()
            }
        }
    }
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[wasm_bindgen]
#[repr(u8)]
pub enum DisplayableAttributesValueType {
    String = 0,
    Integer = 1,
    Boolean = 2,
    Date = 3,
    Bytes = 4,
    Enum = 5,
}

impl std::fmt::Debug for DisplayableAttributesValueType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::String => write!(f, "String"),
            Self::Integer => write!(f, "Integer"),
            Self::Boolean => write!(f, "Boolean"),
            Self::Date => write!(f, "Date"),
            Self::Bytes => write!(f, "Bytes"),
            Self::Enum => write!(f, "Enum"),
        }
    }
}

impl TryFrom<i32> for DisplayableAttributesValueType {
    type Error = anyhow::Error;
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(DisplayableAttributesValueType::String),
            1 => Ok(DisplayableAttributesValueType::Integer),
            2 => Ok(DisplayableAttributesValueType::Boolean),
            3 => Ok(DisplayableAttributesValueType::Date),
            4 => Ok(DisplayableAttributesValueType::Bytes),
            5 => Ok(DisplayableAttributesValueType::Enum),
            _ => Err(anyhow::anyhow!("Invalid value")),
        }
    }
}

impl DisplayableAttributesValueType {
    pub fn into_i32(self) -> i32 {
        match self {
            // match to it's number
            DisplayableAttributesValueType::String => 0,
            DisplayableAttributesValueType::Integer => 1,
            DisplayableAttributesValueType::Boolean => 2,
            DisplayableAttributesValueType::Date => 3,
            DisplayableAttributesValueType::Bytes => 4,
            DisplayableAttributesValueType::Enum => 5,
        }
    }
}

// ================================================================================================= Attirbutes
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[wasm_bindgen]
pub struct DisplayableAttribute {
    pub(crate) attribute_name: String,
    pub(crate) attribute_value: DisplayableAttributesValues,
}

impl DisplayableAttribute {
    pub fn new(a_name: String, val: DisplayableAttributesValues) -> Self {
        Self {
            attribute_name: a_name,
            attribute_value: val,
        }
    }
}

impl From<DisplayableAttribute> for LdapPartialAttribute {
    fn from(val: DisplayableAttribute) -> Self {
        let DisplayableAttribute {
            attribute_name,
            attribute_value,
        } = val;

        LdapPartialAttribute {
            atype: attribute_name,
            vals: attribute_value.into(),
        }
    }
}

// ================================================================================================= Entries
#[derive(Debug, Clone, Serialize)]
pub struct DisplayableEntry {
    pub(crate) dn: String,
    pub(crate) attributes: Vec<DisplayableAttribute>,
}
