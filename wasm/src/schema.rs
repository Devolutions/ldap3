use std::collections::HashMap;

use ldap3_proto::proto::LdapAttribute;
use serde::{Deserialize, Serialize};
use tracing::instrument;
use wasm_bindgen::prelude::wasm_bindgen;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum ADAttributeSyntax {
    Boolean,
    Enumeration,
    EnumerationDeliveryMechanism,
    EnumerationExportInformationLevel,
    EnumerationPreferredDeliveryMethod,
    Integer,
    Interval,
    LargeInteger,
    ObjectAccessPoint,
    ObjectDNBinary,
    ObjectDNString,
    ObjectDSDN,
    ObjectORName,
    ObjectPresentationAddress,
    ObjectReplicaLink,
    StringCaseSensitive,
    StringGeneralizedTime,
    StringIA5,
    StringNTSecDesc,
    StringNumeric,
    StringObjectIdentifier,
    StringOctet,
    StringPrintable,
    StringSid,
    StringTeletex,
    StringUnicode,
    StringUTCTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum DisplayableAttributesValue {
    String(String),
    Integer(i32),
    Boolean(bool),
    Date(String),
    Bytes(Vec<u8>),
    Enum(u8),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen]
pub enum DisplayableAttributesValueTypes {
    String = 0,
    Integer = 1,
    Boolean = 2,
    Date = 3,
    Bytes = 4,
    Enum = 5,
}

impl TryFrom<i32> for DisplayableAttributesValueTypes {
    type Error = anyhow::Error;
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(DisplayableAttributesValueTypes::String),
            1 => Ok(DisplayableAttributesValueTypes::Integer),
            2 => Ok(DisplayableAttributesValueTypes::Boolean),
            3 => Ok(DisplayableAttributesValueTypes::Date),
            4 => Ok(DisplayableAttributesValueTypes::Bytes),
            5 => Ok(DisplayableAttributesValueTypes::Enum),
            _ => Err(anyhow::anyhow!("Invalid value")),
        }
    }
}

pub trait AttributeSyntaxSchema {
    type Error;
    fn to_displayable_attribute(
        &self,
        attribute: &LdapAttribute,
    ) -> Result<DisplayableAttribute, Self::Error>;
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DefaultAttributeSyntaxSchema {
    hash_map: HashMap<String, DisplayableAttributesValueTypes>,
}

impl DefaultAttributeSyntaxSchema {
    pub fn new() -> Self {
        Self {
            hash_map: HashMap::new(),
        }
    }

    pub fn add_attribute_display_type(
        &mut self,
        new_map: HashMap<String, i32>,
    ) -> anyhow::Result<Vec<String>> {
        let mut keys_used = Vec::new();
        for (key, value) in new_map {
            let display_value = DisplayableAttributesValueTypes::try_from(value)?;
            self.hash_map.insert(key.clone(), display_value);
            keys_used.push(key);
        }
        Ok(keys_used)
    }
}

impl AttributeSyntaxSchema for DefaultAttributeSyntaxSchema {
    type Error = anyhow::Error;

    #[instrument(skip(self), level = tracing::Level::TRACE)]
    fn to_displayable_attribute(
        &self,
        attribute: &LdapAttribute,
    ) -> Result<DisplayableAttribute, Self::Error> {
        let displayable_attribute = match self.hash_map.get(&attribute.atype) {
            Some(attribute_display_type) => {
                let attribute_value = match attribute_display_type {
                    DisplayableAttributesValueTypes::String => {
                        self.convert_to_string_attribute(attribute)?
                    }
                    DisplayableAttributesValueTypes::Integer => {
                        self.convert_to_integer_attribute(attribute)?
                    }
                    DisplayableAttributesValueTypes::Boolean => {
                        self.convert_to_boolean_attribute(attribute)?
                    }
                    DisplayableAttributesValueTypes::Date => {
                        self.convert_to_date_attribute(attribute)?
                    }
                    DisplayableAttributesValueTypes::Bytes => {
                        self.convert_to_bytes_attribute(attribute)
                    }
                    DisplayableAttributesValueTypes::Enum => {
                        self.convert_to_u8_attribute(attribute)?
                    }
                };
                DisplayableAttribute {
                    attribute_name: attribute.atype.clone(),
                    attribute_value,
                }
            }
            None => DisplayableAttribute {
                attribute_name: attribute.atype.clone(),
                attribute_value: self.convert_to_bytes_attribute(attribute),
            },
        };
        Ok(displayable_attribute)
    }
}

macro_rules! invalid_attribute_error {
    ($attr_name:expr, $attribute_type:expr, $attribute_err:expr) => {
        anyhow::anyhow!(format!(
            "Invalid attribute: {:?} with type {:?} and error {:?}",
            $attr_name, $attribute_type, $attribute_err
        ))
    };
}

impl DefaultAttributeSyntaxSchema {
    fn convert_to_u8_attribute(
        &self,
        attribute: &LdapAttribute,
    ) -> Result<Vec<DisplayableAttributesValue>, anyhow::Error> {
        attribute
            .vals
            .iter()
            .map(|v| {
                if v.len() == 1 {
                    let value = v[0];
                    Ok(DisplayableAttributesValue::Enum(value))
                } else {
                    Err(invalid_attribute_error!(
                        attribute.atype,
                        DisplayableAttributesValueTypes::Enum,
                        "length of value is not 1"
                    ))
                }
            })
            .collect()
    }

    fn convert_to_string_attribute(
        &self,
        attribute: &LdapAttribute,
    ) -> Result<Vec<DisplayableAttributesValue>, anyhow::Error> {
        attribute
            .vals
            .iter()
            .map(|v| {
                String::from_utf8(v.clone())
                    .map(DisplayableAttributesValue::String)
                    .map_err(|e| invalid_attribute_error!(attribute.atype, "String", e))
            })
            .collect()
    }

    fn convert_to_integer_attribute(
        &self,
        attribute: &LdapAttribute,
    ) -> Result<Vec<DisplayableAttributesValue>, anyhow::Error> {
        attribute
            .vals
            .iter()
            .map(|vec| {
                if vec.len() == 4 {
                    let value =
                        i32::from_be_bytes(vec.as_slice().try_into().map_err(anyhow::Error::new)?);
                    Ok(DisplayableAttributesValue::Integer(value))
                } else {
                    Err(invalid_attribute_error!(
                        attribute.atype,
                        DisplayableAttributesValueTypes::Integer,
                        "length of value is not 4"
                    ))
                }
            })
            .collect()
    }

    fn convert_to_boolean_attribute(
        &self,
        attribute: &LdapAttribute,
    ) -> Result<Vec<DisplayableAttributesValue>, anyhow::Error> {
        attribute
            .vals
            .iter()
            .map(|v| {
                if v.as_slice() == b"TRUE" {
                    Ok(DisplayableAttributesValue::Boolean(true))
                } else if v.as_slice() == b"FALSE" {
                    Ok(DisplayableAttributesValue::Boolean(false))
                } else {
                    Err(invalid_attribute_error!(
                        attribute.atype,
                        "Boolean",
                        "Invalid value found"
                    ))
                }
            })
            .collect()
    }

    fn convert_to_date_attribute(
        &self,
        attribute: &LdapAttribute,
    ) -> Result<Vec<DisplayableAttributesValue>, anyhow::Error> {
        attribute
            .vals
            .iter()
            .map(|v| {
                String::from_utf8(v.clone())
                    .map(DisplayableAttributesValue::Date)
                    .map_err(|e| invalid_attribute_error!(attribute.atype, "Date", e))
            })
            .collect()
    }

    fn convert_to_bytes_attribute(
        &self,
        attribute: &LdapAttribute,
    ) -> Vec<DisplayableAttributesValue> {
        attribute
            .vals
            .iter()
            .map(|v| DisplayableAttributesValue::Bytes(v.clone()))
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisplayableAttribute {
    attribute_name: String,
    attribute_value: Vec<DisplayableAttributesValue>,
}

impl DisplayableAttribute {
    pub fn new(a_name: String, val: Vec<DisplayableAttributesValue>) -> Self {
        Self {
            attribute_name: a_name,
            attribute_value: val,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisplayableEntry {
    pub dn: String,
    pub attributes: Vec<DisplayableAttribute>,
}
