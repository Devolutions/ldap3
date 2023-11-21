use std::collections::HashMap;

use anyhow::Result;

use ldap3_proto::{proto::LdapAttribute, LdapPartialAttribute, LdapSearchResultEntry};
use serde::{Deserialize, Serialize};
use tracing::instrument;

use super::displayables::{
    DisplayableAttribute, DisplayableAttributesValueType, DisplayableAttributesValues,
    DisplayableEntry,
};

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

/*
    {
        type: DisplayableAttributesValueTypes.String,
        value:[
            "string",
            "string2"
        ]
    }

*/

/// LDAP Bytes->Rust->JS
pub trait AttributeSyntaxSchema {
    type Error;
    fn to_displayable_attribute(
        &self,
        attribute: LdapAttribute,
    ) -> Result<DisplayableAttribute, Self::Error>;

    fn convert_to_bytes_attribute(&self, attribute: LdapAttribute) -> DisplayableAttribute;
}

#[derive(Debug, Default, Clone)]
pub struct DefaultAttributeSyntaxSchema {
    hash_map: HashMap<String, DisplayableAttributesValueType>,
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
            let display_value = DisplayableAttributesValueType::try_from(value)?;
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
        attribute: LdapAttribute,
    ) -> Result<DisplayableAttribute, Self::Error> {
        let displayable_attribute = match self.hash_map.get(&attribute.atype) {
            Some(attribute_display_type) => match attribute_display_type {
                DisplayableAttributesValueType::String => {
                    self.convert_to_string_attribute(attribute)
                }
                DisplayableAttributesValueType::Integer => {
                    self.convert_to_integer_attribute(attribute)
                }
                DisplayableAttributesValueType::Boolean => {
                    self.convert_to_boolean_attribute(attribute)
                }
                DisplayableAttributesValueType::Date => self.convert_to_date_attribute(attribute),
                DisplayableAttributesValueType::Bytes => {
                    Ok(self.convert_to_bytes_attribute(attribute))
                }
                DisplayableAttributesValueType::Enum => self.convert_to_u8_attribute(attribute),
            },
            None => Err(anyhow::anyhow!("Attribute not found")),
        }?;
        Ok(displayable_attribute)
    }

    fn convert_to_bytes_attribute(&self, attribute: LdapAttribute) -> DisplayableAttribute {
        let LdapPartialAttribute { atype, vals } = attribute;
        DisplayableAttribute {
            attribute_name: atype,
            attribute_value: DisplayableAttributesValues::Bytes(vals),
        }
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
        attribute: LdapAttribute,
    ) -> Result<DisplayableAttribute, anyhow::Error> {
        let LdapPartialAttribute { atype, vals } = attribute;
        let vec_u8 = vals
            .into_iter()
            .map(|v| {
                if v.len() == 1 {
                    let value = v[0];
                    Ok(value)
                } else {
                    Err(invalid_attribute_error!(
                        atype,
                        DisplayableAttributesValueType::Enum,
                        "length of value is not 1"
                    ))
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(DisplayableAttribute::new(
            atype,
            DisplayableAttributesValues::Enum(vec_u8),
        ))
    }

    fn convert_to_string_attribute(
        &self,
        attribute: LdapAttribute,
    ) -> Result<DisplayableAttribute, anyhow::Error> {
        let LdapPartialAttribute { atype, vals } = attribute;
        let vec_string = vals
            .into_iter()
            .map(|v| String::from_utf8(v).map_err(|e| invalid_attribute_error!(atype, "String", e)))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(DisplayableAttribute::new(
            atype,
            DisplayableAttributesValues::String(vec_string),
        ))
    }

    fn convert_to_integer_attribute(
        &self,
        attribute: LdapAttribute,
    ) -> Result<DisplayableAttribute, anyhow::Error> {
        let LdapPartialAttribute { atype, vals } = attribute;

        let vec_int = vals
            .into_iter()
            .map(|v| {
                if v.len() == 4 {
                    let value =
                        i32::from_be_bytes(v.as_slice().try_into().map_err(anyhow::Error::new)?);
                    Ok(value)
                } else {
                    Err(invalid_attribute_error!(
                        atype,
                        DisplayableAttributesValueType::Integer,
                        "length of value is not 4"
                    ))
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(DisplayableAttribute::new(
            atype,
            DisplayableAttributesValues::Integer(vec_int),
        ))
    }

    fn convert_to_boolean_attribute(
        &self,
        attribute: LdapAttribute,
    ) -> Result<DisplayableAttribute, anyhow::Error> {
        let LdapPartialAttribute { atype, vals } = attribute;
        let vec_bool = vals
            .into_iter()
            .map(|v| {
                if v.as_slice() == b"TRUE" {
                    Ok(true)
                } else if v.as_slice() == b"FALSE" {
                    Ok(false)
                } else {
                    Err(invalid_attribute_error!(
                        atype,
                        DisplayableAttributesValueType::Boolean,
                        "Invalid value found"
                    ))
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(DisplayableAttribute::new(
            atype,
            DisplayableAttributesValues::Boolean(vec_bool),
        ))
    }

    fn convert_to_date_attribute(
        &self,
        attribute: LdapAttribute,
    ) -> Result<DisplayableAttribute, anyhow::Error> {
        // TODO! convert to proper date type
        let LdapPartialAttribute { atype, vals } = attribute;
        let vec_string = vals
            .into_iter()
            .map(|v| String::from_utf8(v).map_err(|e| invalid_attribute_error!(atype, "Date", e)))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(DisplayableAttribute::new(
            atype,
            DisplayableAttributesValues::Date(vec_string),
        ))
    }
}

/* Typescript Type
type Attributes = {
    attribute_name:string,
    attribute_value: {
        type:"String",
        value: string[]
    } | {
        type : "Integer",
        value : number[]
    } | {
        type: "Boolean",
        value: boolean[]
    } | {
        type: "Date",
        value: string[]
    } | {
        type : "Bytes",
        value: Uint8Array[]
    } | {
        type: "Enum",
        value: Uint8Array
    }
}
*/

pub fn to_displayable_entry(
    schema: &DefaultAttributeSyntaxSchema,
    source: LdapSearchResultEntry,
) -> Result<DisplayableEntry> {
    let LdapSearchResultEntry { dn, attributes } = source;

    let mut displayable_attributes = Vec::new();
    for attribute in attributes {
        let displayable_attribute = schema.to_displayable_attribute(attribute)?;
        displayable_attributes.push(displayable_attribute);
    }

    Ok(DisplayableEntry {
        dn,
        attributes: displayable_attributes,
    })
}
