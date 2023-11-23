use core::fmt;
use std::collections::HashMap;

use anyhow::{Ok, Result};

use ldap3_proto::{proto::LdapAttribute, LdapPartialAttribute, LdapSearchResultEntry};
use serde::{Deserialize, Serialize};
use tracing::{instrument, trace};

use tsify::Tsify;

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

/// LDAP Bytes->Rust->JS
pub trait AttributeSyntaxSchema {
    type Error: fmt::Debug;
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

    pub fn from_vector_scheme(vector_scheme: VectorScheme) -> Self {
        let VectorScheme(scheme) = vector_scheme;
        let mut hash_map = HashMap::new();
        for SingleScheme { atype, value } in scheme {
            hash_map.insert(atype, value);
        }
        Self { hash_map }
    }

    pub fn extend_from_vector_scheme(&mut self, vector_scheme: VectorScheme) {
        let VectorScheme(scheme) = vector_scheme;
        for SingleScheme { atype, value } in scheme {
            self.hash_map.insert(atype, value);
        }
    }

    pub fn get_keys(&self) -> Vec<String> {
        self.hash_map.keys().cloned().collect()
    }
}

#[derive(Debug, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct SingleScheme {
    atype: String,
    value: DisplayableAttributesValueType,
}

#[derive(Debug, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct VectorScheme(pub Vec<SingleScheme>);

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
            None => {
                trace!("No attribute type found for {:?}", attribute.atype);
                Ok(self.convert_to_bytes_attribute(attribute))
            }
        }?;
        Ok(displayable_attribute)
    }

    #[instrument(skip(self), level = tracing::Level::TRACE)]
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

//==================================================================================================

#[derive(Debug, Clone, Copy, Default)]
pub struct BinaryAttributeSyntaxSchema;

impl BinaryAttributeSyntaxSchema {
    pub fn new() -> Self {
        Self {}
    }
}

impl AttributeSyntaxSchema for BinaryAttributeSyntaxSchema {
    type Error = anyhow::Error;

    #[instrument(skip(self), level = tracing::Level::TRACE)]
    fn to_displayable_attribute(
        &self,
        attribute: LdapAttribute,
    ) -> Result<DisplayableAttribute, Self::Error> {
        Ok(self.convert_to_bytes_attribute(attribute))
    }

    #[instrument(skip(self), level = tracing::Level::TRACE)]
    fn convert_to_bytes_attribute(&self, attribute: LdapAttribute) -> DisplayableAttribute {
        let LdapPartialAttribute { atype, vals } = attribute;
        DisplayableAttribute {
            attribute_name: atype,
            attribute_value: DisplayableAttributesValues::Bytes(vals),
        }
    }
}

pub fn to_displayable_entry(
    schema: &dyn AttributeSyntaxSchema<Error = anyhow::Error>,
    source: LdapSearchResultEntry,
) -> Result<DisplayableEntry> {
    let LdapSearchResultEntry { dn, attributes } = source;

    let mut displayable_attributes = Vec::new();
    for attribute in attributes {
        let displayable_attribute = schema
            .to_displayable_attribute(attribute)
            .map_err(|e| anyhow::anyhow!("Error converting attribute {:?}", e))?;
        displayable_attributes.push(displayable_attribute);
    }

    Ok(DisplayableEntry {
        dn,
        attributes: displayable_attributes,
    })
}
