use ldap3_proto::{proto::LdapResult, LdapPartialAttribute, LdapSearchResultEntry};
use serde::{Deserialize, Serialize};
use tsify::Tsify;

use crate::control::LdapControlArray;

#[derive(Debug, Serialize, Deserialize, Tsify)]
#[serde(untagged)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub enum AttributeValue {
    Bytes(Vec<Vec<u8>>),
    String(Vec<String>),
}

impl Into<Vec<Vec<u8>>> for AttributeValue {
    fn into(self) -> Vec<Vec<u8>> {
        match self {
            AttributeValue::Bytes(bytes) => bytes,
            AttributeValue::String(strings) => {
                strings.into_iter().map(|s| s.into_bytes()).collect()
            }
        }
    }
}

impl From<Vec<Vec<u8>>> for AttributeValue {
    fn from(bytes: Vec<Vec<u8>>) -> Self {
        AttributeValue::Bytes(bytes)
    }
}
//==============================================================================

#[derive(Debug, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct Attribute {
    attribute_name: String,
    attribute_value: AttributeValue,
}

impl Into<LdapPartialAttribute> for Attribute {
    fn into(self) -> LdapPartialAttribute {
        LdapPartialAttribute {
            atype: self.attribute_name,
            vals: self.attribute_value.into(),
        }
    }
}

impl From<LdapPartialAttribute> for Attribute {
    fn from(attr: LdapPartialAttribute) -> Self {
        Attribute {
            attribute_name: attr.atype,
            attribute_value: attr.vals.into(),
        }
    }
}

//==============================================================================
#[derive(Debug, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct AttributesArray(pub(crate) Vec<Attribute>);

// into Vec<LdapAttributes>
impl Into<Vec<LdapPartialAttribute>> for AttributesArray {
    fn into(self) -> Vec<LdapPartialAttribute> {
        self.0.into_iter().map(|a| a.into()).collect()
    }
}

//==============================================================================
#[derive(Debug, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct SearchEntry {
    pub(crate) dn: String,
    pub(crate) attributes: AttributesArray,
}

impl From<LdapSearchResultEntry> for SearchEntry {
    fn from(entry: LdapSearchResultEntry) -> Self {
        SearchEntry {
            dn: entry.dn,
            attributes: AttributesArray(entry.attributes.into_iter().map(|a| a.into()).collect()),
        }
    }
}

//==============================================================================
#[derive(Debug, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
#[serde(rename_all = "snake_case")]
pub enum SearchOperation {
    SearchEntry(SearchEntry),
    SearchReference(LdapResult),
    SearchDone(LdapResult),
}

//==============================================================================
#[derive(Debug, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct SearchMessage {
    pub msgid: i32,
    pub op: SearchOperation,
    pub ctrl: Option<LdapControlArray>,
}
