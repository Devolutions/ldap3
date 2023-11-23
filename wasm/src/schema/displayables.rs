use ldap3_proto::{
    proto::{LdapControl, LdapOp, LdapResult, LdapSearchResultReference},
    LdapMsg, LdapPartialAttribute, LdapSearchResultEntry,
};
use serde::{Deserialize, Serialize};
use tsify::Tsify;
use wasm_bindgen::prelude::wasm_bindgen;

// ================================================================================================= Attribute Values
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "type", content = "value")]
#[tsify(into_wasm_abi, from_wasm_abi)]
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
#[serde(rename_all = "snake_case")]
pub enum DisplayableAttributesValueType {
    String,
    Integer,
    Boolean,
    Date,
    Bytes,
    Enum,
}

// ================================================================================================= Attirbutes
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct DisplayableAttribute {
    pub attribute_name: String,
    pub attribute_value: DisplayableAttributesValues,
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

#[derive(Debug, Clone, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct DisplayableAttributes(pub Vec<DisplayableAttribute>);

impl From<DisplayableAttributes> for Vec<DisplayableAttribute> {
    fn from(val: DisplayableAttributes) -> Self {
        val.0
    }
}

impl From<DisplayableAttributes> for Vec<LdapPartialAttribute> {
    fn from(val: DisplayableAttributes) -> Self {
        val.0.into_iter().map(|v| v.into()).collect()
    }
}

// ================================================================================================= Entries
#[derive(Debug, Clone, Deserialize, Serialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct DisplayableEntry {
    pub(crate) dn: String,
    pub(crate) attributes: Vec<DisplayableAttribute>,
}

impl From<DisplayableEntry> for LdapSearchResultEntry {
    fn from(val: DisplayableEntry) -> Self {
        let DisplayableEntry { dn, attributes } = val;
        LdapSearchResultEntry {
            dn,
            attributes: attributes.into_iter().map(|a| a.into()).collect(),
        }
    }
}

// ================================================================================================= Messages
#[derive(Debug, Clone, Serialize, Deserialize, Tsify)]
#[serde(rename_all = "snake_case")]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct DisplayableSearchMessage {
    pub(crate) msgid: i32,
    pub(crate) op: DisplayableSearchOp,
    pub(crate) ctrl: LdapControlArray,
}

#[derive(Debug, Clone, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct LdapControlWrapper(pub LdapControl);

#[derive(Debug, Clone, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct LdapControlArray(pub Vec<LdapControl>);

impl From<LdapControlArray> for Vec<LdapControl> {
    fn from(val: LdapControlArray) -> Self {
        val.0
    }
}

impl From<Vec<LdapControl>> for LdapControlArray {
    fn from(val: Vec<LdapControl>) -> Self {
        Self(val)
    }
}

impl From<DisplayableSearchMessage> for LdapMsg {
    fn from(val: DisplayableSearchMessage) -> Self {
        let DisplayableSearchMessage {
            msgid: msg_id,
            op,
            ctrl,
        } = val;
        let search_op = match op {
            DisplayableSearchOp::SearchEntry(ent) => LdapOp::SearchResultEntry(ent.into()),
            DisplayableSearchOp::SearchDone(res) => LdapOp::SearchResultDone(res),
            DisplayableSearchOp::SearchReference(reference) => {
                LdapOp::SearchResultReference(reference)
            }
        };
        LdapMsg {
            msgid: msg_id,
            op: search_op,
            ctrl: ctrl.into(),
        }
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Serialize, Deserialize, Tsify)]
#[serde(rename_all = "snake_case")]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub(crate) enum DisplayableSearchOp {
    SearchEntry(DisplayableEntry),
    SearchDone(LdapResult),
    SearchReference(LdapSearchResultReference),
}
