use anyhow::Ok;
use ldap3_proto::proto::{LdapModify, LdapModifyType};
use serde::{Deserialize, Serialize};
use tsify::Tsify;


use crate::schema::displayables::DisplayableAttribute;

#[derive(Debug, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct DisplayableModify {
    pub(crate) operation: DisplayableLdapModifyType,
    pub(crate) attribute: DisplayableAttribute,
}

/// for the sake of typescript
#[derive(Debug, Tsify, Serialize, Deserialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub enum DisplayableLdapModifyType {
    Add = 0,
    Delete = 1,
    Replace = 2,
}

impl From<LdapModifyType> for DisplayableLdapModifyType {
    fn from(value: LdapModifyType) -> Self {
        match value {
            LdapModifyType::Add => DisplayableLdapModifyType::Add,
            LdapModifyType::Delete => DisplayableLdapModifyType::Delete,
            LdapModifyType::Replace => DisplayableLdapModifyType::Replace,
        }
    }
}

impl From<DisplayableLdapModifyType> for LdapModifyType {
    fn from(val: DisplayableLdapModifyType) -> Self {
        match val {
            DisplayableLdapModifyType::Add => LdapModifyType::Add,
            DisplayableLdapModifyType::Delete => LdapModifyType::Delete,
            DisplayableLdapModifyType::Replace => LdapModifyType::Replace,
        }
    }
}

#[derive(Tsify, Serialize, Deserialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct LdapModifies(Vec<DisplayableModify>);

impl From<LdapModifies> for Vec<DisplayableModify> {
    fn from(value: LdapModifies) -> Self {
        value.0
    }
}

impl TryInto<LdapModify> for DisplayableModify {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<LdapModify, Self::Error> {
        Ok(LdapModify {
            operation: self.operation.into(),
            modification: self.attribute.try_into()?,
        })
    }
}
