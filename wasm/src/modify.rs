use anyhow::Ok;
use ldap3_proto::proto::{LdapModify, LdapModifyType};
use serde::{Deserialize, Serialize};
use tsify::Tsify;

use crate::schema::search_objects::Attribute;

#[derive(Debug, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct ModifyRequest {
    pub(crate) operation: ModifyTypes,
    pub(crate) attribute: Attribute,
}

/// for the sake of typescript
#[derive(Debug, Tsify, Serialize, Deserialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub enum ModifyTypes {
    Add = 0,
    Delete = 1,
    Replace = 2,
}

impl From<LdapModifyType> for ModifyTypes {
    fn from(value: LdapModifyType) -> Self {
        match value {
            LdapModifyType::Add => ModifyTypes::Add,
            LdapModifyType::Delete => ModifyTypes::Delete,
            LdapModifyType::Replace => ModifyTypes::Replace,
        }
    }
}

impl From<ModifyTypes> for LdapModifyType {
    fn from(val: ModifyTypes) -> Self {
        match val {
            ModifyTypes::Add => LdapModifyType::Add,
            ModifyTypes::Delete => LdapModifyType::Delete,
            ModifyTypes::Replace => LdapModifyType::Replace,
        }
    }
}

#[derive(Tsify, Serialize, Deserialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct BinaryLdapModifies(pub(crate) Vec<ModifyRequest>);

impl From<BinaryLdapModifies> for Vec<ModifyRequest> {
    fn from(value: BinaryLdapModifies) -> Self {
        value.0
    }
}

impl TryInto<LdapModify> for ModifyRequest {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<LdapModify, Self::Error> {
        Ok(LdapModify {
            operation: self.operation.into(),
            modification: self.attribute.into(),
        })
    }
}

//==============================================================================
#[derive(Debug, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct SearchMessage {}
