use anyhow::Ok;
use ldap3_proto::proto::{LdapModify, LdapModifyType};
use serde::{Deserialize, Serialize};

use wasm_bindgen::prelude::wasm_bindgen;

use crate::schema::displayables::DisplayableAttribute;

#[wasm_bindgen]
pub enum ModifyOpeartion {
    Add = 0,
    Remove = 1,
    Replace = 2,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeserializableModify {
    operation: i32,
    attribute: DisplayableAttribute,
}

impl TryInto<LdapModify> for DeserializableModify {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<LdapModify, Self::Error> {
        let operation = match self.operation {
            0 => Ok(LdapModifyType::Add),
            1 => Ok(LdapModifyType::Delete),
            2 => Ok(LdapModifyType::Replace),
            _ => Err(anyhow::anyhow!("Invalid ModifyOpeartion value")),
        }?;
        Ok(LdapModify {
            operation,
            modification: self.attribute.try_into()?,
        })
    }
}
