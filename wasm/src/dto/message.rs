#![allow(non_snake_case)]

use serde::{Deserialize, Serialize};
use tsify::Tsify;

#[derive(Debug, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct LdapMsg {
    pub msgid: i32,
    pub op: crate::dto::operation::LdapOp,
    pub ctrl: Vec<crate::dto::control::LdapControl>,
}
