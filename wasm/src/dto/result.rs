#![allow(non_snake_case)]

use serde::{Deserialize, Serialize};
use tsify::Tsify;
use wasm_bindgen::JsValue;

use super::control::LdapResultCode;

#[derive(Debug, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct LdapResult {
    pub code: LdapResultCode,
    pub matcheddn: String,
    pub message: String,
    pub referral: Vec<String>,
}

impl From<LdapResult> for JsValue {
    fn from(val: LdapResult) -> Self {
        serde_wasm_bindgen::to_value(&val).unwrap()
    }
}

impl From<ldap3_proto::proto::LdapResult> for LdapResult {
    fn from(val: ldap3_proto::proto::LdapResult) -> Self {
        LdapResult {
            code: val.code.into(),
            matcheddn: val.matcheddn,
            message: val.message,
            referral: val.referral,
        }
    }
}

impl From<LdapResult> for ldap3_proto::proto::LdapResult {
    fn from(val: LdapResult) -> Self {
        ldap3_proto::proto::LdapResult {
            code: val.code.into(),
            matcheddn: val.matcheddn,
            message: val.message,
            referral: val.referral,
        }
    }
}
