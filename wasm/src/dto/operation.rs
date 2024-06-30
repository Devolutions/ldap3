#![allow(non_snake_case)]

use ldap3_proto::proto;
use serde::{Deserialize, Serialize};
use tsify::Tsify;
use wasm_bindgen::JsValue;

use super::result::LdapResult;

#[derive(Debug, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub enum LdapOp {
    // BindRequest(LdapBindRequest),
    BindResponse(LdapBindResponse),
    UnbindRequest,
    // https://tools.ietf.org/html/rfc4511#section-4.5
    // SearchRequest(LdapSearchRequest),
    // SearchResultEntry(LdapSearchResultEntry),
    SearchResultDone(LdapResult),
    // SearchResultReference(LdapSearchResultReference),
    // https://datatracker.ietf.org/doc/html/rfc4511#section-4.6
    // ModifyRequest(LdapModifyRequest),
    ModifyResponse(LdapResult),
    // https://tools.ietf.org/html/rfc4511#section-4.7
    // AddRequest(LdapAddRequest),
    AddResponse(LdapResult),
    // https://tools.ietf.org/html/rfc4511#section-4.8
    DelRequest(String),
    DelResponse(LdapResult),
    // https://datatracker.ietf.org/doc/html/rfc4511#section-4.9
    // ModifyDNRequest(LdapModifyDNRequest),
    ModifyDNResponse(LdapResult),
    // https://www.rfc-editor.org/rfc/rfc4511#section-4.10
    // CompareRequest(LdapCompareRequest),
    CompareResult(LdapResult),
    // https://tools.ietf.org/html/rfc4511#section-4.11
    AbandonRequest(i32),
    // https://tools.ietf.org/html/rfc4511#section-4.12
    // ExtendedRequest(LdapExtendedRequest),
    // ExtendedResponse(LdapExtendedResponse),
    // // https://www.rfc-editor.org/rfc/rfc4511#section-4.13
    // IntermediateResponse(LdapIntermediateResponse),
}

impl TryFrom<proto::LdapOp> for LdapOp {
    type Error = anyhow::Error;
    fn try_from(value: proto::LdapOp) -> Result<Self, Self::Error> {
        match value {
            proto::LdapOp::UnbindRequest => Ok(LdapOp::UnbindRequest),
            proto::LdapOp::BindResponse(result) => Ok(LdapOp::BindResponse(result.into())),
            proto::LdapOp::SearchResultDone(result) => Ok(LdapOp::SearchResultDone(result.into())),
            proto::LdapOp::ModifyResponse(result) => Ok(LdapOp::ModifyResponse(result.into())),
            proto::LdapOp::AddResponse(result) => Ok(LdapOp::AddResponse(result.into())),
            proto::LdapOp::DelResponse(result) => Ok(LdapOp::DelResponse(result.into())),
            proto::LdapOp::ModifyDNResponse(result) => Ok(LdapOp::ModifyDNResponse(result.into())),
            proto::LdapOp::CompareResult(result) => Ok(LdapOp::CompareResult(result.into())),
            proto::LdapOp::AbandonRequest(id) => Ok(LdapOp::AbandonRequest(id)),
            _ => Err(anyhow::anyhow!("Should no be here!")),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct LdapBindResponse {
    pub res: LdapResult,
    pub saslcreds: Option<Vec<u8>>,
}

impl From<proto::LdapBindResponse> for LdapBindResponse {
    fn from(value: proto::LdapBindResponse) -> Self {
        LdapBindResponse {
            res: value.res.into(),
            saslcreds: value.saslcreds,
        }
    }
}

impl From<LdapBindResponse> for proto::LdapBindResponse {
    fn from(val: LdapBindResponse) -> Self {
        proto::LdapBindResponse {
            res: val.res.into(),
            saslcreds: val.saslcreds,
        }
    }
}

impl From<LdapBindResponse> for JsValue {
    fn from(val: LdapBindResponse) -> Self {
        serde_wasm_bindgen::to_value(&val).unwrap()
    }
}
