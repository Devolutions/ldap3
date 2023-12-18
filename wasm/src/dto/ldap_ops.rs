#![allow(non_snake_case)]
use derive_more::{From, Into};
use ldap3_proto::proto;
use serde::{Deserialize, Serialize};
use tsify::Tsify;
use uuid::Uuid;

use crate::impl_same_enum;

use super::bind::LdapBindResponse;

#[derive(Debug, Clone, Serialize, Deserialize, Tsify)]
#[serde(rename_all = "snake_case")]
#[tsify(into_wasm_abi)]
pub enum LdapOp {
    BindResponse(LdapBindResponse),
    ModifyResponse(LdapResult),
    // https://tools.ietf.org/html/rfc4511#section-4.7
    AddResponse(LdapResult),
    // https://tools.ietf.org/html/rfc4511#section-4.8
    DelResponse(LdapResult),
    // https://datatracker.ietf.org/doc/html/rfc4511#section-4.9
    ModifyDNResponse(LdapResult),
    CompareResult(LdapResult),
    ExtendedResponse(LdapExtendedResponse),
    IntermediateResponse(LdapIntermediateResponse),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify, From, Into)]
#[serde(rename_all = "snake_case")]
#[tsify(into_wasm_abi)]
pub struct LdapResult {
    pub code: LdapResultCode,
    pub matcheddn: String,
    pub message: String,
    pub referral: Vec<String>,
}

impl From<LdapResult> for proto::LdapResult {
    fn from(item: LdapResult) -> Self {
        proto::LdapResult {
            code: item.code.into(),
            matcheddn: item.matcheddn,
            message: item.message,
            referral: item.referral,
        }
    }
}

impl From<proto::LdapResult> for LdapResult {
    fn from(item: proto::LdapResult) -> Self {
        LdapResult {
            code: item.code.into(),
            matcheddn: item.matcheddn,
            message: item.message,
            referral: item.referral,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify, From)]
#[serde(rename_all = "snake_case")]
#[tsify(into_wasm_abi)]
pub enum LdapResultCode {
    Success = 0,
    OperationsError = 1,
    ProtocolError = 2,
    TimeLimitExceeded = 3,
    SizeLimitExceeded = 4,
    CompareFalse = 5,
    CompareTrue = 6,
    AuthMethodNotSupported = 7,
    StrongerAuthRequired = 8,
    Referral = 10,
    AdminLimitExceeded = 11,
    UnavailableCriticalExtension = 12,
    ConfidentialityRequired = 13,
    SaslBindInProgress = 14,
    NoSuchAttribute = 16,
    UndefinedAttributeType = 17,
    InappropriateMatching = 18,
    ConstraintViolation = 19,
    AttributeOrValueExists = 20,
    InvalidAttributeSyntax = 21,
    NoSuchObject = 32,
    AliasProblem = 33,
    InvalidDNSyntax = 34,
    AliasDereferencingProblem = 36,
    InappropriateAuthentication = 48,
    InvalidCredentials = 49,
    InsufficentAccessRights = 50,
    Busy = 51,
    Unavailable = 52,
    UnwillingToPerform = 53,
    LoopDetect = 54,
    NamingViolation = 64,
    ObjectClassViolation = 65,
    NotAllowedOnNonLeaf = 66,
    NotALlowedOnRDN = 67,
    EntryAlreadyExists = 68,
    ObjectClassModsProhibited = 69,
    AffectsMultipleDSAs = 71,
    Other = 80,
    EsyncRefreshRequired = 4096,
}

impl_same_enum!(
    LdapResultCode,
    proto::LdapResultCode,
    Success,
    OperationsError,
    ProtocolError,
    TimeLimitExceeded,
    SizeLimitExceeded,
    CompareFalse,
    CompareTrue,
    AuthMethodNotSupported,
    StrongerAuthRequired,
    Referral,
    AdminLimitExceeded,
    UnavailableCriticalExtension,
    ConfidentialityRequired,
    SaslBindInProgress,
    NoSuchAttribute,
    UndefinedAttributeType,
    InappropriateMatching,
    ConstraintViolation,
    AttributeOrValueExists,
    InvalidAttributeSyntax,
    AliasProblem,
    InvalidDNSyntax,
    AliasDereferencingProblem,
    InappropriateAuthentication,
    InvalidCredentials,
    InsufficentAccessRights,
    Busy,
    Unavailable,
    UnwillingToPerform,
    LoopDetect,
    NamingViolation,
    ObjectClassViolation,
    NotAllowedOnNonLeaf,
    NotALlowedOnRDN,
    EntryAlreadyExists,
    ObjectClassModsProhibited,
    AffectsMultipleDSAs,
    Other,
    NoSuchObject,
    EsyncRefreshRequired
);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify, From, Into)]
#[serde(rename_all = "snake_case")]
#[tsify(into_wasm_abi)]
pub struct LdapExtendedResponse {
    pub res: LdapResult,
    pub name: Option<String>,
    pub value: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Tsify)]
#[serde(rename_all = "snake_case")]
#[tsify(into_wasm_abi)]
pub enum LdapIntermediateResponse {
    SyncInfoNewCookie {
        cookie: Vec<u8>,
    },
    SyncInfoRefreshDelete {
        cookie: Option<Vec<u8>>,
        done: bool,
    },
    SyncInfoRefreshPresent {
        cookie: Option<Vec<u8>>,
        done: bool,
    },
    SyncInfoIdSet {
        cookie: Option<Vec<u8>>,
        refresh_deletes: bool,
        syncuuids: Vec<Uuid>,
    },
    Raw {
        name: Option<String>,
        value: Option<Vec<u8>>,
    },
}

impl From<LdapOp> for proto::LdapOp {
    fn from(value: LdapOp) -> Self {
        match value {
            LdapOp::BindResponse(res) => proto::LdapOp::BindResponse(res.into()),
            LdapOp::ModifyResponse(_) => todo!(),
            LdapOp::AddResponse(_) => todo!(),
            LdapOp::DelResponse(_) => todo!(),
            LdapOp::ModifyDNResponse(_) => todo!(),
            LdapOp::CompareResult(_) => todo!(),
            LdapOp::ExtendedResponse(_) => todo!(),
            LdapOp::IntermediateResponse(_) => todo!(),
        }
    }
}
