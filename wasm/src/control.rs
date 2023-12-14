#![allow(non_snake_case)]
use serde::{Deserialize, Serialize};
use tsify::Tsify;
use uuid::Uuid;

macro_rules! sync_state_enum_convert {
    ($source:ty, $target:ty, $($variant:ident),+) => {
        impl From<$source> for $target {
            fn from(val: $source) -> Self {
                match val {
                    $( <$source>::$variant => <$target>::$variant, )+
                }
            }
        }

        impl Into<$source> for $target {
            fn into(self) -> $source {
                match self {
                    $( <$target>::$variant => <$source>::$variant, )+
                }
            }
        }
    };
}

#[derive(Debug, Serialize, Deserialize, Tsify)]
#[repr(i64)]
#[serde(rename_all = "snake_case")]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub enum SyncRequestMode {
    RefreshOnly = 1,
    RefreshAndPersist = 3,
}

sync_state_enum_convert!(
    ldap3_proto::proto::SyncRequestMode,
    SyncRequestMode,
    RefreshOnly,
    RefreshAndPersist
);

#[derive(Debug, Serialize, Deserialize, Tsify)]
#[repr(i64)]
#[serde(rename_all = "snake_case")]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub enum SyncStateValue {
    Present = 0,
    Add = 1,
    Modify = 2,
    Delete = 3,
}

sync_state_enum_convert!(
    ldap3_proto::proto::SyncStateValue,
    SyncStateValue,
    Present,
    Add,
    Modify,
    Delete
);

#[derive(Debug, Serialize, Deserialize, Tsify)]
#[serde(rename_all = "snake_case")]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub enum LdapControl {
    SyncRequest {
        // Shouldn't this imply true?
        criticality: bool,
        mode: SyncRequestMode,
        cookie: Option<Vec<u8>>,
        reload_hint: bool,
    },
    SyncState {
        state: SyncStateValue,
        entry_uuid: Uuid,
        cookie: Option<Vec<u8>>,
    },
    SyncDone {
        cookie: Option<Vec<u8>>,
        refresh_deletes: bool,
    },
    AdDirsync {
        flags: i64,
        max_bytes: i64,
        cookie: Option<Vec<u8>>,
    },
    SimplePagedResults {
        size: i64,
        cookie: Vec<u8>,
    },
    ManageDsaIT {
        criticality: bool,
    },
    ServerSort {
        sort_requests: Vec<ServerSortRequet>,
    },

    ServerSortResult {
        sort_result: ServerSortResult,
    },
}

impl From<ldap3_proto::control::LdapControl> for LdapControl {
    fn from(value: ldap3_proto::control::LdapControl) -> Self {
        match value {
            ldap3_proto::control::LdapControl::SyncRequest {
                criticality,
                mode,
                cookie,
                reload_hint,
            } => {
                LdapControl::SyncRequest {
                    criticality,
                    mode: mode.into(), // Assuming mode is directly convertible. If not, you need to map the values.
                    cookie,
                    reload_hint,
                }
            }
            ldap3_proto::control::LdapControl::SyncState {
                state,
                entry_uuid,
                cookie,
            } => {
                LdapControl::SyncState {
                    state: state.into(), // Same assumption as above.
                    entry_uuid,
                    cookie,
                }
            }
            ldap3_proto::control::LdapControl::SyncDone {
                cookie,
                refresh_deletes,
            } => LdapControl::SyncDone {
                cookie,
                refresh_deletes,
            },
            ldap3_proto::control::LdapControl::AdDirsync {
                flags,
                max_bytes,
                cookie,
            } => LdapControl::AdDirsync {
                flags,
                max_bytes,
                cookie,
            },
            ldap3_proto::control::LdapControl::SimplePagedResults { size, cookie } => {
                LdapControl::SimplePagedResults { size, cookie }
            }
            ldap3_proto::control::LdapControl::ManageDsaIT { criticality } => {
                LdapControl::ManageDsaIT { criticality }
            }
            ldap3_proto::control::LdapControl::ServerSort { sort_requests } => {
                LdapControl::ServerSort {
                    sort_requests: sort_requests.into_iter().map(|v| v.into()).collect(), // Ensure that the types of sort_requests are compatible or convert as needed.
                }
            }
            ldap3_proto::control::LdapControl::ServerSortResult { sort_result } => {
                LdapControl::ServerSortResult {
                    sort_result: sort_result.into(), // Same as above.
                }
            } // Add cases for other variants if they exist.
        }
    }
}

impl From<LdapControl> for ldap3_proto::control::LdapControl {
    fn from(val: LdapControl) -> Self {
        match val {
            LdapControl::SyncRequest {
                criticality,
                mode,
                cookie,
                reload_hint,
            } => ldap3_proto::control::LdapControl::SyncRequest {
                criticality,
                mode: mode.into(), // Assuming mode is directly convertible. If not, you need to map the values.
                cookie,
                reload_hint,
            },
            LdapControl::SyncState {
                state,
                entry_uuid,
                cookie,
            } => ldap3_proto::control::LdapControl::SyncState {
                state: state.into(), // Same assumption as above.
                entry_uuid,
                cookie,
            },
            LdapControl::SyncDone {
                cookie,
                refresh_deletes,
            } => ldap3_proto::control::LdapControl::SyncDone {
                cookie,
                refresh_deletes,
            },
            LdapControl::AdDirsync {
                flags,
                max_bytes,
                cookie,
            } => ldap3_proto::control::LdapControl::AdDirsync {
                flags,
                max_bytes,
                cookie,
            },
            LdapControl::SimplePagedResults { size, cookie } => {
                ldap3_proto::control::LdapControl::SimplePagedResults { size, cookie }
            }
            LdapControl::ManageDsaIT { criticality } => {
                ldap3_proto::control::LdapControl::ManageDsaIT { criticality }
            }
            LdapControl::ServerSort { sort_requests } => {
                ldap3_proto::control::LdapControl::ServerSort {
                    sort_requests: sort_requests.into_iter().map(|v| v.into()).collect(), // Ensure that the types of sort_requests are compatible or convert as needed.
                }
            }
            LdapControl::ServerSortResult { sort_result } => {
                ldap3_proto::control::LdapControl::ServerSortResult {
                    sort_result: sort_result.into(), // Same as above.
                }
            } // Add cases for other variants if they exist.
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Tsify)]
#[serde(rename_all = "snake_case")]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct ServerSortResult {
    result_code: LdapResultCode,
    attribute_type: Option<String>,
}

impl From<ldap3_proto::control::ServerSortResult> for ServerSortResult {
    fn from(value: ldap3_proto::control::ServerSortResult) -> Self {
        ServerSortResult {
            result_code: value.result_code.into(),
            attribute_type: value.attribute_type,
        }
    }
}

impl From<ServerSortResult> for ldap3_proto::control::ServerSortResult {
    fn from(val: ServerSortResult) -> Self {
        ldap3_proto::control::ServerSortResult {
            result_code: val.result_code.into(),
            attribute_type: val.attribute_type,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Tsify)]
#[serde(rename_all = "snake_case")]
#[tsify(into_wasm_abi, from_wasm_abi)]
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
    // 9 reserved?
    Referral = 10,
    AdminLimitExceeded = 11,
    UnavailableCriticalExtension = 12,
    ConfidentialityRequired = 13,
    SaslBindInProgress = 14,
    // 15 ?
    NoSuchAttribute = 16,
    UndefinedAttributeType = 17,
    InappropriateMatching = 18,
    ConstraintViolation = 19,
    AttributeOrValueExists = 20,
    InvalidAttributeSyntax = 21,
    //22 31
    NoSuchObject = 32,
    AliasProblem = 33,
    InvalidDNSyntax = 34,
    // 35
    AliasDereferencingProblem = 36,
    // 37 - 47
    InappropriateAuthentication = 48,
    InvalidCredentials = 49,
    InsufficentAccessRights = 50,
    Busy = 51,
    Unavailable = 52,
    UnwillingToPerform = 53,
    LoopDetect = 54,
    // 55 - 63
    NamingViolation = 64,
    ObjectClassViolation = 65,
    NotAllowedOnNonLeaf = 66,
    NotALlowedOnRDN = 67,
    EntryAlreadyExists = 68,
    ObjectClassModsProhibited = 69,
    // 70
    AffectsMultipleDSAs = 71,
    // 72 - 79
    Other = 80,
    EsyncRefreshRequired = 4096,
}

sync_state_enum_convert!(
    ldap3_proto::proto::LdapResultCode,
    LdapResultCode,
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
    NoSuchObject,
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
    EsyncRefreshRequired
);

#[derive(Debug, Clone, PartialEq, Hash, Eq, PartialOrd, Ord, Serialize, Deserialize, Tsify)]
#[serde(rename_all = "snake_case")]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct ServerSortRequet {
    pub attribute_name: String,
    pub ordering_rule: Option<String>,
    pub reverse_order: bool,
}

impl From<ldap3_proto::control::ServerSortRequet> for ServerSortRequet {
    fn from(value: ldap3_proto::control::ServerSortRequet) -> Self {
        ServerSortRequet {
            attribute_name: value.attribute_name,
            ordering_rule: value.ordering_rule,
            reverse_order: value.reverse_order,
        }
    }
}

impl From<ServerSortRequet> for ldap3_proto::control::ServerSortRequet {
    fn from(val: ServerSortRequet) -> Self {
        ldap3_proto::control::ServerSortRequet {
            attribute_name: val.attribute_name,
            ordering_rule: val.ordering_rule,
            reverse_order: val.reverse_order,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Tsify, Default)]
#[serde(rename_all = "snake_case")]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct LdapControlArray(pub Vec<LdapControl>);

impl From<LdapControlArray> for Vec<ldap3_proto::control::LdapControl> {
    fn from(val: LdapControlArray) -> Self {
        val.0.into_iter().map(|v| v.into()).collect()
    }
}

impl From<Vec<ldap3_proto::control::LdapControl>> for LdapControlArray {
    fn from(value: Vec<ldap3_proto::control::LdapControl>) -> Self {
        LdapControlArray(value.into_iter().map(|v| v.into()).collect())
    }
}
