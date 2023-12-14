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

impl Into<ldap3_proto::control::LdapControl> for LdapControl {
    fn into(self) -> ldap3_proto::control::LdapControl {
        match self {
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
    result_code: ServerSortResultCode,
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

impl Into<ldap3_proto::control::ServerSortResult> for ServerSortResult {
    fn into(self) -> ldap3_proto::control::ServerSortResult {
        ldap3_proto::control::ServerSortResult {
            result_code: self.result_code.into(),
            attribute_type: self.attribute_type,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Tsify)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub enum ServerSortResultCode {
    Success = 0,
    OperationsError = 1,
    TimeLimitExceeded = 3,
    StrongAuthRequired = 8,
    AdminLimitExceeded = 11,
    NoSuchAttribute = 16,
    InappropriateMatching = 18,
    InsufficientAccessRights = 50,
    Busy = 51,
    UnwillingToPerform = 53,
    Other = 80,
}

sync_state_enum_convert!(
    ldap3_proto::control::ServerSortResultCode,
    ServerSortResultCode,
    Success,
    OperationsError,
    TimeLimitExceeded,
    StrongAuthRequired,
    AdminLimitExceeded,
    NoSuchAttribute,
    InappropriateMatching,
    InsufficientAccessRights,
    Busy,
    UnwillingToPerform,
    Other
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

impl Into<ldap3_proto::control::ServerSortRequet> for ServerSortRequet {
    fn into(self) -> ldap3_proto::control::ServerSortRequet {
        ldap3_proto::control::ServerSortRequet {
            attribute_name: self.attribute_name,
            ordering_rule: self.ordering_rule,
            reverse_order: self.reverse_order,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Tsify, Default)]
#[serde(rename_all = "snake_case")]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct LdapControlArray(pub Vec<LdapControl>);

impl Into<Vec<ldap3_proto::control::LdapControl>> for LdapControlArray {
    fn into(self) -> Vec<ldap3_proto::control::LdapControl> {
        self.0.into_iter().map(|v| v.into()).collect()
    }
}

impl From<Vec<ldap3_proto::control::LdapControl>> for LdapControlArray {
    fn from(value: Vec<ldap3_proto::control::LdapControl>) -> Self {
        LdapControlArray(value.into_iter().map(|v| v.into()).collect())
    }
}
