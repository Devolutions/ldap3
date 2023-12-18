use ldap3_proto::proto;
use serde::{Deserialize, Serialize};
use tsify::Tsify;

use super::{control::LdapControl, ldap_ops::LdapOp};

#[derive(Debug, Serialize, Deserialize, Tsify)]
#[serde(rename_all = "snake_case")]
#[tsify(into_wasm_abi)]
pub struct LdapMsg {
    pub msgid: i32,
    pub op: LdapOp,
    pub ctrl: Vec<LdapControl>,
}

impl From<LdapMsg> for proto::LdapMsg {
    fn from(msg: LdapMsg) -> Self {
        proto::LdapMsg {
            msgid: msg.msgid,
            op: msg.op.try_into().unwrap(),
            ctrl: msg.ctrl.into_iter().map(|c| c.into()).collect(),
        }
    }
}
