#![allow(non_snake_case)]
use anyhow::Result;
use wasm_bindgen::prelude::*;

use serde::{Deserialize, Serialize};
use tracing::debug;

use tsify::Tsify;

use crate::dto::search::AttributeValue;
use crate::error::JsErrorValue;
use crate::JsResult;
use enum_assoc::Assoc;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Assoc, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
#[func(pub fn oid(&self) -> &'static str)]
#[func(pub fn om_syntax(&self) -> &'static str)]
pub enum LdapSyntax {
    #[assoc(om_syntax = "1")]
    #[assoc(oid = "2.5.5.8")]
    Boolean,

    #[assoc(om_syntax = "10")]
    #[assoc(oid = "2.5.5.9")]
    Enumeration,

    #[assoc(om_syntax = "2")]
    #[assoc(oid = "2.5.5.9")]
    Integer,

    /*
       example attributes: account expires
    */
    #[assoc(om_syntax = "65")]
    #[assoc(oid = "2.5.5.16")]
    LargeInteger,

    #[assoc(om_syntax = "127")]
    #[assoc(oid = "2.5.5.14")]
    ObjectAccessPoint,

    #[assoc(om_syntax = "127")]
    #[assoc(oid = "2.5.5.14")]
    ObjectDnString,

    #[assoc(om_syntax = "127")]
    #[assoc(oid = "2.5.5.7")]
    ObjectOrName,

    #[assoc(om_syntax = "127")]
    #[assoc(oid = "2.5.5.7")]
    ObjectDnBinary,

    #[assoc(om_syntax = "127")]
    #[assoc(oid = "2.5.5.1")]
    ObjectDsDn,

    #[assoc(om_syntax = "127")]
    #[assoc(oid = "2.5.5.13")]
    ObjectPresentationAddress,

    #[assoc(om_syntax = "127")]
    #[assoc(oid = "2.5.5.10")]
    ObjectReplicaLink,

    #[assoc(om_syntax = "27")]
    #[assoc(oid = "2.5.5.3")]
    StringCase,

    #[assoc(om_syntax = "22")]
    #[assoc(oid = "2.5.5.5")]
    StringIa5,

    #[assoc(om_syntax = "66")]
    #[assoc(oid = "2.5.5.15")]
    StringNtSecDesc,

    #[assoc(om_syntax = "18")]
    #[assoc(oid = "2.5.5.6")]
    StringNumeric,

    #[assoc(om_syntax = "6")]
    #[assoc(oid = "2.5.5.2")]
    StringObjectIdentifier,

    #[assoc(om_syntax = "4")]
    #[assoc(oid = "2.5.5.10")]
    StringOctet,

    #[assoc(om_syntax = "19")]
    #[assoc(oid = "2.5.5.5")]
    StringPrintable,

    #[assoc(om_syntax = "4")]
    #[assoc(oid = "2.5.5.17")]
    StringSid,

    #[assoc(om_syntax = "20")]
    #[assoc(oid = "2.5.5.4")]
    StringTeletex,

    #[assoc(om_syntax = "64")]
    #[assoc(oid = "2.5.5.12")]
    StringUnicode,

    #[assoc(om_syntax = "23")]
    #[assoc(oid = "2.5.5.11")]
    StringUtcTime,

    #[assoc(om_syntax = "24")]
    #[assoc(oid = "2.5.5.11")]
    StringGeneralizedTime,
}

#[wasm_bindgen]
impl LdapSyntax {
    pub(crate) fn from_oid_to_vec(oid: &str) -> Vec<LdapSyntax> {
        match oid {
            "2.5.5.8" => vec![LdapSyntax::Boolean],
            "2.5.5.9" => vec![LdapSyntax::Enumeration, LdapSyntax::Integer],
            "2.5.5.16" => vec![LdapSyntax::LargeInteger],
            "2.5.5.14" => vec![LdapSyntax::ObjectAccessPoint, LdapSyntax::ObjectDnString],
            "2.5.5.7" => vec![LdapSyntax::ObjectOrName, LdapSyntax::ObjectDnBinary],
            "2.5.5.1" => vec![LdapSyntax::ObjectDsDn],
            "2.5.5.13" => vec![LdapSyntax::ObjectPresentationAddress],
            "2.5.5.10" => vec![LdapSyntax::ObjectReplicaLink, LdapSyntax::StringOctet],
            "2.5.5.3" => vec![LdapSyntax::StringCase],
            "2.5.5.5" => vec![LdapSyntax::StringIa5, LdapSyntax::StringPrintable],
            "2.5.5.15" => vec![LdapSyntax::StringNtSecDesc],
            "2.5.5.6" => vec![LdapSyntax::StringNumeric],
            "2.5.5.2" => vec![LdapSyntax::StringObjectIdentifier],
            "2.5.5.17" => vec![LdapSyntax::StringSid],
            "2.5.5.4" => vec![LdapSyntax::StringTeletex],
            "2.5.5.12" => vec![LdapSyntax::StringUnicode],
            "2.5.5.11" => vec![LdapSyntax::StringUtcTime, LdapSyntax::StringGeneralizedTime],
            _ => vec![],
        }
    }
}

#[wasm_bindgen]
pub struct LdapParser;

#[wasm_bindgen]
impl LdapParser {
    /*
    oid is the attributeSyntax from schema
    om_syntax is the oMSyntax from schema
    a combination of these two identifies a attribute syntax
     */
    pub fn parse_with_syntax_value(
        oid: String,
        om_syntax: String,
        attribute_value: AttributeValue,
    ) -> JsResult<Vec<JsValue>> {
        let syntax = LdapSyntax::from_oid_to_vec(&oid)
            .into_iter()
            .find(|v| v.om_syntax() == om_syntax)
            .ok_or_else(|| JsErrorValue::msg("no syntax found"))?;
        LdapParser::to_displayable_impl(syntax, attribute_value).map_err(JsErrorValue::from_anyhow)
    }

    pub fn parse_value(
        syntax: LdapSyntax,
        attribute_value: AttributeValue,
    ) -> JsResult<Vec<JsValue>> {
        LdapParser::to_displayable_impl(syntax, attribute_value).map_err(JsErrorValue::from_anyhow)
    }

    fn to_displayable_impl(
        syntax: LdapSyntax,
        attribute_value: AttributeValue,
    ) -> Result<Vec<JsValue>> {
        let bytes_arr = attribute_value.into();
        match syntax {
            LdapSyntax::StringUnicode
            | LdapSyntax::StringCase
            | LdapSyntax::StringIa5
            | LdapSyntax::StringNtSecDesc
            | LdapSyntax::StringNumeric
            | LdapSyntax::StringPrintable
            | LdapSyntax::StringTeletex
            | LdapSyntax::ObjectDnString
            | LdapSyntax::ObjectDsDn
            | LdapSyntax::StringObjectIdentifier
            | LdapSyntax::ObjectOrName
            | LdapSyntax::ObjectAccessPoint
            | LdapSyntax::ObjectPresentationAddress
            | LdapSyntax::ObjectReplicaLink
            | LdapSyntax::Integer // this is funny, MSDoc says it is a 32 bit integer, but it is actually a string
            | LdapSyntax::LargeInteger // so is this
            | LdapSyntax::Enumeration
            => LdapSyntax::bytes_arr_as_js_strings(bytes_arr),
            LdapSyntax::StringSid => LdapSyntax::bytes_arr_as_sid(bytes_arr),
            LdapSyntax::StringGeneralizedTime => LdapSyntax::bytes_arr_as_js_date_generialized_time(bytes_arr),
            LdapSyntax::StringUtcTime => LdapSyntax::bytes_arr_to_date_utc(bytes_arr),
            LdapSyntax::StringOctet | LdapSyntax::ObjectDnBinary => LdapSyntax::bytes_arr_as_js_uint8arr(bytes_arr),
            LdapSyntax::Boolean => {
                let strings = LdapSyntax::bytes_arr_to_string(bytes_arr)?;
                let res = strings
                    .into_iter()
                    .map(|v| JsValue::from_bool(v == "TRUE"))
                    .collect::<Vec<_>>();
                Ok(res)
            }
        }
    }
}

impl LdapSyntax {
    fn bytes_arr_to_string(bytes_arr: Vec<Vec<u8>>) -> Result<Vec<String>> {
        let strings = bytes_arr
            .into_iter()
            .map(|v| String::from_utf8(v).map_err(|e| anyhow::anyhow!("{:?}", e)))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(strings)
    }

    fn bytes_arr_as_js_strings(bytes_arr: Vec<Vec<u8>>) -> Result<Vec<JsValue>> {
        let strings = bytes_arr
            .into_iter()
            .map(|v| String::from_utf8(v).map_err(|e| anyhow::anyhow!("{:?}", e)))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|string| JsValue::from_str(string.as_str()))
            .collect::<Vec<_>>();
        Ok(strings)
    }

    fn bytes_arr_as_js_uint8arr(bytes_arr: Vec<Vec<u8>>) -> Result<Vec<JsValue>> {
        let uint8arr = bytes_arr
            .into_iter()
            .map(|v| {
                let uint8arr = js_sys::Uint8Array::from(v.as_slice());
                JsValue::from(uint8arr)
            })
            .collect::<Vec<_>>();
        Ok(uint8arr)
    }

    fn bytes_arr_as_sid(bytes_arr: Vec<Vec<u8>>) -> Result<Vec<JsValue>> {
        let strings: Result<Vec<_>, _> = bytes_arr
            .into_iter()
            .map(|v| decode_sid(&v).ok_or(anyhow::anyhow!("Invalid SID")))
            .map(|string| string.map(|v| JsValue::from_str(v.as_str())))
            .collect();
        strings
    }

    fn bytes_arr_as_js_date_generialized_time(bytes_arr: Vec<Vec<u8>>) -> Result<Vec<JsValue>> {
        let strings = LdapSyntax::bytes_arr_to_string(bytes_arr)?;
        let dates = strings
            .into_iter()
            .map(LdapSyntax::string_to_js_date_generialized_time)
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .map(JsValue::from)
            .collect::<Vec<_>>();
        Ok(dates)
    }

    pub fn string_to_js_date_generialized_time(generalized_time: String) -> Result<js_sys::Date> {
        let re = regex::Regex::new(
            r"^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.\d+)?(Z|[\+-]\d{4})?$",
        )
        .unwrap();
        let caps = re
            .captures(&generalized_time)
            .ok_or(anyhow::anyhow!("Invalid Generalized Time format"))?;

        let year = caps.get(1).unwrap().as_str();
        let month: u32 = caps.get(2).unwrap().as_str().parse().unwrap();
        let day = caps.get(3).unwrap().as_str();
        let hour = caps.get(4).unwrap().as_str();
        let minute = caps.get(5).unwrap().as_str();
        let second = caps.get(6).unwrap().as_str();
        let fractional_second = caps.get(7).map_or("", |m| m.as_str());
        let timezone = caps.get(8).map_or("", |m| m.as_str());

        let js_date_string = format!(
            "{}-{:02}-{}T{}:{}:{}{}{}",
            year,
            (month),
            day,
            hour,
            minute,
            second,
            fractional_second,
            timezone
        );
        let js_date_string = JsValue::from_str(js_date_string.as_str());
        debug!("js_date_string: {:?}", &js_date_string);
        let res = js_sys::Date::new(&js_date_string);
        Ok(res)
    }

    fn bytes_arr_to_date_utc(bytes_arr: Vec<Vec<u8>>) -> Result<Vec<JsValue>> {
        bytes_arr
            .into_iter()
            .map(|bytes| {
                // Ensure each sub-vector has exactly 4 bytes
                if bytes.len() != 4 {
                    return Err(anyhow::anyhow!("Invalid byte array length"));
                }

                // Convert the byte array to a u32 UNIX timestamp
                let timestamp = u32::from_be_bytes(
                    bytes
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("Conversion error"))?,
                );

                // Create a js_sys::Date object from the UNIX timestamp
                // Note: The timestamp is multiplied by 1000 because js_sys::Date expects milliseconds
                Ok(JsValue::from(js_sys::Date::new(&JsValue::from_f64(
                    (timestamp as f64) * 1000.0,
                ))))
            })
            .collect::<Result<Vec<JsValue>, _>>()
    }
}

#[wasm_bindgen]
impl LdapParser {
    pub fn to_string(attribute_value: AttributeValue) -> JsResult<Vec<String>> {
        let bytes_arr: Vec<Vec<u8>> = attribute_value.into();
        let strings = bytes_arr
            .into_iter()
            .map(|v| String::from_utf8(v).map_err(|e| anyhow::anyhow!("{:?}", e)))
            .collect::<Result<Vec<_>, _>>()
            .map_err(JsErrorValue::from_anyhow)?;
        Ok(strings)
    }

    pub fn to_date(attribute_value: AttributeValue) -> JsResult<Vec<js_sys::Date>> {
        let bytes_arr: Vec<Vec<u8>> = attribute_value.into();
        let strings = bytes_arr
            .into_iter()
            .map(|v| String::from_utf8(v).map_err(|e| anyhow::anyhow!("{:?}", e)))
            .collect::<Result<Vec<_>, _>>()
            .map_err(JsErrorValue::from_anyhow)?;
        let dates = strings
            .into_iter()
            .map(LdapSyntax::string_to_js_date_generialized_time)
            .collect::<Result<Vec<_>>>()
            .map_err(JsErrorValue::from_anyhow)?;
        Ok(dates)
    }

    pub fn to_uint_8_array(attribute_value: AttributeValue) -> JsResult<Vec<js_sys::Uint8Array>> {
        let bytes_arr: Vec<Vec<u8>> = attribute_value.into();
        let uint8arr = bytes_arr
            .into_iter()
            .map(|v| js_sys::Uint8Array::from(v.as_slice()))
            .collect::<Vec<_>>();
        Ok(uint8arr)
    }

    pub fn to_boolean(attribute_value: AttributeValue) -> JsResult<JsBooleans> {
        let bytes_arr: Vec<Vec<u8>> = attribute_value.into();
        let res = bytes_arr
            .into_iter()
            .map(|v| String::from_utf8(v).map_err(JsErrorValue::new))
            .map(|v| Ok(v? == "TRUE"))
            .collect::<Result<Vec<_>, JsErrorValue>>()?;

        Ok(res.into())
    }
}

#[derive(Debug, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct JsBooleans(pub(crate) Vec<bool>);

impl From<Vec<bool>> for JsBooleans {
    fn from(value: Vec<bool>) -> Self {
        JsBooleans(value)
    }
}

fn decode_sid(sid: &[u8]) -> Option<String> {
    if sid.len() < 8 {
        return None;
    }

    let mut s = String::from("S-");

    // get version
    let revision = sid[0];
    s.push_str(&revision.to_string());

    // next byte is the count of sub-authorities
    let count_sub_auths = sid[1] as usize;

    // get the authority
    let authority = (sid[2] as u64) << 40
        | (sid[3] as u64) << 32
        | (sid[4] as u64) << 24
        | (sid[5] as u64) << 16
        | (sid[6] as u64) << 8
        | sid[7] as u64;

    s.push('-');
    s.push_str(&authority.to_string());

    // check for the length of the sid with sub authorities
    if sid.len() < 8 + count_sub_auths * 4 {
        return None;
    }

    for i in 0..count_sub_auths {
        let offset = 8 + i * 4;
        let sub_authority = (sid[offset] as u32)
            | (sid[offset + 1] as u32) << 8
            | (sid[offset + 2] as u32) << 16
            | (sid[offset + 3] as u32) << 24;

        s.push('-');
        s.push_str(&sub_authority.to_string());
    }

    Some(s)
}
