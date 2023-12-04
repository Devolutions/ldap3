use anyhow::{Ok, Result};
use wasm_bindgen::prelude::*;

use serde::{Deserialize, Serialize};
use tracing::debug;

use tsify::Tsify;

use crate::error::JsErrorValue;
use crate::{to_js_error, JsResult};

use super::displayables::{AttibuteValue, DisplayableAttribute};
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

    pub(crate) fn from_om_syntax_to_vec(om_syntax: &str) -> Vec<LdapSyntax> {
        match om_syntax {
            "1" => vec![LdapSyntax::Boolean],
            "10" => vec![LdapSyntax::Enumeration],
            "2" => vec![LdapSyntax::Integer],
            "65" => vec![LdapSyntax::LargeInteger],
            "127" => vec![
                LdapSyntax::ObjectAccessPoint,
                LdapSyntax::ObjectDnString,
                LdapSyntax::ObjectOrName,
                LdapSyntax::ObjectDnBinary,
                LdapSyntax::ObjectDsDn,
                LdapSyntax::ObjectPresentationAddress,
                LdapSyntax::ObjectReplicaLink,
            ],
            "27" => vec![LdapSyntax::StringCase],
            "22" => vec![LdapSyntax::StringIa5],
            "66" => vec![LdapSyntax::StringNtSecDesc],
            "18" => vec![LdapSyntax::StringNumeric],
            "6" => vec![LdapSyntax::StringObjectIdentifier],
            "4" => vec![LdapSyntax::StringOctet],
            "19" => vec![LdapSyntax::StringPrintable],
            "20" => vec![LdapSyntax::StringTeletex],
            "64" => vec![LdapSyntax::StringUnicode],
            "23" => vec![LdapSyntax::StringUtcTime],
            "24" => vec![LdapSyntax::StringGeneralizedTime],
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
    a combination of these two identifies a attibute syntax
     */
    pub fn parse_with_syntax_value(
        oid: String,
        om_syntax: String,
        attribute_value: AttibuteValue,
    ) -> JsResult<Vec<JsValue>> {
        let syntax = LdapSyntax::from_oid_to_vec(&oid)
            .into_iter()
            .find(|v| v.om_syntax() == &om_syntax)
            .ok_or(to_js_error!("No syntax found"))?;
        LdapParser::to_displayable_impl(syntax, attribute_value)
            .map_err(|e| to_js_error!("{:?}", e))
    }

    pub fn parse_value(
        syntax: LdapSyntax,
        attribute_value: AttibuteValue,
    ) -> JsResult<Vec<JsValue>> {
        LdapParser::to_displayable_impl(syntax, attribute_value)
            .map_err(|e| to_js_error!("{:?}", e))
    }

    fn to_displayable_impl(
        syntax: LdapSyntax,
        attribute_value: AttibuteValue,
    ) -> Result<Vec<JsValue>> {
        let bytes_arr = attribute_value.0;
        match syntax {
            LdapSyntax::StringUnicode
            | LdapSyntax::StringSid
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
            | LdapSyntax::ObjectReplicaLink => LdapSyntax::bytes_arr_as_js_strings(bytes_arr),
            LdapSyntax::StringGeneralizedTime => {
                LdapSyntax::bytes_arr_as_js_date_generialized_time(bytes_arr)
            }
            LdapSyntax::StringUtcTime => LdapSyntax::bytes_arr_to_date_utc(bytes_arr),
            LdapSyntax::LargeInteger => {
                let numbers = bytes_arr
                    .into_iter()
                    .map(|v| {
                        let byte_arr: Result<[u8; 8], anyhow::Error> = v.try_into().map_err(|e| {
                            anyhow::anyhow!("expecting a bytes arry of length 8, found {:?}", e)
                        });
                        byte_arr
                    })
                    .map(|res| {
                        let byte_arr = res?;
                        let value = i64::from_be_bytes(byte_arr);
                        Ok(JsValue::from_f64(value as f64))
                    })
                    .collect::<Result<Vec<_>, anyhow::Error>>()?;
                Ok(numbers)
            }
            LdapSyntax::Integer | LdapSyntax::Enumeration => {
                let numbers = bytes_arr
                    .into_iter()
                    .map(|v| {
                        let byte_arr: Result<[u8; 4], anyhow::Error> = v.try_into().map_err(|e| {
                            anyhow::anyhow!("expecting a bytes arry of length 4, found {:?}", e)
                        });
                        byte_arr
                    })
                    .map(|res| {
                        let byte_arr = res?;
                        let value = i32::from_be_bytes(byte_arr);
                        Ok(JsValue::from(value))
                    })
                    .collect::<Result<Vec<_>, anyhow::Error>>()?;
                Ok(numbers)
            }
            LdapSyntax::StringOctet | LdapSyntax::ObjectDnBinary => {
                LdapSyntax::bytes_arr_as_js_uint8arr(bytes_arr)
            }
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
                Ok(JsValue::from(uint8arr))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(uint8arr)
    }

    fn bytes_arr_as_js_date_generialized_time(bytes_arr: Vec<Vec<u8>>) -> Result<Vec<JsValue>> {
        let strings = LdapSyntax::bytes_arr_to_string(bytes_arr)?;
        let dates = strings
            .into_iter()
            .map(|s| LdapSyntax::string_to_js_date_generialized_time(s))
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

/*
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/7cda533e-d7a4-4aec-a517-91d02ff4a1aa
Each Syntax is identified by the combination of an OID and an OM syntax.

In active directory, the integer syntax is restrcted to 32 bit integers. the large integer syntax is 64 bit integers.

*/

/*
 Ultimately, I want to give a function such that, given a attribute, and a oid and a om_syntax I shall be able to convert it to a DisplayableAttribute
*/
