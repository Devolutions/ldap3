// use wasm_bindgen::JsValue;
// use wasm_bindgen_test::{console_log, wasm_bindgen_test};

// use crate::schema::{attribute_schema::LdapSyntax, displayables::AttibuteValue};

// #[wasm_bindgen_test]
// pub fn test_parse_larg_integer() {
//     let bytes = vec![vec![0, 0, 0, 0, 0, 0, 0, 0], vec![0, 0, 0, 0, 0, 0, 0, 1]];
//     let big_integer = LdapSyntax::LargeInteger;

//     let attribute_value = AttibuteValue::Bytes(bytes);

//     let mut res = LdapSyntax::parse(
//         big_integer.oid().to_string(),
//         big_integer.om_syntax().to_string(),
//         attribute_value,
//     )
//     .unwrap();
//     let one = res.pop().unwrap();
//     let zero = res.pop().unwrap();
//     assert_eq!(one.as_f64().unwrap(), 1 as f64);
//     assert_eq!(zero.as_f64().unwrap(), 0 as f64);
// }

// #[wasm_bindgen_test]
// pub fn test_parse_date_generalized() {
//     tracing_wasm::set_as_global_default();
//     let bytes = vec!["20231031183842.0Z".as_bytes().to_vec()];
//     let generalized_time = LdapSyntax::StringGeneralizedTime;

//     let attribute_value = AttibuteValue::Bytes(bytes);

//     let mut res = LdapSyntax::parse(
//         generalized_time.oid().to_string(),
//         generalized_time.om_syntax().to_string(),
//         attribute_value,
//     )
//     .unwrap();
//     let date = res.pop().unwrap();
//     let date = js_sys::Date::from(date);

//     // assert that the date is the same as the one we parsed
//     assert_eq!(date.get_utc_full_year(), 2023);
//     assert_eq!(date.get_utc_month(), 9); // why is it 9 and not 10? this should be fully investigated !IMPORTANT
//     assert_eq!(date.get_utc_date(), 31);
//     assert_eq!(date.get_utc_hours(), 18);
//     assert_eq!(date.get_utc_minutes(), 38);
//     assert_eq!(date.get_utc_seconds(), 42);
//     assert_eq!(date.get_utc_milliseconds(), 0);
// }
