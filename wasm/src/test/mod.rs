use wasm_bindgen_test::*;

pub mod attributes_syntax;
pub mod authentication;
pub mod serialization;
wasm_bindgen_test_configure!(run_in_browser);

// #[wasm_bindgen_test]
// async fn test_derialize_modify() {
//     let js_modify = js_sys::JSON::parse(
//         r#"
//             {
//                 "operation": "Add",
//                 "attribute": {
//                     "attribute_name": "cn",
//                     "attribute_value": {
//                         "type": "string",
//                         "value": [
//                             "string",
//                             "string2"
//                         ]
//                     }
//                 }
//             }
//         "#,
//     )
//     .expect("failed to parse json");

//     let _rust_modify: crate::modify::ModifyRequest =
//         serde_wasm_bindgen::from_value(js_modify).expect("failed to deserialize modify");
// }
