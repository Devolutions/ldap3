use wasm_bindgen::prelude::*;

#[wasm_bindgen(typescript_custom_section)]
const ATTRIBUTE_VALUE_TYPE: &'static str = r#"
export type AttributeValue = { type: DisplayableAttributesValueType, value: string[] | number[] | boolean[] | Date[] | number[][] | number[] }; 
"#;

#[wasm_bindgen(typescript_custom_section)]
const ATTRIBUTE_TYPE: &'static str = r#"
export type Attribute = { attribute_name:string, attribute_value: AttributeValue };
"#;
