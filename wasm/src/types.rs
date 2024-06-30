use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen(typescript_custom_section)]
const s: &'static str = r#"
export type Uuid = string; // Assuming Uuid is a string

    type LdapSearchResultReference = {
        uris: string[];
    };
"#;
