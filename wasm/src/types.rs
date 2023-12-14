use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen(typescript_custom_section)]
const s: &'static str = r#"
export type Uuid = string; // Assuming Uuid is a string

    type LdapSearchResultReference = {
        uris: string[];
    };

    type LdapResultCode = 'success' | 'operations_error' | 'protocol_error' | 'time_limit_exceeded' | 'size_limit_exceeded' | 'compare_false' | 'compare_true' | 'auth_method_not_supported' | 'stronger_auth_required' | 'referral' | 'admin_limit_exceeded' | 'unavailable_critical_extension' | 'confidentiality_required' | 'sasl_bind_in_progress' | 'no_such_attribute' | 'undefined_attribute_type' | 'inappropriate_matching' | 'constraint_violation' | 'attribute_or_value_exists' | 'invalid_attribute_syntax' | 'no_such_object' | 'alias_problem' | 'invalid_dn_syntax' | 'alias_dereferencing_problem' | 'inappropriate_authentication' | 'invalid_credentials' | 'insufficent_access_rights' | 'busy' | 'unavailable' | 'unwilling_to_perform' | 'loop_detect' | 'naming_violation' | 'object_class_violation' | 'not_allowed_on_non_leaf' | 'not_allowed_on_rdn' | 'entry_already_exists' | 'object_class_mods_prohibited' | 'affects_multiple_dsas' | 'other' | 'esync_refresh_required';

    type LdapResult = {
        code: LdapResultCode;
        matcheddn: string;
        message: string;
        referral: string[];
    };
"#;
