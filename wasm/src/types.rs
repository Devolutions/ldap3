use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen(typescript_custom_section)]
const s: &'static str = r#"
export type SyncRequestMode = 'refresh_only' | 'refresh_and_persist';
export type SyncStateValue = 'present' | 'add' | 'modify' | 'delete';

export type Uuid = string; // Assuming Uuid is a string

export type LdapControl = 
    | { type: 'sync_request', criticality: boolean, mode: SyncRequestMode, cookie?: Uint8Array, reload_hint: boolean }
    | { type: 'sync_state', state: SyncStateValue, entry_uuid: Uuid, cookie?: Uint8Array }
    | { type: 'sync_done', cookie?: Uint8Array, refresh_deletes: boolean }
    | { type: 'ad_dirsync', flags: number, max_bytes: number, cookie?: Uint8Array }
    | { type: 'simple_paged_results', size: number, cookie: Uint8Array }
    | { type: 'manage_dsa_it', criticality: boolean };

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
