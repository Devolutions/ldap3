#[cfg(test)]
mod tests {
    use ldap3_proto::proto::{LdapControl, SyncRequestMode, SyncStateValue};

    #[test]
    fn test_deser_to_ser_attribute() {
        let json = r#"{"attribute_name":"cn","attribute_value":{"type":"string","value":["test","test2"]}}"#;
        let res: crate::schema::search_objects::Attribute = serde_json::from_str(json).unwrap();

        let res = serde_json::to_string(&res).unwrap();
        print!("{}", res);
        assert_eq!(
            res,
            r#"{"attribute_name":"cn","attribute_value":{"type":"string","value":["test","test2"]}}"#
        );
    }

    #[test]
    fn test_serde_control_sync_request() {
        use serde_json;

        // Create an instance of LdapControl::SyncRequest
        let control = LdapControl::SyncRequest {
            criticality: true,
            mode: SyncRequestMode::RefreshOnly, // replace with actual mode
            cookie: Some(vec![1, 2, 3]),
            reload_hint: false,
        };

        // Serialize it to a JSON string
        let serialized = serde_json::to_string(&control).unwrap();

        assert_eq!(
            serialized,
            r#"{"sync_request":{"criticality":true,"mode":"refresh_only","cookie":[1,2,3],"reload_hint":false}}"#
        );
    }

    #[test]
    fn test_deser_control_sync_request() {
        use serde_json;

        let json = r#"{"sync_request":{"criticality":true,"mode":"refresh_only","cookie":[1,2,3],"reload_hint":false}}"#;
        let res: LdapControl = serde_json::from_str(json).unwrap();

        assert_eq!(
            res,
            LdapControl::SyncRequest {
                criticality: true,
                mode: SyncRequestMode::RefreshOnly,
                cookie: Some(vec![1, 2, 3]),
                reload_hint: false,
            }
        );
    }

    #[test]
    fn test_serde_control_sync_state() {
        use serde_json;
        use uuid::Uuid;

        // Create an instance of LdapControl::SyncState
        let control = LdapControl::SyncState {
            state: SyncStateValue::Present,
            entry_uuid: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            cookie: Some(vec![1, 2, 3]),
        };

        // Serialize it to a JSON string
        let serialized = serde_json::to_string(&control).unwrap();
        println!("{}", serialized);
        // Expected JSON string
        let expected = r#"{"sync_state":{"state":"present","entry_uuid":"550e8400-e29b-41d4-a716-446655440000","cookie":[1,2,3]}}"#;

        // Assert that the serialized string matches the expected string
        assert_eq!(serialized, expected);
    }
}
