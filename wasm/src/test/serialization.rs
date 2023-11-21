#[cfg(test)]
mod tests {
    use ldap3_proto::proto::{LdapControl, SyncRequestMode, SyncStateValue};

    use crate::{
        modify::DisplayableModify,
        schema::displayables::{DisplayableAttribute, DisplayableAttributesValues},
    };

    #[test]
    fn test_ser_attribute_value() {
        let values = crate::schema::displayables::DisplayableAttributesValues::String(vec![
            String::from("test"),
            String::from("test2"),
        ]);
        let res = serde_json::to_string(&values).unwrap();

        assert_eq!(res, r#"{"type":"string","value":["test","test2"]}"#);
    }

    #[test]
    fn test_ser_attribute_entry() {
        let values = crate::schema::displayables::DisplayableAttributesValues::String(vec![
            String::from("test"),
            String::from("test2"),
        ]);
        let entry =
            crate::schema::displayables::DisplayableAttribute::new(String::from("cn"), values);
        let res = serde_json::to_string(&entry).unwrap();

        assert_eq!(
            res,
            r#"{"attribute_name":"cn","attribute_value":{"type":"string","value":["test","test2"]}}"#
        );
    }

    #[test]
    fn test_deser_attibute_value() {
        let json = r#"{"type":"string","value":["test","test2"]}"#;
        let res: crate::schema::displayables::DisplayableAttributesValues =
            serde_json::from_str(json).unwrap();

        assert_eq!(
            res,
            crate::schema::displayables::DisplayableAttributesValues::String(vec![
                String::from("test"),
                String::from("test2"),
            ])
        );
    }

    #[test]
    fn test_deser_attibute_entry() {
        let json = r#"{"attribute_name":"cn","attribute_value":{"type":"string","value":["test","test2"]}}"#;
        let res: crate::schema::displayables::DisplayableAttribute =
            serde_json::from_str(json).unwrap();

        assert_eq!(
            res,
            crate::schema::displayables::DisplayableAttribute::new(
                String::from("cn"),
                crate::schema::displayables::DisplayableAttributesValues::String(vec![
                    String::from("test"),
                    String::from("test2"),
                ])
            )
        );
    }

    #[test]
    fn test_ser_to_deser_attribute() {
        let values = crate::schema::displayables::DisplayableAttributesValues::String(vec![
            String::from("test"),
            String::from("test2"),
        ]);
        let entry =
            crate::schema::displayables::DisplayableAttribute::new(String::from("cn"), values);
        let res = serde_json::to_string(&entry).unwrap();

        let res: crate::schema::displayables::DisplayableAttribute =
            serde_json::from_str(&res).unwrap();

        assert_eq!(
            res,
            crate::schema::displayables::DisplayableAttribute::new(
                String::from("cn"),
                crate::schema::displayables::DisplayableAttributesValues::String(vec![
                    String::from("test"),
                    String::from("test2"),
                ])
            )
        );
    }

    #[test]
    fn test_deser_to_ser_attribute() {
        let json = r#"{"attribute_name":"cn","attribute_value":{"type":"string","value":["test","test2"]}}"#;
        let res: crate::schema::displayables::DisplayableAttribute =
            serde_json::from_str(json).unwrap();

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

    #[test]
    fn test_serde_modify() {
        let modify = DisplayableModify {
            operation: ldap3_proto::proto::LdapModifyType::Add.into(),
            attribute: DisplayableAttribute::new(
                "dn".to_string(),
                DisplayableAttributesValues::String(vec!["test".to_string(), "test2".to_string()]),
            ),
        };

        let res = serde_json::to_string(&modify).unwrap();
        let expected = r#"{"operation":"Add","attribute":{"attribute_name":"dn","attribute_value":{"type":"string","value":["test","test2"]}}}"#;
        assert_eq!(res, expected)
    }
}
