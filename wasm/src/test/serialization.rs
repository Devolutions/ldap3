#[cfg(test)]
mod tests {

    #[test]
    fn test_ser_attribute_value() {
        let values = crate::schema::DisplayableAttributesValues::String(vec![
            String::from("test"),
            String::from("test2"),
        ]);
        let res = serde_json::to_string(&values).unwrap();

        assert_eq!(res, r#"{"type":0,"value":["test","test2"]}"#);
    }

    #[test]
    fn test_ser_attribute_entry() {
        let values = crate::schema::DisplayableAttributesValues::String(vec![
            String::from("test"),
            String::from("test2"),
        ]);
        let entry = crate::schema::DisplayableAttribute::new(String::from("cn"), values);
        let res = serde_json::to_string(&entry).unwrap();

        assert_eq!(
            res,
            r#"{"attribute_name":"cn","attribute_value":{"type":0,"value":["test","test2"]}}"#
        );
    }

    #[test]
    fn test_deser_attibute_value() {
        let json = r#"{"type":0,"value":["test","test2"]}"#;
        let res: crate::schema::DisplayableAttributesValues = serde_json::from_str(json).unwrap();

        assert_eq!(
            res,
            crate::schema::DisplayableAttributesValues::String(vec![
                String::from("test"),
                String::from("test2"),
            ])
        );
    }

    #[test]
    fn test_deser_attibute_entry() {
        let json =
            r#"{"attribute_name":"cn","attribute_value":{"type":0,"value":["test","test2"]}}"#;
        let res: crate::schema::DisplayableAttribute = serde_json::from_str(json).unwrap();

        assert_eq!(
            res,
            crate::schema::DisplayableAttribute::new(
                String::from("cn"),
                crate::schema::DisplayableAttributesValues::String(vec![
                    String::from("test"),
                    String::from("test2"),
                ])
            )
        );
    }

    #[test]
    fn test_ser_to_deser_attribute() {
        let values = crate::schema::DisplayableAttributesValues::String(vec![
            String::from("test"),
            String::from("test2"),
        ]);
        let entry = crate::schema::DisplayableAttribute::new(String::from("cn"), values);
        let res = serde_json::to_string(&entry).unwrap();

        let res: crate::schema::DisplayableAttribute = serde_json::from_str(&res).unwrap();

        assert_eq!(
            res,
            crate::schema::DisplayableAttribute::new(
                String::from("cn"),
                crate::schema::DisplayableAttributesValues::String(vec![
                    String::from("test"),
                    String::from("test2"),
                ])
            )
        );
    }

    #[test]
    fn test_deser_to_ser_attribute() {
        let json =
            r#"{"attribute_name":"cn","attribute_value":{"type":0,"value":["test","test2"]}}"#;
        let res: crate::schema::DisplayableAttribute = serde_json::from_str(json).unwrap();

        let res = serde_json::to_string(&res).unwrap();

        assert_eq!(
            res,
            r#"{"attribute_name":"cn","attribute_value":{"type":0,"value":["test","test2"]}}"#
        );
    }
}
