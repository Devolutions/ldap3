// use crate::{
//     ldap_session::DisplayableAttributesValueType,
//     schema::{DisplayableAttribute, DisplayableAttributesValues},
// };

// struct AttributeBuilder {
//     attribute_name: Option<String>,
//     attribute_type: Option<DisplayableAttributesValueType>,
//     attribute_value: Option<DisplayableAttribute>,
// }

// impl AttributeBuilder {
//     pub fn new() -> Self {
//         Self {
//             attribute_name: None,
//             attribute_value: None,
//             attribute_type: None,
//         }
//     }

//     pub fn attribute_name(mut self, name: String) -> Self {
//         self.attribute_name = Some(name);
//         self
//     }

//     pub fn string_attributes(mut self, value: Vec<String>) -> Self {
//         let AttributeBuilder {
//             attribute_name,
//             attribute_type,
//             ..
//         } = self;
//         self.attribute_value = Some(DisplayableAttribute::new(
//             attribute_name.unwrap(),
//             DisplayableAttributesValues::String(value),
//         ));
//         todo!()
//     }
// }

// pub struct AttributeValueStringBuilder {
//     attribute_name: Option<String>,
//     attribute_values: Vec<String>,
// }
#[macro_export]
macro_rules! send_message {
    ($self:ident, $msg:expr) => {
        $self
            .frame
            .as_ref()
            .borrow_mut()
            .send($msg)
            .await
            .map_err(|e| to_js_error!("failed to send message {:?}", e))?
    };
}

#[macro_export]
macro_rules! receive_message {
    ($self:ident) => {
        $self
            .frame
            .as_ref()
            .borrow_mut()
            .next()
            .await
            .ok_or(to_js_error!(" no result "))?
            .map_err(|e| to_js_error!("{:?}", e))?
    };
}
