// use std::{io, vec};

// use ldap3_proto::{LdapCodec, LdapMsg};
// use tokio_util::{
//     bytes::Buf,
//     codec::{Decoder, Encoder},
// };

// use crate::{authentication::SecurityProvider, dbg_u8_itr};

// pub enum EncryptioinOption {
//     Encryption(Box<dyn SecurityProvider>),
//     NoEncryption,
// }

// impl Default for EncryptioinOption {
//     fn default() -> Self {
//         EncryptioinOption::NoEncryption
//     }
// }

// #[derive(Default)]
// pub struct EncryptionCodec {
//     codec: LdapCodec,
//     encryption: EncryptioinOption,
// }

// impl EncryptionCodec {
//     pub fn new(codec: LdapCodec, encryption: EncryptioinOption) -> Self {
//         Self { codec, encryption }
//     }

//     pub fn set_encryption(&mut self, encryption: EncryptioinOption) {
//         self.encryption = encryption;
//     }
// }

// impl Decoder for EncryptionCodec {
//     type Item = LdapMsg;
//     type Error = io::Error;

//     fn decode(
//         &mut self,
//         src: &mut tokio_util::bytes::BytesMut,
//     ) -> Result<Option<Self::Item>, Self::Error> {
//         match self.encryption {
//             EncryptioinOption::Encryption(ref mut security) => {
//                 // print src as hex string separated by space
//                 dbg_u8_itr(src.iter());
//                 if src.remaining() < 4 {
//                     tracing::info!("not enough bytes to read message length");
//                     return Ok(None);
//                 }
//                 let mut length = src.take(4);
//                 let size = length.get_u32();
//                 tracing::info!("length to read is: {}", size);
//                 if src.remaining() < size as usize {
//                     tracing::info!("not enough bytes to read message");
//                     return Ok(None);
//                 }
//                 let sasl_buffer = src.take(size as usize);
//                 let sasl_buffer = sasl_buffer.get_ref().to_vec();
//                 let decrypted = security.decrypt(sasl_buffer).map_err(|e| {
//                     io::Error::new(
//                         io::ErrorKind::Other,
//                         format!("decryption error: {}", e.to_string()),
//                     )
//                 })?;
//                 src.advance(size as usize);
//                 let mut bytes_mut = tokio_util::bytes::BytesMut::from(decrypted.as_slice());
//                 let mut results = vec![];
//                 while let Some(res) = self.codec.decode(&mut bytes_mut)? {
//                     results.push(res);
//                 }

//                 todo!()
//                 // if results.is_empty() {
//                 //     Ok(None)
//                 // } else {
//                 //     Ok(Some(results))
//                 // }
//             }
//             EncryptioinOption::NoEncryption => {
//                 // let mut results = vec![];
//                 // while let Some(res) = self.codec.decode(src)? {
//                 //     results.push(res);
//                 // }

//                 // if results.is_empty() {
//                 //     Ok(None)
//                 // } else {
//                 //     Ok(Some(results))
//                 // }
//                 todo!()
//             }
//         }
//     }
// }

// impl Encoder<LdapMsg> for EncryptionCodec {
//     type Error = io::Error;

//     fn encode(
//         &mut self,
//         item: LdapMsg,
//         dst: &mut tokio_util::bytes::BytesMut,
//     ) -> Result<(), Self::Error> {
//         let mut unencrypted = tokio_util::bytes::BytesMut::new();
//         self.codec.encode(item, &mut unencrypted)?;
//         let inner_buffer = unencrypted.as_ref();
//         match self.encryption {
//             EncryptioinOption::Encryption(ref mut security) => {
//                 // should not heap allocate here
//                 // TODO: use reference instead of vec
//                 let encrypted = security
//                     .encrypt(inner_buffer.to_vec())
//                     .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
//                 dst.extend_from_slice(encrypted.as_ref());
//             }
//             EncryptioinOption::NoEncryption => {
//                 dst.extend_from_slice(inner_buffer);
//             }
//         }
//         Ok(())
//     }
// }

// #[cfg(test)]
// mod tests {
//     use ldap3_proto::proto::LdapAttribute;

//     use crate::authentication::ntlm::NtlmAuthProvier;

//     use super::*;

//     #[test]
//     fn test_encode_encryption() {
//         let ldap_username = "username";
//         let ldap_password = "password";
//         let server_computer_name = "server_computer_name";
//         let sign = Some(true);
//         let seal = Some(true);
//         let security = NtlmAuthProvier::new(
//             ldap_username,
//             ldap_password,
//             server_computer_name,
//             sign,
//             seal,
//         );
//         let ladp_codec = LdapCodec::new(None);

//         let mut codec = EncryptionCodec::new(
//             ladp_codec,
//             EncryptioinOption::Encryption(Box::new(security)),
//         );

//         let mut bytes = tokio_util::bytes::BytesMut::new();
//         let msg = LdapMsg::new(
//             0,
//             ldap3_proto::proto::LdapOp::AddRequest(ldap3_proto::proto::LdapAddRequest {
//                 dn: "dn".to_string(),
//                 attributes: vec![LdapAttribute {
//                     atype: "attr_type".to_string(),
//                     vals: vec![b"val".to_vec()],
//                 }],
//             }),
//         );

//         codec.encode(msg, &mut bytes).unwrap();
//     }
// }
