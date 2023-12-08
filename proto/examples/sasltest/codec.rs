use tokio_util::codec::Decoder;



#[derive(Debug, Clone, Copy, PartialEq, Eq,Default)]
pub struct SaslCodeC;

// impl Decoder for SaslCodec {
//     type Item;

//     type Error;

//     fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
//         todo!()
//     }
// }

// impl Encoder for SaslCodec {
//     type Item;

//     type Error;

//     fn encode(&mut self, item: Self::Item, dst: &mut bytes::BytesMut) -> Result<(), Self::Error> {
//         todo!()
//     }
// }