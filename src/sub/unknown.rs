use bytes::{BufMut, BytesMut};
use nom_derive::*;

use crate::util::TlvEmitter;

#[derive(Debug, NomBE)]
pub struct IsisSubTlvUnknown {
    #[nom(Ignore)]
    pub code: u8,
    #[nom(Ignore)]
    pub len: u8,
    pub data: Vec<u8>,
}

impl TlvEmitter for IsisSubTlvUnknown {
    fn typ(&self) -> u8 {
        self.code
    }

    fn len(&self) -> u8 {
        self.len
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.data[..]);
    }
}
