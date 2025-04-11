use bitfield_struct::bitfield;
use bytes::BytesMut;
use nom::number::complete::be_u16;
use nom::IResult;
use nom_derive::*;
use serde::Serialize;

use crate::util::{ParseBe, TlvEmitter};
use crate::IsisTlvType;

#[bitfield(u16, debug = true)]
#[derive(Serialize)]
pub struct Srv6TlvFlags {
    #[bits(4)]
    pub resvd: u8,
    #[bits(12)]
    pub v_flag: u16,
}

impl ParseBe<Srv6TlvFlags> for Srv6TlvFlags {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, flags) = be_u16(input)?;
        Ok((input, flags.into()))
    }
}

#[derive(Debug, NomBE, Clone, Default, Serialize)]
pub struct Srv6Locator {
    //
}

#[derive(Debug, NomBE, Clone, Default, Serialize)]
pub struct IsisTlvSrv6 {
    pub flags: Srv6TlvFlags,
    pub locators: Vec<Srv6Locator>,
}

impl TlvEmitter for IsisTlvSrv6 {
    fn typ(&self) -> u8 {
        IsisTlvType::Srv6.into()
    }

    fn len(&self) -> u8 {
        0
    }

    fn emit(&self, _buf: &mut BytesMut) {
        //
    }
}
