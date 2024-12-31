use std::net::Ipv4Addr;

use bytes::{BufMut, BytesMut};
use nom::number::complete::{be_u24, be_u32, be_u8};
use nom::{AsBytes, Err, IResult, Needed};
use nom_derive::*;

use crate::util::{many0, u32_u8_3, ParseBe, TlvEmitter};
use crate::IsisTlvType;

use super::{IsisCapCode, IsisSubCodeLen, IsisSubTlvUnknown};

#[derive(Debug, NomBE)]
#[nom(Selector = "IsisCapCode")]
pub enum IsisSubTlv {
    #[nom(Selector = "IsisCapCode::SegmentRoutingCap")]
    SegmentRoutingCap(IsisSubSegmentRoutingCap),
    #[nom(Selector = "IsisCapCode::SegmentRoutingAlgo")]
    SegmentRoutingAlgo(IsisSubSegmentRoutingAlgo),
    #[nom(Selector = "IsisCapCode::SegmentRoutingLb")]
    SegmentRoutingLB(IsisSubSegmentRoutingLB),
    #[nom(Selector = "IsisCapCode::NodeMaxSidDepth")]
    NodeMaxSidDepth(IsisSubNodeMaxSidDepth),
    #[nom(Selector = "_")]
    Unknown(IsisSubTlvUnknown),
}

impl IsisSubTlv {
    pub fn parse_subs(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, cl) = IsisSubCodeLen::parse_be(input)?;
        if input.len() < cl.len as usize {
            return Err(Err::Incomplete(Needed::new(cl.len as usize)));
        }
        let (sub, input) = input.split_at(cl.len as usize);
        let (_, mut val) = Self::parse_be(sub, cl.code.into())?;
        if let IsisSubTlv::Unknown(ref mut v) = val {
            v.code = cl.code;
            v.len = cl.len;
        }
        Ok((input, val))
    }

    pub fn len(&self) -> u8 {
        use IsisSubTlv::*;
        match self {
            SegmentRoutingCap(v) => v.len(),
            SegmentRoutingAlgo(v) => v.len(),
            SegmentRoutingLB(v) => v.len(),
            NodeMaxSidDepth(v) => v.len(),
            Unknown(v) => v.len,
        }
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        use IsisSubTlv::*;
        match self {
            SegmentRoutingCap(v) => v.tlv_emit(buf),
            SegmentRoutingAlgo(v) => v.tlv_emit(buf),
            SegmentRoutingLB(v) => v.tlv_emit(buf),
            NodeMaxSidDepth(v) => v.tlv_emit(buf),
            Unknown(v) => v.tlv_emit(buf),
        }
    }
}

#[derive(Debug)]
pub enum SidLabel {
    Label(u32),
    Index(u32),
}

impl SidLabel {
    pub fn len(&self) -> u8 {
        use SidLabel::*;
        match self {
            Label(_) => 3,
            Index(_) => 4,
        }
    }
}

pub fn parse_sid_label(input: &[u8]) -> IResult<&[u8], SidLabel> {
    let (input, _typ) = be_u8(input)?;
    let (input, len) = be_u8(input)?;
    match len {
        3 => {
            let (input, label) = be_u24(input)?;
            Ok((input, SidLabel::Label(label)))
        }
        4 => {
            let (input, index) = be_u32(input)?;
            Ok((input, SidLabel::Index(index)))
        }
        _ => Err(Err::Incomplete(Needed::new(len as usize))),
    }
}

#[derive(Debug, NomBE)]
pub struct IsisSubSegmentRoutingCap {
    pub flags: u8,
    #[nom(Parse = "be_u24")]
    pub range: u32,
    #[nom(Parse = "parse_sid_label")]
    pub sid: SidLabel,
}

impl TlvEmitter for IsisSubSegmentRoutingCap {
    fn typ(&self) -> u8 {
        IsisCapCode::SegmentRoutingCap.into()
    }

    fn len(&self) -> u8 {
        // Flags: 1 + Range: 3 + SID Type:1 + SID Length: 1 + SID.
        1 + 3 + 1 + 1 + self.sid.len()
    }

    fn emit(&self, buf: &mut BytesMut) {
        use SidLabel::*;
        buf.put_u8(self.flags);
        buf.put(&u32_u8_3(self.range)[..]);
        buf.put_u8(1); // RFC8667 2.3. SID/Label Type: 1.
        buf.put_u8(self.sid.len());
        match self.sid {
            Label(v) => buf.put(&u32_u8_3(v)[..]),
            Index(v) => buf.put_u32(v),
        }
    }
}

#[derive(Debug, NomBE)]
pub struct IsisSubSegmentRoutingAlgo {
    pub algo: Vec<u8>,
}

impl TlvEmitter for IsisSubSegmentRoutingAlgo {
    fn typ(&self) -> u8 {
        IsisCapCode::SegmentRoutingAlgo.into()
    }

    fn len(&self) -> u8 {
        self.algo.len() as u8
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put(self.algo.as_bytes())
    }
}

#[derive(Debug, NomBE)]
pub struct IsisSubSegmentRoutingLB {
    pub flags: u8,
    #[nom(Parse = "be_u24")]
    pub range: u32,
    #[nom(Parse = "parse_sid_label")]
    pub sid: SidLabel,
}

impl TlvEmitter for IsisSubSegmentRoutingLB {
    fn typ(&self) -> u8 {
        IsisCapCode::SegmentRoutingLb.into()
    }

    fn len(&self) -> u8 {
        // Flags: 1 + Range: 3 + SID Type:1 + SID Length: 1 + SID.
        1 + 3 + 1 + 1 + self.sid.len()
    }

    fn emit(&self, buf: &mut BytesMut) {
        use SidLabel::*;
        buf.put_u8(self.flags);
        buf.put(&u32_u8_3(self.range)[..]);
        buf.put_u8(1); // RFC8667 2.3. SID/Label Type: 1.
        buf.put_u8(self.sid.len());
        match self.sid {
            Label(v) => buf.put(&u32_u8_3(v)[..]),
            Index(v) => buf.put_u32(v),
        }
    }
}

#[derive(Debug, NomBE)]
pub struct IsisSubNodeMaxSidDepth {
    pub flags: u8,
    pub depth: u8,
}

impl TlvEmitter for IsisSubNodeMaxSidDepth {
    fn typ(&self) -> u8 {
        IsisCapCode::NodeMaxSidDepth.into()
    }

    fn len(&self) -> u8 {
        2
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.flags);
        buf.put_u8(self.depth);
    }
}

#[derive(Debug)]
pub struct IsisTlvRouterCap {
    pub router_id: Ipv4Addr,
    pub flags: u8,
    pub subs: Vec<IsisSubTlv>,
}

impl ParseBe<IsisTlvRouterCap> for IsisTlvRouterCap {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, router_id) = Ipv4Addr::parse_be(input)?;
        let (input, flags) = be_u8(input)?;
        let (input, subs) = many0(IsisSubTlv::parse_subs)(input)?;
        let tlv = Self {
            router_id,
            flags,
            subs,
        };
        Ok((input, tlv))
    }
}

impl IsisTlvRouterCap {
    fn sub_len(&self) -> u8 {
        self.subs.iter().map(|sub| sub.len() + 2).sum()
    }
}

impl TlvEmitter for IsisTlvRouterCap {
    fn typ(&self) -> u8 {
        IsisTlvType::RouterCap.into()
    }

    fn len(&self) -> u8 {
        5 + self.sub_len()
    }

    fn emit(&self, buf: &mut bytes::BytesMut) {
        buf.put(&self.router_id.octets()[..]);
        buf.put_u8(self.flags);
        self.subs.iter().for_each(|sub| sub.emit(buf));
    }
}
