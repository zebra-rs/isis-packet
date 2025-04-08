use std::net::{Ipv4Addr, Ipv6Addr};

use bitfield_struct::bitfield;
use bytes::{BufMut, BytesMut};
use nom::bytes::complete::take;
use nom::number::complete::{be_u24, be_u8};
use nom::{Err, IResult, Needed};
use nom_derive::*;
use serde::Serialize;

use crate::util::{many0, u32_u8_3, ParseBe, TlvEmitter};
use crate::{
    IsisNeighborId, IsisSysId, IsisTlv, IsisTlvType, SidLabelValue, IPV4_ADDR_LEN, IPV6_ADDR_LEN,
};

use super::{IsisNeighCode, IsisSubCodeLen, IsisSubTlvUnknown};

#[derive(Debug, Default, Clone, Serialize)]
pub struct IsisTlvExtIsReach {
    pub entries: Vec<IsisTlvExtIsReachEntry>,
}

impl From<IsisTlvExtIsReach> for IsisTlv {
    fn from(tlv: IsisTlvExtIsReach) -> Self {
        IsisTlv::ExtIsReach(tlv)
    }
}

impl ParseBe<IsisTlvExtIsReach> for IsisTlvExtIsReach {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, entries) = many0(IsisTlvExtIsReachEntry::parse_be)(input)?;
        Ok((input, Self { entries }))
    }
}

impl TlvEmitter for IsisTlvExtIsReach {
    fn typ(&self) -> u8 {
        IsisTlvType::ExtIsReach.into()
    }

    fn len(&self) -> u8 {
        self.entries.iter().map(|entry| entry.len()).sum()
    }

    fn emit(&self, buf: &mut BytesMut) {
        self.entries.iter().for_each(|entry| entry.emit(buf));
    }
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct IsisTlvExtIsReachEntry {
    pub neighbor_id: IsisNeighborId,
    pub metric: u32,
    pub subs: Vec<IsisSubTlv>,
}

impl IsisTlvExtIsReachEntry {
    fn len(&self) -> u8 {
        11 + self.sub_len() // 11 is TLV length without sub TLVs.
    }

    fn sub_len(&self) -> u8 {
        self.subs.iter().map(|sub| sub.len() + 2).sum()
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.neighbor_id.id[..]);
        buf.put(&u32_u8_3(self.metric)[..]);
        buf.put_u8(self.sub_len());
        for sub in self.subs.iter() {
            sub.emit(buf);
        }
    }
}

impl ParseBe<IsisTlvExtIsReachEntry> for IsisTlvExtIsReachEntry {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, neighbor_id) = take(7usize)(input)?;
        let (input, metric) = be_u24(input)?;
        let (input, sublen) = be_u8(input)?;
        let (sub, input) = input.split_at(sublen as usize);
        let (_, subs) = many0(IsisSubTlv::parse_subs)(sub)?;

        let mut tlv = Self::default();
        tlv.neighbor_id.id.copy_from_slice(neighbor_id);
        tlv.metric = metric;
        tlv.subs = subs;

        Ok((input, tlv))
    }
}

#[derive(Debug, NomBE, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
#[nom(Selector = "IsisNeighCode")]
pub enum IsisSubTlv {
    #[nom(Selector = "IsisNeighCode::Ipv4IfAddr")]
    Ipv4IfAddr(IsisSubIpv4IfAddr),
    #[nom(Selector = "IsisNeighCode::Ipv4NeighAddr")]
    Ipv4NeighAddr(IsisSubIpv4NeighAddr),
    #[nom(Selector = "IsisNeighCode::Ipv6IfAddr")]
    Ipv6IfAddr(IsisSubIpv6IfAddr),
    #[nom(Selector = "IsisNeighCode::Ipv6NeighAddr")]
    Ipv6NeighAddr(IsisSubIpv6NeighAddr),
    #[nom(Selector = "IsisNeighCode::AdjSid")]
    AdjSid(IsisSubAdjSid),
    #[nom(Selector = "IsisNeighCode::LanAdjSid")]
    LanAdjSid(IsisSubLanAdjSid),
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
            Ipv4IfAddr(v) => v.len(),
            Ipv4NeighAddr(v) => v.len(),
            Ipv6IfAddr(v) => v.len(),
            Ipv6NeighAddr(v) => v.len(),
            AdjSid(v) => v.len(),
            LanAdjSid(v) => v.len(),
            Unknown(v) => v.len,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        use IsisSubTlv::*;
        match self {
            Ipv4IfAddr(v) => v.tlv_emit(buf),
            Ipv4NeighAddr(v) => v.tlv_emit(buf),
            Ipv6IfAddr(v) => v.tlv_emit(buf),
            Ipv6NeighAddr(v) => v.tlv_emit(buf),
            AdjSid(v) => v.tlv_emit(buf),
            LanAdjSid(v) => v.tlv_emit(buf),
            Unknown(v) => v.tlv_emit(buf),
        }
    }
}

#[derive(Debug, NomBE, Clone, Serialize)]
pub struct IsisSubIpv4IfAddr {
    pub addr: Ipv4Addr,
}

impl TlvEmitter for IsisSubIpv4IfAddr {
    fn typ(&self) -> u8 {
        IsisNeighCode::Ipv4IfAddr.into()
    }

    fn len(&self) -> u8 {
        IPV4_ADDR_LEN
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.addr.octets()[..]);
    }
}

#[derive(Debug, NomBE, Clone, Serialize)]
pub struct IsisSubIpv4NeighAddr {
    pub addr: Ipv4Addr,
}

impl TlvEmitter for IsisSubIpv4NeighAddr {
    fn typ(&self) -> u8 {
        IsisNeighCode::Ipv4NeighAddr.into()
    }

    fn len(&self) -> u8 {
        IPV4_ADDR_LEN
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.addr.octets()[..]);
    }
}

#[derive(Debug, NomBE, Clone, Serialize)]
pub struct IsisSubIpv6IfAddr {
    pub addr: Ipv6Addr,
}

impl TlvEmitter for IsisSubIpv6IfAddr {
    fn typ(&self) -> u8 {
        IsisNeighCode::Ipv6IfAddr.into()
    }

    fn len(&self) -> u8 {
        IPV6_ADDR_LEN
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.addr.octets()[..]);
    }
}

#[derive(Debug, NomBE, Clone, Serialize)]
pub struct IsisSubIpv6NeighAddr {
    pub addr: Ipv6Addr,
}

impl TlvEmitter for IsisSubIpv6NeighAddr {
    fn typ(&self) -> u8 {
        IsisNeighCode::Ipv6NeighAddr.into()
    }

    fn len(&self) -> u8 {
        IPV6_ADDR_LEN
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.addr.octets()[..]);
    }
}

#[bitfield(u8, debug = true)]
#[derive(Serialize)]
pub struct AdjSidFlags {
    #[bits(2)]
    pub resvd: u8,
    pub p_flag: bool,
    pub s_flag: bool,
    pub l_flag: bool,
    pub v_flag: bool,
    pub b_flag: bool,
    pub f_flag: bool,
}

impl ParseBe<AdjSidFlags> for AdjSidFlags {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, flags) = be_u8(input)?;
        Ok((input, flags.into()))
    }
}

#[derive(Debug, NomBE, Clone, Serialize)]
pub struct IsisSubAdjSid {
    pub flags: AdjSidFlags,
    pub weight: u8,
    pub sid: SidLabelValue,
}

impl TlvEmitter for IsisSubAdjSid {
    fn typ(&self) -> u8 {
        IsisNeighCode::AdjSid.into()
    }

    fn len(&self) -> u8 {
        2 + self.sid.len()
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.flags.into());
        buf.put_u8(self.weight);
        self.sid.emit(buf);
    }
}

#[derive(Debug, NomBE, Clone, Serialize)]
pub struct IsisSubLanAdjSid {
    pub flags: AdjSidFlags,
    pub weight: u8,
    pub system_id: IsisSysId,
    pub sid: SidLabelValue,
}

impl TlvEmitter for IsisSubLanAdjSid {
    fn typ(&self) -> u8 {
        IsisNeighCode::LanAdjSid.into()
    }

    fn len(&self) -> u8 {
        8 + self.sid.len()
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.flags.into());
        buf.put_u8(self.weight);
        buf.put(&self.system_id.id[..]);
        self.sid.emit(buf);
    }
}
