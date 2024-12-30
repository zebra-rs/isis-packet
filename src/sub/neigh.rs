use std::net::Ipv4Addr;

use bytes::{BufMut, BytesMut};
use nom::bytes::complete::take;
use nom::number::complete::{be_u24, be_u8};
use nom::{Err, IResult, Needed};
use nom_derive::*;

use crate::sub::{IsisSubCode, IsisSubCodeLen};
use crate::util::{many0, u32_u8_3, ParseBe};
use crate::*;

#[derive(Debug, Default)]
pub struct IsisTlvExtIsReach {
    pub entries: Vec<IsisTlvExtIsReachEntry>,
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

#[derive(Debug, Default)]
pub struct IsisTlvExtIsReachEntry {
    pub neighbor_id: [u8; 7],
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
        buf.put(&self.neighbor_id[..]);
        buf.put(&u32_u8_3(self.metric)[..]);
        //buf.put(&self.metric_raw[..]);
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
        tlv.neighbor_id.copy_from_slice(neighbor_id);
        tlv.metric = metric;
        tlv.subs = subs;

        Ok((input, tlv))
    }
}

// Sub TLV codepoints for Neighbor Information.
const ISIS_CODE_IPV4_IF_ADDR: u8 = 6;
const ISIS_CODE_IPV4_NEIGH_ADDR: u8 = 8;
const ISIS_CODE_LAN_ADJ_SID: u8 = 32;

#[derive(Debug, NomBE)]
#[nom(Selector = "IsisSubCode")]
pub enum IsisSubTlv {
    #[nom(Selector = "IsisSubCode(ISIS_CODE_IPV4_IF_ADDR)")]
    Ipv4IfAddr(IsisSubIpv4IfAddr),
    #[nom(Selector = "IsisSubCode(ISIS_CODE_IPV4_NEIGH_ADDR)")]
    Ipv4NeighAddr(IsisSubIpv4NeighAddr),
    #[nom(Selector = "IsisSubCode(ISIS_CODE_LAN_ADJ_SID)")]
    LanAdjSid(IsisSubLanAdjSid),
    #[nom(Selector = "IsisSubCode(_)")]
    Unknown(IsisSubTlvUnknown),
}

impl IsisSubTlv {
    pub fn parse_subs(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, cl) = IsisSubCodeLen::parse_be(input)?;
        if input.len() < cl.len as usize {
            return Err(Err::Incomplete(Needed::new(cl.len as usize)));
        }
        let (sub, input) = input.split_at(cl.len as usize);
        let (_, val) = Self::parse_be(sub, cl.code)?;
        Ok((input, val))
    }

    pub fn len(&self) -> u8 {
        use IsisSubTlv::*;
        match self {
            Ipv4IfAddr(v) => v.len(),
            Ipv4NeighAddr(v) => v.len(),
            LanAdjSid(v) => v.len(),
            _ => 0,
        }
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        use IsisSubTlv::*;
        match self {
            Ipv4IfAddr(v) => v.tlv_emit(buf),
            Ipv4NeighAddr(v) => v.tlv_emit(buf),
            LanAdjSid(v) => v.tlv_emit(buf),
            _ => {
                //
            }
        }
    }
}

#[derive(Debug, NomBE)]
pub struct IsisSubIpv4IfAddr {
    pub addr: Ipv4Addr,
}

impl TlvEmitter for IsisSubIpv4IfAddr {
    fn typ(&self) -> u8 {
        ISIS_CODE_IPV4_IF_ADDR
    }

    fn len(&self) -> u8 {
        4
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.addr.octets()[..]);
    }
}

#[derive(Debug, NomBE)]
pub struct IsisSubIpv4NeighAddr {
    pub addr: Ipv4Addr,
}

impl TlvEmitter for IsisSubIpv4NeighAddr {
    fn typ(&self) -> u8 {
        ISIS_CODE_IPV4_IF_ADDR
    }

    fn len(&self) -> u8 {
        4
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.addr.octets()[..]);
    }
}

#[derive(Debug, NomBE)]
pub struct IsisSubLanAdjSid {
    pub flags: u8,
    pub weight: u8,
    pub system_id: [u8; 6],
    #[nom(Parse = "be_u24")]
    pub sid: u32,
}

impl TlvEmitter for IsisSubLanAdjSid {
    fn typ(&self) -> u8 {
        ISIS_CODE_LAN_ADJ_SID
    }

    fn len(&self) -> u8 {
        11
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.flags);
        buf.put_u8(self.weight);
        buf.put(&self.system_id[..]);
        buf.put(&u32_u8_3(self.sid)[..]);
    }
}

#[derive(Debug, Default, NomBE)]
pub struct IsisSubTlvUnknown {
    pub typ: u8,
    pub length: u8,
    pub values: Vec<u8>,
}
