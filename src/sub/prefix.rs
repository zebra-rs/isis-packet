use std::net::{Ipv4Addr, Ipv6Addr};

use bitfield_struct::bitfield;
use bytes::{BufMut, BytesMut};
use ipnet::{Ipv4Net, Ipv6Net};
use nom::bytes::complete::take;
use nom::number::complete::{be_u32, be_u8};
use nom::{Err, IResult, Needed};
use nom_derive::*;

use crate::sub::{IsisSubCode, IsisSubCodeLen};
use crate::util::{many0, ParseBe};
use crate::*;

// Sub TLV codepoints for Prefix Reachability.
const ISIS_CODE_PREFIX_SID: u8 = 3;

#[derive(Debug, NomBE)]
#[nom(Selector = "IsisSubCode")]
pub enum IsisSubTlv {
    #[nom(Selector = "IsisSubCode(ISIS_CODE_PREFIX_SID)")]
    PrefixSid(IsisSubPrefixSid),
}

#[derive(Debug, NomBE)]
pub struct IsisSubPrefixSid {
    pub flags: u8,
    pub algo: u8,
    pub sid: u32,
}

impl TlvEmitter for IsisSubPrefixSid {
    fn typ(&self) -> u8 {
        ISIS_CODE_PREFIX_SID
    }

    fn len(&self) -> u8 {
        6
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.flags);
        buf.put_u8(self.algo);
        buf.put_u32(self.sid);
    }
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
            PrefixSid(v) => v.len(),
        }
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        use IsisSubTlv::*;
        match self {
            PrefixSid(v) => v.tlv_emit(buf),
        }
    }
}

#[bitfield(u8, debug = true)]
pub struct Ipv4ControlInfo {
    #[bits(6)]
    pub prefixlen: usize,
    pub sub_tlv: bool,
    pub distribution: bool,
}

#[derive(Debug)]
pub struct IsisTlvExtIpReach {
    pub entries: Vec<IsisTlvExtIpReachEntry>,
}

impl ParseBe<IsisTlvExtIpReach> for IsisTlvExtIpReach {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, entries) = many0(IsisTlvExtIpReachEntry::parse_be)(input)?;
        Ok((input, Self { entries }))
    }
}

impl TlvEmitter for IsisTlvExtIpReach {
    fn typ(&self) -> u8 {
        IsisTlvType::ExtIpReach.into()
    }

    fn len(&self) -> u8 {
        self.entries.iter().map(|entry| entry.len()).sum()
    }

    fn emit(&self, buf: &mut BytesMut) {
        self.entries.iter().for_each(|entry| entry.emit(buf));
    }
}

#[derive(Debug)]
pub struct IsisTlvExtIpReachEntry {
    pub metric: u32,
    pub flags: Ipv4ControlInfo,
    pub prefix: Ipv4Net,
    pub subs: Vec<IsisSubTlv>,
}

impl IsisTlvExtIpReachEntry {
    fn len(&self) -> u8 {
        if self.subs.is_empty() {
            // Metric:4 + Flags:1 + Prefix.
            4 + 1 + (psize(self.prefix.prefix_len()) as u8)
        } else {
            // Metric:4 + Flags:1 + Prefix + Sub TLV length + Sub TLV.
            4 + 1 + (psize(self.prefix.prefix_len()) as u8) + 1 + self.sub_len()
        }
    }

    fn sub_len(&self) -> u8 {
        self.subs.iter().map(|sub| sub.len() + 2).sum()
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u32(self.metric);
        buf.put_u8(self.flags.into());
        let plen = psize(self.prefix.prefix_len());
        if plen != 0 {
            buf.put(&self.prefix.addr().octets()[..plen]);
        }
        if self.subs.is_empty() {
            return;
        }
        buf.put_u8(self.sub_len());
        for sub in self.subs.iter() {
            sub.emit(buf);
        }
    }
}

#[derive(Debug)]
pub struct IsisTlvIpv6Reach {
    pub entries: Vec<IsisTlvIpv6ReachEntry>,
}

impl ParseBe<IsisTlvIpv6Reach> for IsisTlvIpv6Reach {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, entries) = many0(IsisTlvIpv6ReachEntry::parse_be)(input)?;
        Ok((input, Self { entries }))
    }
}

impl TlvEmitter for IsisTlvIpv6Reach {
    fn typ(&self) -> u8 {
        IsisTlvType::Ipv6Reach.into()
    }

    fn len(&self) -> u8 {
        self.entries.iter().map(|entry| entry.len()).sum()
    }

    fn emit(&self, buf: &mut BytesMut) {
        self.entries.iter().for_each(|entry| entry.emit(buf));
    }
}

#[bitfield(u8, debug = true)]
pub struct Ipv6ControlInfo {
    #[bits(5)]
    pub resvd: usize,
    pub sub_tlv: bool,
    pub dist_internal: bool,
    pub dist_up: bool,
}

#[derive(Debug)]
pub struct IsisTlvIpv6ReachEntry {
    pub metric: u32,
    pub flags: Ipv6ControlInfo,
    pub prefix: Ipv6Net,
    pub subs: Vec<IsisSubTlv>,
}

impl IsisTlvIpv6ReachEntry {
    fn len(&self) -> u8 {
        if self.subs.is_empty() {
            // Metric:4 + Flags:1 + Prefixlen:1.
            4 + 1 + 1 + (psize(self.prefix.prefix_len()) as u8)
        } else {
            // Metric:4 + Flags:1 + Prefix len:1 + Sub TLV length + Sub TLV.
            4 + 1 + 1 + (psize(self.prefix.prefix_len()) as u8) + 1 + self.sub_len()
        }
    }

    fn sub_len(&self) -> u8 {
        self.subs.iter().map(|sub| sub.len() + 2).sum()
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u32(self.metric);
        buf.put_u8(self.flags.into());
        buf.put_u8(self.prefix.prefix_len());
        let plen = psize(self.prefix.prefix_len());
        if plen != 0 {
            buf.put(&self.prefix.addr().octets()[..plen]);
        }
        if self.subs.is_empty() {
            return;
        }
        buf.put_u8(self.sub_len());
        for sub in self.subs.iter() {
            sub.emit(buf);
        }
    }
}

pub fn psize(plen: u8) -> usize {
    ((plen + 7) / 8) as usize
}

pub fn ptake(input: &[u8], prefixlen: u8) -> IResult<&[u8], Ipv4Net> {
    if prefixlen == 0 {
        return Ok((input, Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 0).unwrap()));
    }
    let psize = psize(prefixlen);
    if input.len() < psize {
        return Err(nom::Err::Incomplete(Needed::new(psize)));
    }
    let mut addr = [0u8; 4];
    addr[..psize].copy_from_slice(&input[..psize]);
    let (input, _) = take(psize)(input)?;
    let Ok(prefix) = Ipv4Net::new(Ipv4Addr::from(addr), prefixlen) else {
        return Err(nom::Err::Incomplete(Needed::new(psize)));
    };
    Ok((input, prefix))
}

pub fn ptakev6(input: &[u8], prefixlen: u8) -> IResult<&[u8], Ipv6Net> {
    if prefixlen == 0 {
        return Ok((input, Ipv6Net::new(Ipv6Addr::UNSPECIFIED, 0).unwrap()));
    }
    let psize = psize(prefixlen);
    if input.len() < psize {
        return Err(nom::Err::Incomplete(Needed::new(psize)));
    }
    let mut addr = [0u8; 16];
    addr[..psize].copy_from_slice(&input[..psize]);
    let (input, _) = take(psize)(input)?;
    let Ok(prefix) = Ipv6Net::new(Ipv6Addr::from(addr), prefixlen) else {
        return Err(nom::Err::Incomplete(Needed::new(psize)));
    };
    Ok((input, prefix))
}

impl ParseBe<IsisTlvExtIpReachEntry> for IsisTlvExtIpReachEntry {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, metric) = be_u32(input)?;
        let (input, flags) = be_u8(input)?;
        let flags: Ipv4ControlInfo = flags.into();
        let (input, prefix) = ptake(input, flags.prefixlen() as u8)?;
        let mut tlv = Self {
            metric,
            flags,
            prefix,
            subs: Vec::new(),
        };
        if !flags.sub_tlv() {
            return Ok((input, tlv));
        }
        let (input, sublen) = be_u8(input)?;
        let (sub, input) = input.split_at(sublen as usize);
        let (_, subs) = many0(IsisSubTlv::parse_subs)(sub)?;
        tlv.subs = subs;
        Ok((input, tlv))
    }
}

impl ParseBe<IsisTlvIpv6ReachEntry> for IsisTlvIpv6ReachEntry {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, metric) = be_u32(input)?;
        let (input, flags) = be_u8(input)?;
        let flags: Ipv6ControlInfo = flags.into();
        let (input, prefixlen) = be_u8(input)?;
        let (input, prefix) = ptakev6(input, prefixlen)?;
        let mut tlv = Self {
            metric,
            flags,
            prefix,
            subs: Vec::new(),
        };
        if !flags.sub_tlv() {
            return Ok((input, tlv));
        }
        let (input, sublen) = be_u8(input)?;
        let (sub, input) = input.split_at(sublen as usize);
        let (_, subs) = many0(IsisSubTlv::parse_subs)(sub)?;
        tlv.subs = subs;
        Ok((input, tlv))
    }
}
