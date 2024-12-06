use std::net::Ipv4Addr;

use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, BytesMut};
use nom::number::complete::be_u32;
use nom::{AsBytes, Err, IResult, Needed};
use nom_derive::*;

use crate::sub::{IsisTlvExtIpReach, IsisTlvExtIsReach, IsisTlvIpv6Reach, IsisTlvRouterCap};
use crate::util::{many0, ParseBe};

// IS-IS discriminator.
const ISIS_IRDP_DISC: u8 = 0x83;

// IS-IS PDU Types.
const ISIS_L1LAN_HELLO_PDU: u8 = 0x0F;
// const ISIS_L2LAN_HELLO_PDU: u8 = 0x10;
// const ISIS_P2P_HELLO_PDU: u8 = 0x11;
const ISIS_L1LSP_PDU: u8 = 0x12;
// const ISIS_L2LSP_PDU: u8 = 0x14;
const ISIS_CSNP_PDU: u8 = 0x18;
const ISIS_PSNP_PDU: u8 = 0x1a;

#[derive(Debug, PartialEq, Eq, Clone, Copy, NomBE)]
pub struct IsisPduType(pub u8);

#[derive(Debug, NomBE)]
pub struct IsisPacket {
    #[nom(Verify = "*discriminator == ISIS_IRDP_DISC")]
    pub discriminator: u8,
    pub length_indicator: u8,
    pub id_extension: u8,
    pub id_length: u8,
    pub pdu_type: IsisPduType,
    pub version: u8,
    pub reserved: u8,
    pub max_area_addr: u8,
    #[nom(Parse = "{ |x| IsisPdu::parse_be(x, pdu_type) }")]
    pub pdu: IsisPdu,
}

impl IsisPacket {
    pub fn emit(&self, buf: &mut BytesMut) {
        use IsisPdu::*;
        buf.put_u8(self.discriminator);
        buf.put_u8(self.length_indicator);
        buf.put_u8(self.id_extension);
        buf.put_u8(self.id_length);
        buf.put_u8(self.pdu_type.0);
        buf.put_u8(self.version);
        buf.put_u8(self.reserved);
        buf.put_u8(self.max_area_addr);
        match &self.pdu {
            L1Hello(v) => v.emit(buf),
            L1Lsp(v) => v.emit(buf),
            Csnp(v) => v.emit(buf),
            Psnp(v) => v.emit(buf),
        }
    }
}

#[derive(Debug, NomBE)]
#[nom(Selector = "IsisPduType")]
pub enum IsisPdu {
    #[nom(Selector = "IsisPduType(ISIS_L1LAN_HELLO_PDU)")]
    L1Hello(IsisL1Hello),
    #[nom(Selector = "IsisPduType(ISIS_L1LSP_PDU)")]
    L1Lsp(IsisL1Lsp),
    #[nom(Selector = "IsisPduType(ISIS_CSNP_PDU)")]
    Csnp(IsisCsnp),
    #[nom(Selector = "IsisPduType(ISIS_PSNP_PDU)")]
    Psnp(IsisPsnp),
}

#[derive(Debug, NomBE)]
pub struct IsisL1Lsp {
    pub pdu_len: u16,
    pub lifetime: u16,
    pub lsp_id: [u8; 8],
    pub seq_number: u32,
    pub checksum: u16,
    pub types: u8,
    #[nom(Parse = "IsisTlv::parse_tlvs")]
    pub tlvs: Vec<IsisTlv>,
}

impl IsisL1Lsp {
    pub fn emit(&self, buf: &mut BytesMut) {
        let pp = buf.len();
        buf.put_u16(self.pdu_len);
        buf.put_u16(self.lifetime);
        buf.put(&self.lsp_id[..]);
        buf.put_u32(self.seq_number);
        buf.put_u16(self.checksum);
        buf.put_u8(self.types);
        self.tlvs.iter().for_each(|tlv| tlv.emit(buf));
        let pdu_len: u16 = buf.len() as u16;
        BigEndian::write_u16(&mut buf[pp..pp + 2], pdu_len);
    }
}

#[derive(Debug, NomBE)]
pub struct IsisL1Hello {
    pub circuit_type: u8,
    pub source_id: [u8; 6],
    pub holding_timer: u16,
    pub pdu_len: u16,
    pub priority: u8,
    pub lan_id: [u8; 7],
    #[nom(Parse = "IsisTlv::parse_tlvs")]
    pub tlvs: Vec<IsisTlv>,
}

impl IsisL1Hello {
    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.circuit_type);
        buf.put(&self.source_id[..]);
        buf.put_u16(self.holding_timer);
        let pp = buf.len();
        buf.put_u16(self.pdu_len);
        buf.put_u8(self.priority);
        buf.put(&self.lan_id[..]);
        self.tlvs.iter().for_each(|tlv| tlv.emit(buf));
        let pdu_len: u16 = buf.len() as u16;
        BigEndian::write_u16(&mut buf[pp..pp + 2], pdu_len);
    }
}

#[derive(Debug, NomBE)]
pub struct IsisCsnp {
    pub pdu_len: u16,
    pub source_id: [u8; 6],
    pub source_id_curcuit: u8,
    pub start: [u8; 8],
    pub end: [u8; 8],
    #[nom(Parse = "IsisTlv::parse_tlvs")]
    pub tlvs: Vec<IsisTlv>,
}

impl IsisCsnp {
    pub fn emit(&self, buf: &mut BytesMut) {
        let pp = buf.len();
        buf.put_u16(self.pdu_len);
        buf.put(&self.source_id[..]);
        buf.put_u8(self.source_id_curcuit);
        buf.put(&self.start[..]);
        buf.put(&self.end[..]);
        self.tlvs.iter().for_each(|tlv| tlv.emit(buf));
        let pdu_len: u16 = buf.len() as u16;
        BigEndian::write_u16(&mut buf[pp..pp + 2], pdu_len);
    }
}

#[derive(Debug, NomBE)]
pub struct IsisPsnp {
    pub pdu_len: u16,
    pub source_id: [u8; 6],
    pub source_id_curcuit: u8,
    #[nom(Parse = "IsisTlv::parse_tlvs")]
    pub tlvs: Vec<IsisTlv>,
}

impl IsisPsnp {
    pub fn emit(&self, buf: &mut BytesMut) {
        let pp = buf.len();
        buf.put_u16(self.pdu_len);
        buf.put(&self.source_id[..]);
        buf.put_u8(self.source_id_curcuit);
        self.tlvs.iter().for_each(|tlv| tlv.emit(buf));
        let pdu_len: u16 = buf.len() as u16;
        BigEndian::write_u16(&mut buf[pp..pp + 2], pdu_len);
    }
}

// TLVs.
pub const ISIS_TLV_AREA_ADDR: u8 = 1;
pub const ISIS_TLV_IS_NEIGHBOR: u8 = 6;
pub const ISIS_TLV_PADDING: u8 = 8;
pub const ISIS_TLV_LSP_ENTRIES: u8 = 9;
pub const ISIS_TLV_EXT_IS_REACH: u8 = 22;
pub const ISIS_TLV_PROT_SUPPORTED: u8 = 129;
pub const ISIS_TLV_IPV4_IF_ADDR: u8 = 132;
pub const ISIS_TLV_TE_ROUTER_ID: u8 = 134;
pub const ISIS_TLV_EXT_IP_REACH: u8 = 135;
pub const ISIS_TLV_DYNAMIC_HOSTNAME: u8 = 137;
pub const ISIS_TLV_IPV6_REACH: u8 = 236;
pub const ISIS_TLV_ROUTER_CAP: u8 = 242;

#[derive(Debug, NomBE)]
#[nom(Selector = "IsisTlvType")]
pub enum IsisTlv {
    #[nom(Selector = "IsisTlvType(ISIS_TLV_AREA_ADDR)")]
    AreaAddr(IsisTlvAreaAddr),
    #[nom(Selector = "IsisTlvType(ISIS_TLV_IS_NEIGHBOR)")]
    IsNeighbor(IsisTlvIsNeighbor),
    #[nom(Selector = "IsisTlvType(ISIS_TLV_PADDING)")]
    Padding(IsisTlvPadding),
    #[nom(Selector = "IsisTlvType(ISIS_TLV_LSP_ENTRIES)")]
    LspEntries(IsisTlvLspEntries),
    #[nom(Selector = "IsisTlvType(ISIS_TLV_EXT_IS_REACH)")]
    ExtIsReach(IsisTlvExtIsReach),
    #[nom(Selector = "IsisTlvType(ISIS_TLV_PROT_SUPPORTED)")]
    ProtSupported(IsisTlvProtSupported),
    #[nom(Selector = "IsisTlvType(ISIS_TLV_IPV4_IF_ADDR)")]
    Ipv4IfAddr(IsisTlvIpv4IfAddr),
    #[nom(Selector = "IsisTlvType(ISIS_TLV_TE_ROUTER_ID)")]
    TeRouterId(IsisTlvTeRouterId),
    #[nom(Selector = "IsisTlvType(ISIS_TLV_EXT_IP_REACH)")]
    ExtIpReach(IsisTlvExtIpReach),
    #[nom(Selector = "IsisTlvType(ISIS_TLV_DYNAMIC_HOSTNAME)")]
    Hostname(IsisTlvHostname),
    #[nom(Selector = "IsisTlvType(ISIS_TLV_IPV6_REACH)")]
    Ipv6Reach(IsisTlvIpv6Reach),
    #[nom(Selector = "IsisTlvType(ISIS_TLV_ROUTER_CAP)")]
    RouterCap(IsisTlvRouterCap),
    #[nom(Selector = "IsisTlvType(_)")]
    Unknown(IsisTlvUnknown),
}

#[allow(clippy::len_without_is_empty)]
pub trait TlvEmitter {
    fn typ(&self) -> u8;
    fn len(&self) -> u8;
    fn emit(&self, buf: &mut BytesMut);

    fn tlv_emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.typ());
        buf.put_u8(self.len());
        self.emit(buf);
    }
}

impl IsisTlv {
    pub fn emit(&self, buf: &mut BytesMut) {
        use IsisTlv::*;
        match self {
            AreaAddr(v) => v.tlv_emit(buf),
            IsNeighbor(v) => v.tlv_emit(buf),
            Padding(v) => v.tlv_emit(buf),
            LspEntries(v) => v.tlv_emit(buf),
            ExtIsReach(v) => v.tlv_emit(buf),
            ProtSupported(v) => v.tlv_emit(buf),
            Ipv4IfAddr(v) => v.tlv_emit(buf),
            TeRouterId(v) => v.tlv_emit(buf),
            ExtIpReach(v) => v.tlv_emit(buf),
            Hostname(v) => v.tlv_emit(buf),
            Ipv6Reach(v) => v.tlv_emit(buf),
            RouterCap(v) => v.tlv_emit(buf),
            Unknown(v) => v.emit(buf),
        }
    }
}

#[derive(Debug, NomBE)]
pub struct IsisTlvAreaAddr {
    pub area_addr: [u8; 4],
}

impl TlvEmitter for IsisTlvAreaAddr {
    fn typ(&self) -> u8 {
        ISIS_TLV_AREA_ADDR
    }

    fn len(&self) -> u8 {
        self.area_addr.len() as u8
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.area_addr[..]);
    }
}

#[derive(Debug, NomBE)]
pub struct IsisTlvIsNeighbor {
    pub addr: [u8; 6],
}

impl TlvEmitter for IsisTlvIsNeighbor {
    fn typ(&self) -> u8 {
        ISIS_TLV_AREA_ADDR
    }

    fn len(&self) -> u8 {
        self.addr.len() as u8
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.addr[..]);
    }
}

#[derive(Debug, NomBE)]
pub struct IsisTlvPadding {
    pub padding: Vec<u8>,
}

impl TlvEmitter for IsisTlvPadding {
    fn typ(&self) -> u8 {
        ISIS_TLV_AREA_ADDR
    }

    fn len(&self) -> u8 {
        self.padding.len() as u8
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.padding[..]);
    }
}

#[derive(Debug, NomBE)]
pub struct IsisLspEntry {
    pub lifetime: u16,
    pub lsp_id: [u8; 8],
    pub seq_number: u32,
    pub checksum: u16,
}

impl IsisLspEntry {
    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u16(self.lifetime);
        buf.put(&self.lsp_id[..]);
        buf.put_u32(self.seq_number);
        buf.put_u16(self.checksum);
    }
}

#[derive(Debug, NomBE)]
pub struct IsisTlvLspEntries {
    pub entries: Vec<IsisLspEntry>,
}

impl TlvEmitter for IsisTlvLspEntries {
    fn typ(&self) -> u8 {
        ISIS_TLV_LSP_ENTRIES
    }

    fn len(&self) -> u8 {
        (self.entries.len() * std::mem::size_of::<IsisLspEntry>()) as u8
    }

    fn emit(&self, buf: &mut BytesMut) {
        for entry in self.entries.iter() {
            entry.emit(buf);
        }
    }
}

#[derive(Debug, NomBE)]
pub struct IsisTlvProtSupported {
    pub nlpid: u8,
}

impl TlvEmitter for IsisTlvProtSupported {
    fn typ(&self) -> u8 {
        ISIS_TLV_PROT_SUPPORTED
    }

    fn len(&self) -> u8 {
        1
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.nlpid);
    }
}

#[derive(Debug, NomBE)]
pub struct IsisTlvIpv4IfAddr {
    pub addr: Ipv4Addr,
}

impl TlvEmitter for IsisTlvIpv4IfAddr {
    fn typ(&self) -> u8 {
        ISIS_TLV_IPV4_IF_ADDR
    }

    fn len(&self) -> u8 {
        4
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.addr.octets()[..])
    }
}

#[derive(Debug, NomBE)]
pub struct IsisTlvTeRouterId {
    pub router_id: Ipv4Addr,
}

impl TlvEmitter for IsisTlvTeRouterId {
    fn typ(&self) -> u8 {
        ISIS_TLV_TE_ROUTER_ID
    }

    fn len(&self) -> u8 {
        4
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.router_id.octets()[..])
    }
}

#[derive(Debug)]
pub struct IsisTlvHostname {
    pub hostname: String,
}

impl TlvEmitter for IsisTlvHostname {
    fn typ(&self) -> u8 {
        ISIS_TLV_TE_ROUTER_ID
    }

    fn len(&self) -> u8 {
        self.hostname.len() as u8
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put(self.hostname.as_bytes());
    }
}

#[derive(Debug, Default, NomBE)]
pub struct IsisTlvUnknown {
    pub typ: u8,
    pub len: u8,
    pub values: Vec<u8>,
}

impl IsisTlvUnknown {
    pub fn parse_tlv(input: &[u8], tl: IsisTypeLen) -> IResult<&[u8], Self> {
        let tlv = IsisTlvUnknown {
            typ: tl.typ.0,
            len: tl.len,
            values: Vec::new(),
        };
        Ok((input, tlv))
    }
}

impl TlvEmitter for IsisTlvUnknown {
    fn typ(&self) -> u8 {
        self.typ
    }

    fn len(&self) -> u8 {
        self.len
    }

    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u8(self.typ);
        buf.put_u8(self.len);
        buf.put(self.values.as_bytes());
    }
}

impl ParseBe<Ipv4Addr> for Ipv4Addr {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        if input.len() < 4 {
            return Err(Err::Incomplete(Needed::new(4)));
        }
        let (input, addr) = be_u32(input)?;
        Ok((input, Self::from(addr)))
    }
}

impl ParseBe<IsisTlvHostname> for IsisTlvHostname {
    fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let hostname = Self {
            hostname: String::from_utf8_lossy(input).to_string(),
        };
        Ok((input, hostname))
    }
}

#[derive(Debug, NomBE)]
pub struct IsisTlvType(pub u8);

impl IsisTlvType {
    pub fn is_known(&self) -> bool {
        matches!(
            self.0,
            ISIS_TLV_AREA_ADDR
                | ISIS_TLV_IS_NEIGHBOR
                | ISIS_TLV_PADDING
                | ISIS_TLV_LSP_ENTRIES
                | ISIS_TLV_EXT_IS_REACH
                | ISIS_TLV_PROT_SUPPORTED
                | ISIS_TLV_IPV4_IF_ADDR
                | ISIS_TLV_TE_ROUTER_ID
                | ISIS_TLV_EXT_IP_REACH
                | ISIS_TLV_DYNAMIC_HOSTNAME
                | ISIS_TLV_IPV6_REACH
                | ISIS_TLV_ROUTER_CAP
        )
    }
}

#[derive(NomBE)]
pub struct IsisTypeLen {
    pub typ: IsisTlvType,
    pub len: u8,
}

impl IsisTlv {
    pub fn parse_tlv(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, tl) = IsisTypeLen::parse_be(input)?;
        if input.len() < tl.len as usize {
            return Err(Err::Incomplete(Needed::new(tl.len as usize)));
        }
        let (tlv, input) = input.split_at(tl.len as usize);
        if tl.typ.is_known() {
            let (_, val) = Self::parse_be(tlv, tl.typ)?;
            Ok((input, val))
        } else {
            let (_, val) = IsisTlvUnknown::parse_tlv(tlv, tl)?;
            Ok((input, Self::Unknown(val)))
        }
    }

    pub fn parse_tlvs(input: &[u8]) -> IResult<&[u8], Vec<Self>> {
        many0(Self::parse_tlv)(input)
    }
}

pub fn parse(input: &[u8]) -> IResult<&[u8], IsisPacket> {
    let (input, packet) = IsisPacket::parse_be(input)?;
    Ok((input, packet))
}
