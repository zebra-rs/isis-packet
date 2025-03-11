use std::fmt::{Display, Formatter, Result};

use crate::{
    IsisCsnp, IsisHello, IsisLsp, IsisLspEntry, IsisPacket, IsisPdu, IsisProto, IsisPsnp,
    IsisSysId, IsisTlv, IsisTlvAreaAddr, IsisTlvHostname, IsisTlvIpv4IfAddr, IsisTlvIsNeighbor,
    IsisTlvLspEntries, IsisTlvPadding, IsisTlvProtoSupported, IsisTlvTeRouterId,
};

impl Display for IsisPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"== IRPD: ISIS (0x{:x}) ==
 Length Indicator: {}
 Version/Protocol ID Extension: {}
 ID Length: {}
 PDU Type: {}
 Version: {}
 Reserved: {}
 Maximum Area Address: {}
{}"#,
            self.discriminator,
            self.length_indicator,
            self.id_extension,
            self.id_length,
            self.pdu_type,
            self.version,
            self.resvd,
            self.max_area_addr,
            self.pdu,
        )
    }
}

impl Display for IsisPdu {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        use IsisPdu::*;
        match self {
            L1Hello(v) => write!(f, "{}", v),
            L2Hello(v) => write!(f, "{}", v),
            L1Lsp(v) => write!(f, "{}", v),
            L2Lsp(v) => write!(f, "{}", v),
            Csnp(v) => write!(f, "{}", v),
            Psnp(v) => write!(f, "{}", v),
            Unknown(_) => write!(f, "Unknown"),
        }
    }
}

impl Display for IsisLsp {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"== IS-IS L1 LSP ==
 PDU length: {}
 Lifetime: {}
 LSP ID: {:?}
 Sequence number: 0x{:x}
 Checksum: 0x{:x}
 Type block: {:x}"#,
            self.pdu_len, self.lifetime, self.lsp_id, self.seq_number, self.checksum, self.types,
        )?;
        for tlv in self.tlvs.iter() {
            write!(f, "\n{}", tlv)?;
        }
        Ok(())
    }
}

impl Display for IsisHello {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"== IS-IS Hello ==
 Circuit type: {}
 Source ID: {}
 Holding timer: {}
 PDU length: {}
 Priority: {}
 LAN ID {:?}"#,
            self.circuit_type,
            self.source_id,
            self.hold_timer,
            self.pdu_len,
            self.priority,
            self.lan_id
        )?;
        for tlv in self.tlvs.iter() {
            write!(f, "\n{}", tlv)?;
        }
        Ok(())
    }
}

impl Display for IsisCsnp {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"== IS-IS CSNP ==
 PDU length: {}
 Source ID: {:?}
 Source ID Curcuit: {}
 Start: {:?}
 End: {:?}"#,
            self.pdu_len, self.source_id, self.source_id_curcuit, self.start, self.end
        )?;
        for tlv in self.tlvs.iter() {
            write!(f, "{}", tlv)?;
        }
        Ok(())
    }
}

impl Display for IsisPsnp {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"== IS-IS PSNP ==
 PDU length: {}
 Source ID: {}
 Source ID Curcuit: {}"#,
            self.pdu_len, self.source_id, self.source_id_curcuit
        )?;
        for tlv in self.tlvs.iter() {
            write!(f, "{}", tlv)?;
        }
        Ok(())
    }
}

impl Display for IsisTlv {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        use IsisTlv::*;
        match self {
            AreaAddr(v) => write!(f, "{}", v),
            IsNeighbor(v) => write!(f, "{}", v),
            Padding(v) => write!(f, "{}", v),
            LspEntries(v) => write!(f, "{}", v),
            ExtIsReach(v) => write!(f, "{}", v),
            ProtoSupported(v) => write!(f, "{}", v),
            Ipv4IfAddr(v) => write!(f, "{}", v),
            TeRouterId(v) => write!(f, "{}", v),
            ExtIpReach(v) => write!(f, "{}", v),
            Hostname(v) => write!(f, "{}", v),
            Ipv6Reach(v) => write!(f, "{}", v),
            RouterCap(v) => write!(f, "{}", v),
            _ => {
                write!(f, "  Unknown")
            }
        }
    }
}

impl Display for IsisSysId {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            "{:02x}{:02x}.{:02x}{:02x}.{:02x}{:02x}",
            self.sys_id[0],
            self.sys_id[1],
            self.sys_id[2],
            self.sys_id[3],
            self.sys_id[4],
            self.sys_id[5],
        )
    }
}

impl Display for IsisTlvAreaAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            "  Area address: ({}) {:02x}.{:02x}{:02x}",
            self.area_addr[0], self.area_addr[1], self.area_addr[2], self.area_addr[3]
        )
    }
}

impl Display for IsisTlvIsNeighbor {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "  IS Neighbor: {:?}", self.addr)
    }
}

impl Display for IsisTlvPadding {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "  Padding: length {}", self.padding.len())
    }
}

impl Display for IsisLspEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#" LSP Entry:
  Lifetime: {}
  Sequence number: 0x{:x}
  Checksum: 0x{:x}
  LSP ID {:?}"#,
            self.lifetime, self.seq_number, self.checksum, self.lsp_id,
        )
    }
}

impl Display for IsisTlvLspEntries {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        for entry in self.entries.iter() {
            write!(f, "\n{}", entry)?;
        }
        Ok(())
    }
}

pub fn nlpid_str(nlpid: u8) -> &'static str {
    match nlpid.into() {
        IsisProto::Ipv4 => "IPv4",
        IsisProto::Ipv6 => "IPv6",
        _ => "Unknown",
    }
}

impl Display for IsisTlvProtoSupported {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "  Protocol Supported: ").unwrap();
        for nlpid in &self.nlpids {
            write!(f, "{}", nlpid_str(*nlpid)).unwrap();
        }
        Ok(())
    }
}

impl Display for IsisTlvIpv4IfAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "  IPv4 interface addr: {}", self.addr)
    }
}

impl Display for IsisTlvHostname {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "  Hostname: {}", self.hostname)
    }
}

impl Display for IsisTlvTeRouterId {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "  TE Router ID: {}", self.router_id)
    }
}
