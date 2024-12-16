use std::fmt::{Display, Formatter, Result};

use super::*;

impl Display for IsisPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"== IRPD: ISIS (0x{:x}) ==
 Length Indicator: {}
 Version/Protocol ID Extension: {}
 ID Length: {}
 PDU Type: 0x{:x}
 Version: {}
 Reserved: {}
 Maximum Area Address: {}
{}"#,
            self.discriminator,
            self.length_indicator,
            self.id_extension,
            self.id_length,
            self.pdu_type.0,
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
            L1Lsp(v) => write!(f, "{}", v),
            Csnp(v) => write!(f, "{}", v),
            Psnp(v) => write!(f, "{}", v),
        }
    }
}

impl Display for IsisL1Lsp {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"== IS-IS L1 LSP ==
 PDU length: {}
 Lifetime: {}
 Sequence number: 0x{:x}
 Checksum: 0x{:x}
 Type block: {:x}"#,
            self.pdu_len, self.lifetime, self.seq_number, self.checksum, self.types,
        )?;
        for tlv in self.tlvs.iter() {
            write!(f, "\n{}", tlv)?;
        }
        Ok(())
    }
}

impl Display for IsisL1Hello {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"== IS-IS L1 LAN Hello ==
 Circuit type: {}
 Source ID: {:?}
 Holding timer: {}
 PDU length: {}
 Priority: {}
 LAN ID {:?}"#,
            self.circuit_type,
            self.source_id,
            self.holding_timer,
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
 Source ID: {:?}
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
            ProtSupported(v) => write!(f, "{}", v),
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

impl Display for IsisTlvAreaAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "  Area address: {:?}", self.area_addr)
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

impl Display for IsisTlvProtSupported {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "  Protocol Supported: {:x}", self.nlpid)
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
