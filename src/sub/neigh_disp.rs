use std::fmt::{Display, Formatter, Result};

use super::neigh::{IsisSubAdjSid, IsisSubTlv};
use super::{
    IsisSubIpv4IfAddr, IsisSubIpv4NeighAddr, IsisSubIpv6IfAddr, IsisSubIpv6NeighAddr,
    IsisSubLanAdjSid, IsisTlvExtIsReach, IsisTlvExtIsReachEntry,
};

impl Display for IsisTlvExtIsReach {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "  Extended IS Reachability:")?;
        for entry in self.entries.iter() {
            write!(f, "\n{}", entry)?;
        }
        Ok(())
    }
}

impl Display for IsisTlvExtIsReachEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"   Neighbor ID: {}, Metric: {}"#,
            self.neighbor_id, self.metric
        )?;
        for sub in self.subs.iter() {
            write!(f, "\n{}", sub)?;
        }
        Ok(())
    }
}

impl Display for IsisSubTlv {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        use IsisSubTlv::*;
        match self {
            Ipv4IfAddr(v) => write!(f, "{}", v),
            Ipv4NeighAddr(v) => write!(f, "{}", v),
            Ipv6IfAddr(v) => write!(f, "{}", v),
            Ipv6NeighAddr(v) => write!(f, "{}", v),
            AdjSid(v) => write!(f, "{}", v),
            LanAdjSid(v) => write!(f, "{}", v),
            _ => {
                write!(f, "    Unknown")
            }
        }
    }
}

impl Display for IsisSubIpv4IfAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "    IPv4 interface addr: {}", self.addr)
    }
}

impl Display for IsisSubIpv4NeighAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "    IPv4 neighbor addr: {}", self.addr)
    }
}

impl Display for IsisSubIpv6IfAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "    IPv6 interface addr: {}", self.addr)
    }
}

impl Display for IsisSubIpv6NeighAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "    IPv6 neighbor addr: {}", self.addr)
    }
}

impl Display for IsisSubAdjSid {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            "    Adjacency SID: {}, Flag: {}, Weight: {}",
            self.sid, self.flags, self.weight
        )
    }
}

impl Display for IsisSubLanAdjSid {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            "    LAN Adjacency SID: {}, Neighbor {}, Flag: {}, Weight: {}",
            self.sid, self.system_id, self.flags, self.weight
        )
    }
}
