use std::fmt::{Display, Formatter, Result};

use super::prefix::{IsisSubSrv6EndSid, IsisSubTlv, PrefixSidFlags};
use super::{
    IsisSubPrefixSid, IsisTlvExtIpReach, IsisTlvExtIpReachEntry, IsisTlvIpv6Reach,
    IsisTlvIpv6ReachEntry,
};

impl Display for IsisTlvExtIpReach {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        for (pos, entry) in self.entries.iter().enumerate() {
            if pos == 0 {
                write!(f, "{}", entry)?;
            } else {
                write!(f, "\n{}", entry)?;
            }
        }
        Ok(())
    }
}

impl Display for IsisTlvExtIpReachEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"  Extended IP Reachability: {} (Metric: {})"#,
            self.prefix,
            self.metric,
            // self.flags.distribution(),
            // self.flags.sub_tlv(),
            // self.flags.prefixlen(),
        )?;
        for sub in self.subs.iter() {
            write!(f, "\n{}", sub)?;
        }
        Ok(())
    }
}

impl Display for IsisTlvIpv6Reach {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        for (pos, entry) in self.entries.iter().enumerate() {
            if pos == 0 {
                write!(f, "{}", entry)?;
            } else {
                write!(f, "\n{}", entry)?;
            }
        }
        Ok(())
    }
}

impl Display for IsisTlvIpv6ReachEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"  IPv6 Reachability: {} (Metric: {})"#,
            self.prefix,
            self.metric,
            // self.flags.dist_up(),
            // self.flags.dist_internal(),
            // self.flags.sub_tlv(),
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
            PrefixSid(v) => write!(f, "{}", v),
            Srv6EndSid(v) => write!(f, "{}", v),
            Unknown(v) => write!(f, "Unknown: Code {}, Length {}", v.code, v.len),
        }
    }
}

impl Display for PrefixSidFlags {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            "R:{} N:{} P:{} E:{} V:{} L:{}",
            self.r_flag() as u8,
            self.n_flag() as u8,
            self.p_flag() as u8,
            self.e_flag() as u8,
            self.v_flag() as u8,
            self.l_flag() as u8
        )
    }
}

impl Display for IsisSubPrefixSid {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"   SID: {:?}, Algorithm: {}, Flags: {}"#,
            self.sid, self.algo, self.flags,
        )
    }
}

impl Display for IsisSubSrv6EndSid {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"   SID: {:?}, Behavior: {}, Flags: {}"#,
            self.sids, self.behavior, self.flags,
        )
    }
}
