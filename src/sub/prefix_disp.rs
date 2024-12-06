use std::fmt::{Display, Formatter, Result};

use super::prefix::IsisSubTlv;
use super::*;

impl Display for IsisTlvExtIpReach {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "  Extended IP Reachability:")?;
        for entry in self.entries.iter() {
            write!(f, "\n{}", entry)?;
        }
        Ok(())
    }
}

impl Display for IsisTlvExtIpReachEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"    Metric: {}
    Flags: distribution: {}, sub_tlv: {}, prefixlen: {}
    Prefix: {}"#,
            self.metric,
            self.flags.distribution(),
            self.flags.sub_tlv(),
            self.flags.prefixlen(),
            self.prefix
        )?;
        for sub in self.subs.iter() {
            write!(f, "\n{}", sub)?;
        }
        Ok(())
    }
}

impl Display for IsisTlvIpv6Reach {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "  IPv6 Reachability:")?;
        for entry in self.entries.iter() {
            write!(f, "\n{}", entry)?;
        }
        Ok(())
    }
}

impl Display for IsisTlvIpv6ReachEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"    Metric: {}
    Flags: distribution up: {}, distribution internal: {}, sub_tlv: {}
    Prefix: {}"#,
            self.metric,
            self.flags.dist_up(),
            self.flags.dist_internal(),
            self.flags.sub_tlv(),
            self.prefix
        )?;
        for sub in self.subs.iter() {
            write!(f, "\n{}", sub)?;
        }
        Ok(())
    }
}

impl Display for IsisSubTlv {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        use prefix::IsisSubTlv::*;
        match self {
            PrefixSid(v) => write!(f, "{}", v),
        }
    }
}

impl Display for IsisSubPrefixSid {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"     Flags: {}
     Algorithm: {}
     SID: {}"#,
            self.flags, self.algo, self.sid
        )
    }
}
