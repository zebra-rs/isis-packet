use std::fmt::{Display, Formatter, Result};

use super::cap::IsisSubTlv;
use super::{
    IsisSubNodeMaxSidDepth, IsisSubSegmentRoutingAlgo, IsisSubSegmentRoutingCap,
    IsisSubSegmentRoutingLB, IsisTlvRouterCap, SegmentRoutingCapFlags,
};

impl Display for IsisTlvRouterCap {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"  Router Capability: {}
   Flags: {}"#,
            self.router_id, self.flags
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
            SegmentRoutingCap(v) => write!(f, "{}", v),
            SegmentRoutingAlgo(v) => write!(f, "{}", v),
            SegmentRoutingLB(v) => write!(f, "{}", v),
            NodeMaxSidDepth(v) => write!(f, "{}", v),
            Unknown(v) => write!(f, "Unknown Code: {} Len: {}", v.code, v.len),
        }
    }
}

impl Display for SegmentRoutingCapFlags {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "I:{} V:{}", self.i_flag() as u8, self.v_flag() as u8,)
    }
}

impl Display for IsisSubSegmentRoutingCap {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"   Segment Routing Capability: {}
    Range: {}
    SID: {:?}"#,
            self.flags, self.range, self.sid
        )
    }
}

impl Display for IsisSubSegmentRoutingAlgo {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"   Segment Routing Algorithm:
    Algo: {:?}"#,
            self.algo
        )
    }
}

impl Display for IsisSubSegmentRoutingLB {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"   Segment Routing Local Block:
    Flags: {}
    Range: {}
    SID: {:?}"#,
            self.flags, self.range, self.sid
        )
    }
}

impl Display for IsisSubNodeMaxSidDepth {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"   Node Maximum SID Depth: : MSD Type {}
    MSD Value: {}"#,
            self.flags, self.depth
        )
    }
}
