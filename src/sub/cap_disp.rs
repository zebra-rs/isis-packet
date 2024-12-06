use std::fmt::{Display, Formatter, Result};

use super::cap::IsisSubTlv;
use super::*;

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
        }
    }
}

impl Display for IsisSubSegmentRoutingCap {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            r#"   Segment Routing Capability:
    Flags: {}
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
