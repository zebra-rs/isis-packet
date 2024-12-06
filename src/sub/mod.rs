use nom_derive::*;

#[derive(Debug, NomBE)]
pub struct IsisSubCode(pub u8);

#[derive(NomBE)]
pub struct IsisSubCodeLen {
    pub code: IsisSubCode,
    pub len: u8,
}

pub mod neigh;
pub use neigh::{
    IsisSubIpv4IfAddr, IsisSubIpv4NeighAddr, IsisSubLanAdjSid, IsisTlvExtIsReach,
    IsisTlvExtIsReachEntry,
};
pub mod neigh_disp;

pub mod prefix;
pub use prefix::{
    IsisSubPrefixSid, IsisTlvExtIpReach, IsisTlvExtIpReachEntry, IsisTlvIpv6Reach,
    IsisTlvIpv6ReachEntry,
};
pub mod prefix_disp;

pub mod cap;
pub use cap::{
    IsisSubNodeMaxSidDepth, IsisSubSegmentRoutingAlgo, IsisSubSegmentRoutingCap,
    IsisSubSegmentRoutingLB, IsisTlvRouterCap,
};
pub mod cap_disp;
