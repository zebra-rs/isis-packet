use nom_derive::*;

#[derive(NomBE)]
pub struct IsisSubCodeLen {
    pub code: u8,
    pub len: u8,
}

pub mod neigh;
pub use neigh::{
    IsisSubIpv4IfAddr, IsisSubIpv4NeighAddr, IsisSubLanAdjSid, IsisTlvExtIsReach,
    IsisTlvExtIsReachEntry,
};
pub mod neigh_code;
pub use neigh_code::IsisNeighCode;
pub mod neigh_disp;

pub mod prefix;
pub use prefix::{
    IsisSubPrefixSid, IsisTlvExtIpReach, IsisTlvExtIpReachEntry, IsisTlvIpv6Reach,
    IsisTlvIpv6ReachEntry,
};
pub mod prefix_code;
pub use prefix_code::IsisPrefixCode;
pub mod prefix_disp;

pub mod cap;
pub use cap::{
    IsisSubNodeMaxSidDepth, IsisSubSegmentRoutingAlgo, IsisSubSegmentRoutingCap,
    IsisSubSegmentRoutingLB, IsisTlvRouterCap,
};
pub mod cap_code;
pub use cap_code::IsisCapCode;
pub mod cap_disp;
