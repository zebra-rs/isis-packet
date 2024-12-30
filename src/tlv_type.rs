use nom::number::complete::be_u8;
use nom::IResult;
use nom_derive::*;

#[repr(u8)]
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub enum IsisTlvType {
    #[default]
    AreaAddr = 1,
    IsNeighbor = 6,
    Padding = 8,
    LspEntries = 9,
    ExtIsReach = 22,
    ProtSupported = 129,
    Ipv4IfAddr = 132,
    TeRouterId = 134,
    ExtIpReach = 135,
    DynamicHostname = 137,
    Ipv6Reach = 236,
    RouterCap = 242,
    Unknown(u8),
}

impl IsisTlvType {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, typ) = be_u8(input)?;
        let tlv_type: Self = typ.into();
        Ok((input, tlv_type))
    }
}

impl IsisTlvType {
    pub fn is_known(&self) -> bool {
        use IsisTlvType::*;
        matches!(
            self,
            AreaAddr
                | IsNeighbor
                | Padding
                | LspEntries
                | ExtIsReach
                | ProtSupported
                | Ipv4IfAddr
                | TeRouterId
                | ExtIpReach
                | DynamicHostname
                | Ipv6Reach
                | RouterCap
        )
    }
}

impl From<IsisTlvType> for u8 {
    fn from(typ: IsisTlvType) -> Self {
        use IsisTlvType::*;
        match typ {
            AreaAddr => 1,
            IsNeighbor => 6,
            Padding => 8,
            LspEntries => 9,
            ExtIsReach => 22,
            ProtSupported => 129,
            Ipv4IfAddr => 132,
            TeRouterId => 134,
            ExtIpReach => 135,
            DynamicHostname => 137,
            Ipv6Reach => 236,
            RouterCap => 242,
            Unknown(v) => v,
        }
    }
}

impl From<u8> for IsisTlvType {
    fn from(typ: u8) -> Self {
        use IsisTlvType::*;
        match typ {
            1 => AreaAddr,
            6 => IsNeighbor,
            8 => Padding,
            9 => LspEntries,
            22 => ExtIsReach,
            129 => ProtSupported,
            132 => Ipv4IfAddr,
            134 => TeRouterId,
            135 => ExtIpReach,
            137 => DynamicHostname,
            236 => Ipv6Reach,
            242 => RouterCap,
            v => Unknown(v),
        }
    }
}