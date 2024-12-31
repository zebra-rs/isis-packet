use nom::number::complete::be_u8;
use nom::IResult;
use nom_derive::*;

#[repr(u8)]
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub enum IsisNeighCode {
    #[default]
    Ipv4IfAddr = 6,
    Ipv4NeighAddr = 8,
    LanAdjSid = 32,
    Unknown(u8),
}

impl From<IsisNeighCode> for u8 {
    fn from(typ: IsisNeighCode) -> Self {
        use IsisNeighCode::*;
        match typ {
            Ipv4IfAddr => 6,
            Ipv4NeighAddr => 8,
            LanAdjSid => 32,
            Unknown(v) => v,
        }
    }
}

impl From<u8> for IsisNeighCode {
    fn from(typ: u8) -> Self {
        use IsisNeighCode::*;
        match typ {
            6 => Ipv4IfAddr,
            8 => Ipv4NeighAddr,
            32 => LanAdjSid,
            v => Unknown(v),
        }
    }
}

impl IsisNeighCode {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, typ) = be_u8(input)?;
        let isis_type: Self = typ.into();
        Ok((input, isis_type))
    }
}
