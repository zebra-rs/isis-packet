use std::fmt::Display;

use nom::number::complete::be_u8;
use nom::IResult;
use nom_derive::*;

#[repr(u8)]
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub enum IsisType {
    #[default]
    L1Hello = 0x0f,
    L2Hello = 0x10,
    P2PHello = 0x11,
    L1Lsp = 0x12,
    L2Lsp = 0x14,
    Csnp = 0x18,
    Psnp = 0x1a,
    Unknown(u8),
}

impl Display for IsisType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use IsisType::*;
        let str = match self {
            L1Hello => "L1 LAN Hello",
            L2Hello => "L2 LAN Hello",
            P2PHello => "P2P LAN Hello",
            L1Lsp => "L1 LSP",
            L2Lsp => "L2 LSP",
            Csnp => "CSNP",
            Psnp => "PSNP",
            Unknown(_v) => "Unknown",
        };
        write!(f, "{str}")
    }
}

impl From<IsisType> for u8 {
    fn from(typ: IsisType) -> Self {
        use IsisType::*;
        match typ {
            L1Hello => 0x0f,
            L2Hello => 0x10,
            P2PHello => 0x11,
            L1Lsp => 0x12,
            L2Lsp => 0x14,
            Csnp => 0x18,
            Psnp => 0x1a,
            Unknown(v) => v,
        }
    }
}

impl From<u8> for IsisType {
    fn from(typ: u8) -> Self {
        use IsisType::*;
        match typ {
            0x0f => L1Hello,
            0x10 => L2Hello,
            0x11 => P2PHello,
            0x12 => L1Lsp,
            0x14 => L2Lsp,
            0x18 => Csnp,
            0x1a => Psnp,
            v => Unknown(v),
        }
    }
}

impl IsisType {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, typ) = be_u8(input)?;
        let isis_type: Self = typ.into();
        Ok((input, isis_type))
    }
}
