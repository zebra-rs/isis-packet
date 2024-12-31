use nom::number::complete::be_u8;
use nom::IResult;
use nom_derive::*;

#[repr(u8)]
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub enum IsisPrefixCode {
    #[default]
    PrefixSid = 3,
    Unknown(u8),
}

impl From<IsisPrefixCode> for u8 {
    fn from(typ: IsisPrefixCode) -> Self {
        use IsisPrefixCode::*;
        match typ {
            PrefixSid => 3,
            Unknown(v) => v,
        }
    }
}

impl From<u8> for IsisPrefixCode {
    fn from(typ: u8) -> Self {
        use IsisPrefixCode::*;
        match typ {
            3 => PrefixSid,
            v => Unknown(v),
        }
    }
}

impl IsisPrefixCode {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, typ) = be_u8(input)?;
        let isis_type: Self = typ.into();
        Ok((input, isis_type))
    }
}
