use nom::{error::ParseError, IResult};

// many0 which avoid passing empty input to the parser.
pub fn many0<'a, O, E: ParseError<&'a [u8]>>(
    parser: impl Fn(&'a [u8]) -> IResult<&'a [u8], O, E>,
) -> impl Fn(&'a [u8]) -> IResult<&'a [u8], Vec<O>, E> {
    move |input| {
        let mut res = Vec::new();
        let mut remaining = input;

        while !remaining.is_empty() {
            let (new_input, value) = parser(remaining)?;
            remaining = new_input;
            res.push(value);
        }

        Ok((remaining, res))
    }
}

pub fn u32_u8_3(value: u32) -> [u8; 3] {
    // Extract the three least significant bytes as big-endian
    [
        (value >> 16) as u8, // Most significant byte of the remaining 3 bytes
        (value >> 8) as u8,  // Middle byte
        value as u8,         // Least significant byte
    ]
}

pub trait ParseBe<T> {
    fn parse_be(input: &[u8]) -> IResult<&[u8], T>;
}
