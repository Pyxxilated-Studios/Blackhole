use crate::dns::{
    traits::{FromBuffer, WriteTo, IO},
    Result, ResultCode,
};

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Header {
    pub id: u16,

    pub recursion_desired: bool,
    pub truncated_message: bool,
    pub authoritative_answer: bool,
    pub opcode: u8,
    pub response: bool,

    pub rescode: ResultCode,
    pub checking_disabled: bool,
    pub authed_data: bool,
    pub z: bool,
    pub recursion_available: bool,

    pub questions: u16,
    pub answers: u16,
    pub authoritative_entries: u16,
    pub resource_entries: u16,
}

impl<I: IO> FromBuffer<I> for Header {
    fn from_buffer(buffer: &mut I) -> Result<Header> {
        let id = buffer.read()?;
        let [a, b] = buffer.read::<u16>()?.to_be_bytes();

        let header = Header {
            id,

            recursion_desired: (a & (1 << 0)) > 0,
            truncated_message: (a & (1 << 1)) > 0,
            authoritative_answer: (a & (1 << 2)) > 0,
            opcode: (a >> 3) & 0x0F,
            response: (a & (1 << 7)) > 0,

            rescode: (b & 0x0F).into(),
            checking_disabled: (b & (1 << 4)) > 0,
            authed_data: (b & (1 << 5)) > 0,
            z: (b & (1 << 6)) > 0,
            recursion_available: (b & (1 << 7)) > 0,

            questions: buffer.read()?,
            answers: buffer.read()?,
            authoritative_entries: buffer.read()?,
            resource_entries: buffer.read()?,
        };

        Ok(header)
    }
}

impl<'a, T: IO> WriteTo<'a, T> for Header {
    fn write_to(&self, out: &'a mut T) -> Result<&'a mut T> {
        out.write(self.id)?
            .write(
                u8::from(self.recursion_desired)
                    | (u8::from(self.truncated_message) << 1)
                    | (u8::from(self.authoritative_answer) << 2)
                    | (self.opcode << 3)
                    | (u8::from(self.response) << 7),
            )?
            .write(
                u8::from(self.rescode)
                    | (u8::from(self.checking_disabled) << 4)
                    | (u8::from(self.authed_data) << 5)
                    | (u8::from(self.z) << 6)
                    | (u8::from(self.recursion_available) << 7),
            )?
            .write(self.questions)?
            .write(self.answers)?
            .write(self.authoritative_entries)?
            .write(self.resource_entries)
    }
}
