use crate::dns::{
    packet::Buffer,
    qualified_name::QualifiedName,
    traits::{WriteTo, IO},
    DNSError, QueryType, Result,
};

#[derive(Debug, Clone, PartialEq, Eq, Default, PartialOrd, Ord)]
pub struct Question {
    pub name: QualifiedName,
    pub qtype: QueryType,
}

impl<'a, T: IO> WriteTo<'a, T> for Question {
    fn write_to(&self, out: &'a mut T) -> Result<&'a mut T> {
        out.write(&self.name)?
            .write(self.qtype)?
            .write(&1u16.to_be_bytes())
    }
}

impl TryFrom<&mut Buffer> for Question {
    type Error = DNSError;

    fn try_from(buffer: &mut Buffer) -> Result<Self> {
        let question = Question {
            name: buffer.read::<QualifiedName>()?,
            qtype: QueryType::from(buffer.read::<u16>()?),
        };

        let _ = buffer.read::<u16>()?;

        Ok(question)
    }
}
