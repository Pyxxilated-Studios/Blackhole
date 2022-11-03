use serde::Serialize;

use crate::dns::{
    qualified_name::QualifiedName,
    traits::{FromBuffer, WriteTo, IO},
    QueryType, Result,
};

#[derive(Debug, Clone, PartialEq, Eq, Default, PartialOrd, Ord, Serialize)]
pub struct Question {
    pub name: QualifiedName,
    pub qtype: QueryType,
}

impl<'a, T: IO> WriteTo<'a, T> for Question {
    type Out = T;

    #[inline]
    fn write_to(self, out: &'a mut T) -> Result<&'a mut T> {
        out.write(self.name)?.write(self.qtype)?.write(1u16)
    }
}

impl<I: IO> FromBuffer<I> for Question {
    fn from_buffer(buffer: &mut I) -> Result<Self> {
        let question = Question {
            name: buffer.read()?,
            qtype: QueryType::from(buffer.read::<u16>()?),
        };

        let _class = buffer.read::<u16>()?;

        Ok(question)
    }
}
