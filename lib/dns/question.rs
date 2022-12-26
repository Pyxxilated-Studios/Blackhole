use serde::{Deserialize, Serialize};

use crate::dns::{
    qualified_name::QualifiedName,
    traits::{FromBuffer, WriteTo, IO},
    QueryType, Result,
};

#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Clone, PartialEq, Eq, Default, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Question {
    pub name: QualifiedName,
    pub qtype: QueryType,
    pub class: u16,
}

impl<'a, T: IO> WriteTo<'a, T> for Question {
    type Out = T;

    #[inline]
    fn write_to(self, out: &'a mut T) -> Result<&'a mut T> {
        out.write(self.name)?.write(self.qtype)?.write(self.class)
    }
}

impl<I: IO> FromBuffer<I> for Question {
    fn from_buffer(buffer: &mut I) -> Result<Self> {
        let question = Question {
            name: buffer.read()?,
            qtype: QueryType::from(buffer.read::<u16>()?),
            class: buffer.read()?,
        };

        Ok(question)
    }
}
