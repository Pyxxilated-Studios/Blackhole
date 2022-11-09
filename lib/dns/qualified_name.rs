use bstr::{BString, ByteSlice, ByteVec};
use serde::Serialize;

use crate::dns::{
    traits::{WriteTo, IO},
    DNSError, Result,
};

use super::traits::FromBuffer;

pub const MAX_QUALIFIED_NAME_LENGTH: usize = 2048;

#[derive(Clone, Default, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct QualifiedName(pub BString);

impl QualifiedName {
    #[inline]
    pub fn name(&self) -> &BString {
        &self.0
    }
}

impl Serialize for QualifiedName {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.0.to_str().unwrap())
    }
}

impl<'a, T: IO> WriteTo<'a, T> for QualifiedName {
    type Out = T;

    fn write_to(self, out: &'a mut T) -> Result<&'a mut T> {
        if self.0.is_empty() {
            out.write(0u8)
        } else {
            self.name()
                .split(|&c| c == b'.')
                .try_fold(out, |buffer, label| {
                    let len = label.len();
                    if len > 0x3f {
                        Err(DNSError::InvalidPacket)
                    } else {
                        buffer.write(len as u8)?.write(label.as_bytes())
                    }
                })?
                .write(0u8)
        }
    }
}

impl<'a> From<&'a QualifiedName> for &'a BString {
    #[inline]
    fn from(qn: &'a QualifiedName) -> Self {
        &qn.0
    }
}

impl<I: IO> FromBuffer<I> for QualifiedName {
    /// Read a qname
    ///
    /// The tricky part: Reading domain names, taking labels into consideration.
    /// Will take something like [3]www[6]google[3]com[0] and append
    /// www.google.com to outstr.
    fn from_buffer(buffer: &mut I) -> Result<Self> {
        let mut pos = buffer.pos();
        let mut jumped = false;
        let mut outstr = BString::new(Vec::with_capacity(128));

        loop {
            if outstr.len() > MAX_QUALIFIED_NAME_LENGTH {
                return Err(DNSError::InvalidPacket);
            }

            let len = buffer.get(pos)?;

            pos += 1;

            // Names are terminated by an empty label of length 0
            if len == 0 {
                break;
            }

            // A two byte sequence, where the two highest bits of the first byte is
            // set, represents an offset relative to the start of the buffer. We
            // handle this by jumping to the offset, setting a flag to indicate
            // that we shouldn't update the shared buffer position once done.
            if (len & 0xC0) > 0 {
                // When a jump is performed, we only modify the shared buffer
                // position once, and avoid making the change later on.
                if !jumped {
                    buffer.seek(pos + 1)?;
                }

                let b2 = u16::from(buffer.get(pos)?);
                let offset = ((u16::from(len) ^ 0xC0) << 8) | b2;
                pos = offset as usize;
                jumped = true;
            } else {
                if outstr.len() > 0 {
                    outstr.push_char('.');
                }

                outstr.push_str(buffer.get_range(pos, len as usize)?);

                pos += len as usize;
            }
        }

        if !jumped {
            buffer.seek(pos)?;
        }

        Ok(QualifiedName(outstr))
    }
}
