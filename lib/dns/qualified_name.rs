use serde::Serialize;

use crate::dns::{
    packet::Buffer,
    traits::{WriteTo, IO},
    DNSError, Result,
};

#[derive(Clone, Default, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct QualifiedName(pub String);

impl QualifiedName {
    #[inline]
    pub fn name(&self) -> String {
        self.0.clone()
    }
}

impl<'a, T: IO> WriteTo<'a, T> for &QualifiedName {
    fn write_to(&self, out: &'a mut T) -> Result<&'a mut T> {
        self.name()
            .split('.')
            .try_fold(out, |buffer, label| {
                let len = label.len();
                if len > 0x3f {
                    Err(DNSError::EndOfBuffer)
                } else {
                    buffer.write(len as u8)?.write(label.as_bytes())
                }
            })?
            .write(0u8)
    }
}

impl<'a> From<&'a QualifiedName> for &'a str {
    #[inline]
    fn from(qn: &'a QualifiedName) -> Self {
        &qn.0
    }
}

impl TryFrom<&mut Buffer> for QualifiedName {
    type Error = DNSError;

    /// Read a qname
    ///
    /// The tricky part: Reading domain names, taking labels into consideration.
    /// Will take something like [3]www[6]google[3]com[0] and append
    /// www.google.com to outstr.
    fn try_from(buffer: &mut Buffer) -> Result<QualifiedName> {
        let mut pos = buffer.pos();
        let mut jumped = false;
        let mut outstr = String::new();

        let mut delim = "";
        loop {
            let len = buffer.get(pos)?;

            // A two byte sequence, where the two highest bits of the first byte is
            // set, represents a offset relative to the start of the buffer. We
            // handle this by jumping to the offset, setting a flag to indicate
            // that we shouldn't update the shared buffer position once done.
            if (len & 0xC0) > 0 {
                // When a jump is performed, we only modify the shared buffer
                // position once, and avoid making the change later on.
                if !jumped {
                    buffer.seek(pos + 2)?;
                }

                let b2 = u16::from(buffer.get(pos + 1)?);
                let offset = ((u16::from(len) ^ 0xC0) << 8) | b2;
                pos = offset as usize;
                jumped = true;
                continue;
            }

            pos += 1;

            // Names are terminated by an empty label of length 0
            if len == 0 {
                break;
            }

            outstr.push_str(delim);

            let str_buffer = buffer.get_range(pos, len as usize)?;
            outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

            delim = ".";

            pos += len as usize;
        }

        if !jumped {
            buffer.seek(pos)?;
        }

        Ok(QualifiedName(outstr))
    }
}
