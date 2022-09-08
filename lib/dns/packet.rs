use std::convert::TryFrom;

use crate::dns::{DNSError, Header, Question, Record, Result};

pub(crate) const DNS_PACKET_SIZE: usize = 512;

pub trait WriteTo<'a, T> {
    ///
    /// Write an element (or series thereof) to an output.
    ///
    /// This is intended to be used for Buffers (or their variants),
    /// where it is nice to chain writes, i.e.
    ///
    /// ```
    /// let buffer = Buffer::default();
    /// buffer.write(1u16)?.write(0u16)
    /// ```
    ///
    /// # Errors
    /// This could fail for many reasons, this simplest being that
    /// writing the element to the buffer caused it to overflow its
    /// internal buffer
    ///
    fn write_to(&self, out: &'a mut T) -> Result<&'a mut T>;
}

pub(crate) trait IO {
    /// Current position within buffer
    fn pos(&self) -> usize;

    /// Step the buffer position forward a specific number of steps
    fn step(&mut self, steps: usize) -> Result<&mut Self>;

    /// Change the buffer position
    fn seek(&mut self, pos: usize) -> Result<&mut Self>;

    /// Get a single byte, without changing the buffer position
    fn get(&mut self, pos: usize) -> Result<u8>;

    /// Set a byte at a specific position
    fn set<T>(&mut self, pos: usize, val: T) -> Result<&mut Self>
    where
        T: num::Unsigned + num::PrimInt;

    /// Get a range of bytes
    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]>;

    fn read<'a, T>(&'a mut self) -> Result<T>
    where
        T: TryFrom<&'a mut Self, Error = DNSError> + Default;

    fn write<'a, T>(&'a mut self, val: T) -> Result<&'a mut Self>
    where
        Self: Sized,
        T: WriteTo<'a, Self>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Buffer {
    pub buffer: [u8; DNS_PACKET_SIZE],
    pub pos: usize,
}

impl Buffer {
    pub(crate) fn buffer(&self) -> &[u8; DNS_PACKET_SIZE] {
        &self.buffer
    }

    pub(crate) fn buffer_mut(&mut self) -> &mut [u8; DNS_PACKET_SIZE] {
        &mut self.buffer
    }
}

macro_rules! impl_write {
    ( $($t:ty),* ) => {
        $(impl<'a> WriteTo<'a, Buffer> for $t {
            fn write_to(&self, buffer: &'a mut Buffer) -> Result<&'a mut Buffer> {
                if core::any::TypeId::of::<$t>() == core::any::TypeId::of::<u8>() {
                    buffer.set(buffer.pos(), *self as u8)?;
                    buffer.pos += 1;

                    Ok(buffer)
                } else {
                    let bytes = core::mem::size_of::<$t>();
                    let val = self.to_be();

                    (0..bytes).try_fold(buffer, |buffer, byte| {
                        let v = (val >> (byte * u8::BITS as usize)) as u8 & 0xFF;
                        (*buffer).write(v)
                    })
                }
            }
        })*
    }
}

macro_rules! impl_try_from {
    ( $($t:ty),* ) => {
        $(impl TryFrom<&mut Buffer> for $t {
            type Error = DNSError;

            /// Read two bytes, stepping two steps forward
            fn try_from(buffer: &mut Buffer) -> Result<$t> {
                let res = <$t>::from_be_bytes(std::array::try_from_fn(|_| buffer.read())?);

                Ok(res)
            }
        })*
    }
}

impl TryFrom<&mut Buffer> for u8 {
    type Error = DNSError;

    fn try_from(buffer: &mut Buffer) -> Result<u8> {
        let res = buffer.get(buffer.pos())?;
        buffer.pos += 1;

        Ok(res)
    }
}

impl_write!(u8, i8, u16, i16, u32, i32, u64, i64, u128, i128, usize);
impl_try_from!(i8, u16, i16, u32, i32, u64, i64, u128, i128, usize);

impl<'a> WriteTo<'a, Buffer> for &[u8] {
    fn write_to(&self, out: &'a mut Buffer) -> Result<&'a mut Buffer> {
        self.iter().try_fold(out, |buffer, &val| buffer.write(val))
    }
}

impl<'a, const N: usize> WriteTo<'a, Buffer> for &[u8; N] {
    fn write_to(&self, out: &'a mut Buffer) -> Result<&'a mut Buffer> {
        self.iter().try_fold(out, |buffer, &val| buffer.write(val))
    }
}

impl<'a, T> WriteTo<'a, Buffer> for Vec<T>
where
    T: WriteTo<'a, Buffer> + Clone,
{
    fn write_to(&self, out: &'a mut Buffer) -> Result<&'a mut Buffer> {
        self.iter()
            .try_fold(out, |buffer, val| buffer.write(val.clone()))
    }
}

impl IO for Buffer {
    fn pos(&self) -> usize {
        self.pos
    }

    fn step(&mut self, steps: usize) -> Result<&mut Buffer> {
        if self.pos + steps >= DNS_PACKET_SIZE {
            Err(DNSError::EndOfBuffer)
        } else {
            self.pos += steps;
            Ok(self)
        }
    }

    fn seek(&mut self, pos: usize) -> Result<&mut Buffer> {
        if pos >= DNS_PACKET_SIZE {
            Err(DNSError::EndOfBuffer)
        } else {
            self.pos = pos;
            Ok(self)
        }
    }

    fn get(&mut self, pos: usize) -> Result<u8> {
        if pos >= DNS_PACKET_SIZE {
            Err(DNSError::EndOfBuffer)
        } else {
            Ok(self.buffer[pos])
        }
    }

    fn set<T>(&mut self, pos: usize, val: T) -> Result<&mut Buffer>
    where
        T: num::Unsigned + num::PrimInt,
    {
        if pos >= DNS_PACKET_SIZE {
            return Err(DNSError::EndOfBuffer);
        }

        let bytes = std::mem::size_of::<T>();

        if bytes == 1 {
            self.buffer[pos] = val.to_u8().unwrap();
        } else {
            (1..=bytes).for_each(|byte| {
                self.buffer[pos + byte - 1] = (val >> ((bytes - byte) * u8::BITS as usize)
                    & T::from(0xFF).unwrap())
                .to_u8()
                .unwrap();
            });
        }

        Ok(self)
    }

    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= DNS_PACKET_SIZE {
            Err(DNSError::EndOfBuffer)
        } else {
            Ok(&self.buffer[start..start + len as usize])
        }
    }

    fn read<'a, T>(&'a mut self) -> Result<T>
    where
        T: TryFrom<&'a mut Self, Error = DNSError> + Default,
    {
        T::try_from(self)
    }

    fn write<'a, T>(&'a mut self, val: T) -> Result<&'a mut Self>
    where
        T: WriteTo<'a, Self>,
    {
        val.write_to(self)
    }
}

impl TryFrom<Packet> for Buffer {
    type Error = DNSError;

    fn try_from(mut packet: Packet) -> Result<Self> {
        let mut buffer = Buffer::default();
        packet.header.questions = packet.questions.len() as u16;
        packet.header.answers = packet.answers.len() as u16;
        packet.header.authoritative_entries = packet.authorities.len() as u16;
        packet.header.resource_entries = packet.resources.len() as u16;

        buffer
            .write(packet.header)?
            .write(packet.questions)?
            .write(packet.answers)?
            .write(packet.authorities)?
            .write(packet.resources)?;

        Ok(buffer)
    }
}

impl Default for Buffer {
    fn default() -> Self {
        Buffer {
            buffer: [0; DNS_PACKET_SIZE],
            pos: 0,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Packet {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub resources: Vec<Record>,
}

impl TryFrom<&mut Buffer> for Packet {
    type Error = DNSError;

    fn try_from(buffer: &mut Buffer) -> Result<Packet> {
        buffer.seek(0)?;
        let header = Header::try_from(&mut *buffer)?;

        let questions = header.questions;
        let answers = header.answers;
        let authorities = header.authoritative_entries;
        let resources = header.resource_entries;

        let result = Packet {
            header,
            questions: (0..questions)
                .filter_map(|_| Question::try_from(&mut *buffer).ok())
                .collect(),
            answers: (0..answers)
                .filter_map(|_| Record::try_from(&mut *buffer).ok())
                .collect(),
            authorities: (0..authorities)
                .filter_map(|_| Record::try_from(&mut *buffer).ok())
                .collect(),
            resources: (0..resources)
                .filter_map(|_| Record::try_from(&mut *buffer).ok())
                .collect(),
        };

        Ok(result)
    }
}

#[allow(unused_imports)]
mod test {
    use crate::dns::{
        packet::{Buffer, Packet},
        Header, QualifiedName, QueryType, Question, Record, ResultCode, Ttl,
    };

    #[test]
    fn serialise() {
        let packet = Packet {
            header: Header {
                id: 56029,
                recursion_desired: true,
                truncated_message: false,
                authoritative_answer: false,
                opcode: 0,
                response: true,
                rescode: ResultCode::NOERROR,
                checking_disabled: false,
                authed_data: true,
                z: false,
                recursion_available: true,
                questions: 1,
                answers: 2,
                authoritative_entries: 0,
                resource_entries: 0,
            },
            questions: vec![Question {
                name: QualifiedName("example.com".to_owned()),
                qtype: QueryType::MX,
            }],
            answers: vec![
                Record::MX {
                    domain: QualifiedName("example.com".to_owned()),
                    priority: 10,
                    host: QualifiedName("mail.example.com".to_owned()),
                    ttl: Ttl(3600),
                },
                Record::MX {
                    domain: QualifiedName("example.com".to_owned()),
                    priority: 20,
                    host: QualifiedName("mailsec.example.com".to_owned()),
                    ttl: Ttl(3600),
                },
            ],
            authorities: vec![],
            resources: vec![],
        };

        let pack = Packet::try_from(&mut Buffer::try_from(packet.clone()).unwrap()).unwrap();
        assert_eq!(packet.header, pack.header);
        assert_eq!(packet.questions, pack.questions);
        assert_eq!(packet.answers, pack.answers);
        assert_eq!(packet.resources, pack.resources);
        assert_eq!(packet.authorities, pack.authorities);
    }
}
