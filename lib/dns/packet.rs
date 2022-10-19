use std::convert::TryFrom;

use crate::dns::{
    header::Header,
    question::Question,
    traits::{WriteTo, IO},
    DNSError, Record, Result,
};

use super::traits::FromBuffer;

pub(crate) const DNS_PACKET_SIZE: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Buffer {
    pub buffer: [u8; DNS_PACKET_SIZE],
    pub pos: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ResizableBuffer {
    pub buffer: Vec<u8>,
    pub pos: usize,
}

impl Default for ResizableBuffer {
    fn default() -> Self {
        Self {
            buffer: vec![0; DNS_PACKET_SIZE],
            pos: Default::default(),
        }
    }
}

impl Buffer {
    #[inline]
    pub(crate) fn buffer_mut(&mut self) -> &mut [u8] {
        &mut self.buffer
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

    fn get(&self, pos: usize) -> Result<u8> {
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

    fn get_range(&self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= DNS_PACKET_SIZE {
            Err(DNSError::EndOfBuffer)
        } else {
            Ok(&self.buffer[start..start + len])
        }
    }

    fn read<T>(&'_ mut self) -> Result<T>
    where
        T: FromBuffer<Self> + Default,
    {
        T::from_buffer(self)
    }

    fn write<'a, T>(&'a mut self, val: T) -> Result<&'a mut Self>
    where
        T: WriteTo<'a, Self, Out = Self>,
    {
        val.write_to(self)
    }
}

impl IO for ResizableBuffer {
    fn pos(&self) -> usize {
        self.pos
    }

    fn step(&mut self, steps: usize) -> Result<&mut ResizableBuffer> {
        if self.pos + steps >= self.buffer.len() {
            self.buffer.resize(self.buffer.len() << 1, 0);
        }

        self.pos += steps;
        Ok(self)
    }

    fn seek(&mut self, pos: usize) -> Result<&mut ResizableBuffer> {
        if pos >= self.buffer.len() {
            Err(DNSError::EndOfBuffer)
        } else {
            self.pos = pos;
            Ok(self)
        }
    }

    fn get(&self, pos: usize) -> Result<u8> {
        if pos >= self.buffer.len() {
            Err(DNSError::EndOfBuffer)
        } else {
            Ok(self.buffer[pos])
        }
    }

    fn set<T>(&mut self, pos: usize, val: T) -> Result<&mut ResizableBuffer>
    where
        T: num::Unsigned + num::PrimInt,
    {
        let bytes = std::mem::size_of::<T>();

        if pos >= self.buffer.len() {
            self.buffer.resize(self.buffer.len() + pos + bytes, 0);
        }

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

    fn get_range(&self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= self.buffer.len() {
            Err(DNSError::EndOfBuffer)
        } else {
            Ok(&self.buffer[start..start + len])
        }
    }

    fn read<T>(&'_ mut self) -> Result<T>
    where
        T: FromBuffer<Self> + Default,
    {
        T::from_buffer(self)
    }

    fn write<'a, T>(&'a mut self, val: T) -> Result<&'a mut Self>
    where
        T: WriteTo<'a, Self, Out = Self>,
    {
        val.write_to(self)
    }
}

impl TryFrom<Packet> for Buffer {
    type Error = DNSError;

    fn try_from(mut packet: Packet) -> Result<Self> {
        packet.header.questions = packet.questions.len() as u16;
        packet.header.answers = packet.answers.len() as u16;
        packet.header.authoritative_entries = packet.authorities.len() as u16;
        packet.header.resource_entries = packet.resources.len() as u16;

        Buffer::default()
            .write(packet.header)?
            .write(packet.questions)?
            .write(packet.answers)?
            .write(packet.authorities)?
            .write(packet.resources)
            .cloned()
    }
}

impl TryFrom<Packet> for ResizableBuffer {
    type Error = DNSError;

    fn try_from(mut packet: Packet) -> Result<Self> {
        packet.header.questions = packet.questions.len() as u16;
        packet.header.answers = packet.answers.len() as u16;
        packet.header.authoritative_entries = packet.authorities.len() as u16;
        packet.header.resource_entries = packet.resources.len() as u16;

        ResizableBuffer::default()
            .write(packet.header)?
            .write(packet.questions)?
            .write(packet.answers)?
            .write(packet.authorities)?
            .write(packet.resources)
            .cloned()
    }
}

impl Default for Buffer {
    #[inline]
    fn default() -> Self {
        Buffer {
            buffer: [0; DNS_PACKET_SIZE],
            pos: 0,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Packet {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub resources: Vec<Record>,
}

impl<I: IO> FromBuffer<I> for Packet {
    fn from_buffer(buffer: &mut I) -> Result<Packet> {
        buffer.seek(0)?;
        let header = Header::from_buffer(buffer)?;

        let questions = header.questions;
        let answers = header.answers;
        let authorities = header.authoritative_entries;
        let resources = header.resource_entries;

        let result = Packet {
            header,
            questions: (0..questions)
                .filter_map(|_| Question::from_buffer(buffer).ok())
                .collect(),
            answers: (0..answers)
                .filter_map(|_| Record::from_buffer(buffer).ok())
                .collect(),
            authorities: (0..authorities)
                .filter_map(|_| Record::from_buffer(buffer).ok())
                .collect(),
            resources: (0..resources)
                .filter_map(|_| Record::from_buffer(buffer).ok())
                .collect(),
        };

        Ok(result)
    }
}

#[allow(unused_imports)]
mod test {
    use crate::dns::{
        header::Header,
        packet::{Buffer, Packet, ResizableBuffer},
        qualified_name::QualifiedName,
        question::Question,
        traits::FromBuffer,
        QueryType, Record, ResultCode, Ttl, RR,
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
                    record: RR {
                        domain: QualifiedName("example.com".to_owned()),
                        ttl: Ttl(3600),
                        query_type: QueryType::MX,
                        class: 1,
                        data_length: 20,
                    },
                    priority: 10,
                    host: QualifiedName("mail.example.com".to_owned()),
                },
                Record::MX {
                    record: RR {
                        domain: QualifiedName("example.com".to_owned()),
                        ttl: Ttl(3600),
                        query_type: QueryType::MX,
                        class: 1,
                        data_length: 23,
                    },
                    priority: 20,
                    host: QualifiedName("mailsec.example.com".to_owned()),
                },
            ],
            authorities: vec![],
            resources: vec![],
        };

        let pack =
            Packet::from_buffer(&mut ResizableBuffer::try_from(packet.clone()).unwrap()).unwrap();
        assert_eq!(packet.header, pack.header);
        assert_eq!(packet.questions, pack.questions);
        assert_eq!(packet.answers, pack.answers);
        assert_eq!(packet.resources, pack.resources);
        assert_eq!(packet.authorities, pack.authorities);
    }
}
