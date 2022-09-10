use std::convert::TryFrom;

use crate::dns::{
    header::Header,
    question::Question,
    traits::{WriteTo, IO},
    DNSError, Record, Result,
};

pub(crate) const DNS_PACKET_SIZE: usize = 512;

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
        T: WriteTo<'a, Self, Out = Self>,
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
        header::Header,
        packet::{Buffer, Packet},
        qualified_name::QualifiedName,
        question::Question,
        QueryType, Record, ResultCode, Ttl,
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
