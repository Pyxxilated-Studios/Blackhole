use std::convert::TryFrom;

use crate::dns::{
    header::Header,
    question::Question,
    traits::{FromBuffer, IO},
    DNSError, Record, Result,
};

pub(crate) const DNS_PACKET_SIZE: usize = 512;

#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Buffer {
    pub buffer: [u8; DNS_PACKET_SIZE],
    pub pos: usize,
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

#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ResizableBuffer {
    pub buffer: Vec<u8>,
    pub pos: usize,
}

impl Default for ResizableBuffer {
    fn default() -> Self {
        let mut buffer = vec![0; DNS_PACKET_SIZE];
        buffer.reserve(DNS_PACKET_SIZE << 2);
        Self {
            buffer,
            pos: Default::default(),
        }
    }
}

impl IO for Buffer {
    #[inline]
    fn buffer(&self) -> &[u8] {
        &self.buffer
    }

    #[inline]
    fn buffer_mut(&mut self) -> &mut [u8] {
        &mut self.buffer
    }

    #[inline]
    fn pos(&self) -> usize {
        self.pos
    }

    #[inline]
    fn grow(&mut self) -> Result<&Self> {
        Err(DNSError::EndOfBuffer)
    }

    #[inline]
    fn seek(&mut self, pos: usize) -> Result<&mut Buffer> {
        if pos >= self.buffer().len() {
            Err(DNSError::EndOfBuffer)
        } else {
            self.pos = pos;
            Ok(self)
        }
    }
}

impl IO for ResizableBuffer {
    #[inline]
    fn buffer(&self) -> &[u8] {
        &self.buffer
    }

    #[inline]
    fn buffer_mut(&mut self) -> &mut [u8] {
        &mut self.buffer
    }

    #[inline]
    fn pos(&self) -> usize {
        self.pos
    }

    #[inline]
    fn grow(&mut self) -> Result<&Self> {
        self.buffer.resize(
            if self.buffer().is_empty() {
                DNS_PACKET_SIZE
            } else {
                self.buffer().len() << 1
            },
            0,
        );
        Ok(self)
    }

    #[inline]
    fn seek(&mut self, pos: usize) -> Result<&mut ResizableBuffer> {
        if pos >= self.buffer.len() {
            self.grow()?;
        }

        self.pos = pos;
        Ok(self)
    }
}

macro_rules! impl_try_from {
    ($($t:ty),*) => {
        $(impl TryFrom<Packet> for $t {
            type Error = DNSError;

            fn try_from(mut packet: Packet) -> Result<Self> {
                packet.header.questions = packet.questions.len() as u16;
                packet.header.answers = packet.answers.len() as u16;
                packet.header.authoritative_entries = packet.authorities.len() as u16;
                packet.header.resource_entries = packet.resources.len() as u16;

                <$t>::default()
                    .write(packet.header)?
                    .write(packet.questions)?
                    .write(packet.answers)?
                    .write(packet.authorities)?
                    .write(packet.resources)
                    .cloned()
            }
        })*
    };
}

impl_try_from!(Buffer, ResizableBuffer);

#[derive(Clone, Default)]
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

#[cfg(test)]
mod test {
    use std::net::Ipv6Addr;

    use pretty_assertions::assert_eq;

    use crate::dns::{
        header::Header,
        packet::{Buffer, Packet, ResizableBuffer},
        qualified_name::QualifiedName,
        question::Question,
        traits::{FromBuffer, IO},
        QueryType, Record, ResultCode, Ttl, RR,
    };

    #[allow(unused)]
    fn serialize<T>(packet: &Packet) -> Packet
    where
        T: IO + TryFrom<Packet>,
        T::Error: std::fmt::Debug,
    {
        Packet::from_buffer(&mut T::try_from(packet.clone()).unwrap()).unwrap()
    }

    #[test]
    fn serialise_resizable_buffer() {
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
                name: QualifiedName("example.com".into()),
                qtype: QueryType::MX,
                class: 1u16,
            }],
            answers: vec![
                Record::MX {
                    record: RR {
                        domain: QualifiedName("example.com".into()),
                        ttl: Ttl(3600),
                        query_type: QueryType::MX,
                        class: 1,
                        data_length: 20,
                    },
                    priority: 10,
                    host: QualifiedName("mail.example.com".into()),
                },
                Record::MX {
                    record: RR {
                        domain: QualifiedName("example.com".into()),
                        ttl: Ttl(3600),
                        query_type: QueryType::MX,
                        class: 1,
                        data_length: 23,
                    },
                    priority: 20,
                    host: QualifiedName("mailsec.example.com".into()),
                },
            ],
            authorities: vec![],
            resources: vec![],
        };

        let pack = serialize::<ResizableBuffer>(&packet);
        assert_eq!(packet.header, pack.header);
        assert_eq!(packet.questions, pack.questions);
        assert_eq!(packet.answers, pack.answers);
        assert_eq!(packet.resources, pack.resources);
        assert_eq!(packet.authorities, pack.authorities);
    }

    #[test]
    fn serialise_buffer() {
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
                answers: 1,
                authoritative_entries: 0,
                resource_entries: 0,
            },
            questions: vec![Question {
                name: QualifiedName("example.com".into()),
                qtype: QueryType::AAAA,
                class: 1u16,
            }],
            answers: vec![Record::AAAA {
                record: RR {
                    domain: QualifiedName("example.com".into()),
                    ttl: Ttl(3600),
                    query_type: QueryType::AAAA,
                    class: 1,
                    data_length: 16,
                },
                addr: Ipv6Addr::UNSPECIFIED,
            }],
            authorities: vec![],
            resources: vec![],
        };

        let pack = serialize::<Buffer>(&packet);
        assert_eq!(packet.header, pack.header);
        assert_eq!(packet.questions, pack.questions);
        assert_eq!(packet.answers, pack.answers);
        assert_eq!(packet.resources, pack.resources);
        assert_eq!(packet.authorities, pack.authorities);
    }
}
