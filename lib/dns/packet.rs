use std::convert::TryFrom;

use tracing::instrument;

use crate::dns::{Error, Header, Question, Record, Result};

pub(crate) const DNS_PACKET_SIZE: usize = 512;

pub(crate) trait IO {
    fn read<'a, T>(&'a mut self) -> Result<T>
    where
        T: TryFrom<&'a mut Self, Error = Error> + Default;

    fn write<T>(&mut self, val: T) -> Result<&mut Self>
    where
        T: num::Unsigned + num::PrimInt + std::fmt::Debug + 'static;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Buffer {
    pub buf: [u8; DNS_PACKET_SIZE],
    pub pos: usize,
}

impl Buffer {
    /// Current position within buffer
    pub(crate) fn pos(&self) -> usize {
        self.pos
    }

    /// Step the buffer position forward a specific number of steps
    pub(crate) fn step(&mut self, steps: usize) {
        self.pos += steps;
    }

    /// Change the buffer position
    pub(crate) fn seek(&mut self, pos: usize) {
        self.pos = pos;
    }

    pub fn set<T>(&mut self, pos: usize, val: T) -> Result<&mut Buffer>
    where
        T: num::Unsigned + num::PrimInt,
    {
        if pos >= DNS_PACKET_SIZE {
            return Err("Position out of range".into());
        }

        let bytes = std::mem::size_of::<T>() / u8::BITS as usize;
        (1..=bytes).for_each(|byte| {
            self.buf[pos + byte - 1] = (val >> ((bytes - byte) * u8::BITS as usize)
                & T::from(0xFF).unwrap())
            .to_u8()
            .unwrap();
        });

        Ok(self)
    }

    pub fn write_bytes(&mut self, buff: &[u8]) -> Result<&mut Buffer> {
        buff.iter().try_fold(self, |buffer, &val| buffer.write(val))
    }

    pub fn write_string(&mut self, string: &str) -> Result<&mut Buffer> {
        string
            .split('.')
            .try_fold(self, |buffer, label| {
                let len = label.len();
                if len > 0x3f {
                    Err("Single label exceeds 63 characters of length".into())
                } else {
                    buffer.write(len as u8)?.write_bytes(label.as_bytes())
                }
            })?
            .write(0u8)
    }

    /// Get a single byte, without changing the buffer position
    pub(crate) fn get(&mut self, pos: usize) -> Result<u8> {
        if pos >= DNS_PACKET_SIZE {
            Err("End of buffer".into())
        } else {
            Ok(self.buf[pos])
        }
    }

    /// Get a range of bytes
    pub(crate) fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= DNS_PACKET_SIZE {
            Err("End of buffer".into())
        } else {
            Ok(&self.buf[start..start + len as usize])
        }
    }
}

impl IO for Buffer {
    fn read<'a, T>(&'a mut self) -> Result<T>
    where
        T: TryFrom<&'a mut Self, Error = Error> + Default,
    {
        T::try_from(self)
    }

    fn write<T>(&mut self, val: T) -> Result<&mut Buffer>
    where
        T: num::Unsigned + num::PrimInt + std::fmt::Debug + 'static,
    {
        if core::any::TypeId::of::<T>() == core::any::TypeId::of::<u8>() {
            if self.pos >= DNS_PACKET_SIZE {
                Err("End of buffer".into())
            } else {
                self.buf[self.pos] = val.to_u8().unwrap();
                self.pos += 1;

                Ok(self)
            }
        } else {
            let bytes = core::mem::size_of::<T>();
            let val = val.to_be();

            (0..bytes).try_fold(self, |buffer, byte| {
                let v = (val >> (byte * u8::BITS as usize) & T::from(0xFF).unwrap())
                    .to_u8()
                    .unwrap();
                buffer.write(v)
            })
        }
    }
}

impl TryFrom<Packet> for Buffer {
    type Error = Error;

    #[instrument]
    fn try_from(mut packet: Packet) -> Result<Self> {
        let mut buffer = Buffer::default();
        packet.header.questions = packet.questions.len() as u16;
        packet.header.answers = packet.answers.len() as u16;
        packet.header.authoritative_entries = packet.authorities.len() as u16;
        packet.header.resource_entries = packet.resources.len() as u16;

        packet.header.write(&mut buffer)?;

        for question in &packet.questions {
            question.write(&mut buffer)?;
        }

        for rec in &packet.answers {
            rec.write(&mut buffer)?;
        }

        for rec in &packet.authorities {
            rec.write(&mut buffer)?;
        }

        for rec in &packet.resources {
            rec.write(&mut buffer)?;
        }

        Ok(buffer)
    }
}

impl TryFrom<&mut Buffer> for u8 {
    type Error = Error;

    fn try_from(packet: &mut Buffer) -> Result<u8> {
        if packet.pos >= DNS_PACKET_SIZE {
            Err("End of buffer".into())
        } else {
            let res = packet.buf[packet.pos];
            packet.pos += 1;

            Ok(res)
        }
    }
}

impl TryFrom<&mut Buffer> for u16 {
    type Error = Error;

    /// Read two bytes, stepping two steps forward
    fn try_from(packet: &mut Buffer) -> Result<u16> {
        let res = u16::from_be_bytes(std::array::try_from_fn(|_| packet.read::<u8>())?);

        Ok(res)
    }
}

impl TryFrom<&mut Buffer> for u32 {
    type Error = Error;

    /// Read four bytes, stepping four steps forward
    fn try_from(packet: &mut Buffer) -> Result<u32> {
        let res = u32::from_be_bytes(std::array::try_from_fn(|_| packet.read::<u8>())?);

        Ok(res)
    }
}

impl TryFrom<&mut Buffer> for u64 {
    type Error = Error;

    /// Read four bytes, stepping four steps forward
    fn try_from(packet: &mut Buffer) -> Result<u64> {
        let res = u64::from_be_bytes(std::array::try_from_fn(|_| packet.read::<u8>())?);

        Ok(res)
    }
}

impl TryFrom<&mut Buffer> for u128 {
    type Error = Error;

    /// Read four bytes, stepping four steps forward
    fn try_from(packet: &mut Buffer) -> Result<u128> {
        let res = u128::from_be_bytes(std::array::try_from_fn(|_| packet.read::<u8>())?);

        Ok(res)
    }
}

impl Default for Buffer {
    fn default() -> Self {
        Buffer {
            buf: [0; DNS_PACKET_SIZE],
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
    type Error = Error;

    #[instrument]
    fn try_from(buffer: &mut Buffer) -> Result<Packet> {
        buffer.seek(0);

        let mut result = Packet {
            header: Header::try_from(&mut *buffer)?,
            ..Default::default()
        };

        result.questions = (0..result.header.questions)
            .filter_map(|_| Question::try_from(&mut *buffer).ok())
            .collect();

        result.answers = (0..result.header.answers)
            .filter_map(|_| Record::try_from(&mut *buffer).ok())
            .collect();

        result.authorities = (0..result.header.authoritative_entries)
            .filter_map(|_| Record::try_from(&mut *buffer).ok())
            .collect();

        result.resources = (0..result.header.resource_entries)
            .filter_map(|_| Record::try_from(&mut *buffer).ok())
            .collect();

        Ok(result)
    }
}

mod test {
    use crate::dns::{
        packet::{Buffer, Packet},
        Header, QualifiedName, QueryType, Question, Record, ResultCode,
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
                    ttl: 3600,
                },
                Record::MX {
                    domain: QualifiedName("example.com".to_owned()),
                    priority: 20,
                    host: QualifiedName("mailsec.example.com".to_owned()),
                    ttl: 3600,
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
