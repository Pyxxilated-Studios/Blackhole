pub mod packet;

use core::{
    cmp::{Ord, Ordering},
    hash::{Hash, Hasher},
};
use std::net::{Ipv4Addr, Ipv6Addr};

use tracing::warn;

use crate::dns::packet::{Buffer, IO};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Error {
    Io(String),
    EndOfBuffer,
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::Io(format!("{err}"))
    }
}

pub(crate) type Result<T> = std::result::Result<T, Error>;

#[derive(Copy, Clone, Debug, Eq, Default)]
pub struct Ttl(pub u32);

impl From<u32> for Ttl {
    fn from(val: u32) -> Self {
        Ttl(val)
    }
}

impl From<Ttl> for u32 {
    fn from(ttl: Ttl) -> Self {
        ttl.0
    }
}

impl TryFrom<&mut Buffer> for Ttl {
    type Error = Error;

    fn try_from(value: &mut Buffer) -> Result<Self> {
        Ok(Self::from(value.read::<u32>()?))
    }
}

impl PartialEq<Ttl> for Ttl {
    fn eq(&self, _: &Ttl) -> bool {
        true
    }
}

impl Ord for Ttl {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).unwrap()
    }
}

impl PartialOrd<Ttl> for Ttl {
    fn partial_cmp(&self, _: &Ttl) -> Option<Ordering> {
        Some(Ordering::Equal)
    }
}

impl Hash for Ttl {
    fn hash<H>(&self, _: &mut H)
    where
        H: Hasher,
    {
    }
}

#[derive(Clone, Default, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct QualifiedName(pub String);

impl QualifiedName {
    pub fn name(&self) -> String {
        self.0.clone()
    }
}

impl<'a> From<&'a QualifiedName> for &'a str {
    fn from(qn: &'a QualifiedName) -> Self {
        &qn.0
    }
}

impl TryFrom<&mut Buffer> for QualifiedName {
    type Error = Error;
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

                let b2 = buffer.get(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
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

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResultCode {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMPLEMENTED = 4,
    REFUSED = 5,
}

impl Default for ResultCode {
    fn default() -> Self {
        ResultCode::NOERROR
    }
}

impl From<u8> for ResultCode {
    fn from(num: u8) -> ResultCode {
        match num {
            1 => ResultCode::FORMERR,
            2 => ResultCode::SERVFAIL,
            3 => ResultCode::NXDOMAIN,
            4 => ResultCode::NOTIMPLEMENTED,
            5 => ResultCode::REFUSED,
            _ => ResultCode::NOERROR,
        }
    }
}

impl From<ResultCode> for u8 {
    fn from(code: ResultCode) -> Self {
        match code {
            ResultCode::FORMERR => 1,
            ResultCode::SERVFAIL => 2,
            ResultCode::NXDOMAIN => 3,
            ResultCode::NOTIMPLEMENTED => 4,
            ResultCode::REFUSED => 5,
            ResultCode::NOERROR => 6,
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy, PartialOrd, Ord)]
pub enum QueryType {
    UNKNOWN(u16),
    A,
    NS,
    CNAME,
    SOA,
    MX,
    TXT,
    AAAA,
    SRV,
    OPT,
}

impl Default for QueryType {
    fn default() -> Self {
        QueryType::UNKNOWN(0)
    }
}

impl From<QueryType> for u16 {
    fn from(val: QueryType) -> Self {
        match val {
            QueryType::UNKNOWN(x) => x,
            QueryType::A => 1,
            QueryType::NS => 2,
            QueryType::CNAME => 5,
            QueryType::SOA => 6,
            QueryType::MX => 15,
            QueryType::TXT => 16,
            QueryType::AAAA => 28,
            QueryType::SRV => 33,
            QueryType::OPT => 41,
        }
    }
}

impl From<u16> for QueryType {
    fn from(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            2 => QueryType::NS,
            5 => QueryType::CNAME,
            6 => QueryType::SOA,
            15 => QueryType::MX,
            16 => QueryType::TXT,
            28 => QueryType::AAAA,
            33 => QueryType::SRV,
            41 => QueryType::OPT,
            _ => QueryType::UNKNOWN(num),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, PartialOrd, Ord)]
pub struct Question {
    pub name: QualifiedName,
    pub qtype: QueryType,
}

impl Question {
    pub(crate) fn write(&self, buffer: &mut Buffer) -> Result<()> {
        buffer.write_string((&self.name).into())?;

        buffer.write_bytes(&u16::from(self.qtype).to_be_bytes())?;
        buffer.write_bytes(&1u16.to_be_bytes())?;

        Ok(())
    }
}

impl TryFrom<&mut Buffer> for Question {
    type Error = Error;
    fn try_from(buffer: &mut Buffer) -> Result<Self> {
        let question = Question {
            name: buffer.read::<QualifiedName>()?,
            qtype: QueryType::from(buffer.read::<u16>()?),
        };

        let _ = buffer.read::<u16>()?;

        Ok(question)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[allow(dead_code)]
pub enum Record {
    UNKNOWN {
        domain: QualifiedName,
        qtype: u16,
        data_len: u16,
        ttl: Ttl,
    },
    A {
        domain: QualifiedName,
        addr: Ipv4Addr,
        ttl: Ttl,
    },
    NS {
        domain: QualifiedName,
        host: QualifiedName,
        ttl: Ttl,
    },
    CNAME {
        domain: QualifiedName,
        host: QualifiedName,
        ttl: Ttl,
    },
    SOA {
        domain: QualifiedName,
        m_name: QualifiedName,
        r_name: QualifiedName,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
        ttl: Ttl,
    },
    MX {
        domain: QualifiedName,
        priority: u16,
        host: QualifiedName,
        ttl: Ttl,
    },
    TXT {
        domain: QualifiedName,
        data: String,
        ttl: Ttl,
    },
    AAAA {
        domain: QualifiedName,
        addr: Ipv6Addr,
        ttl: Ttl,
    },
    SRV {
        domain: QualifiedName,
        priority: u16,
        weight: u16,
        port: u16,
        host: QualifiedName,
        ttl: Ttl,
    },
    OPT {
        packet_len: u16,
        flags: u32,
        data: String,
    },
}

impl Record {
    pub(crate) fn write(&self, buffer: &mut Buffer) -> Result<usize> {
        let start_pos = buffer.pos();

        match *self {
            Record::A {
                ref domain,
                addr,
                ttl,
            } => {
                buffer
                    .write_string(domain.into())?
                    .write(u16::from(QueryType::A))?
                    .write(1u16)?
                    .write(ttl.0)?
                    .write(4u16)?
                    .write(u32::from(addr))?;
            }
            Record::NS {
                ref domain,
                ref host,
                ttl,
            } => {
                buffer
                    .write_string(domain.into())?
                    .write(u16::from(QueryType::NS))?
                    .write(1u16)?
                    .write(ttl.0)?;

                let pos = buffer.pos();
                buffer.write(0u16)?.write_string(host.into())?;

                let size = buffer.pos() - (pos + 2);
                buffer.set(pos, size as u16)?;
            }
            Record::CNAME {
                ref domain,
                ref host,
                ttl,
            } => {
                buffer
                    .write_string(domain.into())?
                    .write(u16::from(QueryType::CNAME))?
                    .write(1u16)?
                    .write(ttl.0)?;

                let pos = buffer.pos();
                buffer.write(0u16)?.write_string(host.into())?;

                let size = buffer.pos() - (pos + 2);
                buffer.set(pos, size as u16)?;
            }
            Record::MX {
                ref domain,
                priority,
                ref host,
                ttl,
            } => {
                buffer
                    .write_string(domain.into())?
                    .write(u16::from(QueryType::MX))?
                    .write(1u16)?
                    .write(ttl.0)?;

                let pos = buffer.pos();
                buffer.write(0u16)?;

                buffer.write(priority)?.write_string(host.into())?;

                let size = buffer.pos() - (pos + 2);
                buffer.set(pos, size as u16)?;
            }
            Record::AAAA {
                ref domain,
                addr,
                ttl,
            } => {
                buffer
                    .write_string(domain.into())?
                    .write(u16::from(QueryType::AAAA))?
                    .write(1u16)?
                    .write(ttl.0)?
                    .write(16u16)?
                    .write(u128::from(addr))?;
            }
            Record::SOA {
                ref domain,
                ref m_name,
                ref r_name,
                serial,
                refresh,
                retry,
                expire,
                minimum,
                ttl,
            } => {
                buffer
                    .write_string(domain.into())?
                    .write(u16::from(QueryType::SOA))?
                    .write(1u16)?
                    .write(u32::from(ttl))?;

                let pos = buffer.pos();
                buffer
                    .write(0u16)?
                    .write_string(m_name.into())?
                    .write_string(r_name.into())?
                    .write(serial)?
                    .write(refresh)?
                    .write(retry)?
                    .write(expire)?
                    .write(minimum)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set(pos, size as u16)?;
            }
            Record::TXT {
                ref domain,
                ref data,
                ttl,
            } => {
                buffer
                    .write_string(domain.into())?
                    .write(u16::from(QueryType::TXT))?
                    .write(1u16)?
                    .write(u32::from(ttl))?
                    .write(data.len() as u16)?;

                for b in data.as_bytes() {
                    buffer.write(*b)?;
                }
            }
            Record::SRV {
                ref domain,
                priority,
                weight,
                port,
                ref host,
                ttl,
            } => {
                buffer
                    .write_string(domain.into())?
                    .write(u16::from(QueryType::SRV))?
                    .write(1u16)?
                    .write(u32::from(ttl))?;

                let pos = buffer.pos();
                buffer
                    .write(0u16)?
                    .write(priority)?
                    .write(weight)?
                    .write(port)?
                    .write_string(host.into())?;

                let size = buffer.pos() - (pos + 2);
                buffer.set(pos, size as u16)?;
            }
            Record::OPT { .. } => {}
            Record::UNKNOWN { .. } => {
                warn!("Skipping record: {:?}", self);
            }
        }

        Ok(buffer.pos() - start_pos)
    }
}

impl TryFrom<&mut Buffer> for Record {
    type Error = Error;

    fn try_from(buffer: &mut Buffer) -> Result<Record> {
        let domain = buffer.read()?;

        let qtype = buffer.read::<u16>()?.into();
        let class = buffer.read()?;
        let ttl = buffer.read()?;
        let data_len = buffer.read()?;

        match qtype {
            QueryType::A => {
                let addr = Ipv4Addr::from(buffer.read::<u32>()?);

                Ok(Record::A { domain, addr, ttl })
            }
            QueryType::AAAA => {
                let addr = Ipv6Addr::from(buffer.read::<u128>()?);

                Ok(Record::AAAA { domain, addr, ttl })
            }
            QueryType::NS => {
                let host = buffer.read()?;

                Ok(Record::NS { domain, host, ttl })
            }
            QueryType::CNAME => {
                let host = buffer.read()?;

                Ok(Record::CNAME { domain, host, ttl })
            }
            QueryType::MX => {
                let priority = buffer.read()?;
                let host = buffer.read()?;

                Ok(Record::MX {
                    domain,
                    priority,
                    host,
                    ttl,
                })
            }
            QueryType::SOA => {
                let priority = buffer.read()?;
                let weight = buffer.read()?;
                let port = buffer.read()?;
                let host = buffer.read()?;

                Ok(Record::SRV {
                    domain,
                    priority,
                    weight,
                    port,
                    host,
                    ttl,
                })
            }
            QueryType::TXT => {
                let mut data = String::new();

                let cur_pos = buffer.pos();
                data.push_str(&String::from_utf8_lossy(
                    buffer.get_range(cur_pos, data_len as usize)?,
                ));

                buffer.step(data_len as usize)?;

                Ok(Record::TXT { domain, data, ttl })
            }
            QueryType::SRV => {
                let priority = buffer.read()?;
                let weight = buffer.read()?;
                let port = buffer.read()?;

                let host = buffer.read()?;

                Ok(Record::SRV {
                    domain,
                    priority,
                    weight,
                    port,
                    host,
                    ttl,
                })
            }
            QueryType::OPT => {
                let mut data = String::new();

                let cur_pos = buffer.pos();
                data.push_str(&String::from_utf8_lossy(
                    buffer.get_range(cur_pos, data_len as usize)?,
                ));
                buffer.step(data_len as usize)?;

                Ok(Record::OPT {
                    packet_len: class,
                    flags: ttl.into(),
                    data,
                })
            }
            QueryType::UNKNOWN(_) => {
                buffer.step(data_len as usize)?;

                Ok(Record::UNKNOWN {
                    domain,
                    qtype: qtype.into(),
                    data_len,
                    ttl,
                })
            }
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Header {
    pub id: u16,

    pub recursion_desired: bool,
    pub truncated_message: bool,
    pub authoritative_answer: bool,
    pub opcode: u8,
    pub response: bool,

    pub rescode: ResultCode,
    pub checking_disabled: bool,
    pub authed_data: bool,
    pub z: bool,
    pub recursion_available: bool,

    pub questions: u16,
    pub answers: u16,
    pub authoritative_entries: u16,
    pub resource_entries: u16,
}

impl Header {
    pub(crate) fn write(&self, buffer: &mut Buffer) -> Result<()> {
        buffer
            .write(self.id)?
            .write(
                u8::from(self.recursion_desired)
                    | (u8::from(self.truncated_message) << 1)
                    | (u8::from(self.authoritative_answer) << 2)
                    | (self.opcode << 3)
                    | (u8::from(self.response) << 7),
            )?
            .write(
                u8::from(self.rescode)
                    | (u8::from(self.checking_disabled) << 4)
                    | (u8::from(self.authed_data) << 5)
                    | (u8::from(self.z) << 6)
                    | (u8::from(self.recursion_available) << 7),
            )?
            .write(self.questions)?
            .write(self.answers)?
            .write(self.authoritative_entries)?
            .write(self.resource_entries)?;

        Ok(())
    }
}

impl TryFrom<&mut Buffer> for Header {
    type Error = Error;

    fn try_from(buffer: &mut Buffer) -> Result<Self> {
        let id = buffer.read()?;
        let [a, b] = buffer.read::<u16>()?.to_be_bytes();

        let header = Header {
            id,

            recursion_desired: (a & (1 << 0)) > 0,
            truncated_message: (a & (1 << 1)) > 0,
            authoritative_answer: (a & (1 << 2)) > 0,
            opcode: (a >> 3) & 0x0F,
            response: (a & (1 << 7)) > 0,

            rescode: (b & 0x0F).into(),
            checking_disabled: (b & (1 << 4)) > 0,
            authed_data: (b & (1 << 5)) > 0,
            z: (b & (1 << 6)) > 0,
            recursion_available: (b & (1 << 7)) > 0,

            questions: buffer.read()?,
            answers: buffer.read()?,
            authoritative_entries: buffer.read()?,
            resource_entries: buffer.read()?,
        };

        Ok(header)
    }
}
