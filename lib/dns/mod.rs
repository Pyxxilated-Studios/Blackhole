pub mod header;
pub mod packet;
pub mod qualified_name;
pub mod question;
pub mod traits;

use core::{
    cmp::{Ord, Ordering},
    hash::{Hash, Hasher},
};
use std::net::{Ipv4Addr, Ipv6Addr};

use serde::Serialize;
use thiserror::Error;
use tracing::warn;

use crate::dns::{
    packet::Buffer,
    qualified_name::QualifiedName,
    traits::{WriteTo, IO},
};

#[derive(Debug, Error)]
pub enum DNSError {
    #[error("IO Error: {0}")]
    Io(#[from] std::io::Error),
    #[error("End of Buffer")]
    EndOfBuffer,
}

pub(crate) type Result<T> = std::result::Result<T, DNSError>;

#[derive(Copy, Clone, Debug, Eq, Default, Serialize)]
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
    type Error = DNSError;

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

impl<'a, T: IO> WriteTo<'a, T> for Ttl {
    fn write_to(&self, out: &'a mut T) -> Result<&'a mut T> {
        out.write(self.0)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
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

#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy, PartialOrd, Ord, Serialize)]
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

impl<'a, T: IO> WriteTo<'a, T> for QueryType {
    fn write_to(&self, out: &'a mut T) -> Result<&'a mut T> {
        out.write(&u16::from(*self).to_be_bytes())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
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
    pub fn domain(&self) -> Option<&String> {
        match self {
            Record::UNKNOWN { domain, .. }
            | Record::A { domain, .. }
            | Record::NS { domain, .. }
            | Record::CNAME { domain, .. }
            | Record::SOA { domain, .. }
            | Record::MX { domain, .. }
            | Record::TXT { domain, .. }
            | Record::AAAA { domain, .. }
            | Record::SRV { domain, .. } => Some(&domain.0),
            Record::OPT { .. } => None,
        }
    }
}

impl<'a, T: IO> WriteTo<'a, T> for Record {
    #[allow(clippy::too_many_lines)]
    fn write_to(&self, out: &'a mut T) -> Result<&'a mut T> {
        match *self {
            Record::A {
                ref domain,
                addr,
                ttl,
            } => out
                .write(domain)?
                .write(QueryType::A)?
                .write(1u16)?
                .write(ttl.0)?
                .write(4u16)?
                .write(u32::from(addr)),
            Record::NS {
                ref domain,
                ref host,
                ttl,
            } => {
                let pos = out
                    .write(domain)?
                    .write(QueryType::NS)?
                    .write(1u16)?
                    .write(ttl.0)?
                    .pos();

                let size = out.write(0u16)?.write(host)?.pos() - (pos + 2);
                out.set(pos, size as u16)
            }
            Record::CNAME {
                ref domain,
                ref host,
                ttl,
            } => {
                let pos = out
                    .write(domain)?
                    .write(QueryType::CNAME)?
                    .write(1u16)?
                    .write(ttl.0)?
                    .pos();

                let size = out.write(0u16)?.write(host)?.pos() - (pos + 2);
                out.set(pos, size as u16)
            }
            Record::MX {
                ref domain,
                priority,
                ref host,
                ttl,
            } => {
                let pos = out
                    .write(domain)?
                    .write(QueryType::MX)?
                    .write(1u16)?
                    .write(ttl.0)?
                    .pos();

                let size = out.write(0u16)?.write(priority)?.write(host)?.pos() - (pos + 2);
                out.set(pos, size as u16)
            }
            Record::AAAA {
                ref domain,
                addr,
                ttl,
            } => out
                .write(domain)?
                .write(QueryType::AAAA)?
                .write(1u16)?
                .write(ttl.0)?
                .write(16u16)?
                .write(u128::from(addr)),
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
                let pos = out
                    .write(domain)?
                    .write(QueryType::SOA)?
                    .write(1u16)?
                    .write(ttl)?
                    .pos();

                let size = out
                    .write(0u16)?
                    .write(m_name)?
                    .write(r_name)?
                    .write(serial)?
                    .write(refresh)?
                    .write(retry)?
                    .write(expire)?
                    .write(minimum)?
                    .pos() as u16;

                out.set(pos, size - (pos as u16 + 2))
            }
            Record::TXT {
                ref domain,
                ref data,
                ttl,
            } => out
                .write(domain)?
                .write(QueryType::TXT)?
                .write(1u16)?
                .write(ttl)?
                .write(data.len() as u16)?
                .write(data.as_bytes()),
            Record::SRV {
                ref domain,
                priority,
                weight,
                port,
                ref host,
                ttl,
            } => {
                let pos = out
                    .write(domain)?
                    .write(QueryType::SRV)?
                    .write(1u16)?
                    .write(ttl)?
                    .pos();

                out.write(0u16)?
                    .write(priority)?
                    .write(weight)?
                    .write(port)?
                    .write(host)?;

                let size = out.pos() - (pos + 2);
                out.set(pos, size as u16)
            }
            Record::OPT { .. } => Ok(out),
            Record::UNKNOWN { .. } => {
                warn!("Skipping record: {:?}", self);
                Ok(out)
            }
        }
    }
}

impl TryFrom<&mut Buffer> for Record {
    type Error = DNSError;

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
                let m_name = buffer.read()?;

                let r_name = buffer.read()?;

                let serial = buffer.read()?;
                let refresh = buffer.read()?;
                let retry = buffer.read()?;
                let expire = buffer.read()?;
                let minimum = buffer.read()?;

                Ok(Record::SOA {
                    domain,
                    m_name,
                    r_name,
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum,
                    ttl,
                })
            }
            QueryType::TXT => {
                let cur_pos = buffer.pos();
                let data = String::from_utf8_lossy(buffer.get_range(cur_pos, data_len as usize)?)
                    .to_string();

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
                let cur_pos = buffer.pos();
                let data = String::from_utf8_lossy(buffer.get_range(cur_pos, data_len as usize)?)
                    .to_string();
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
