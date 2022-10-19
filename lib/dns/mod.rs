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
    qualified_name::QualifiedName,
    traits::{FromBuffer, WriteTo, IO},
};

#[derive(Debug, Error)]
pub enum DNSError {
    #[error("IO Error: {0}")]
    Io(#[from] std::io::Error),
    #[error("End of Buffer")]
    EndOfBuffer,
}

pub(crate) type Result<T> = std::result::Result<T, DNSError>;

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct RR {
    pub domain: QualifiedName,
    pub query_type: QueryType,
    pub class: u16,
    pub ttl: Ttl,
    pub data_length: u16,
}

impl<I: IO> FromBuffer<I> for RR {
    fn from_buffer(buffer: &mut I) -> std::result::Result<Self, DNSError> {
        Ok(RR {
            domain: buffer.read()?,
            query_type: buffer.read()?,
            class: buffer.read()?,
            ttl: buffer.read()?,
            data_length: buffer.read()?,
        })
    }
}

impl<'a, T: IO> WriteTo<'a, T> for &RR {
    fn write_to(&self, out: &'a mut T) -> Result<&'a mut T> {
        out.write(&self.domain)?
            .write(self.query_type)?
            .write(self.class)?
            .write(self.ttl)?
            .write(self.data_length)
    }
}

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

impl<I: IO> FromBuffer<I> for Ttl {
    fn from_buffer(value: &mut I) -> Result<Self> {
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
            ResultCode::NOERROR => 0,
            ResultCode::FORMERR => 1,
            ResultCode::SERVFAIL => 2,
            ResultCode::NXDOMAIN => 3,
            ResultCode::NOTIMPLEMENTED => 4,
            ResultCode::REFUSED => 5,
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
    RRSIG,
    NSEC,
    DNSKEY,
    NSEC3,
    NSEC3PARAM,
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
            QueryType::RRSIG => 46,
            QueryType::NSEC => 47,
            QueryType::DNSKEY => 48,
            QueryType::NSEC3 => 50,
            QueryType::NSEC3PARAM => 51,
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
            46 => QueryType::RRSIG,
            47 => QueryType::NSEC,
            48 => QueryType::DNSKEY,
            50 => QueryType::NSEC3,
            51 => QueryType::NSEC3PARAM,
            _ => QueryType::UNKNOWN(num),
        }
    }
}

impl<I: IO> FromBuffer<I> for QueryType {
    fn from_buffer(buffer: &mut I) -> Result<Self>
    where
        I: IO,
        Self: Sized,
    {
        Ok(buffer.read::<u16>()?.into())
    }
}

impl<'a, T: IO> WriteTo<'a, T> for QueryType {
    fn write_to(&self, out: &'a mut T) -> Result<&'a mut T> {
        out.write(&u16::from(*self).to_be_bytes())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Record {
    UNKNOWN {
        record: RR,
    },
    A {
        record: RR,
        addr: Ipv4Addr,
    },
    NS {
        record: RR,
        host: QualifiedName,
    },
    CNAME {
        record: RR,
        host: QualifiedName,
    },
    SOA {
        record: RR,
        m_name: QualifiedName,
        r_name: QualifiedName,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    MX {
        record: RR,
        priority: u16,
        host: QualifiedName,
    },
    TXT {
        record: RR,
        data: String,
    },
    AAAA {
        record: RR,
        addr: Ipv6Addr,
    },
    SRV {
        record: RR,
        priority: u16,
        weight: u16,
        port: u16,
        host: QualifiedName,
    },
    OPT {
        packet_len: u16,
        flags: u32,
        data: Vec<u8>,
    },
    RRSIG {
        record: RR,
        ty: u16,
        algorithm: u8,
        labels: u8,
        original_ttl: Ttl,
        expiration: u32,
        inception: u32,
        tag: u16,
        name: QualifiedName,
        signature: Vec<u8>,
    },
    NSEC {
        record: RR,
        next_domain: QualifiedName,
        type_map: Vec<u8>,
    },
    DNSKEY {
        record: RR,
        flags: u16,
        protocol: u8,
        algorithm: u8,
        public_key: Vec<u8>,
    },
    NSEC3 {
        record: RR,
        algorithm: u8,
        flags: u8,
        iterations: u16,
        salt_length: u8,
        salt: Vec<u8>,
        hash_length: u8,
        hash: Vec<u8>,
        type_map: Vec<u8>,
    },
    NSEC3PARAM {
        record: RR,
        algorithm: u8,
        flags: u8,
        iterations: u16,
        salt_length: u8,
        salt: Vec<u8>,
    },
}

impl Record {
    pub fn domain(&self) -> Option<&String> {
        match self {
            Record::UNKNOWN { record, .. }
            | Record::A { record, .. }
            | Record::NS { record, .. }
            | Record::CNAME { record, .. }
            | Record::SOA { record, .. }
            | Record::MX { record, .. }
            | Record::TXT { record, .. }
            | Record::AAAA { record, .. }
            | Record::SRV { record, .. }
            | Record::RRSIG { record, .. }
            | Record::NSEC { record, .. }
            | Record::DNSKEY { record, .. }
            | Record::NSEC3 { record, .. }
            | Record::NSEC3PARAM { record, .. } => Some(&record.domain.0),
            Record::OPT { .. } => None,
        }
    }
}

impl<'a, T: IO> WriteTo<'a, T> for Record {
    #[allow(clippy::too_many_lines)]
    fn write_to(&self, out: &'a mut T) -> Result<&'a mut T> {
        match *self {
            Record::A { ref record, addr } => {
                let start = out.write(record)?.pos();
                let end = out.write(u32::from(addr))?.pos();
                out.set(start - 2, (end - start) as u16)
            }
            Record::NS {
                ref record,
                ref host,
            }
            | Record::CNAME {
                ref record,
                ref host,
            } => {
                let start = out.write(record)?.pos();
                let end = out.write(host)?.pos();
                out.set(start - 2, (end - start) as u16)
            }
            Record::MX {
                ref record,
                priority,
                ref host,
            } => {
                let start = out.write(record)?.pos();
                let end = out.write(priority)?.write(host)?.pos();
                out.set(start - 2, (end - start) as u16)
            }
            Record::AAAA { ref record, addr } => {
                let start = out.write(record)?.pos();
                let end = out.write(u128::from(addr))?.pos();
                out.set(start - 2, (end - start) as u16)
            }
            Record::SOA {
                ref record,
                ref m_name,
                ref r_name,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                let start = out.write(record)?.pos();
                let end = out
                    .write(m_name)?
                    .write(r_name)?
                    .write(serial)?
                    .write(refresh)?
                    .write(retry)?
                    .write(expire)?
                    .write(minimum)?
                    .pos();

                out.set(start - 2, (end - start) as u16)
            }
            Record::TXT {
                ref record,
                ref data,
            } => out
                .write(record)?
                .write(data.len() as u16)?
                .write(data.as_bytes()),
            Record::SRV {
                ref record,
                priority,
                weight,
                port,
                ref host,
            } => {
                let start = out.write(record)?.pos();
                let end = out
                    .write(priority)?
                    .write(weight)?
                    .write(port)?
                    .write(host)?
                    .pos();

                out.set(start - 2, (end - start) as u16)
            }
            Record::OPT {
                ref data,
                packet_len,
                flags,
            } => out
                .write(0u8)?
                .write(QueryType::OPT)?
                .write(packet_len)?
                .write(flags)?
                .write(data.len() as u16)?
                .write(data.clone()),
            Record::RRSIG {
                ref record,
                ty,
                algorithm,
                labels,
                original_ttl,
                expiration,
                inception,
                tag,
                ref name,
                ref signature,
            } => {
                let start = out.write(record)?.pos();
                let end = out
                    .write(ty)?
                    .write(algorithm)?
                    .write(labels)?
                    .write(original_ttl)?
                    .write(expiration)?
                    .write(inception)?
                    .write(tag)?
                    .write(name)?
                    .write(signature.clone())?
                    .pos();

                out.set(start - 2, (end - start) as u16)
            }
            Record::NSEC {
                ref record,
                ref next_domain,
                ref type_map,
            } => out
                .write(record)?
                .write((type_map.len() + next_domain.0.len()) as u16)?
                .write(next_domain)?
                .write(type_map.clone()),
            Record::DNSKEY {
                ref record,
                flags,
                protocol,
                algorithm,
                ref public_key,
            } => {
                let start = out.write(record)?.pos();
                let end = out
                    .write(flags)?
                    .write(protocol)?
                    .write(algorithm)?
                    .write(public_key.clone())?
                    .pos();

                out.set(start - 2, (end - start) as u16)
            }
            Record::NSEC3 {
                ref record,
                algorithm,
                flags,
                iterations,
                salt_length,
                ref salt,
                hash_length,
                ref hash,
                ref type_map,
            } => {
                let start = out.write(record)?.pos();
                let end = out
                    .write(algorithm)?
                    .write(flags)?
                    .write(iterations)?
                    .write(salt_length)?
                    .write(salt.clone())?
                    .write(hash_length)?
                    .write(hash.clone())?
                    .write(type_map.clone())?
                    .pos();

                out.set(start - 2, (end - start) as u16)
            }
            Record::NSEC3PARAM {
                ref record,
                algorithm,
                flags,
                iterations,
                salt_length,
                ref salt,
            } => {
                let start = out.write(record)?.pos();
                let end = out
                    .write(algorithm)?
                    .write(flags)?
                    .write(iterations)?
                    .write(salt_length)?
                    .write(salt.clone())?
                    .pos();

                out.set(start - 2, (end - start) as u16)
            }
            Record::UNKNOWN { .. } => {
                warn!("Skipping record: {:?}", self);
                Ok(out)
            }
        }
    }
}

impl<I: IO> FromBuffer<I> for Record {
    #[allow(clippy::too_many_lines)]
    fn from_buffer(buffer: &mut I) -> Result<Record> {
        let record: RR = buffer.read()?;

        match record.query_type {
            QueryType::A => Ok(Record::A {
                record,
                addr: Ipv4Addr::from(buffer.read::<u32>()?),
            }),
            QueryType::AAAA => Ok(Record::AAAA {
                record,
                addr: Ipv6Addr::from(buffer.read::<u128>()?),
            }),
            QueryType::NS => Ok(Record::NS {
                record,
                host: buffer.read()?,
            }),
            QueryType::CNAME => Ok(Record::CNAME {
                record,
                host: buffer.read()?,
            }),
            QueryType::MX => Ok(Record::MX {
                record,
                priority: buffer.read()?,
                host: buffer.read()?,
            }),
            QueryType::SOA => Ok(Record::SOA {
                record,
                m_name: buffer.read()?,
                r_name: buffer.read()?,
                serial: buffer.read()?,
                refresh: buffer.read()?,
                retry: buffer.read()?,
                expire: buffer.read()?,
                minimum: buffer.read()?,
            }),
            QueryType::TXT => {
                let data = String::from_utf8_lossy(
                    buffer.get_range(buffer.pos(), record.data_length as usize)?,
                )
                .to_string();

                buffer.step(record.data_length as usize)?;

                Ok(Record::TXT { record, data })
            }
            QueryType::SRV => Ok(Record::SRV {
                record,
                priority: buffer.read()?,
                weight: buffer.read()?,
                port: buffer.read()?,
                host: buffer.read()?,
            }),
            QueryType::OPT => {
                let data = buffer
                    .get_range(buffer.pos(), record.data_length as usize)?
                    .to_vec();
                buffer.step(record.data_length as usize)?;

                Ok(Record::OPT {
                    packet_len: record.class,
                    flags: record.ttl.into(),
                    data,
                })
            }
            QueryType::RRSIG => {
                let start = buffer.pos();
                let ty = buffer.read()?;
                let algorithm = buffer.read()?;
                let labels = buffer.read()?;
                let original_ttl = buffer.read()?;
                let expiration = buffer.read()?;
                let inception = buffer.read()?;
                let tag = buffer.read()?;
                let name = buffer.read()?;

                let sign_len = record.data_length as usize - (buffer.pos() - start);
                let signature = buffer.get_range(buffer.pos(), sign_len)?.to_vec();
                buffer.step(sign_len)?;

                Ok(Record::RRSIG {
                    record,
                    ty,
                    algorithm,
                    labels,
                    original_ttl,
                    expiration,
                    inception,
                    tag,
                    name,
                    signature,
                })
            }
            QueryType::NSEC => {
                let start = buffer.pos();
                let next_domain = buffer.read()?;

                let map_len = record.data_length as usize - (buffer.pos() - start);
                let type_map = buffer.get_range(buffer.pos(), map_len)?.to_vec();
                buffer.step(map_len)?;

                Ok(Record::NSEC {
                    record,
                    next_domain,
                    type_map,
                })
            }
            QueryType::DNSKEY => {
                let flags = buffer.read()?;
                let protocol = buffer.read()?;
                let algorithm = buffer.read()?;
                let public_key = buffer
                    .get_range(buffer.pos(), record.data_length as usize - 4)?
                    .to_vec();

                buffer.step(record.data_length as usize - 4)?;

                Ok(Record::DNSKEY {
                    record,
                    flags,
                    protocol,
                    algorithm,
                    public_key,
                })
            }
            QueryType::NSEC3 => {
                let start = buffer.pos();
                let algorithm = buffer.read()?;
                let flags = buffer.read()?;
                let iterations = buffer.read()?;

                let salt_length = buffer.read()?;
                let salt = buffer.get_range(buffer.pos(), salt_length)?.to_vec();
                buffer.step(salt_length)?;

                let hash_length = buffer.read()?;
                let hash = buffer.get_range(buffer.pos(), hash_length)?.to_vec();
                buffer.step(hash_length)?;

                let map_len = record.data_length as usize - (buffer.pos() - start);
                let type_map = buffer.get_range(buffer.pos(), map_len)?.to_vec();
                buffer.step(map_len)?;

                Ok(Record::NSEC3 {
                    record,
                    algorithm,
                    flags,
                    iterations,
                    salt_length: salt_length as u8,
                    salt,
                    hash_length: hash_length as u8,
                    hash,
                    type_map,
                })
            }
            QueryType::NSEC3PARAM => {
                let algorithm = buffer.read()?;
                let flags = buffer.read()?;
                let iterations = buffer.read()?;

                let salt_length = buffer.read()?;
                let salt = buffer.get_range(buffer.pos(), salt_length)?.to_vec();
                buffer.step(salt_length)?;

                Ok(Record::NSEC3PARAM {
                    record,
                    algorithm,
                    flags,
                    iterations,
                    salt_length: salt_length as u8,
                    salt,
                })
            }
            QueryType::UNKNOWN(_) => {
                buffer.step(record.data_length as usize)?;

                Ok(Record::UNKNOWN { record })
            }
        }
    }
}
