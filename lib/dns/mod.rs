pub mod header;
pub mod packet;
pub mod qualified_name;
pub mod question;
pub mod traits;

use core::{
    cmp::{Ord, Ordering},
    hash::Hash,
};
use std::net::{Ipv4Addr, Ipv6Addr};

use bstr::BString;
use serde::Serialize;
use thiserror::Error;
use tracing::trace;

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
    #[error("Timeout")]
    Timeout(#[from] tokio::time::error::Elapsed),
    #[error("Packet is Invalid")]
    InvalidPacket,
}

pub(crate) type Result<T> = std::result::Result<T, DNSError>;

#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Serialize)]
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

impl<'a, T: IO> WriteTo<'a, T> for RR {
    type Out = T;

    fn write_to(self, out: &'a mut T) -> Result<&'a mut T> {
        out.write(self.domain)?
            .write(self.query_type)?
            .write(self.class)?
            .write(self.ttl)?
            .write(self.data_length)
    }
}

#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Copy, Clone, Eq, Default, Serialize)]
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

impl<'a, T: IO> WriteTo<'a, T> for Ttl {
    type Out = T;

    fn write_to(self, out: &'a mut T) -> Result<&'a mut T> {
        out.write(self.0)
    }
}

#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
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

#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(PartialEq, Eq, Clone, Hash, Copy, PartialOrd, Ord, Serialize)]
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
    DS,
    RRSIG,
    NSEC,
    DNSKEY,
    NSEC3,
    NSEC3PARAM,
    SVCB,
    HTTPS,
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
            QueryType::DS => 43,
            QueryType::RRSIG => 46,
            QueryType::NSEC => 47,
            QueryType::DNSKEY => 48,
            QueryType::NSEC3 => 50,
            QueryType::NSEC3PARAM => 51,
            QueryType::SVCB => 64,
            QueryType::HTTPS => 65,
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
            43 => QueryType::DS,
            46 => QueryType::RRSIG,
            47 => QueryType::NSEC,
            48 => QueryType::DNSKEY,
            50 => QueryType::NSEC3,
            51 => QueryType::NSEC3PARAM,
            64 => QueryType::SVCB,
            65 => QueryType::HTTPS,
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
    type Out = T;

    fn write_to(self, out: &'a mut T) -> Result<&'a mut T> {
        out.write(&u16::from(self).to_be_bytes())
    }
}

#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
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
        data: Vec<u8>,
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
    DS {
        record: RR,
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: Vec<u8>,
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
    SVCB {
        record: RR,
        priority: u16,
        target: QualifiedName,
        params: Vec<u8>,
    },
    HTTPS {
        record: RR,
        priority: u16,
        target: QualifiedName,
        params: Vec<u8>,
    },
}

impl Record {
    pub fn domain(&self) -> Option<&BString> {
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
            | Record::NSEC3PARAM { record, .. }
            | Record::DS { record, .. }
            | Record::SVCB { record, .. }
            | Record::HTTPS { record, .. } => Some(&record.domain.0),
            Record::OPT { .. } => None,
        }
    }

    pub fn record(&mut self) -> Option<&mut RR> {
        match self {
            Record::UNKNOWN { ref mut record, .. }
            | Record::A { ref mut record, .. }
            | Record::NS { ref mut record, .. }
            | Record::CNAME { ref mut record, .. }
            | Record::SOA { ref mut record, .. }
            | Record::MX { ref mut record, .. }
            | Record::TXT { ref mut record, .. }
            | Record::AAAA { ref mut record, .. }
            | Record::SRV { ref mut record, .. }
            | Record::RRSIG { ref mut record, .. }
            | Record::NSEC { ref mut record, .. }
            | Record::DNSKEY { ref mut record, .. }
            | Record::NSEC3 { ref mut record, .. }
            | Record::NSEC3PARAM { ref mut record, .. }
            | Record::DS { ref mut record, .. }
            | Record::SVCB { ref mut record, .. }
            | Record::HTTPS { ref mut record, .. } => Some(record),
            Record::OPT { .. } => None,
        }
    }

    pub fn ttl(&self) -> Option<Ttl> {
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
            | Record::NSEC3PARAM { record, .. }
            | Record::DS { record, .. }
            | Record::SVCB { record, .. }
            | Record::HTTPS { record, .. } => Some(record.ttl),
            Record::OPT { .. } => None,
        }
    }
}

macro_rules! write_record {
    ($out:expr, $rr:expr, $($rdata:expr),+) => {
        {
            let start = $out.write($rr)?.pos();
            let end = $out$(.write($rdata)?)+.pos();
            $out.set(start - 2, (end - start) as u16)
        }
    };
}

impl<'a, T: IO> WriteTo<'a, T> for Record {
    type Out = T;

    #[allow(clippy::too_many_lines)]
    fn write_to(self, out: &'a mut T) -> Result<&'a mut T> {
        match self {
            Record::A { record, addr } => {
                write_record!(out, record, u32::from(addr))
            }
            Record::NS { record, host } | Record::CNAME { record, host } => {
                write_record!(out, record, host)
            }
            Record::MX {
                record,
                priority,
                host,
            } => {
                write_record!(out, record, priority, host)
            }
            Record::AAAA { record, addr } => {
                write_record!(out, record, u128::from(addr))
            }
            Record::SOA {
                record,
                m_name,
                r_name,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                write_record!(
                    out, record, m_name, r_name, serial, refresh, retry, expire, minimum
                )
            }
            Record::TXT { record, data } => write_record!(out, record, data),
            Record::SRV {
                record,
                priority,
                weight,
                port,
                host,
            } => {
                write_record!(out, record, priority, weight, port, host)
            }
            Record::OPT {
                data,
                packet_len,
                flags,
            } => out
                .write(0u8)?
                .write(QueryType::OPT)?
                .write(packet_len)?
                .write(flags)?
                .write(data.len() as u16)?
                .write(data),
            Record::DS {
                record,
                key_tag,
                algorithm,
                digest_type,
                digest,
            } => {
                write_record!(out, record, key_tag, algorithm, digest_type, digest)
            }
            Record::RRSIG {
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
            } => {
                write_record!(
                    out,
                    record,
                    ty,
                    algorithm,
                    labels,
                    original_ttl,
                    expiration,
                    inception,
                    tag,
                    name,
                    signature
                )
            }
            Record::NSEC {
                record,
                next_domain,
                type_map,
            } => write_record!(out, record, next_domain, type_map),
            Record::DNSKEY {
                record,
                flags,
                protocol,
                algorithm,
                public_key,
            } => write_record!(out, record, flags, protocol, algorithm, public_key),
            Record::NSEC3 {
                record,
                algorithm,
                flags,
                iterations,
                salt_length,
                salt,
                hash_length,
                hash,
                type_map,
            } => write_record!(
                out,
                record,
                algorithm,
                flags,
                iterations,
                salt_length,
                salt,
                hash_length,
                hash,
                type_map
            ),
            Record::NSEC3PARAM {
                record,
                algorithm,
                flags,
                iterations,
                salt_length,
                salt,
            } => {
                write_record!(out, record, algorithm, flags, iterations, salt_length, salt)
            }
            Record::SVCB {
                record,
                priority,
                target,
                params,
            }
            | Record::HTTPS {
                record,
                priority,
                target,
                params,
            } => {
                write_record!(out, record, priority, target, params)
            }
            Record::UNKNOWN { .. } => {
                trace!("Skipping UNKNOWN record");
                Ok(out)
            }
        }
    }
}

impl<I: IO> FromBuffer<I> for Record {
    ///
    /// A `Record`, in accordance with [RFC-1035](https://www.rfc-editor.org/rfc/rfc1035.html)
    /// contains the following:
    ///
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///   |                                               |
    ///   /                                               /
    ///   /                      NAME                     /
    ///   |                                               |
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///   |                      TYPE                     |
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///   |                     CLASS                     |
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///   |                      TTL                      |
    ///   |                                               |
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///   |                   RDLENGTH                    |
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    ///   /                     RDATA                     /
    ///   /                                               /
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///
    /// Where:
    ///  - NAME is the domain name the Record is for
    ///  - TYPE is a type code (e.g. A)
    ///  - CLASS is a class code (typically IN)
    ///  - TTL an integer determining the interval for which
    ///    the record is valid/can be cached for
    ///  - RDLENGTH is the length of the RDATA section
    ///  - RDATA is the information associated with the record
    ///    (which varies depending on the TYPE).
    ///
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
                let data = buffer.read_range(record.data_length as usize)?.to_vec();

                Ok(Record::TXT { record, data })
            }
            QueryType::SRV => Ok(Record::SRV {
                record,
                priority: buffer.read()?,
                weight: buffer.read()?,
                port: buffer.read()?,
                host: buffer.read()?,
            }),
            QueryType::OPT => Ok(Record::OPT {
                packet_len: record.class,
                flags: record.ttl.into(),
                data: buffer.read_range(record.data_length as usize)?.to_vec(),
            }),
            QueryType::DS => {
                let start = buffer.pos();
                let key_tag = buffer.read()?;
                let algorithm = buffer.read()?;
                let digest_type = buffer.read()?;

                let Some(digest_length) = (record.data_length as usize).checked_sub(buffer.pos() - start) else {
                    return Err(DNSError::InvalidPacket);
                };

                Ok(Record::DS {
                    record,
                    key_tag,
                    algorithm,
                    digest_type,
                    digest: buffer.read_range(digest_length)?.to_vec(),
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

                let Some(sign_len) =
                    (record.data_length as usize).checked_sub(buffer.pos() - start)
                else {
                    return Err(DNSError::InvalidPacket);
                };

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
                    signature: buffer.read_range(sign_len)?.to_vec(),
                })
            }
            QueryType::NSEC => {
                let start = buffer.pos();
                let next_domain = buffer.read()?;

                let Some(map_len) = (record.data_length as usize).checked_sub(buffer.pos() - start) else {
                    return Err(DNSError::InvalidPacket);
                };

                Ok(Record::NSEC {
                    record,
                    next_domain,
                    type_map: buffer.read_range(map_len)?.to_vec(),
                })
            }
            QueryType::DNSKEY => {
                let flags = buffer.read()?;
                let protocol = buffer.read()?;
                let algorithm = buffer.read()?;
                let Some(pub_key_length) = (record.data_length as usize).checked_sub(4) else { return Err(DNSError::InvalidPacket) };
                let public_key = buffer.read_range(pub_key_length)?.to_vec();

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
                let salt = buffer.read_range(salt_length)?.to_vec();

                let hash_length = buffer.read()?;
                let hash = buffer.read_range(hash_length)?.to_vec();

                let Some(map_len) = (record.data_length as usize).checked_sub(buffer.pos() - start) else {
                    return Err(DNSError::InvalidPacket);
                };

                let type_map = buffer.read_range(map_len)?.to_vec();

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

                Ok(Record::NSEC3PARAM {
                    record,
                    algorithm,
                    flags,
                    iterations,
                    salt_length: salt_length as u8,
                    salt: buffer.read_range(salt_length)?.to_vec(),
                })
            }
            QueryType::SVCB | QueryType::HTTPS => {
                let start = buffer.pos();
                let priority = buffer.read()?;
                let target = buffer.read()?;

                let Some(params_length) = (record.data_length as usize).checked_sub(buffer.pos() - start) else {
                    return Err(DNSError::InvalidPacket);
                };

                let params = buffer.read_range(params_length)?.to_vec();

                if record.query_type == QueryType::SVCB {
                    Ok(Record::SVCB {
                        record,
                        priority,
                        target,
                        params,
                    })
                } else {
                    Ok(Record::HTTPS {
                        record,
                        priority,
                        target,
                        params,
                    })
                }
            }
            QueryType::UNKNOWN(_) => {
                buffer.step(record.data_length as usize)?;
                Ok(Record::UNKNOWN { record })
            }
        }
    }
}
