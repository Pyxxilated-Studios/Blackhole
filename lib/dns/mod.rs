pub mod packet;

use std::net::{Ipv4Addr, Ipv6Addr};

use tracing::warn;

use crate::dns::packet::{Buffer, IO};

pub(crate) type Error = Box<dyn std::error::Error>;
pub(crate) type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Default, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct QualifiedName(String);

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
    fn try_from(packet: &mut Buffer) -> Result<QualifiedName> {
        // Since we might encounter jumps, we'll keep track of our position
        // locally as opposed to using the position within the struct. This
        // allows us to move the shared position to a point past our current
        // qname, while keeping track of our progress on the current qname
        // using this variable.
        let mut pos = packet.pos();

        // track whether or not we've jumped
        let mut jumped = false;
        let max_jumps = 5;
        let mut jumps_performed = 0;

        // Our delimiter which we append for each label. Since we don't want a
        // dot at the beginning of the domain name we'll leave it empty for now
        // and set it to "." at the end of the first iteration.
        let mut delim = "";

        let mut outstr = String::default();

        loop {
            // Dns Packets are untrusted data, so we need to be paranoid. Someone
            // can craft a packet with a cycle in the jump instructions. This guards
            // against such packets.
            if jumps_performed > max_jumps {
                return Err(format!("Limit of {} jumps exceeded", max_jumps).into());
            }

            // At this point, we're always at the beginning of a label. Recall
            // that labels start with a length byte.
            let len = packet.get(pos)?;

            // If len has the two most significant bits set, it represents a
            // jump to some other offset in the packet:
            if (len & 0xC0) == 0xC0 {
                // Update the buffer position to a point past the current
                // label. We don't need to touch it any further.
                if !jumped {
                    packet.seek(pos + 2);
                }

                // Read another byte, calculate offset and perform the jump by
                // updating our local position variable
                let b2 = u16::from(packet.get(pos + 1)?);
                let offset = ((u16::from(len) ^ 0xC0) << 8) | b2;
                pos = offset as usize;

                // Indicate that a jump was performed.
                jumped = true;
                jumps_performed += 1;
            } else {
                // The base scenario, where we're reading a single label and
                // appending it to the output:

                // Move a single byte forward to move past the length byte.
                pos += 1;

                // Domain names are terminated by an empty label of length 0,
                // so if the length is zero we're done.
                if len == 0 {
                    break;
                }

                // Append the delimiter to our output buffer first.
                outstr.push_str(delim);

                // Extract the actual ASCII bytes for this label and append them
                // to the output buffer.
                let str_buffer = packet.get_range(pos, len as usize)?;
                outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

                delim = ".";

                // Move forward the full length of the label.
                pos += len as usize;
            }
        }

        if !jumped {
            packet.seek(pos);
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
    NOTIMP = 4,
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
            4 => ResultCode::NOTIMP,
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
            ResultCode::NOTIMP => 4,
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
    MX,
    AAAA,
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
            QueryType::MX => 15,
            QueryType::AAAA => 28,
        }
    }
}

impl From<u16> for QueryType {
    fn from(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            2 => QueryType::NS,
            5 => QueryType::CNAME,
            15 => QueryType::MX,
            28 => QueryType::AAAA,
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
        ttl: u32,
    },
    A {
        domain: QualifiedName,
        addr: Ipv4Addr,
        ttl: u32,
    },
    NS {
        domain: QualifiedName,
        host: QualifiedName,
        ttl: u32,
    },
    CNAME {
        domain: QualifiedName,
        host: QualifiedName,
        ttl: u32,
    },
    MX {
        domain: QualifiedName,
        priority: u16,
        host: QualifiedName,
        ttl: u32,
    },
    AAAA {
        domain: QualifiedName,
        addr: Ipv6Addr,
        ttl: u32,
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
                    .write(ttl)?
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
                    .write(ttl)?;

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
                    .write(ttl)?;

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
                    .write(ttl)?;

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
                    .write(ttl)?
                    .write(16u16)?
                    .write(u128::from(addr))?;
            }
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

        let qtype_num = buffer.read()?;
        let qtype = QueryType::from(qtype_num);
        let _ = buffer.read::<u16>()?;
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
            QueryType::UNKNOWN(_) => {
                buffer.step(data_len as usize);

                Ok(Record::UNKNOWN {
                    domain,
                    qtype: qtype_num,
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
