use tracing::{instrument, trace};

use std::net::Ipv4Addr;

use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, UdpSocket};

type Error = Box<dyn std::error::Error>;
type Result<T> = std::result::Result<T, Error>;

const DNS_PACKET_SIZE: usize = 512;

#[derive(Clone, Default, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct QualifiedName(String);

#[derive(Clone, Copy, Debug)]
pub struct PacketBuffer {
    pub buf: [u8; DNS_PACKET_SIZE],
    pub pos: usize,
}

impl PacketBuffer {
    /// Current position within buffer
    fn pos(&self) -> usize {
        self.pos
    }

    /// Step the buffer position forward a specific number of steps
    fn step(&mut self, steps: usize) {
        self.pos += steps;
    }

    /// Change the buffer position
    fn seek(&mut self, pos: usize) {
        self.pos = pos;
    }

    fn read<'a, T: TryFrom<&'a mut Self, Error = Error> + Default>(&'a mut self) -> Result<T> {
        T::try_from(self)
    }

    /// Get a single byte, without changing the buffer position
    fn get(&mut self, pos: usize) -> Result<u8> {
        if pos >= DNS_PACKET_SIZE {
            Err("End of buffer".into())
        } else {
            Ok(self.buf[pos])
        }
    }

    /// Get a range of bytes
    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= DNS_PACKET_SIZE {
            Err("End of buffer".into())
        } else {
            Ok(&self.buf[start..start + len as usize])
        }
    }
}

impl TryFrom<&mut PacketBuffer> for QualifiedName {
    type Error = Error;
    /// Read a qname
    ///
    /// The tricky part: Reading domain names, taking labels into consideration.
    /// Will take something like [3]www[6]google[3]com[0] and append
    /// www.google.com to outstr.
    fn try_from(packet: &mut PacketBuffer) -> Result<QualifiedName> {
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
                let b2 = packet.get(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;

                // Indicate that a jump was performed.
                jumped = true;
                jumps_performed += 1;

                continue;
            }
            // The base scenario, where we're reading a single label and
            // appending it to the output:
            else {
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

impl TryFrom<&mut PacketBuffer> for u8 {
    type Error = Error;

    fn try_from(packet: &mut PacketBuffer) -> Result<u8> {
        if packet.pos >= DNS_PACKET_SIZE {
            Err("End of buffer".into())
        } else {
            let res = packet.buf[packet.pos];
            packet.pos += 1;

            Ok(res)
        }
    }
}

impl TryFrom<&mut PacketBuffer> for u16 {
    type Error = Error;

    /// Read two bytes, stepping two steps forward
    fn try_from(packet: &mut PacketBuffer) -> Result<u16> {
        let res = ((packet.read::<u8>()? as u16) << 8) | (packet.read::<u8>()? as u16);

        Ok(res)
    }
}

impl TryFrom<&mut PacketBuffer> for u32 {
    type Error = Error;

    /// Read four bytes, stepping four steps forward
    fn try_from(packet: &mut PacketBuffer) -> Result<u32> {
        let res = ((packet.read::<u16>()? as u32) << 16) | (packet.read::<u16>()? as u32);

        Ok(res)
    }
}

impl Default for PacketBuffer {
    fn default() -> Self {
        PacketBuffer {
            buf: [0; DNS_PACKET_SIZE],
            pos: 0,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
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

#[derive(Clone, Debug, Default)]
pub struct Header {
    pub id: u16, // 16 bits

    pub recursion_desired: bool,    // 1 bit
    pub truncated_message: bool,    // 1 bit
    pub authoritative_answer: bool, // 1 bit
    pub opcode: u8,                 // 4 bits
    pub response: bool,             // 1 bit

    pub rescode: ResultCode,       // 4 bits
    pub checking_disabled: bool,   // 1 bit
    pub authed_data: bool,         // 1 bit
    pub z: bool,                   // 1 bit
    pub recursion_available: bool, // 1 bit

    pub questions: u16,             // 16 bits
    pub answers: u16,               // 16 bits
    pub authoritative_entries: u16, // 16 bits
    pub resource_entries: u16,      // 16 bits
}

impl TryFrom<&mut PacketBuffer> for Header {
    type Error = Error;

    fn try_from(buffer: &mut PacketBuffer) -> Result<Self> {
        let id = buffer.read()?;
        let flags = buffer.read::<u16>()?;
        let a = (flags >> 8) as u8;
        let b = (flags & 0xFF) as u8;

        let header = Header {
            id,

            recursion_desired: (a & (1 << 0)) > 0,
            truncated_message: (a & (1 << 1)) > 0,
            authoritative_answer: (a & (1 << 2)) > 0,
            opcode: (a >> 3) & 0x0F,
            response: (a & (1 << 7)) > 0,

            rescode: ResultCode::from(b & 0x0F),
            checking_disabled: (b & (1 << 4)) > 0,
            authed_data: (b & (1 << 5)) > 0,
            z: (b & (1 << 6)) > 0,
            recursion_available: (b & (1 << 7)) > 0,

            questions: buffer.read()?,
            answers: buffer.read()?,
            authoritative_entries: buffer.read()?,
            resource_entries: buffer.read()?,
        };

        // Return the constant header size
        Ok(header)
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy)]
pub enum QueryType {
    UNKNOWN(u16),
    A,
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
        }
    }
}

impl From<u16> for QueryType {
    fn from(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            _ => QueryType::UNKNOWN(num),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Question {
    pub name: QualifiedName,
    pub qtype: QueryType,
}

impl TryFrom<&mut PacketBuffer> for Question {
    type Error = Error;
    fn try_from(buffer: &mut PacketBuffer) -> Result<Self> {
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
}

impl TryFrom<&mut PacketBuffer> for Record {
    type Error = Error;

    fn try_from(buffer: &mut PacketBuffer) -> Result<Record> {
        let domain = buffer.read::<QualifiedName>()?;

        let qtype_num = buffer.read()?;
        let qtype = QueryType::from(qtype_num);
        let _ = buffer.read::<u16>()?;
        let ttl = buffer.read()?;
        let data_len = buffer.read()?;

        match qtype {
            QueryType::A => {
                let raw_addr = buffer.read::<u32>()?;
                let addr = Ipv4Addr::from(raw_addr);

                Ok(Record::A { domain, addr, ttl })
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

#[derive(Clone, Debug, Default)]
pub struct Packet {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub resources: Vec<Record>,
}

impl Packet {
    #[instrument]
    pub async fn from_udp(socket: &mut UdpSocket) -> Result<Packet> {
        let mut buffer = PacketBuffer::default();
        let _ = socket.recv(&mut buffer.buf).await.unwrap();

        let packet = Packet::try_from(&mut buffer)?;
        // trace!("{:#?}", packet);
        trace!("{:#?}", buffer);

        Ok(packet)
    }

    #[instrument]
    pub async fn from_tcp(stream: &mut TcpStream) -> Result<Packet> {
        let mut buffer = PacketBuffer::default();
        let _ = stream.read(&mut buffer.buf).await?;

        let packet = Packet::try_from(&mut buffer)?;
        trace!("{:#?}", packet);

        Ok(packet)
    }
}

impl TryFrom<&mut PacketBuffer> for Packet {
    type Error = Error;

    fn try_from(buffer: &mut PacketBuffer) -> Result<Packet> {
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
