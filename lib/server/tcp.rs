use std::{
    fmt::Debug,
    marker::PhantomData,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::RwLock,
};
use tracing::{error, info, instrument, trace};

use crate::{
    cache::Cache,
    config::Config,
    dns::{
        packet::{Packet, ResizableBuffer},
        qualified_name::QualifiedName,
        question::Question,
        traits::{FromBuffer, IO},
        DNSError, QueryType, Record, Result, ResultCode, Ttl, RR,
    },
    filter::{
        rules::{Kind, Rewrite, Rule},
        Filter,
    },
    server::Upstream,
    statistics::Request,
};

pub struct ServerBuilder {
    port: u16,
    addr: IpAddr,
}

impl ServerBuilder {
    #[must_use]
    pub fn listen(mut self, addr: IpAddr) -> ServerBuilder {
        self.addr = addr;
        self
    }

    #[must_use]
    pub fn on(mut self, port: u16) -> ServerBuilder {
        self.port = port;
        self
    }

    ///
    /// Build the server
    ///
    /// # Errors
    /// If we fail to bind to the socket
    ///
    pub async fn build(self) -> Result<Server> {
        let address = (self.addr, self.port).into();
        Ok(Server {
            listener: Arc::new(RwLock::new(TcpListener::bind(address).await?)),
            address,
        })
    }
}

#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Clone)]
pub struct Server {
    listener: Arc<RwLock<TcpListener>>,
    address: SocketAddr,
}

impl Server {
    pub fn builder() -> ServerBuilder {
        ServerBuilder {
            port: 53,
            addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        }
    }

    #[instrument(skip(self),
        fields(
            addr = %self.address
        )
    )]
    pub async fn run(&self) -> Result<()> {
        info!("listening on {}", self.listener.read().await.local_addr()?);

        while let Ok((stream, packet, address)) = self.receive().await {
            tokio::spawn(async move {
                Handler::<ResizableBuffer>::serve(stream, packet, address).await;
            });
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn receive(&self) -> Result<(TcpStream, Packet, SocketAddr)> {
        trace!("Waiting for requests ...");

        let mut buffer = ResizableBuffer::default();

        let listener = self.listener.read().await;
        let (mut stream, address) = listener.accept().await?;

        stream.readable().await?;
        let _length = stream.read_u16().await?;
        let _bytes = stream.read_buf(&mut buffer.buffer_mut()).await?;

        let packet = Packet::from_buffer(&mut buffer)?;

        trace!(
            "DNS request received from {}:{}: ID: {}",
            address.ip().to_canonical(),
            address.port(),
            packet.header.id
        );

        Ok((stream, packet, address))
    }
}

#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Default, Serialize, Deserialize)]
pub(crate) struct Handler<I> {
    client: String,
    question: Question,
    answers: Vec<Record>,
    rule: Option<Rule>,
    status: ResultCode,
    elapsed: usize,
    timestamp: DateTime<Utc>,
    cached: bool,
    #[serde(skip)]
    phantom: PhantomData<I>,
}

impl<I> Handler<I>
where
    I: IO + TryFrom<Packet> + Default,
    DNSError: From<<I as TryFrom<Packet>>::Error>,
    <I as TryFrom<Packet>>::Error: Debug,
{
    #[instrument(skip(self, stream, packet))]
    async fn respond(&mut self, stream: &mut TcpStream, mut packet: Packet) -> Result<()> {
        self.status = packet.header.rescode;
        self.answers = packet.answers.clone();

        let mut buffer = I::try_from(packet.clone()).or_else(|err| {
            error!("{err:?}");

            packet.header.rescode = ResultCode::SERVFAIL;
            packet.header.response = true;
            packet.header.answers = 0;
            packet.header.truncated_message = false;
            packet.answers = Vec::default();
            packet.authorities = Vec::default();
            packet.resources = Vec::default();

            I::try_from(packet)
        })?;

        // TCP needs the length
        buffer.insert(0, buffer.pos() as u16)?;
        stream
            .write_all(buffer.get_range(0, buffer.pos() + 2)?)
            .await?;

        Ok(())
    }

    #[instrument(skip(self, stream))]
    async fn respond_error(&mut self, stream: &mut TcpStream, id: u16) {
        let mut packet = Packet::default();
        packet.header.id = id;
        packet.header.rescode = ResultCode::SERVFAIL;
        self.answers = Vec::default();
        packet.header.response = true;
        packet.header.answers = 0;
        packet.header.truncated_message = false;
        packet.answers = Vec::default();
        self.status = ResultCode::SERVFAIL;
        packet.authorities = Vec::default();
        packet.resources = Vec::default();

        let buffer = match I::try_from(packet) {
            Ok(buffer) => buffer,
            Err(err) => {
                error!("{err:?}");
                return;
            }
        };

        if let Err(err) = stream.writable().await {
            error!("{err:?}");
            return;
        }

        if let Err(err) = stream
            .write(buffer.get_range(0, buffer.pos()).unwrap())
            .await
        {
            error!("{err:?}");
        }
    }

    #[instrument(skip(self, packet))]
    async fn forward(&mut self, packet: Packet) -> Result<Packet> {
        trace!("Forwarding packet: ID: {}", packet.header.id);

        let server = Config::get(|config| {
            config
                .upstreams
                .iter()
                .next()
                .cloned()
                .unwrap_or_else(|| Upstream {
                    ip: IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
                    port: 53,
                })
        })
        .await;

        let forwarder = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;

        let buffer = I::try_from(packet)?;

        forwarder.set_tos(0xFE)?;

        tokio::time::timeout(
            Duration::from_secs(5),
            forwarder.send_to(buffer.get_range(0, buffer.pos())?, (server.ip, server.port)),
        )
        .await??;

        let mut res_buffer = ResizableBuffer::default();
        tokio::time::timeout(
            Duration::from_secs(5),
            forwarder.recv_from(res_buffer.buffer_mut()),
        )
        .await??;

        Packet::from_buffer(&mut res_buffer)
    }

    async fn filter(&mut self, packet: Packet) -> Result<Packet> {
        match Filter::check(&packet) {
            Some(rule) if rule.ty == Kind::Allow => {
                self.rule = Some(rule);
                self.forward(packet).await
            }
            Some(rule) if rule.ty == Kind::Deny => {
                let action = rule.action.clone();
                self.rule = Some(rule);
                let mut packet = packet;
                packet.header.recursion_available = true;
                packet.header.response = true;
                packet.header.rescode = ResultCode::NOERROR;
                packet.header.truncated_message = false;
                match packet.questions.first() {
                    Some(Question {
                        qtype: QueryType::A,
                        ..
                    }) => {
                        packet.header.answers = 1;
                        packet.answers = vec![Record::A {
                            record: RR {
                                domain: QualifiedName(packet.questions[0].name.name().clone()),
                                ttl: Ttl(600),
                                query_type: QueryType::A,
                                class: 1,
                                data_length: 0,
                            },
                            addr: match action
                                .and_then(|action| action.rewrite)
                                .unwrap_or(Rewrite {
                                    v4: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                                    v6: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                                })
                                .v4
                            {
                                IpAddr::V4(addr) => addr,
                                IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
                            },
                        }];
                    }
                    Some(Question {
                        qtype: QueryType::AAAA,
                        ..
                    }) => {
                        packet.header.answers = 1;
                        packet.answers = vec![Record::AAAA {
                            record: RR {
                                domain: QualifiedName(packet.questions[0].name.name().clone()),
                                ttl: Ttl(600),
                                query_type: QueryType::AAAA,
                                class: 1,
                                data_length: 0,
                            },
                            addr: match action
                                .and_then(|action| action.rewrite)
                                .unwrap_or(Rewrite {
                                    v4: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                                    v6: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                                })
                                .v6
                            {
                                IpAddr::V4(_) => Ipv6Addr::UNSPECIFIED,
                                IpAddr::V6(addr) => addr,
                            },
                        }];
                    }
                    _ => {}
                }
                packet.authorities = Vec::default();
                packet.resources = Vec::default();

                Ok(packet)
            }
            _ => self.forward(packet).await,
        }
    }

    #[instrument(skip(stream, packet, address))]
    async fn serve(mut stream: TcpStream, packet: Packet, address: SocketAddr) {
        let mut handler = Handler::<I> {
            client: address.ip().to_canonical().to_string(),
            timestamp: Utc::now(),
            question: packet.questions[0].clone(),
            ..Default::default()
        };

        let id = packet.header.id;

        let start = Instant::now();

        let response = if let Some(mut cached) = Cache::get(&packet).await {
            cached.header.id = id;
            handler.cached = true;
            handler.rule = Filter::check(&packet);

            Ok(cached)
        } else {
            handler.filter(packet).await
        };

        match response {
            Ok(response_packet) => {
                let id = response_packet.header.id;

                Cache::insert(&response_packet).await;

                if let Err(err) = handler.respond(&mut stream, response_packet).await {
                    error!("{err:?}");
                    handler.respond_error(&mut stream, id).await;
                }
            }
            Err(err) => match err {
                DNSError::Timeout(_) => {}
                _ => {
                    error!("{err:?}");
                }
            },
        }

        handler.elapsed = start.elapsed().as_nanos() as usize;

        trace!(statistics_requests = json!({ "request": handler }).to_string(),);
    }
}

impl<I> From<Handler<I>> for Request {
    fn from(handler: Handler<I>) -> Request {
        Request {
            client: handler.client,
            question: handler.question,
            answers: handler.answers,
            rule: handler.rule,
            status: handler.status,
            elapsed: handler.elapsed,
            timestamp: handler.timestamp,
            cached: handler.cached,
        }
    }
}
