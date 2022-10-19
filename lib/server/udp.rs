use std::{
    fmt::Debug,
    marker::PhantomData,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Instant,
};

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::{net::UdpSocket, sync::RwLock};
use tracing::{error, info, instrument, log::trace};

use crate::{
    config::Config,
    dns::{
        packet::{Buffer, Packet, ResizableBuffer},
        qualified_name::QualifiedName,
        question::Question,
        traits::{FromBuffer, IO},
        DNSError, QueryType, Record, Result, ResultCode, Ttl, RR,
    },
    filter::{Filter, Kind, Rewrite, Rule},
    statistics::{Average, Request, Statistic, STATISTICS},
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
            socket: Arc::new(RwLock::new(UdpSocket::bind(address).await?)),
            address,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Server {
    socket: Arc<RwLock<UdpSocket>>,
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
        info!("listening on {}", self.socket.read().await.local_addr()?);

        while let Ok((packet, address)) = self.receive().await {
            let socket = self.socket.clone();

            tokio::spawn(async move {
                if let Some(Record::OPT { .. }) = packet.resources.first() {
                    Handler::<ResizableBuffer>::serve(socket, packet, address).await;
                } else {
                    Handler::<Buffer>::serve(socket, packet, address).await;
                }
            });
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn receive(&self) -> Result<(Packet, SocketAddr)> {
        trace!("Waiting for requests ...");

        let mut buffer = Buffer::default();

        let sock = self.socket.read().await;
        sock.readable().await?;
        let (bytes, address) = sock.recv_from(buffer.buffer_mut()).await?;
        trace!("DNS request received from {address}: {bytes}");

        Ok((Packet::from_buffer(&mut buffer)?, address))
    }
}

#[derive(Default, Serialize)]
struct Handler<I> {
    client: String,
    question: Question,
    answers: Vec<Record>,
    rule: Option<Rule>,
    status: ResultCode,
    elapsed: usize,
    timestamp: DateTime<Utc>,
    phantom: PhantomData<I>,
}

impl<I> Handler<I>
where
    I: IO + TryFrom<Packet> + Default,
    DNSError: From<<I as TryFrom<Packet>>::Error>,
    <I as TryFrom<Packet>>::Error: Debug,
{
    #[instrument(skip(self, socket, packet, address))]
    async fn respond(
        &mut self,
        socket: &Arc<RwLock<UdpSocket>>,
        mut packet: Packet,
        address: SocketAddr,
    ) -> Result<()> {
        let buffer = I::try_from(packet.clone()).or_else(|err| {
            error!("{err:?}");

            packet.header.rescode = ResultCode::SERVFAIL;
            packet.header.response = true;
            packet.header.answers = 0;
            packet.header.truncated_message = false;
            packet.answers = vec![];
            packet.authorities = vec![];
            packet.resources = vec![];

            I::try_from(packet.clone())
        })?;

        let sock = socket.read().await;

        sock.writable().await?;
        sock.send_to(buffer.get_range(0, buffer.pos())?, address)
            .await?;

        self.status = packet.header.rescode;
        self.answers = packet.answers;

        Ok(())
    }

    #[instrument(skip(self, socket, address))]
    async fn respond_error(
        &mut self,
        socket: &Arc<RwLock<UdpSocket>>,
        address: SocketAddr,
        id: u16,
    ) {
        let mut packet = Packet::default();
        packet.header.id = id;
        packet.header.rescode = ResultCode::SERVFAIL;
        packet.header.response = true;
        packet.header.answers = 0;
        packet.header.truncated_message = false;
        packet.answers = vec![];
        packet.authorities = vec![];
        packet.resources = vec![];

        self.status = packet.header.rescode;

        let buffer = match I::try_from(packet) {
            Ok(buffer) => buffer,
            Err(err) => {
                error!("{err:?}");
                return;
            }
        };

        let sock = socket.read().await;

        if let Err(err) = sock.writable().await {
            error!("{err:?}");
            return;
        }

        if let Err(err) = sock
            .send_to(buffer.get_range(0, buffer.pos()).unwrap(), address)
            .await
        {
            error!("{err:?}");
        }
    }

    #[instrument(skip(self, packet))]
    async fn forward(&mut self, packet: Packet) -> Result<Packet> {
        let server = Config::get(|config| config.upstreams.iter().next().unwrap().clone()).await;

        let forwarder = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;

        self.question = packet.questions[0].clone();

        let buffer = I::try_from(packet)?;

        forwarder
            .send_to(buffer.get_range(0, buffer.pos())?, (server.ip, server.port))
            .await?;

        let mut res_buffer = Buffer::default();
        forwarder.recv_from(res_buffer.buffer_mut()).await?;

        Packet::from_buffer(&mut res_buffer)
    }

    async fn filter(&mut self, packet: Packet) -> Result<Packet> {
        match Filter::check(&packet) {
            Some(rule) if rule.ty == Kind::Allow => {
                self.rule = Some(rule);
                self.forward(packet).await
            }
            Some(rule) if rule.ty == Kind::Deny => {
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
                                domain: QualifiedName(packet.questions[0].name.name()),
                                ttl: Ttl(10),
                                query_type: QueryType::A,
                                class: 1,
                                data_length: 0,
                            },
                            addr: match rule
                                .action
                                .clone()
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
                                domain: QualifiedName(packet.questions[0].name.name()),
                                ttl: Ttl(10),
                                query_type: QueryType::AAAA,
                                class: 1,
                                data_length: 0,
                            },
                            addr: match rule
                                .action
                                .clone()
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
                packet.authorities = vec![];
                packet.resources = vec![];

                self.rule = Some(rule);

                Ok(packet)
            }
            _ => self.forward(packet).await,
        }
    }

    async fn serve(socket: Arc<RwLock<UdpSocket>>, packet: Packet, address: SocketAddr) {
        let mut handler = Handler::<I> {
            client: address.ip().to_string(),
            timestamp: Utc::now(),
            ..Default::default()
        };

        let id = packet.header.id;

        let start = Instant::now();

        match handler.filter(packet).await {
            Ok(response_packet) => {
                let id = response_packet.header.id;

                if let Err(err) = handler.respond(&socket, response_packet, address).await {
                    error!("{err:?}");
                    handler.respond_error(&socket, address, id).await;
                }
            }
            Err(err) => {
                error!("{err:?}");
                handler.respond_error(&socket, address, id).await;
            }
        }

        handler.elapsed = start.elapsed().as_nanos() as usize;

        STATISTICS
            .write()
            .await
            .record(Statistic::Average(Average {
                count: 1,
                average: handler.elapsed,
            }))
            .record(Statistic::Request(handler.into()));
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
        }
    }
}
