use std::{
    fmt::Debug,
    marker::PhantomData,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpStream, UdpSocket},
    sync::RwLock,
};
use tracing::{error, instrument, trace};

use crate::{
    cache::Cache,
    config::Config,
    dns::{
        packet::Packet,
        question::Question,
        traits::{FromBuffer, IO},
        DNSError, Record, Result, ResultCode,
    },
    filter::{rules::Rule, Filter},
    server::Upstream,
    statistics::Request,
};

pub(crate) trait Stream {
    type Res;

    async fn write<Buffer>(
        &mut self,
        buffer: &mut Buffer,
        address: SocketAddr,
    ) -> Result<Self::Res>
    where
        Buffer: IO + TryFrom<Packet> + Default;
}

impl Stream for TcpStream {
    type Res = ();

    async fn write<Buffer>(
        &mut self,
        buffer: &mut Buffer,
        _address: SocketAddr,
    ) -> Result<Self::Res>
    where
        Buffer: IO + TryFrom<Packet> + Default,
    {
        self.writable().await?;
        buffer.insert(0, buffer.pos() as u16)?;
        self.write_all(buffer.get_range(0, buffer.pos() + 2)?)
            .await?;

        Ok(())
    }
}

impl Stream for Arc<RwLock<UdpSocket>> {
    type Res = usize;

    async fn write<Buffer>(&mut self, buffer: &mut Buffer, address: SocketAddr) -> Result<Self::Res>
    where
        Buffer: IO + TryFrom<Packet> + Default,
    {
        let socket = self.read().await;
        socket.writable().await?;
        let bytes = socket.send_to(buffer.buffer(), address).await?;

        Ok(bytes)
    }
}

pub(crate) struct Client<S: Stream> {
    pub(crate) client: S,
    pub(crate) address: SocketAddr,
}

impl<S: Stream> Client<S> {
    async fn write<Buffer>(&mut self, buffer: &mut Buffer) -> Result<S::Res>
    where
        Buffer: IO + TryFrom<Packet> + Default,
    {
        self.client.write(buffer, self.address).await
    }
}

#[cfg_attr(any(debug_assertions, test), derive(Debug))]
#[derive(Default, Serialize, Deserialize, Clone)]
pub(crate) struct Handler<Buff> {
    client: String,
    pub(crate) question: Question,
    pub(crate) answers: Vec<Record>,
    pub(crate) rule: Option<Rule>,
    pub(crate) status: ResultCode,
    elapsed: usize,
    timestamp: DateTime<Utc>,
    pub(crate) cached: bool,
    #[serde(skip)]
    phantom: PhantomData<Buff>,
}

impl<Buff> Handler<Buff>
where
    Buff: IO + TryFrom<Packet> + Default + Clone,
    DNSError: From<<Buff as TryFrom<Packet>>::Error>,
    <Buff as TryFrom<Packet>>::Error: Debug,
{
    #[instrument(skip(self, client, packet))]
    async fn respond<S: Stream>(
        &mut self,
        client: &mut Client<S>,
        mut packet: Packet,
    ) -> Result<()> {
        self.status = packet.header.rescode;
        self.answers = packet.answers.clone();

        let mut buffer = Buff::try_from(packet.clone()).or_else(|err| {
            error!("{err:?}");

            packet.header.rescode = ResultCode::SERVFAIL;
            packet.header.response = true;
            packet.header.answers = 0;
            packet.header.truncated_message = false;
            packet.answers = Vec::default();
            packet.authorities = Vec::default();
            packet.resources = Vec::default();

            Buff::try_from(packet)
        })?;

        client.write(&mut buffer).await?;

        Ok(())
    }

    #[instrument(skip(self, client))]
    async fn respond_error<S: Stream>(&mut self, client: &mut Client<S>, id: u16) {
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

        let mut buffer = match Buff::try_from(packet) {
            Ok(buffer) => buffer,
            Err(err) => {
                error!("{err:?}");
                return;
            }
        };

        if let Err(err) = client.write(&mut buffer).await {
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

        let buffer = Buff::try_from(packet)?;

        forwarder.set_tos(0xFE)?;

        tokio::time::timeout(
            Duration::from_secs(5),
            forwarder.send_to(buffer.get_range(0, buffer.pos())?, (server.ip, server.port)),
        )
        .await??;

        let mut res_buffer = Buff::default();
        tokio::time::timeout(
            Duration::from_secs(5),
            forwarder.recv_from(res_buffer.buffer_mut()),
        )
        .await??;

        Packet::from_buffer(&mut res_buffer)
    }

    #[instrument(skip(client, packet))]
    pub(crate) async fn serve<S: Stream>(mut client: Client<S>, packet: Packet) {
        let mut handler = Handler::<Buff> {
            client: client.address.ip().to_canonical().to_string(),
            timestamp: Utc::now(),
            question: packet.questions[0].clone(),
            ..Default::default()
        };

        let id = packet.header.id;

        let start = Instant::now();

        let response_packet = if let Some(cached) = Cache::get(&packet).await {
            handler.cached = true;
            Some(cached)
        } else {
            Some(packet)
        };

        if let Some(mut response_packet) = response_packet {
            Filter::apply(&mut handler, &mut response_packet);

            let forwarded = if !handler.cached
                && (handler.rule.is_none()
                    || handler
                        .rule
                        .as_ref()
                        .unwrap()
                        .action
                        .as_ref()
                        .map_or_else(|| false, |action| action.rewrite.is_some()))
            {
                handler.forward(response_packet).await
            } else {
                Ok(response_packet)
            };

            match forwarded {
                Ok(mut response_packet) => {
                    response_packet.header.id = id;

                    if !handler.cached && response_packet.header.rescode != ResultCode::SERVFAIL {
                        Cache::insert(&response_packet).await;
                    }

                    if let Err(err) = handler.respond(&mut client, response_packet).await {
                        error!("{err:?}");
                        handler.respond_error(&mut client, id).await;
                    }
                }
                Err(err) => match err {
                    DNSError::Timeout(_) => {}
                    err => {
                        error!("{err}");
                    }
                },
            }
        }

        handler.elapsed = start.elapsed().as_nanos() as usize;

        trace!(statistics_requests = json!({ "request": handler }).to_string(),);
    }
}

impl<Buff> From<Handler<Buff>> for Request {
    fn from(handler: Handler<Buff>) -> Request {
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
