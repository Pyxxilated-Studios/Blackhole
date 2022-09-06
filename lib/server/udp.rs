use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use tokio::{net::UdpSocket, sync::RwLock};
use tracing::{error, info};

use crate::dns::{
    packet::{Buffer, Packet},
    Result, ResultCode,
};

pub struct ServerBuilder {
    port: u16,
    addr: IpAddr,
}

impl ServerBuilder {
    pub fn listen(mut self, addr: IpAddr) -> ServerBuilder {
        self.addr = addr;
        self
    }

    pub fn on(mut self, port: u16) -> ServerBuilder {
        self.port = port;
        self
    }

    pub async fn build(self) -> Result<Server> {
        Ok(Server {
            socket: Arc::new(RwLock::new(UdpSocket::bind((self.addr, self.port)).await?)),
            requests: Arc::new(RwLock::new(HashMap::new())),
        })
    }
}

#[derive(Debug, Clone)]
pub struct Server {
    socket: Arc<RwLock<UdpSocket>>,
    requests: Arc<RwLock<HashMap<String, usize>>>,
}

impl Server {
    pub fn builder() -> ServerBuilder {
        ServerBuilder {
            port: 53,
            addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        }
    }

    pub fn requests(&self) -> &Arc<RwLock<HashMap<String, usize>>> {
        &self.requests
    }

    pub async fn run(&self) -> Result<()> {
        info!("listening on {}", self.socket.read().await.local_addr()?);

        while let Ok((packet, address)) = self.receive().await {
            let server = self.clone();

            tokio::spawn(async move {
                for question in packet.clone().questions {
                    *server
                        .requests
                        .write()
                        .await
                        .entry(question.name.name())
                        .or_default() += 1;
                }

                server.serve(packet, address).await;
            });
        }

        Ok(())
    }

    async fn receive(&self) -> Result<(Packet, SocketAddr)> {
        let mut buffer = Buffer::default();

        self.socket.read().await.readable().await?;
        let (_, address) = self
            .socket
            .read()
            .await
            .recv_from(buffer.buffer_mut())
            .await?;

        Ok((Packet::try_from(&mut buffer)?, address))
    }

    async fn respond(&self, mut packet: Packet, address: SocketAddr) -> Result<()> {
        let buffer = Buffer::try_from(packet.clone()).unwrap_or_else(|_| {
            packet.header.rescode = ResultCode::SERVFAIL;
            packet.header.answers = 0;
            packet.answers = vec![];
            packet.authorities = vec![];
            packet.resources = vec![];

            Buffer::try_from(packet).unwrap()
        });

        self.socket.read().await.writable().await?;
        self.socket
            .read()
            .await
            .send_to(&buffer.buffer()[0..buffer.pos()], address)
            .await?;

        Ok(())
    }

    async fn forward(&self, packet: Packet) -> Result<Packet> {
        const SERVER: (&str, u16) = ("192.168.1.123", 53);
        let forwarder = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 43210)).await?;

        let buffer = Buffer::try_from(packet)?;

        forwarder
            .send_to(&buffer.buffer()[0..buffer.pos()], SERVER)
            .await?;

        let mut res_buffer = Buffer::default();
        forwarder.recv_from(res_buffer.buffer_mut()).await?;

        Packet::try_from(&mut res_buffer)
    }

    async fn serve(&self, packet: Packet, address: SocketAddr) {
        match self.forward(packet).await {
            Ok(response_packet) => {
                if let Err(err) = self.respond(response_packet, address).await {
                    error!("{err:?}")
                }
            }
            Err(err) => {
                error!("{err:?}");
            }
        }
    }
}
