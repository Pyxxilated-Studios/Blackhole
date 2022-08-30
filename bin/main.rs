use tokio::net::TcpListener;
use tokio::net::UdpSocket;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .pretty()
        // .with_file(false)
        // .with_line_number(false)
        .with_env_filter(EnvFilter::from_env("LOG_LEVEL"))
        .init();

    let listener = TcpListener::bind("0.0.0.0:6379").await?;
    let mut udp = UdpSocket::bind("0.0.0.0:6379").await?;

    let udp_joiner = tokio::spawn(async move {
        loop {
            let _ = blackhole::dns::Packet::from_udp(&mut udp).await.unwrap();
        }
    });

    let tcp_joiner = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            stream.readable().await.unwrap();
            let _ = blackhole::dns::Packet::from_tcp(&mut stream).await.unwrap();
        }
    });

    tokio::join!(udp_joiner, tcp_joiner).0?;

    Ok(())
}
