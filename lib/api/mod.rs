pub mod server;

use std::sync::Arc;

use crate::server as dnsServer;

#[derive(Clone)]
pub struct Context {
    // Whatever data your application needs can go here
    pub server: Arc<dnsServer::udp::Server>,
}
