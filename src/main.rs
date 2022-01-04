mod proxy;
mod tls;

use crate::proxy::TcpProxy;

fn main() {
    let server = "127.0.0.1:4433";
    log::info!("starting client");
    let _proxy = TcpProxy::new(9091, server.parse().unwrap(), false);
    loop {}
}