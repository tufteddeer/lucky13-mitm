mod proxy;
mod tls;

use crate::proxy::TcpProxy;

extern crate log;
extern crate simplelog;

use simplelog::*;

fn main() {
    CombinedLogger::init(vec![TermLogger::new(
        LevelFilter::Info,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )])
    .unwrap();

    let server = "127.0.0.1:4433";
    let proxy_port = 9091;

    log::info!("Starting proxy on Port {}, forwarding to {}", proxy_port, server);
    let _proxy = TcpProxy::new(proxy_port, server.parse().unwrap(), false);
    loop {}
}
