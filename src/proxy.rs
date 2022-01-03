use std::cmp::{min};
use std::fs::copy;
/**
Based on the basic_ctp_proxy crate (https://crates.io/crates/basic_tcp_proxy), MIT/Apache-2.0
https://github.com/jamesmcm/basic_tcp_proxy/blob/master/src/lib.rs
*/

use log::debug;
use std::io::{BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv6Addr};
use std::net::{TcpListener, TcpStream};
use crate::tls::{APPLICATION_CONTENT, read_header, TLS_V_1_2};

/// TcpProxy runs one thread looping to accept new connections
/// and then two separate threads per connection for writing to each end
pub struct TcpProxy {
    /// The handle for the outer thread, accepting new connections
    pub forward_thread: std::thread::JoinHandle<()>,
}

impl TcpProxy {
    /// Create a new TCP proxy, binding to listen_port and forwarding and receiving traffic from
    /// proxy_to
    pub fn new(
        listen_port: u16,
        proxy_to: SocketAddr,
        local_only: bool,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let ip = if local_only {
            Ipv6Addr::LOCALHOST
        } else {
            Ipv6Addr::UNSPECIFIED
        };
        let listener_forward = TcpListener::bind(SocketAddr::new(IpAddr::V6(ip), listen_port))?;

        let forward_thread = std::thread::spawn(move || {
            loop {
                let (stream_forward, _addr) = listener_forward
                    .accept()
                    .expect("Failed to accept connection");
                debug!("New connection");

                let mut sender_forward = TcpStream::connect(proxy_to).expect("Failed to bind");
                let sender_backward = sender_forward.try_clone().expect("Failed to clone stream");
                let mut stream_backward =
                    stream_forward.try_clone().expect("Failed to clone stream");

                std::thread::spawn(move || {
                    let mut stream_forward = BufReader::new(stream_forward);
                    loop {
                        let length = {
                            let buffer = stream_forward.fill_buf().unwrap();
                            let length = buffer.len();
                            if buffer.is_empty() {
                                // Connection closed
                                debug!("Client closed connection");
                                return;
                            }

                            let mut forward_buff = vec![0u8; length];
                            forward_buff.copy_from_slice(buffer);

                            if length >= 5 {

                                let header = read_header(&buffer);
                                if header.version == TLS_V_1_2 && header.content_type == APPLICATION_CONTENT {
                                    println!("found app content");

                                    //forward_buff[length-1] = 0x01;

                                    for i in 1 .. min(900, length - 4) {
                                        forward_buff[length-i] =  0x11;
                                        println!("{}", i)
                                    }
                                    /*
                                    forward_buff[length-1] = 0x03;
                                    forward_buff[length-2] = 0x03;
                                    forward_buff[length-3] = 0x03;*/
                                }
                            }

                            sender_forward
                                .write_all(&forward_buff)
                                .expect("Failed to write to remote");
                            sender_forward.flush().expect("Failed to flush remote");
                            length
                        };
                        stream_forward.consume(length);
                    }
                });

                let _backward_thread = std::thread::spawn(move || {
                    let mut sender_backward = BufReader::new(sender_backward);
                    loop {
                        let length = {
                            let buffer = sender_backward.fill_buf().unwrap();
                            let length = buffer.len();
                            if buffer.is_empty() {
                                // Connection closed
                                debug!("Remote closed connection");
                                return;
                            }

                            if length >= 3 {
                                let header = read_header(&buffer);
                                if header.version == TLS_V_1_2 && header.content_type == APPLICATION_CONTENT {
                                    println!("found app content")
                                }
                            }

                            if stream_backward.write_all(&buffer).is_err() {
                                // Connection closed
                                debug!("Client closed connection");
                                return;
                            }

                            stream_backward.flush().expect("Failed to flush locally");
                            length
                        };
                        sender_backward.consume(length);
                    }
                });
            }
        });

        Ok(Self { forward_thread })
    }
}
