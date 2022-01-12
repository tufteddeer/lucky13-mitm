/**
Based on the basic_ctp_proxy crate (https://crates.io/crates/basic_tcp_proxy), MIT/Apache-2.0
https://github.com/jamesmcm/basic_tcp_proxy/blob/master/src/lib.rs
 */

use std::sync::Mutex;
use std::sync::Arc;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv6Addr};
use std::net::{TcpListener, TcpStream};
use std::time::Instant;
use crate::tls::{TLS_APPLICATION_CONTENT, read_header, TLS_HEADER_SIZE, TLS_V_1_2, TLS_ALERT};

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
        invalidate_padding: bool,
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
                log::debug!("New connection");

                let mut sender_forward = TcpStream::connect(proxy_to).expect("Failed to bind");
                let sender_backward = sender_forward.try_clone().expect("Failed to clone stream");
                let mut stream_backward =
                    stream_forward.try_clone().expect("Failed to clone stream");

                let bad_padding_sent_time = Arc::new(Mutex::new(Option::None));
                // copy bad_padding_sent_time, cause the original is owned by the "forward stream" closure
                let bad_padding_sent_time_copy = bad_padding_sent_time.clone();
                
                std::thread::spawn(move || {
                    let mut stream_forward = BufReader::new(stream_forward);
                    loop {
                        let buffer = stream_forward.fill_buf().unwrap();

                        if buffer.is_empty() {
                            // Connection closed
                            log::debug!("Client closed connection");
                            return;
                        }

                        let mut length = buffer.len();
                        let mut forward_buff = vec![0u8; length];
                        forward_buff.copy_from_slice(buffer);

                        if length >= TLS_HEADER_SIZE {
                            log::debug!("buff size is {}, reading header", buffer.len());
                            let header = read_header(buffer);
                            if header.version == TLS_V_1_2 && header.content_type == TLS_APPLICATION_CONTENT {
                                log::debug!("found app content");

                                log::debug!("content size: {}", header.content_len);
                                log::debug!("buff size: {}", buffer.len());
                                log::debug!("buffer content: {:02X?}", buffer);

                                // since there was no call to stream_forward.consume yet,
                                // we can read TLS_HEADER_SIZE + content_len bytes (aka read the header again and wait for the rest of the record)

                                // aaaaand it seems to work! (as long as stream_forward.fill_buf() gives us a buffer that contains the tls record right at the start)

                                // content_len does not include the 5 tls header bytes
                                let tls_record_size = TLS_HEADER_SIZE + header.content_len;

                                let mut tls_record_buff = vec![0u8; tls_record_size];
                                stream_forward.read_exact(&mut tls_record_buff).expect("failed to read whole tsl record");
                                log::debug!("got record: {:02X?}", tls_record_buff);
                                log::debug!("record length: {:?}", tls_record_buff.len());

                                length = tls_record_buff.len();
                                // forward the whole tls record we captured
                                forward_buff = tls_record_buff;

                                if invalidate_padding {
                                    // mess with the padding
                                    log::info!("Manipulating padding, setting length to 0x{:02X}", 0x12);
                                    forward_buff[length-1] = 0x12;

                                    let mut time = bad_padding_sent_time.lock().unwrap();
                                    *time = Some(Instant::now());
                                }
                                
                            }
                        }

                        let res = sender_forward
                            .write_all(&forward_buff);
                        match res {
                            Ok(_) => {},
                            Err(error) => log::error!("Failed to write to server, probably the session is terminated: {}", error)
                        }
                        
                        sender_forward.flush().expect("Failed to flush remote");
                        stream_forward.consume(length);
                    }
                });

                let _backward_thread = std::thread::spawn(move || {
                    let mut sender_backward = BufReader::new(sender_backward);
                    loop {
                        let length = {
                            // this will fail when the tls server terminates the connection after our manipulation/the alert is sent
                            let buffer = sender_backward.fill_buf().expect("failed to read from server");
                            let length = buffer.len();
                            if buffer.is_empty() {
                                // Connection closed
                                log::info!("Remote closed connection");
                                return;
                            }

                            if invalidate_padding && length >= TLS_HEADER_SIZE {
                                let header = read_header(buffer);

                                if header.version == TLS_V_1_2 && header.content_type == TLS_ALERT {
                                    log::info!("Server has sent an alert!");

                                    let time = bad_padding_sent_time_copy.lock().unwrap();
                                    match *time {
                                        None => log::warn!("got alert, but padding was not modified"),
                                        Some(sent_time) => {
                                            let elapsed = sent_time.elapsed().as_nanos();
                                            log::info!("got alert after {}ns", elapsed);
                                        }
                                    }
                                }
                            }
                            

                            if stream_backward.write_all(buffer).is_err() {
                                // Connection closed
                                log::info!("Client closed connection");
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
