use std::fmt::{Debug};

pub const TLS_ALERT: u8 = 0x15;
pub const TLS_APPLICATION_CONTENT: u8 = 0x17;
pub const TLS_V_1_2: u16 = 0x0303;
pub const TLS_HEADER_SIZE: usize = 5;

#[derive(Debug)]
pub struct Header {
    pub content_type: u8,
    pub version: u16,
    pub content_len: usize,
}

pub fn read_header(buffer: &[u8]) -> Header {
    assert!(buffer.len() >= 5, "buffer length must be at least 5 bytes to read header, was {}", buffer.len());

    let ver = ((buffer[1] as u16) << 8) | buffer[2] as u16;

    let content_len = ((buffer[3] as u16) << 8) | buffer[4] as u16;
    Header {
        content_type: buffer[0],
        version: ver,
        content_len: content_len as usize,
    }
}



