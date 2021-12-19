use std::fmt::{Debug};
use std::io::{BufReader, Read};

pub const APPLICATION_CONTENT: u8 = 0x17;
pub const TLS_V_1_2: u16 = 0x0303;

#[derive(Debug)]
pub struct Header {
    pub content_type: u8,
    pub version: u16,
}

pub fn read_header(buffer: &[u8]) -> Header {

    // read the first 3 bytes (content type (1) and version (2))
    let mut header_buff = [0u8; 3];
    let mut header_reader = BufReader::new(buffer);

    header_reader.read_exact(&mut header_buff).expect("Failed to read header");

    let ver = ((header_buff[1] as u16) << 8) | header_buff[2] as u16;

    Header {
        content_type: header_buff[0],
        version: ver,
    }
}



