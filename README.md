
TCP Proxy that demonstrates the basics of Lucky13 style padding oracles against TLS servers.

# Running

The Proxy listens for incoming connections on port 9091 and forwards everything between the client and the TCP server set in the `server` string (`main.rs`). You can switch the attack on and off using the `invalidate_padding` variable.

Use `cargo run` to start the program.

# Libraries

The whole Proxy logic in `proxy.rs` is taken from the [basic_tcp_proxy Crate](https://crates.io/crates/basic_tcp_proxy),  (MIT or Apache-2.0)

- [simplelog](https://crates.io/crates/simplelog)
- [log](https://crates.io/crates/log)