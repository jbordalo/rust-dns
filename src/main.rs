use std::net::UdpSocket;
mod dns;
use bytes::{self, BytesMut};
use dns::{build_dns_request, parse_response};

fn send_udp_request() -> std::io::Result<()> {
    {
    let socket = UdpSocket::bind("127.0.0.1:34254")?;

        let msg = build_dns_request("google.com".to_string());

        // socket.send_to(&msg, "127.0.0.1:4242").expect("couldn't send data");
        socket.send_to(&msg, "127.0.0.53:53").expect("Couldn't send message");

        // Receives a single datagram message on the socket. If `buf` is too small to hold
        // the message, it will be cut off.
        let mut buf = [0; 60];
        let (amt, _src) = socket.recv_from(&mut buf)?;

        
        // Redeclare `buf` as slice of the received data and send reverse data back to origin.
        let reply = &mut buf[..amt];
        
        let mut bytes = BytesMut::with_capacity(amt);
        bytes.extend_from_slice(reply);

        let resp = parse_response(bytes.freeze());

        println!("Response:\n{}", resp);

        // socket.send_to(buf, &src)?;
    } // the socket is closed here

    Ok(())
}

fn main() {
    match send_udp_request() {
        Ok(_) => println!("Success!"),
        Err(e) => println!("Failure! {}", e),
    }
}