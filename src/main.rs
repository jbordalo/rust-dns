use std::{net::UdpSocket, vec};

fn encode_name(name: String) -> Vec<u8> {
    let labels = name.split("."); //.collect::<Vec<&str>>();

    let mut encoded: Vec<u8> = Vec::new();

    for l in labels {
        encoded.push(l.len().try_into().unwrap());
        encoded.append(&mut l.as_bytes().to_vec());
    }

    encoded.push(0);
    encoded
}

fn build_dns_request(name: String) -> Vec<u8> {
    let mut header: Vec<u8> = vec!
        [
            // Id
            0xff, 0xff,
            // Flags
            0x1, 0x20,
            // Query count
            0, 0x1,
            // Answer RRs
            0, 0,
            // Authority RRs
            0, 0,
            // Additional RRs
            0, 0
        ];

    let mut name = encode_name(name);

    let mut question = vec!
        [
            // Query Type
            0, 0x1,
            // Query Class
            0, 0x1,
        ];

    header.append(&mut name);
    header.append(&mut question);
    header
}

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

        println!("Received reply with size {}: {:x?}", amt, reply);
        
        let ip = &mut reply[amt-4..amt];

        println!("Ip: {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);

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