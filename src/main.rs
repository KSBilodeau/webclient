use anyhow::bail;
use std::net::TcpStream;

fn main() -> anyhow::Result<()> {
    // RETRIEVE SERVER INFORMATION FROM ENVIRONMENT VARIABLES

    let Ok(ip_addr) = std::env::var("SERVER_IP") else {
        bail!("Missing server IP address envvar")
    };

    let Ok(ip_port) = std::env::var("SERVER_PORT") else {
        bail!("Missing server port envvar")
    };

    // CONNECT THE CLIENT TO THE GIVEN IP ADDRESS AND PORT

    let Ok(mut stream) = TcpStream::connect(format!("{ip_addr}:{ip_port}")) else {
        bail!("Failed to connect to the server")
    };

    // GENERATE THE RSA KEY PAIR FOR MESSAGE ENCRYPTION

    let key_pair = webutils::generate_key_pair()?;

    // EXCHANGE KEYS WITH SERVER

    let client_public_key = webutils::exchange_keys(&key_pair.public_key, &mut stream)?;

    // CONFIRM KEYS WERE SUCCESSFULLY SWAPPED

    let ack = webutils::send_message(
        &client_public_key,
        &key_pair.private_key,
        &mut stream,
        b"ACK",
    )?;

    if ack != "ACK" {
        bail!("ACKNOWLEDGEMENT FAILED")
    }

    println!("ACKNOWLEDGEMENT SUCCEEDED");

    loop {
        std::hint::spin_loop();
    }
}
