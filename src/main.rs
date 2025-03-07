use anyhow::Context;
use std::net::TcpStream;

fn main() -> anyhow::Result<()> {
    // RETRIEVE SERVER INFORMATION FROM ENVIRONMENT VARIABLES

    let ip_addr = std::env::var("SERVER_IP").with_context(|| "Missing server IP address envvar")?;
    let ip_port = std::env::var("SERVER_PORT").with_context(|| "Missing server port envvar")?;

    // CONNECT THE CLIENT TO THE GIVEN IP ADDRESS AND PORT

    let mut stream = TcpStream::connect(format!("{ip_addr}:{ip_port}"))
        .with_context(|| "Failed to connect to the server")?;

    // GENERATE THE RSA KEY PAIR FOR MESSAGE ENCRYPTION

    let key_pair = webutils::generate_key_pair()?;

    // EXCHANGE KEYS WITH SERVER

    let client_public_key = webutils::exchange_keys(&key_pair.public_key, &mut stream)
        .with_context(|| "Failed to exchange keys with server")?;

    // CONFIRM KEYS WERE SUCCESSFULLY SWAPPED

    webutils::synchronize(&client_public_key, &key_pair.private_key, &mut stream)
        .with_context(|| "Failed to synchronize with server")?;

    println!("CLIENT-SERVER SYNC SUCCEEDED");

    loop {
        std::hint::spin_loop();
    }
}
