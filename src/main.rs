use anyhow::Context;
use std::net::TcpStream;

fn main() -> anyhow::Result<()> {
    // RETRIEVE SERVER INFORMATION FROM ENVIRONMENT VARIABLES

    let ip_addr = std::env::var("SERVER_IP").with_context(|| "Missing server IP address envvar")?;
    let ip_port = std::env::var("SERVER_PORT").with_context(|| "Missing server port envvar")?;

    // CONNECT THE CLIENT TO THE GIVEN IP ADDRESS AND PORT

    println!("Connecting to server...");
    let mut stream = TcpStream::connect(format!("{ip_addr}:{ip_port}"))
        .with_context(|| "Failed to connect to the server")?;

    // GENERATE THE RSA KEY PAIR FOR MESSAGE ENCRYPTION

    println!("Generating key pair...");
    let key_pair = webutils::generate_key_pair()?;

    // EXCHANGE KEYS WITH SERVER

    println!("Exchanging keys with the server...");
    let server_public_key = webutils::exchange_keys(&key_pair.public_key, &mut stream)
        .with_context(|| "Failed to exchange keys with server")?;

    // CONFIRM KEYS WERE SUCCESSFULLY SWAPPED

    println!("Synchronizing with the server...");
    webutils::synchronize(&server_public_key, &key_pair.private_key, &mut stream)
        .with_context(|| "Failed to synchronize with server")?;

    println!("CLIENT-SERVER SYNC SUCCEEDED");

    loop {
        webutils::send_sync_message(
            &server_public_key,
            &key_pair.private_key,
            &mut stream,
            b"HEARTBEAT",
        )
            .with_context(|| "Failed to synchronize heartbeat")?;
        println!(
            "HEARTBEAT SYNCHRONIZED [Time since epoch: {:.2?}]",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?
        );

        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}
