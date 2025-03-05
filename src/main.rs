use anyhow::bail;
use rsa::pkcs8::{DecodePublicKey, EncodePublicKey};
use std::io::{Read, Write};
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

    // Create the RNG generator for the key
    let mut rng = rand::thread_rng();

    // Create the key pair
    let Ok(private_key) = rsa::RsaPrivateKey::new(&mut rng, 2048) else {
        bail!("Failed to generate private key")
    };
    let public_key = rsa::RsaPublicKey::from(&private_key);

    // EXCHANGE KEYS WITH SERVER

    // Convert the public key into a string
    let Ok(public_key) = public_key.to_public_key_pem(Default::default()) else {
        bail!("Failed to convert the public key into a string")
    };

    // Write the public key to the stream for the server to read
    let Ok(_) = stream.write_all(public_key.as_bytes()) else {
        bail!("Failed to write public key to client stream")
    };

    // Read the server's public key from the stream
    let mut key_buffer = [0u8; 451];
    let Ok(_) = stream.read_exact(&mut key_buffer) else {
        bail!("Failed to read public key from client stream")
    };

    // Convert server's public key into a PEM formatted string
    let client_key_str = String::from_utf8_lossy(&key_buffer);

    // Convert client's public key's bytes back into a key
    let Ok(client_public_key) = rsa::RsaPublicKey::from_public_key_pem(&client_key_str) else {
        bail!("Failed to create public key from client public key string")
    };

    // CONFIRM KEYS WERE SUCCESSFULLY SWAPPED

    // Encrypt the acknowledgement message
    let ack = *b"ACK";
    let Ok(ack_bytes) = client_public_key.encrypt(&mut rng, rsa::Pkcs1v15Encrypt, &ack) else {
        bail!("Failed to encrypt acknowledgement message")
    };

    // Write the acknowledgement to the stream
    let Ok(_) = stream.write_all(&ack_bytes) else {
        bail!("Failed to write acknowledgement to client stream")
    };

    // Read the acknowledgement from the server
    let mut ack_buf = [0u8; 256];
    let Ok(_) = stream.read_exact(&mut ack_buf) else {
        bail!("Failed to read acknowledgement from client stream")
    };

    // Decrypt the client's acknowledgement
    let Ok(ack_plaintext) = private_key.decrypt(rsa::Pkcs1v15Encrypt, &ack_buf) else {
        bail!("Failed to decrypt client acknowledgement message")
    };

    if &ack_plaintext[0..3] != b"ACK" {
        bail!("ACKNOWLEDGEMENT FAILED")
    }

    println!("ACKNOWLEDGEMENT SUCCEEDED");

    loop {
        std::hint::spin_loop();
    }
}
