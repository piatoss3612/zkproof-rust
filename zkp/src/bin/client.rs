use std::io::stdin;

use num_bigint::BigUint;
use zkp::{zkp_auth::RegisterRequest, ZKP};

use crate::zkp::zkp_auth::auth_client::AuthClient;

extern crate zkp;

#[tokio::main]
async fn main() {
    let (alpha, beta, p, q) = zkp::ZKP::get_constants();
    let zkp = zkp::ZKP { alpha, beta, p, q };

    let mut buf = String::new();
    let mut client = AuthClient::connect("http://127.0.0.1:50051").await.unwrap();

    println!("Connected to server!");

    println!("Enter your username: ");
    stdin().read_line(&mut buf).expect("Failed to read line");
    let username = buf.trim().to_string();
    buf.clear();

    println!("Enter your password: ");
    stdin().read_line(&mut buf).expect("Failed to read line");
    let password = BigUint::from_bytes_be(buf.trim().as_bytes());

    let y1 = ZKP::exponentiate(&zkp.alpha, &password, &zkp.p);
    let y2 = ZKP::exponentiate(&zkp.beta, &password, &zkp.p);

    let request = RegisterRequest {
        user: username,
        y1: y1.to_bytes_be(),
        y2: y2.to_bytes_be(),
    };

    let response = client.register(request).await.unwrap();
    println!("Response: {:?}", response);
}
