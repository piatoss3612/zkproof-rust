use std::io::stdin;

use num_bigint::BigUint;
use zkp::{
    zkp_auth::{AuthenticationAnswerRequest, AuthenticationChallendgeRequest, RegisterRequest},
    ZKP,
};

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
        user: username.clone(),
        y1: y1.to_bytes_be(),
        y2: y2.to_bytes_be(),
    };

    let response = client.register(request).await.unwrap().into_inner();
    println!("Register Response: {:?}", response);

    let k = ZKP::generate_random_number(&zkp.q);
    let r1 = ZKP::exponentiate(&zkp.alpha, &k, &zkp.p);
    let r2 = ZKP::exponentiate(&zkp.beta, &k, &zkp.p);

    let request = AuthenticationChallendgeRequest {
        user: username.clone(),
        r1: r1.to_bytes_be(),
        r2: r2.to_bytes_be(),
    };

    let response = client
        .create_authentication_challenge(request)
        .await
        .unwrap()
        .into_inner();
    println!("Authentication Challenge Response: {:?}", response);

    let auth_id = response.auth_id;
    let c = BigUint::from_bytes_be(&response.c);

    let s = zkp.solve(&k, &c, &password);

    let request = AuthenticationAnswerRequest {
        auth_id,
        s: s.to_bytes_be(),
    };

    let response = client
        .verify_authentication(request)
        .await
        .unwrap()
        .into_inner();

    println!("Authentication Verification Response: {:?}", response);
}
