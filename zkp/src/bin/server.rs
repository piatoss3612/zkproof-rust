use std::{collections::HashMap, sync::Mutex};

use num_bigint::BigUint;
use tonic::{transport::Server, Response};
use zkp::zkp_auth::{auth_server::{Auth, AuthServer}, RegisterRequest, RegisterResponse, AuthenticationChallendgeRequest, AuthenticationChallendgeResponse, AuthenticationAnswerRequest, AuthenticationAnswerResponse};

extern crate zkp;

#[derive(Debug, Default)]
pub struct AuthImpl {
    pub user_info: Mutex<HashMap<String, UserInfo>>,
}

#[derive(Debug, Default)]
pub struct UserInfo {
    // registration
    pub username: String,
    pub y1: BigUint,
    pub y2: BigUint,

    // authorization
    pub r1: BigUint,
    pub r2: BigUint,

    // verification
    pub c: BigUint,
    pub s: BigUint,
    pub session_id: String,
}

#[tonic::async_trait]
impl Auth for AuthImpl {
    async fn register(
        &self,
        request: tonic::Request<RegisterRequest>,
    ) -> std::result::Result<
        tonic::Response<RegisterResponse>,
        tonic::Status,
    > {
        let request = request.into_inner();

        let username = request.user;
        let y1 = BigUint::from_bytes_be(request.y1.as_slice());
        let y2 = BigUint::from_bytes_be(request.y2.as_slice());

        let mut user_info = UserInfo::default();
        user_info.username = username.clone();
        user_info.y1 = y1;
        user_info.y2 = y2;

        let mut user_info_map = self.user_info.lock().unwrap();
        user_info_map.insert(username, user_info);

        println!("Successfully registered user");

        Ok(Response::new(RegisterResponse::default()))
    }
    async fn create_authentication_challenge(
        &self,
        request: tonic::Request<AuthenticationChallendgeRequest>,
    ) -> std::result::Result<
        tonic::Response<AuthenticationChallendgeResponse>,
        tonic::Status,
    > {todo!()}
    async fn verify_authentication(
        &self,
        request: tonic::Request<AuthenticationAnswerRequest>,
    ) -> std::result::Result<
        tonic::Response<AuthenticationAnswerResponse>,
        tonic::Status,
    > {todo!()}
}


#[tokio::main]
async fn main() {
    let addr = "127.0.0.1:50051".to_string();

    println!("Running server on {}", addr);

    let auth_server = AuthServer::new(AuthImpl::default());

    Server::builder()
        .add_service(auth_server)
        .serve(addr.parse().expect("could not parse address"))
        .await
        .unwrap()
}