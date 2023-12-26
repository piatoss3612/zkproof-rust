use std::{collections::HashMap, sync::Mutex};

use num_bigint::BigUint;
use tonic::{transport::Server, Response, Status, Code};
use zkp::zkp_auth::{auth_server::{Auth, AuthServer}, RegisterRequest, RegisterResponse, AuthenticationChallendgeRequest, AuthenticationChallendgeResponse, AuthenticationAnswerRequest, AuthenticationAnswerResponse};
use zkp::ZKP;

extern crate zkp;

#[derive(Debug, Default)]
pub struct AuthImpl {
    pub user_info: Mutex<HashMap<String, UserInfo>>,
    pub auth_id_to_user: Mutex<HashMap<String, String>>,
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
    > {
        let request = request.into_inner();

        let username = request.user;
        let r1 = BigUint::from_bytes_be(request.r1.as_slice());
        let r2 = BigUint::from_bytes_be(request.r2.as_slice());

        let mut user_info_map = self.user_info.lock().unwrap();
        if let Some(user_info) = user_info_map.get_mut(&username) {
            let (_, _, _, q) = ZKP::get_constants();
            let c = ZKP::generate_random_number(&q);
            let auth_id = ZKP::generate_random_string(12);

            user_info.r1 = r1;
            user_info.r2 = r2;
            user_info.c = c.clone();
            user_info.session_id = auth_id.clone();

            let mut auth_id_to_user_map = self.auth_id_to_user.lock().unwrap();

            auth_id_to_user_map.insert(auth_id.clone(), username.clone());

            println!("Successfully created authentication challenge");

            Ok(Response::new(AuthenticationChallendgeResponse{
                c: c.to_bytes_be(),
                auth_id,
            }))
        } else {
            return Err(Status::new(Code::NotFound, format!("User {} not found", username)));
        }
    }

    async fn verify_authentication(
        &self,
        request: tonic::Request<AuthenticationAnswerRequest>,
    ) -> std::result::Result<
        tonic::Response<AuthenticationAnswerResponse>,
        tonic::Status,
    > {
        let request = request.into_inner();

        let auth_id = request.auth_id;
        let s = BigUint::from_bytes_be(request.s.as_slice());
        
        let  auth_id_to_user_map = self.auth_id_to_user.lock().unwrap();

        if let Some(username) = auth_id_to_user_map.get(&auth_id) {
            let mut user_info_map = self.user_info.lock().unwrap();

            if let Some(user_info) = user_info_map.get_mut(username) {
                let (alpha, beta, p, q) = ZKP::get_constants();
                let zkp = ZKP {
                    alpha,
                    beta,
                    p,
                    q,
                };

                let verified = zkp.verify(
                 &user_info.r1, &user_info.r2, 
                 &user_info.y1, &user_info.y2, 
                 &user_info.c, &s);

                if !verified {
                    return Err(Status::new(Code::InvalidArgument, format!("Invalid proof")));
                }

                Ok(Response::new(AuthenticationAnswerResponse{
                    session_id: user_info.session_id.clone(),
                }))
            } else {
                return Err(Status::new(Code::NotFound, format!("User {} not found", username)));
            }
        } else {
            return Err(Status::new(Code::NotFound, format!("Auth id {} not found", auth_id)));
        }
    }
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