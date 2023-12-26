use tonic::transport::Server;
use zkp::zkp_auth::{auth_server::{Auth, AuthServer}, RegisterRequest, RegisterResponse, AuthenticationChallendgeRequest, AuthenticationChallendgeResponse, AuthenticationAnswerRequest, AuthenticationAnswerResponse};

extern crate zkp;

#[derive(Debug, Default)]
struct AuthImpl;

#[tonic::async_trait]
impl Auth for AuthImpl {
    async fn register(
        &self,
        request: tonic::Request<RegisterRequest>,
    ) -> std::result::Result<
        tonic::Response<RegisterResponse>,
        tonic::Status,
    > {
        todo!()
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