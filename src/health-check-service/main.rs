use std::env;

use authentication::auth_client::AuthClient;
use authentication::{SignInRequest, SignOutRequest, SignUpRequest};
use tokio::time::{sleep, Duration};
use uuid::Uuid;

use crate::authentication::StatusCode;

pub mod authentication {
    tonic::include_proto!("authentication");
}

/// The main function of the health check service.
///
/// This function continuously performs sign-up, sign-in, and sign-out operations with the authentication service.
/// It logs the response status of each operation and sleeps for a duration before repeating the process.
///
/// # Returns
///
/// An `Ok(())` result if the service runs successfully, otherwise an error message.
///
/// # Errors
///
/// This function returns an error if there are issues with establishing connections or performing gRPC requests.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // AUTH_SERVICE_HOST_NAME will be set to 'auth' when running the health check service in Docker
    // ::0 is required for Docker to work: https://stackoverflow.com/questions/59179831/docker-app-server-ip-address-127-0-0-1-difference-of-0-0-0-0-ip
    let auth_hostname = env::var("AUTH_SERVICE_HOST_NAME").unwrap_or("[::0]".to_owned());
    // let auth_hostname = env::var("AUTH_SERVICE_HOST_NAME").unwrap_or("127.0.0.1".to_owned());
    println!("Connecting to: {}", auth_hostname);

    // Establish connection with auth service
    let mut client = AuthClient::connect(format!("http://{}:50051", auth_hostname)).await?;

    loop {
        let username = Uuid::new_v4().to_string();
        let password = Uuid::new_v4().to_string();

        // SIGN UP
        // ---------------------------------------------

        let request = tonic::Request::new(SignUpRequest {
            username: username.clone(),
            password: password.clone(),
        });

        let response = client.sign_up(request).await?;

        // Log the response
        println!(
            "SIGN UP RESPONSE STATUS: {:?}",
            StatusCode::from_i32(response.into_inner().status_code)
        );

        // SIGN IN
        // ---------------------------------------------

        let request = tonic::Request::new(SignInRequest {
            username: username.clone(),
            password: password.clone(),
        });

        // Make a sign in request
        let response = client.sign_in(request).await?.into_inner();

        println!(
            "SIGN IN RESPONSE STATUS: {:?}",
            StatusCode::from_i32(response.status_code)
        );

        // SIGN OUT
        // ---------------------------------------------

        let request = tonic::Request::new(SignOutRequest {
            session_token: response.session_token,
        });

        let response = client.sign_out(request).await?;

        println!(
            "SIGN OUT RESPONSE STATUS: {:?}",
            StatusCode::from_i32(response.into_inner().status_code)
        );

        println!("--------------------------------------");

        sleep(Duration::from_secs(3)).await;
    }
}