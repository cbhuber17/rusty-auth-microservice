use std::sync::Mutex;

mod auth;
mod sessions;
mod users;

use auth::*;
use sessions::SessionsImpl;
use users::UsersImpl;

/// The main function of the authentication service.
///
/// # Returns
///
/// An `Ok(())` result if the service starts successfully, otherwise an error message.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting Auth Service...");
    // Using IP 0.0.0.0 here so the service is listening on all the configured network interfaces.
    // This is needed for Docker to work.
    // See: https://stackoverflow.com/questions/39525820/docker-port-forwarding-not-working
    // Port 50051 is the recommended gRPC port.
    let addr = "[::0]:50051".parse()?;
    // let addr = "127.0.0.1:50051".parse()?;

    let users_service = Box::new(Mutex::new(UsersImpl::default()));
    let sessions_service = Box::new(Mutex::new(SessionsImpl::default()));

    let auth_service = AuthService::new(users_service, sessions_service);

    println!("Server started at: {}", addr);

    // Instantiate gRPC server
    Server::builder()
        .add_service(AuthServer::new(auth_service))
        .serve(addr)
        .await?;

    Ok(())
}