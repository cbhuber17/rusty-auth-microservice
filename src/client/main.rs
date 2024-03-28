use std::env;
use clap::{Parser, Subcommand};

use authentication::auth_client::AuthClient;
use authentication::{SignInRequest, SignOutRequest, SignUpRequest};
use tonic::transport::Channel;
use tonic::{Request, Response};

use crate::authentication::{SignUpResponse, SignInResponse, SignOutResponse};

pub mod authentication {
    tonic::include_proto!("authentication");
}

/// CLI struct representing the command-line interface options.
///
/// This struct is used to define command-line arguments and subcommands.
#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Represents the subcommand to be executed.
    #[command(subcommand)]
    command: Option<Commands>,
}

/// Enum representing the available commands for the CLI.
///
/// This enum defines subcommands for signing in, signing up, and signing out.
#[derive(Subcommand)]
enum Commands {
    /// Sign-in subcommand.
    ///
    /// Allows users to sign in by providing their username and password.
    SignIn {
        /// Username of the user.
        #[arg(short, long)]
        username: String,

        /// Password of the user.
        #[arg(short, long)]
        password: String,
    },

    /// Sign-up subcommand.
    ///
    /// Allows users to sign up by providing a new username and password.
    SignUp {
        /// Username of the new user.
        #[arg(short, long)]
        username: String,

        /// Password of the new user.
        #[arg(short, long)]
        password: String,
    },

    /// Sign-out subcommand.
    ///
    /// Allows users to sign out by providing their session token.
    SignOut {
        /// Session token of the user.
        #[arg(short, long)]
        session_token: String,
    },
}

/// The main function of the authentication client.
///
/// This function establishes a connection with the authentication service and executes the specified command.
///
/// # Returns
///
/// An `Ok(())` result if the client runs successfully, otherwise an error message.
///
/// # Errors
///
/// This function returns an error if there are issues with establishing connections or performing gRPC requests.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    
    // AUTH_SERVICE_IP is to ne set to the droplet's IP address once deployed
    let auth_ip = env::var("AUTH_SERVICE_IP").unwrap_or("[::0]".to_owned());
    let mut client = AuthClient::connect(format!("http://{}:50051", auth_ip)).await?;

    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::SignIn { username, password }) => {
            let request = tonic::Request::new(SignInRequest {
                username: username.clone(),
                password: password.clone(),
            });
        
            // Make a sign in request
            let response = client.sign_in(request).await?.into_inner();
        
            println!("{:?}", response);
        }
        Some(Commands::SignUp { username, password }) => {
            let request = tonic::Request::new(SignUpRequest {
                username: username.clone(),
                password: password.clone(),
            });
        
            let response = client.sign_up(request).await?;
        
            println!("{:?}", response.into_inner());
        }
        Some(Commands::SignOut { session_token }) => {
            let request = tonic::Request::new(SignOutRequest {
                session_token: session_token.clone(),
            });
        
            let response = client.sign_out(request).await?;
        
            println!("{:?}", response.into_inner());
        }
        None => {}
    }

    Ok(())
}