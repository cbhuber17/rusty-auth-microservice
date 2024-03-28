use std::sync::Mutex;

use crate::{sessions::Sessions, users::Users};

use tonic::{Request, Response, Status};

use authentication::auth_server::Auth;
use authentication::{
    SignInRequest, SignInResponse, SignOutRequest, SignOutResponse, SignUpRequest, SignUpResponse,
    StatusCode,
};

pub mod authentication {
    tonic::include_proto!("authentication");
}

// Re-exporting
pub use authentication::auth_server::AuthServer;
pub use tonic::transport::Server;

/// `AuthService` struct represents the authentication service.
pub struct AuthService {

    /// `users_service` represents the service for managing users.
    users_service: Box<Mutex<dyn Users + Send + Sync>>,

    /// `sessions_service` represents the service for managing sessions.
    sessions_service: Box<Mutex<dyn Sessions + Send + Sync>>,
}

impl AuthService {

    /// Constructs a new `AuthService` instance.
    ///
    /// # Arguments
    ///
    /// * `users_service` - A boxed trait object representing the service for managing users.
    /// * `sessions_service` - A boxed trait object representing the service for managing sessions.
    ///
    /// # Returns
    ///
    /// A new instance of `AuthService`.
    ///
    /// # Example
    ///
    /// ```
    /// use your_crate_name::{AuthService, Users, Sessions};
    /// use std::sync::Mutex;
    ///
    /// // Assuming you have implementations for Users and Sessions traits
    /// let users_service = Box::new(Mutex::new(/* your implementation */));
    /// let sessions_service = Box::new(Mutex::new(/* your implementation */));
    /// let auth_service = AuthService::new(users_service, sessions_service);
    /// ```
    pub fn new(
        users_service: Box<Mutex<dyn Users + Send + Sync>>,
        sessions_service: Box<Mutex<dyn Sessions + Send + Sync>>,
    ) -> Self {
        Self {
            users_service,
            sessions_service,
        }
    }
}

#[tonic::async_trait]
impl Auth for AuthService {

    /// Handles user sign-in requests.
    ///
    /// # Arguments
    ///
    /// * `request` - A gRPC request containing sign-in credentials.
    ///
    /// # Returns
    ///
    /// A gRPC response containing the sign-in status and session information.
    ///
    /// # Errors
    ///
    /// This method returns an error if there are issues with authentication or session creation.
    ///
    /// # Example
    ///
    /// ```
    /// // Assuming `auth_service` is an instance of AuthService
    /// let request = SignInRequest {
    ///     username: "example_user".to_string(),
    ///     password: "example_password".to_string(),
    /// };
    /// let response = auth_service.sign_in(Request::new(request)).await;
    /// assert!(response.is_ok());
    /// ```
    async fn sign_in(
        &self,
        request: Request<SignInRequest>,
    ) -> Result<Response<SignInResponse>, Status> {
        println!("Got a request: {:?}", request);

        let req = request.into_inner();

        let result = self.users_service.lock()
                                                       .expect("lock should not be tampered")
                                                       .get_user_uuid(req.username, req.password);

        let user_uuid = match result {
            Some(uuid) => uuid,
            None => {
                let reply = SignInResponse {
                    status_code: StatusCode::Failure.into(),
                    user_uuid: "".to_owned(),
                    session_token: "".to_owned(),
                };

                return Ok(Response::new(reply));
            }
        };

        let session_token = self.sessions_service.lock()
                                                         .expect("lock should not be tampered")
                                                         .create_session(&user_uuid);

        let reply = SignInResponse {
            status_code: StatusCode::Success.into(),
            user_uuid,
            session_token
        };

        Ok(Response::new(reply))
    }

    /// Handles user sign-up requests.
    ///
    /// # Arguments
    ///
    /// * `request` - A gRPC request containing sign-up credentials.
    ///
    /// # Returns
    ///
    /// A gRPC response containing the sign-up status.
    ///
    /// # Errors
    ///
    /// This method returns an error if there are issues with user creation.
    ///
    /// # Example
    ///
    /// ```
    /// // Assuming `auth_service` is an instance of AuthService
    /// let request = SignUpRequest {
    ///     username: "new_user".to_string(),
    ///     password: "new_password".to_string(),
    /// };
    /// let response = auth_service.sign_up(Request::new(request)).await;
    /// assert!(response.is_ok());
    /// ```
    async fn sign_up(&self, request: Request<SignUpRequest>) -> Result<Response<SignUpResponse>, Status> {
        println!("Got a request: {:?}", request);

        let req = request.into_inner();

        let result = self.users_service.lock()
                                                           .expect("lock should not be tampered")
                                                           .create_user(req.username, req.password);

        match result {
            Ok(_) => {
                let reply = SignUpResponse {
                    status_code: StatusCode::Success.into(),
                };

                Ok(Response::new(reply))
            }
            Err(_) => {
                let reply = SignUpResponse {
                    status_code: StatusCode::Failure.into(),
                };

                Ok(Response::new(reply))
            }
        }
    }

    /// Handles user sign-out requests.
    ///
    /// # Arguments
    ///
    /// * `request` - A gRPC request containing the session token to be invalidated.
    ///
    /// # Returns
    ///
    /// A gRPC response containing the sign-out status.
    ///
    /// # Errors
    ///
    /// This method returns an error if there are issues with session deletion.
    ///
    /// # Example
    ///
    /// ```
    /// // Assuming `auth_service` is an instance of AuthService
    /// let request = SignOutRequest {
    ///     session_token: "example_session_token".to_string(),
    /// };
    /// let response = auth_service.sign_out(Request::new(request)).await;
    /// assert!(response.is_ok());
    /// ```
    async fn sign_out(&self, request: Request<SignOutRequest>) -> Result<Response<SignOutResponse>, Status> {
        println!("Got a request: {:?}", request);

        let req = request.into_inner();

        self.sessions_service.lock().expect("lock should not be tampered").delete_session(&req.session_token);

        let reply = SignOutResponse {
            status_code: StatusCode::Success.into(),
        };

        Ok(Response::new(reply))
    }
}

#[cfg(test)]
mod tests {
    use crate::{users::UsersImpl, sessions::SessionsImpl};

    use super::*;

    #[tokio::test]
    async fn sign_in_should_fail_if_user_not_found() {
        let users_service = Box::new(Mutex::new(UsersImpl::default()));
        let sessions_service = Box::new(Mutex::new(SessionsImpl::default()));

        let auth_service = AuthService::new(users_service, sessions_service);

        let request = tonic::Request::new(SignInRequest {
            username: "123456".to_owned(),
            password: "654321".to_owned(),
        });

        let result = auth_service.sign_in(request).await.unwrap().into_inner();

        assert_eq!(result.status_code, StatusCode::Failure.into());
        assert_eq!(result.user_uuid.is_empty(), true);
        assert_eq!(result.session_token.is_empty(), true);
    }

    #[tokio::test]
    async fn sign_in_should_fail_if_incorrect_password() {
        let mut users_service = UsersImpl::default();

        let _ = users_service.create_user("123456".to_owned(), "654321".to_owned());

        let users_service = Box::new(Mutex::new(users_service));
        let sessions_service = Box::new(Mutex::new(SessionsImpl::default()));

        let auth_service = AuthService::new(users_service, sessions_service);

        let request = tonic::Request::new(SignInRequest {
            username: "123456".to_owned(),
            password: "wrong password".to_owned(),
        });

        let result = auth_service.sign_in(request).await.unwrap().into_inner();

        assert_eq!(result.status_code, StatusCode::Failure.into());
        assert_eq!(result.user_uuid.is_empty(), true);
        assert_eq!(result.session_token.is_empty(), true);
    }

    #[tokio::test]
    async fn sign_in_should_succeed() {
        let mut users_service = UsersImpl::default();

        let _ = users_service.create_user("123456".to_owned(), "654321".to_owned());

        let users_service = Box::new(Mutex::new(users_service));
        let sessions_service = Box::new(Mutex::new(SessionsImpl::default()));

        let auth_service = AuthService::new(users_service, sessions_service);

        let request = tonic::Request::new(SignInRequest {
            username: "123456".to_owned(),
            password: "654321".to_owned(),
        });

        let result = auth_service.sign_in(request).await.unwrap().into_inner();

        assert_eq!(result.status_code, StatusCode::Success.into());
        assert_eq!(result.user_uuid.is_empty(), false);
        assert_eq!(result.session_token.is_empty(), false);
    }

    #[tokio::test]
    async fn sign_up_should_fail_if_username_exists() {
        let mut users_service = UsersImpl::default();

        let _ = users_service.create_user("123456".to_owned(), "654321".to_owned());

        let users_service = Box::new(Mutex::new(users_service));
        let sessions_service = Box::new(Mutex::new(SessionsImpl::default()));

        let auth_service = AuthService::new(users_service, sessions_service);

        let request = tonic::Request::new(SignUpRequest {
            username: "123456".to_owned(),
            password: "654321".to_owned(),
        });

        let result = auth_service.sign_up(request).await.unwrap();

        assert_eq!(result.into_inner().status_code, StatusCode::Failure.into());
    }

    #[tokio::test]
    async fn sign_up_should_succeed() {
        let users_service = Box::new(Mutex::new(UsersImpl::default()));
        let sessions_service = Box::new(Mutex::new(SessionsImpl::default()));

        let auth_service = AuthService::new(users_service, sessions_service);

        let request = tonic::Request::new(SignUpRequest {
            username: "123456".to_owned(),
            password: "654321".to_owned(),
        });

        let result = auth_service.sign_up(request).await.unwrap();

        assert_eq!(result.into_inner().status_code, StatusCode::Success.into());
    }

    #[tokio::test]
    async fn sign_out_should_succeed() {
        let users_service = Box::new(Mutex::new(UsersImpl::default()));
        let sessions_service = Box::new(Mutex::new(SessionsImpl::default()));

        let auth_service = AuthService::new(users_service, sessions_service);

        let request = tonic::Request::new(SignOutRequest {
            session_token: "".to_owned()
        });

        let result = auth_service.sign_out(request).await.unwrap();

        assert_eq!(result.into_inner().status_code, StatusCode::Success.into());
    }
}