use std::collections::HashMap;

use uuid::Uuid;

/// `Sessions` trait defines methods for managing user sessions.
pub trait Sessions {

    /// Creates a new session for the specified user.
    ///
    /// # Arguments
    ///
    /// * `user_uuid` - A string representing the UUID of the user for whom the session is created.
    ///
    /// # Returns
    ///
    /// A string representing the session token.
    ///
    /// # Example
    ///
    /// ```
    /// // Assuming `sessions_service` implements `Sessions` trait
    /// let session_token = sessions_service.create_session("user_uuid");
    /// println!("Created session with token: {}", session_token);
    /// ```
    fn create_session(&mut self, user_uuid: &str) -> String;

    /// Deletes the session associated with the specified user.
    ///
    /// # Arguments
    ///
    /// * `user_uuid` - A string representing the UUID of the user whose session is to be deleted.
    ///
    /// # Example
    ///
    /// ```
    /// // Assuming `sessions_service` implements `Sessions` trait
    /// sessions_service.delete_session("user_uuid");
    /// println!("Session deleted successfully.");
    /// ```
    fn delete_session(&mut self, user_uuid: &str);
}

/// `SessionsImpl` represents an implementation of the `Sessions` trait.
///
/// This implementation stores session data in memory using a HashMap.
#[derive(Default)]
pub struct SessionsImpl {

    /// A HashMap that maps user UUIDs to session tokens.
    uuid_to_session: HashMap<String, String>,
}

impl Sessions for SessionsImpl {

    /// Creates a new session for the specified user UUID.
    ///
    /// # Arguments
    ///
    /// * `user_uuid` - A string representing the UUID of the user for whom the session is created.
    ///
    /// # Returns
    ///
    /// A string representing the session token.
    ///
    /// # Example
    ///
    /// ```
    /// // Assuming `sessions_impl` is an instance of `SessionsImpl`
    /// let session_token = sessions_impl.create_session("user_uuid");
    /// println!("Created session with token: {}", session_token);
    /// ```
    fn create_session(&mut self, user_uuid: &str) -> String {
        let session: String = Uuid::new_v4().to_string();
        self.uuid_to_session.insert(user_uuid.to_owned(), session.clone());
        session
    }

    /// Deletes the session associated with the specified user UUID.
    ///
    /// # Arguments
    ///
    /// * `user_uuid` - A string representing the UUID of the user whose session is to be deleted.
    ///
    /// # Example
    ///
    /// ```
    /// // Assuming `sessions_impl` is an instance of `SessionsImpl`
    /// sessions_impl.delete_session("user_uuid");
    /// println!("Session deleted successfully.");
    /// ```
    fn delete_session(&mut self, user_uuid: &str) {
        if self.uuid_to_session.contains_key(user_uuid) {
            self.uuid_to_session.remove(user_uuid);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_create_session() {
        let mut session_service = SessionsImpl::default();
        assert_eq!(session_service.uuid_to_session.len(), 0);
        let session = session_service.create_session("123456");
        assert_eq!(session_service.uuid_to_session.len(), 1);
        assert_eq!(session_service.uuid_to_session.get("123456").unwrap(), &session);
    }

    #[test]
    fn should_delete_session() {
        let mut session_service = SessionsImpl::default();
        session_service.create_session("123456");
        session_service.delete_session("123456");
        assert_eq!(session_service.uuid_to_session.len(), 0);
    }
}