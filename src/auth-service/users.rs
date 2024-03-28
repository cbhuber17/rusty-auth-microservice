use pbkdf2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Pbkdf2,
};
use rand_core::OsRng;
use uuid::Uuid;

use std::collections::HashMap;

/// `Users` trait defines methods for managing user data.
pub trait Users {

    /// Creates a new user with the provided username and password.
    ///
    /// # Arguments
    ///
    /// * `username` - A string representing the username of the user to be created.
    /// * `password` - A string representing the password of the user to be created.
    ///
    /// # Returns
    ///
    /// An `Ok(())` result if the user is created successfully, otherwise an error message.
    ///
    /// # Example
    ///
    /// ```
    /// // Assuming `users_service` implements `Users` trait
    /// let result = users_service.create_user("username".to_string(), "password".to_string());
    /// match result {
    ///     Ok(_) => println!("User created successfully."),
    ///     Err(error) => eprintln!("Failed to create user: {}", error),
    /// }
    /// ```
    fn create_user(&mut self, username: String, password: String) -> Result<(), String>;

    /// Retrieves the UUID of the user with the provided username and password.
    ///
    /// # Arguments
    ///
    /// * `username` - A string representing the username of the user to retrieve.
    /// * `password` - A string representing the password of the user to retrieve.
    ///
    /// # Returns
    ///
    /// An `Option<String>` containing the UUID of the user if found, otherwise `None`.
    ///
    /// # Example
    ///
    /// ```
    /// // Assuming `users_service` implements `Users` trait
    /// let user_uuid = users_service.get_user_uuid("username".to_string(), "password".to_string());
    /// match user_uuid {
    ///     Some(uuid) => println!("User UUID: {}", uuid),
    ///     None => println!("User not found."),
    /// }
    /// ```
    fn get_user_uuid(&self, username: String, password: String) -> Option<String>;

    /// Deletes the user with the specified UUID.
    ///
    /// # Arguments
    ///
    /// * `user_uuid` - A string representing the UUID of the user to be deleted.
    ///
    /// # Example
    ///
    /// ```
    /// // Assuming `users_service` implements `Users` trait
    /// users_service.delete_user("user_uuid".to_string());
    /// println!("User deleted successfully.");
    /// ```
    fn delete_user(&mut self, user_uuid: String);
}

/// `User` struct represents user data.
#[derive(Clone)]
pub struct User {
    /// A string representing the UUID of the user.
    pub user_uuid: String,

    /// A string representing the username of the user.
    pub username: String,

    /// A string representing the password of the user.
    pub password: String,
}

/// `UsersImpl` represents an implementation of the `Users` trait.
///
/// This implementation stores user data in memory using two HashMaps: one mapping UUIDs to users
/// and the other mapping usernames to users.
#[derive(Default)]
pub struct UsersImpl {
    /// A HashMap that maps user UUIDs to user data.
    pub uuid_to_user: HashMap<String, User>,

    /// A HashMap that maps usernames to user data.
    pub username_to_user: HashMap<String, User>,
}

impl Users for UsersImpl {

    /// Creates a new user with the provided username and password.
    ///
    /// # Arguments
    ///
    /// * `username` - A string representing the username of the user to be created.
    /// * `password` - A string representing the password of the user to be created.
    ///
    /// # Returns
    ///
    /// An `Ok(())` result if the user is created successfully, otherwise an error message.
    ///
    /// # Example
    ///
    /// ```
    /// // Assuming `users_impl` is an instance of `UsersImpl`
    /// let result = users_impl.create_user("username".to_string(), "password".to_string());
    /// match result {
    ///     Ok(_) => println!("User created successfully."),
    ///     Err(error) => eprintln!("Failed to create user: {}", error),
    /// }
    /// ```
    fn create_user(&mut self, username: String, password: String) -> Result<(), String> {

        // Check if username already exists. If so return an error.
        if self.username_to_user.contains_key(&username) {
            return Err("Unable to create user. Username already exists.".to_owned());
        }

        let salt = SaltString::generate(&mut OsRng);

        let hashed_password = Pbkdf2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| format!("Failed to hash password.\n{e:?}"))?
            .to_string();

        let user: User = User {
            user_uuid: Uuid::new_v4().to_string(),
            username: username.clone(),
            password: hashed_password,
        };

        self.username_to_user.insert(username, user.clone());
        self.uuid_to_user.insert(user.user_uuid.clone(), user);

        Ok(())
    }

    /// Retrieves the UUID of the user with the provided username and password.
    ///
    /// # Arguments
    ///
    /// * `username` - A string representing the username of the user to retrieve.
    /// * `password` - A string representing the password of the user to retrieve.
    ///
    /// # Returns
    ///
    /// An `Option<String>` containing the UUID of the user if found, otherwise `None`.
    ///
    /// # Example
    ///
    /// ```
    /// // Assuming `users_impl` is an instance of `UsersImpl`
    /// let user_uuid = users_impl.get_user_uuid("username".to_string(), "password".to_string());
    /// match user_uuid {
    ///     Some(uuid) => println!("User UUID: {}", uuid),
    ///     None => println!("User not found."),
    /// }
    /// ```
    fn get_user_uuid(&self, username: String, password: String) -> Option<String> {
        let user = self.username_to_user.get(&username)?;

        // Get user's password as `PasswordHash` instance. 
        let hashed_password = user.password.clone();
        let parsed_hash = PasswordHash::new(&hashed_password).ok()?;

        // Verify passed in password matches user's password.
        let result = Pbkdf2.verify_password(password.as_bytes(), &parsed_hash);

        if user.username == username && result.is_ok() {
            return Some(user.user_uuid.clone());
        }

        None
    }

    /// Deletes the user with the specified UUID.
    ///
    /// # Arguments
    ///
    /// * `user_uuid` - A string representing the UUID of the user to be deleted.
    ///
    /// # Example
    ///
    /// ```
    /// // Assuming `users_impl` is an instance of `UsersImpl`
    /// users_impl.delete_user("user_uuid".to_string());
    /// println!("User deleted successfully.");
    /// ```
    fn delete_user(&mut self, user_uuid: String) {
        if let Some(user) = self.uuid_to_user.get(&user_uuid) {
            let user_uuid = user.user_uuid.clone();
            self.username_to_user.remove(&user.username);
            self.uuid_to_user.remove(&user_uuid);
        }
    }
    
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_create_user() {
        let mut user_service = UsersImpl::default();
        user_service
            .create_user("username".to_owned(), "password".to_owned())
            .expect("should create user");

        assert_eq!(user_service.uuid_to_user.len(), 1);
        assert_eq!(user_service.username_to_user.len(), 1);
    }

    #[test]
    fn should_fail_creating_user_with_existing_username() {
        let mut user_service = UsersImpl::default();
        user_service
            .create_user("username".to_owned(), "password".to_owned())
            .expect("should create user");

        let result = user_service.create_user("username".to_owned(), "password".to_owned());

        assert!(result.is_err());
    }

    #[test]
    fn should_retrieve_user_uuid() {
        let mut user_service = UsersImpl::default();
        user_service
            .create_user("username".to_owned(), "password".to_owned())
            .expect("should create user");

        assert!(user_service
            .get_user_uuid("username".to_owned(), "password".to_owned())
            .is_some());
    }

    #[test]
    fn should_fail_to_retrieve_user_uuid_with_incorrect_password() {
        let mut user_service = UsersImpl::default();
        user_service
            .create_user("username".to_owned(), "password".to_owned())
            .expect("should create user");

        assert!(user_service
            .get_user_uuid("username".to_owned(), "incorrect password".to_owned())
            .is_none());
    }

    #[test]
    fn should_delete_user() {
        let mut user_service = UsersImpl::default();
        user_service
            .create_user("username".to_owned(), "password".to_owned())
            .expect("should create user");

        let user_uuid = user_service
            .get_user_uuid("username".to_owned(), "password".to_owned())
            .unwrap();

        user_service.delete_user(user_uuid);

        assert_eq!(user_service.uuid_to_user.len(), 0);
        assert_eq!(user_service.username_to_user.len(), 0);
    }
}