use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use rand_core::OsRng;

/// Hashes the provided password using Argon2id with a randomly generated salt.
pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(password_hash.to_string())
}

/// Verifies that the plaintext password matches the previously hashed password.
pub fn verify_password(
    password: &str,
    password_hash: &str,
) -> Result<bool, argon2::password_hash::Error> {
    let parsed_hash = PasswordHash::new(password_hash)?;
    let argon2 = Argon2::default();
    Ok(argon2
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::{hash_password, verify_password};

    #[test]
    fn successful_login_with_valid_credentials() {
        let password = "CorrectHorseBatteryStaple";
        let hash = hash_password(password).expect("hashing should succeed");

        let is_valid = verify_password(password, &hash).expect("verification should succeed");

        assert!(is_valid, "expected the password to verify successfully");
    }

    #[test]
    fn login_rejected_with_invalid_password() {
        let password = "CorrectHorseBatteryStaple";
        let hash = hash_password(password).expect("hashing should succeed");

        let is_valid = verify_password("Tr0ub4dor&3", &hash).expect("verification should succeed");

        assert!(
            !is_valid,
            "expected verification to fail for invalid password"
        );
    }
}
