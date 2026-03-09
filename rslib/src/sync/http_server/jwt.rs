// Copyright: Ankitects Pty Ltd and contributors
// License: GNU AGPL, version 3 or later; http://www.gnu.org/licenses/agpl.html

use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use snafu::ResultExt;
use snafu::Whatever;

use crate::error;

#[derive(serde::Deserialize)]
struct JwtClaims {
    sub: String,
    exp: usize,
}

pub(super) fn verify_jwt(token: &str, secret: &str) -> error::Result<String, Whatever> {
    let key = DecodingKey::from_secret(secret.as_bytes());
    let mut validation = Validation::new(Algorithm::HS256);
    validation.leeway = 0;
    decode::<JwtClaims>(token, &key, &validation)
        .map(|data| data.claims.sub)
        .whatever_context("invalid or expired JWT")
}

pub(super) fn make_jwt(user_id: &str, secret: &str) -> error::Result<String, Whatever> {
    use jsonwebtoken::{encode, EncodingKey, Header, Algorithm};
    #[derive(serde::Serialize)]
    struct Claims {
        sub: String,
        exp: usize,
    }
    let exp = (chrono::Utc::now().timestamp() + 86400) as usize;
    let claims = Claims { sub: user_id.into(), exp };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .whatever_context("encoding JWT")
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header, Algorithm};

    #[derive(serde::Serialize)]
    struct TestClaims {
        sub: String,
        exp: usize,
    }

    fn make_token(sub: &str, exp_offset_secs: i64, secret: &str) -> String {
        let exp = (chrono::Utc::now().timestamp() + exp_offset_secs) as usize;
        let claims = TestClaims { sub: sub.into(), exp };
        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap()
    }

    #[test]
    fn valid_token_returns_sub() {
        let token = make_token("user123", 3600, "testsecret");
        assert_eq!(verify_jwt(&token, "testsecret").unwrap(), "user123");
    }

    #[test]
    fn wrong_secret_returns_none() {
        let token = make_token("user123", 3600, "testsecret");
        assert!(verify_jwt(&token, "wrongsecret").is_err());
    }

    #[test]
    fn expired_token_returns_none() {
        let token = make_token("user123", -10, "testsecret");
        assert!(verify_jwt(&token, "testsecret").is_err());
    }

    #[test]
    fn garbage_token_returns_none() {
        assert!(verify_jwt("not.a.token", "testsecret").is_err());
    }

    #[test]
    fn make_jwt_produces_valid_token() {
        let token = make_jwt("user456", "testsecret").unwrap();
        assert_eq!(verify_jwt(&token, "testsecret").unwrap(), "user456");
    }
}
