//! An access key id and a secret access key in a file, in the AWS shared credentials
//! format. AWS KMS and an S3 key source both read theirs this way.

use std::path::Path;

use zeroize::Zeroizing;

use crate::KeyError;
use crate::wrap::check_private;

/// Credentials from a file.
pub(crate) struct Credentials {
    pub access_key_id: String,
    pub secret_access_key: Zeroizing<String>,
    pub session_token: Option<Zeroizing<String>>,
}

/// Reads one profile of a shared credentials file: `[name]`, then `key = value` lines.
pub(crate) fn parse_credentials(text: &str, profile: &str) -> Option<Credentials> {
    let (mut inside, mut id, mut secret, mut token) = (false, None, None, None);
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(section) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            inside = section.trim() == profile;
            continue;
        }
        if !inside {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        match name.trim() {
            "aws_access_key_id" => id = Some(value.to_owned()),
            "aws_secret_access_key" => secret = Some(Zeroizing::new(value.to_owned())),
            "aws_session_token" => token = Some(Zeroizing::new(value.to_owned())),
            _ => {}
        }
    }
    let visible = |value: &str| !value.is_empty() && value.bytes().all(|b| b.is_ascii_graphic());
    let (access_key_id, secret_access_key) = (id?, secret?);
    let valid = visible(&access_key_id)
        && visible(&secret_access_key)
        && token.as_ref().is_none_or(|token| visible(token));
    valid.then_some(Credentials {
        access_key_id,
        secret_access_key,
        session_token: token,
    })
}

/// Reads one profile of a credentials file that only its owner can read.
pub(crate) fn read_credentials(path: &Path, profile: &str) -> Result<Credentials, KeyError> {
    if !path.exists() {
        return Err(KeyError::Invalid("the credentials file does not exist"));
    }
    check_private(path)?;
    let text = Zeroizing::new(
        std::fs::read_to_string(path)
            .map_err(|_| KeyError::Invalid("the credentials file cannot be read"))?,
    );
    parse_credentials(&text, profile).ok_or(KeyError::Invalid(
        "the credentials file has no such profile with a key id and a secret key",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_profile_is_read_from_a_shared_credentials_file() {
        let text = "# a comment\n[other]\naws_access_key_id = AKIAOTHER\naws_secret_access_key = no\n\n\
                    [default]\naws_access_key_id=AKIAEXAMPLE\n  aws_secret_access_key =  secret/with+signs==  \n\
                    region = eu-central-1\n; another comment\n[ temporary ]\naws_access_key_id = ASIAEXAMPLE\n\
                    aws_secret_access_key = temporary\naws_session_token = a-token\n";
        let default = parse_credentials(text, "default").unwrap();
        assert_eq!(default.access_key_id, "AKIAEXAMPLE");
        assert_eq!(default.secret_access_key.as_str(), "secret/with+signs==");
        assert!(default.session_token.is_none());
        let temporary = parse_credentials(text, "temporary").unwrap();
        assert_eq!(temporary.access_key_id, "ASIAEXAMPLE");
        assert_eq!(temporary.session_token.unwrap().as_str(), "a-token");

        assert!(parse_credentials(text, "missing").is_none());
        assert!(parse_credentials("[default]\naws_access_key_id = A\n", "default").is_none());
        assert!(
            parse_credentials(
                "aws_access_key_id = A\naws_secret_access_key = b\n",
                "default"
            )
            .is_none()
        );
        for bad in ["a b", "", "tab\there"] {
            let text = format!("[default]\naws_access_key_id = A\naws_secret_access_key = {bad}\n");
            assert!(parse_credentials(&text, "default").is_none(), "{bad:?}");
        }
    }
}
