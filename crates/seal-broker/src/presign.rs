//! Presigned URLs and shared access signatures: credentials for one object that the
//! caller can copy and pass on, and that work without seal until they expire.
//!
//! This is the one place seal hands a caller something it can use on its own, so it
//! happens only where a value's rule allows it by name, within the lifetime the rule
//! gives, for a URL the rule would allow a request to.

use std::time::{Duration, SystemTime};

use seal_format::policy::{Inject, Method, PRESIGN_METHODS, Scheme};
use zeroize::Zeroizing;

use crate::error::{BrokerError, ErrorCode};
use crate::inject::{Sources, azure, sigv4};
use crate::matcher::Plan;
use crate::target::Target;

fn denied(detail: &'static str) -> BrokerError {
    BrokerError::new(ErrorCode::PolicyDenied, detail)
}

/// The presigned URL for a request the matcher allowed, if its rule allows presigning
/// for this long.
///
/// # Errors
///
/// [`ErrorCode::PolicyDenied`] if the rule does not allow presigning, or not for this
/// long or this method, or more than one value would sign; [`ErrorCode::BadRequest`]
/// for a URL that cannot be presigned.
pub(crate) fn presigned_url(
    plan: &Plan,
    target: &Target,
    method: Method,
    expires_s: u32,
    sources: &Sources<'_>,
    now: SystemTime,
) -> Result<Zeroizing<String>, BrokerError> {
    if expires_s == 0 {
        return Err(BrokerError::new(
            ErrorCode::BadRequest,
            "a presigned URL lasts at least a second",
        ));
    }
    if !PRESIGN_METHODS.contains(&method) {
        return Err(denied("a URL cannot be presigned for this method"));
    }
    // A presigned URL is used with no body or headers of seal's making, so a rule that
    // needs either cannot be honoured.
    if plan.response.is_some() || !plan.form_requirements.is_empty() {
        return Err(denied("a rule here needs seal to send the request"));
    }
    let [injection] = plan.injections.as_slice() else {
        return Err(denied("one value presigns a URL, and no other may be used"));
    };
    let secret = sources.secrets.get(&injection.field).ok_or_else(|| {
        BrokerError::for_field(
            ErrorCode::Internal,
            "a matched secret is missing",
            &injection.field,
        )
    })?;
    let within = |terms: &Option<seal_format::policy::Presign>| match terms {
        None => Err(BrokerError::for_field(
            ErrorCode::PolicyDenied,
            "this value's rule does not allow presigning",
            &injection.field,
        )),
        Some(terms) if expires_s > terms.max_expiry_s => Err(BrokerError::for_field(
            ErrorCode::PolicyDenied,
            "the rule does not allow a URL to last this long",
            &injection.field,
        )),
        Some(_) => Ok(()),
    };
    let method_name = match method {
        Method::Get => "GET",
        Method::Head => "HEAD",
        Method::Put => "PUT",
        _ => "DELETE",
    };
    let query = match &injection.inject {
        Inject::AwsSigv4 {
            region,
            service,
            access_key_id,
            session_token,
            allow_presign,
            ..
        } => {
            within(allow_presign)?;
            let access_key_id = sources.part(access_key_id)?;
            let session_token = session_token
                .as_ref()
                .map(|token| sources.part(token))
                .transpose()?;
            let signer = secret.expose(|secret_key| {
                sigv4::Signer::new(sigv4::SignerParts {
                    secret: secret_key,
                    access_key_id: &access_key_id,
                    session_token,
                    region,
                    service,
                    now,
                    payload: sigv4::Payload::Unsigned,
                })
            })?;
            signer.presign(
                method_name,
                &target.authority(),
                &target.path,
                target.query.as_deref().unwrap_or(""),
                expires_s,
            )?
        }
        Inject::AzureSharedKey {
            account,
            service,
            allow_presign,
        } => {
            within(allow_presign)?;
            if target.query.is_some() {
                return Err(BrokerError::new(
                    ErrorCode::BadRequest,
                    "a shared access signature is for a URL with no query",
                ));
            }
            // What each method needs, in the order the service lists permissions.
            let permissions = match method {
                Method::Get | Method::Head => "r",
                Method::Put => "cw",
                _ => "d",
            };
            let account = sources.part(account)?;
            let signer = secret.expose(|key| azure::Signer::new(key, &account, *service, now))?;
            signer.sas(
                permissions,
                &target.host,
                &target.path,
                now + Duration::from_secs(u64::from(expires_s)),
                target.scheme == Scheme::Https,
            )?
        }
        _ => {
            return Err(BrokerError::for_field(
                ErrorCode::PolicyDenied,
                "this value's rule does not allow presigning",
                &injection.field,
            ));
        }
    };
    let scheme = match target.scheme {
        Scheme::Https => "https",
        Scheme::Http => "http",
    };
    let authority = target.authority();
    let mut url = Zeroizing::new(String::with_capacity(
        scheme.len() + 3 + authority.len() + target.path.len() + 1 + query.len(),
    ));
    url.push_str(scheme);
    url.push_str("://");
    url.push_str(&authority);
    url.push_str(&target.path);
    url.push('?');
    url.push_str(&query);
    Ok(url)
}
