//! Admitting an intake envelope: secrets sealed where they were entered become the
//! values an application stores, under the policies the envelope names and no others.
//!
//! This is the one place a secret gets its policy inside seal, so what it holds to is
//! narrow. Only an intake envelope goes in, so a stored value can never be given a new
//! policy. Only a policy whose digest the envelope names comes out, so whoever calls
//! cannot choose where a secret goes after it was sealed. The values stay on the
//! envelope's keyset and item.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::UNIX_EPOCH;

use seal_format::policy::MAX_INTAKE_OUTPUTS;
use seal_format::{
    Binding, Envelope, FieldName, FormatError, ItemId, KeysetId, Policy, intake_field,
    seal as seal_value,
};
use seal_keys::KeyError;

use super::{Broker, key_error};
use crate::audit::{AuditGuard, Outcome};
use crate::body::Progress;
use crate::error::{BrokerError, ErrorCode};

/// One field to seal from an intake envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmitOutput {
    /// The policy to seal it under, which must be the one the envelope names for it.
    pub policy: Policy,
    /// Whether the field may be absent. An absent optional field has no value in the
    /// answer; an absent one that is not optional refuses the whole call.
    pub optional: bool,
}

/// An intake envelope to admit. It holds no credentials.
pub struct AdmitRequest {
    /// Who is asking, for the audit record.
    pub caller: String,
    /// The keyset the envelope is sealed to, which the values stay in.
    pub keyset: KeysetId,
    /// The record the envelope is bound to, which the values are bound to.
    pub item: ItemId,
    /// The intake envelope.
    pub envelope: Envelope,
    /// The fields to seal, by name.
    pub outputs: BTreeMap<FieldName, AdmitOutput>,
}

impl Broker {
    /// Seals the fields of an intake envelope, each under its policy, to the keyset's
    /// current key. Every call leaves one audit record, with the digest of each policy.
    ///
    /// Either every field asked for is sealed, or nothing is returned.
    ///
    /// # Errors
    ///
    /// Returns a [`BrokerError`] with the reason, which never includes a value.
    /// [`ErrorCode::IntakeStale`] means a new offer is needed: the envelope is past its
    /// time, or a policy is no longer the one it names.
    pub async fn admit(
        &self,
        request: AdmitRequest,
    ) -> Result<BTreeMap<FieldName, Envelope>, BrokerError> {
        let mut record = self.first_record(
            "admit",
            &request.caller,
            &request.keyset,
            &request.item,
            &BTreeMap::new(),
        );
        record.fields = request.outputs.keys().map(ToString::to_string).collect();
        let mut audit = AuditGuard::new(Arc::clone(&self.audit), record, Arc::new(Progress::new()));
        match self.admit_audited(&request, &mut audit).await {
            Ok(sealed) => {
                audit.finish(Outcome::Ok, None).map_err(|_| {
                    BrokerError::new(ErrorCode::Internal, "could not write the audit record")
                })?;
                Ok(sealed)
            }
            Err(error) => {
                // The caller hears the refusal either way.
                let _ = audit.finish(Outcome::Refused, Some(error.code()));
                Err(error)
            }
        }
    }

    async fn admit_audited(
        &self,
        request: &AdmitRequest,
        audit: &mut AuditGuard,
    ) -> Result<BTreeMap<FieldName, Envelope>, BrokerError> {
        self.audit_ready()?;
        let AdmitRequest {
            keyset,
            item,
            envelope,
            outputs,
            ..
        } = request;
        if outputs.is_empty() || outputs.len() > MAX_INTAKE_OUTPUTS {
            return Err(BrokerError::new(
                ErrorCode::BadRequest,
                "an admission names between one and sixteen fields",
            ));
        }
        // Decided before anything is opened: what each field would be sealed under.
        let mut digests = BTreeMap::new();
        for (field, output) in outputs {
            output.policy.validate().map_err(|_| {
                BrokerError::for_field(ErrorCode::BadRequest, "a policy is not valid", field)
            })?;
            if output.policy.intake.is_some() {
                return Err(BrokerError::for_field(
                    ErrorCode::PolicyDenied,
                    "a field cannot be sealed as an intake",
                    field,
                ));
            }
            let digest = output.policy.digest().map_err(|_| {
                BrokerError::for_field(ErrorCode::BadRequest, "a policy is not valid", field)
            })?;
            digests.insert(field, digest);
        }
        audit.update(|record| {
            record.policies = digests
                .iter()
                .map(|(field, digest)| format!("{field}={digest}"))
                .collect();
        });

        let field = intake_field();
        let key = self
            .keys
            .private_key(keyset, envelope.kid())
            .await
            .map_err(|error| key_error(error, &field))?;
        let binding = Binding {
            keyset,
            item,
            field: &field,
        };
        let opened = seal_format::open(&key, envelope, binding)
            .map_err(|_| BrokerError::new(ErrorCode::OpenFailed, "the envelope did not open"))?;
        drop(key);
        // A stored value never gets a new policy this way.
        let Some(intake) = &opened.policy.intake else {
            return Err(BrokerError::new(
                ErrorCode::PolicyDenied,
                "only an intake envelope is admitted",
            ));
        };

        let now = self
            .clock
            .now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        if now > intake.not_after {
            return Err(BrokerError::new(
                ErrorCode::IntakeStale,
                "the envelope is past its time",
            ));
        }
        // Whoever sealed the envelope wrote its time, so it is held to the operator's.
        if intake.not_after - now > self.limits.max_intake_lifetime.as_secs() {
            return Err(BrokerError::new(
                ErrorCode::PolicyDenied,
                "the envelope's time is further ahead than is admitted",
            ));
        }
        for (field, digest) in &digests {
            match intake.outputs.get(*field) {
                None => {
                    return Err(BrokerError::for_field(
                        ErrorCode::PolicyDenied,
                        "the envelope does not name this field",
                        field,
                    ));
                }
                // Neither is secret: the caller has both.
                Some(named) if named != digest => {
                    return Err(BrokerError::for_field(
                        ErrorCode::IntakeStale,
                        "the policy is not the one the envelope names",
                        field,
                    ));
                }
                Some(_) => {}
            }
        }

        let invalid = |detail| BrokerError::new(ErrorCode::IntakeInvalid, detail);
        let members = opened
            .secret
            .expose(crate::intake::parse)
            .map_err(|_| invalid("the envelope's secret is not an object of fields"))?;
        drop(opened);
        // Members no output names are dropped here, and nothing says they were there.
        for (field, output) in outputs {
            if !output.optional && !members.contains_key(field) {
                return Err(BrokerError::for_field(
                    ErrorCode::IntakeInvalid,
                    "the envelope has no such field",
                    field,
                ));
            }
        }

        let (kid, public) =
            self.keys
                .current_public_key(keyset)
                .await
                .map_err(|error| match error {
                    KeyError::UnknownKeyset | KeyError::UnknownKey => {
                        BrokerError::new(ErrorCode::KeysetUnknown, "the keyset has no current key")
                    }
                    _ => {
                        BrokerError::new(ErrorCode::KeysUnavailable, "the keys could not be loaded")
                    }
                })?;
        let mut sealed = BTreeMap::new();
        for (field, output) in outputs {
            let Some(secret) = members.get(field) else {
                continue;
            };
            let binding = Binding {
                keyset,
                item,
                field,
            };
            let envelope = secret
                .expose(|secret| seal_value(&public, &kid, binding, secret, &output.policy))
                .map_err(|error| match error {
                    FormatError::PlaintextTooLarge => BrokerError::for_field(
                        ErrorCode::IntakeInvalid,
                        "the field does not fit in a value beside its policy",
                        field,
                    ),
                    _ => {
                        BrokerError::for_field(ErrorCode::Internal, "could not seal a field", field)
                    }
                })?;
            sealed.insert(field.clone(), envelope);
        }
        Ok(sealed)
    }
}
