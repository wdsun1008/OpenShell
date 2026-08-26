// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Fresh, display-only sandbox appraisal over the existing supervisor relay.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::{Bytes, BytesMut};
use http::header::{CONNECTION, CONTENT_LENGTH, HOST};
use http_body_util::{BodyExt as _, Empty};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use openshell_core::proto::{
    AttestationServiceRelayTarget, GetSandboxAttestationResponse, SandboxAttestationMeasurement,
    SandboxAttestationTrustworthinessVector, relay_open,
};
use rand::RngCore as _;
use serde_json::{Value, json};
use url::Url;

use crate::config_file::AttestationReportFileConfig;
use crate::supervisor_session::SupervisorSessionRegistry;

const MAX_EVIDENCE_BYTES: usize = 256 * 1024;
const MAX_EAR_BYTES: usize = 256 * 1024;
const MAX_REFERENCE_BYTES: u64 = 64 * 1024;
const MAX_PUBLIC_KEY_BYTES: u64 = 16 * 1024;
const MAX_POLICY_ID_BYTES: usize = 256;
const MAX_EAR_STATUS_BYTES: usize = 64;
const RELAY_WAIT_TIMEOUT: Duration = Duration::from_secs(12);

type ReferenceValues = BTreeMap<String, Vec<String>>;

/// Immutable inputs used for every explicit appraisal request.
pub struct AttestationReporter {
    trustee_attestation_url: Url,
    policy_id: String,
    references: ReferenceValues,
    decoding_key: DecodingKey,
    http: reqwest::Client,
}

impl std::fmt::Debug for AttestationReporter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttestationReporter")
            .field("trustee_attestation_url", &self.trustee_attestation_url)
            .field("policy_id", &self.policy_id)
            .field("reference_keys", &self.references.len())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum AppraisalError {
    #[error("sandbox attestation relay is unavailable")]
    RelayUnavailable,
    #[error("sandbox evidence collection failed")]
    EvidenceCollection,
    #[error("Trustee appraisal request failed")]
    TrusteeRequest,
    #[error("Trustee returned an invalid appraisal")]
    InvalidAppraisal,
}

impl AttestationReporter {
    pub fn from_config(config: &AttestationReportFileConfig) -> Result<Self, String> {
        let trustee_attestation_url = trustee_attestation_url(&config.trustee_url)?;
        let policy_id = validate_display_text(
            config.policy_id.trim(),
            MAX_POLICY_ID_BYTES,
            "attestation_report.policy_id",
        )?;
        let reference_bytes = read_bounded_file(
            &config.reference_values_path,
            MAX_REFERENCE_BYTES,
            "reference values",
        )?;
        let references: ReferenceValues =
            serde_json::from_slice(&reference_bytes).map_err(|e| {
                format!(
                    "failed to parse attestation reference values {}: {e}",
                    config.reference_values_path.display()
                )
            })?;
        let references = normalize_references(references)?;
        let public_key = read_bounded_file(
            &config.as_public_key_path,
            MAX_PUBLIC_KEY_BYTES,
            "attestation-service public key",
        )?;
        let decoding_key = DecodingKey::from_ec_pem(&public_key).map_err(|e| {
            format!(
                "failed to parse attestation-service EC public key {}: {e}",
                config.as_public_key_path.display()
            )
        })?;
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|e| format!("failed to build Trustee HTTP client: {e}"))?;

        Ok(Self {
            trustee_attestation_url,
            policy_id,
            references,
            decoding_key,
            http,
        })
    }

    pub async fn collect(
        &self,
        sessions: &SupervisorSessionRegistry,
        sandbox_id: &str,
    ) -> Result<GetSandboxAttestationResponse, AppraisalError> {
        let session_id = sessions
            .current_session_id(sandbox_id)
            .ok_or(AppraisalError::RelayUnavailable)?;
        let mut nonce = [0_u8; 32];
        rand::rng().fill_bytes(&mut nonce);

        let (_, relay_rx) = sessions
            .open_relay_with_target(
                sandbox_id,
                relay_open::Target::AttestationService(AttestationServiceRelayTarget {}),
                "attestation-report".to_string(),
                Duration::from_secs(2),
            )
            .await
            .map_err(|_| AppraisalError::RelayUnavailable)?;
        let stream = tokio::time::timeout(RELAY_WAIT_TIMEOUT, relay_rx)
            .await
            .map_err(|_| AppraisalError::RelayUnavailable)?
            .map_err(|_| AppraisalError::RelayUnavailable)?
            .map_err(|_| AppraisalError::RelayUnavailable)?;
        let evidence = request_asr_evidence(stream, &nonce).await?;
        let token = self.request_trustee(&evidence, &nonce).await?;
        let appraisal = verify_ear(
            &token,
            &nonce,
            &self.decoding_key,
            &self.references,
            &self.policy_id,
        )?;

        if !sessions.is_current_session(sandbox_id, &session_id) {
            return Err(AppraisalError::RelayUnavailable);
        }
        Ok(appraisal)
    }

    async fn request_trustee(
        &self,
        evidence: &[u8],
        nonce: &[u8; 32],
    ) -> Result<String, AppraisalError> {
        let request = json!({
            "verification_requests": [{
                "tee": "tdx",
                "evidence": URL_SAFE_NO_PAD.encode(evidence),
                "runtime_data": {"raw": URL_SAFE_NO_PAD.encode(nonce)}
            }],
            "policy_ids": [&self.policy_id]
        });
        let response = self
            .http
            .post(self.trustee_attestation_url.clone())
            .json(&request)
            .send()
            .await
            .map_err(|_| AppraisalError::TrusteeRequest)?;
        if !response.status().is_success() {
            return Err(AppraisalError::TrusteeRequest);
        }
        let body = read_reqwest_body(response, MAX_EAR_BYTES).await?;
        let token = std::str::from_utf8(&body)
            .map_err(|_| AppraisalError::InvalidAppraisal)?
            .trim();
        if token.is_empty() {
            return Err(AppraisalError::InvalidAppraisal);
        }
        Ok(token.to_string())
    }
}

fn read_bounded_file(path: &Path, max: u64, label: &str) -> Result<Vec<u8>, String> {
    let file = std::fs::File::open(path)
        .map_err(|e| format!("failed to open {label} {}: {e}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("failed to inspect {label} {}: {e}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("{label} {} must be a regular file", path.display()));
    }
    if metadata.len() > max {
        return Err(format!("{label} {} exceeds {max} bytes", path.display()));
    }
    let mut bytes = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("failed to read {label} {}: {e}", path.display()))?;
    if bytes.len() as u64 > max {
        return Err(format!("{label} {} exceeds {max} bytes", path.display()));
    }
    Ok(bytes)
}

fn trustee_attestation_url(base: &str) -> Result<Url, String> {
    let mut url =
        Url::parse(base).map_err(|e| format!("invalid attestation_report.trustee_url: {e}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err("attestation_report.trustee_url must use http or https".to_string());
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(
            "attestation_report.trustee_url must not contain credentials, query, or fragment"
                .to_string(),
        );
    }
    let host = url
        .host_str()
        .ok_or_else(|| "attestation_report.trustee_url requires a host".to_string())?;
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    if !loopback {
        return Err("attestation_report.trustee_url must use a loopback host".to_string());
    }
    let path = format!("{}/attestation", url.path().trim_end_matches('/'));
    url.set_path(&path);
    Ok(url)
}

async fn request_asr_evidence(
    stream: tokio::io::DuplexStream,
    nonce: &[u8; 32],
) -> Result<Vec<u8>, AppraisalError> {
    let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|_| AppraisalError::EvidenceCollection)?;
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let path = format!(
        "/aa/evidence?runtime_data={}&encoding=base64",
        URL_SAFE_NO_PAD.encode(nonce)
    );
    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri(path)
        .header(HOST, "localhost")
        .header(CONNECTION, "close")
        .body(Empty::<Bytes>::new())
        .map_err(|_| AppraisalError::EvidenceCollection)?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|_| AppraisalError::EvidenceCollection)?;
    if !response.status().is_success() {
        return Err(AppraisalError::EvidenceCollection);
    }
    if response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|length| length > MAX_EVIDENCE_BYTES)
    {
        return Err(AppraisalError::EvidenceCollection);
    }

    let mut body = response.into_body();
    let mut evidence = BytesMut::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| AppraisalError::EvidenceCollection)?;
        if let Some(data) = frame.data_ref() {
            if evidence.len().saturating_add(data.len()) > MAX_EVIDENCE_BYTES {
                return Err(AppraisalError::EvidenceCollection);
            }
            evidence.extend_from_slice(data);
        }
    }
    if evidence.is_empty() {
        return Err(AppraisalError::EvidenceCollection);
    }
    Ok(evidence.to_vec())
}

async fn read_reqwest_body(
    mut response: reqwest::Response,
    max: usize,
) -> Result<Vec<u8>, AppraisalError> {
    if response
        .content_length()
        .is_some_and(|length| length > max as u64)
    {
        return Err(AppraisalError::InvalidAppraisal);
    }
    let mut body = BytesMut::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| AppraisalError::TrusteeRequest)?
    {
        if body.len().saturating_add(chunk.len()) > max {
            return Err(AppraisalError::InvalidAppraisal);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body.to_vec())
}

fn verify_ear(
    token: &str,
    nonce: &[u8; 32],
    decoding_key: &DecodingKey,
    references: &ReferenceValues,
    expected_policy_id: &str,
) -> Result<GetSandboxAttestationResponse, AppraisalError> {
    let mut validation = Validation::new(Algorithm::ES256);
    validation.leeway = 0;
    validation.set_required_spec_claims(&["exp"]);
    let claims = decode::<Value>(token, decoding_key, &validation)
        .map_err(|_| AppraisalError::InvalidAppraisal)?
        .claims;
    appraisal_from_claims(&claims, nonce, references, expected_policy_id)
}

fn appraisal_from_claims(
    claims: &Value,
    nonce: &[u8; 32],
    references: &ReferenceValues,
    expected_policy_id: &str,
) -> Result<GetSandboxAttestationResponse, AppraisalError> {
    let cpu = claims
        .pointer("/submods/cpu0")
        .ok_or(AppraisalError::InvalidAppraisal)?;
    let ear_status = required_display_string(cpu, "ear.status", MAX_EAR_STATUS_BYTES)?;
    let policy_id = required_display_string(cpu, "ear.appraisal-policy-id", MAX_POLICY_ID_BYTES)?;
    if policy_id != expected_policy_id {
        return Err(AppraisalError::InvalidAppraisal);
    }
    let vector = cpu
        .get("ear.trustworthiness-vector")
        .ok_or(AppraisalError::InvalidAppraisal)?;
    let ar4si_vector = SandboxAttestationTrustworthinessVector {
        hardware: required_ar4si_value(vector, "hardware")?,
        executables: required_ar4si_value(vector, "executables")?,
        configuration: required_ar4si_value(vector, "configuration")?,
        file_system: required_ar4si_value(vector, "file-system")?,
    };
    let annotated_evidence = cpu
        .get("ear.veraison.annotated-evidence")
        .ok_or(AppraisalError::InvalidAppraisal)?;
    let report_data = required_hex(annotated_evidence, "report_data", 128)?;
    let expected_report_data = format!("{}{}", hex::encode(nonce), "0".repeat(64));
    if report_data != expected_report_data {
        return Err(AppraisalError::InvalidAppraisal);
    }
    let tdx = annotated_evidence
        .get("tdx")
        .ok_or(AppraisalError::InvalidAppraisal)?;
    let measurements = measurements_from_tdx(tdx, references)?;

    Ok(GetSandboxAttestationResponse {
        ear_status,
        policy_id,
        ar4si_vector: Some(ar4si_vector),
        measurements,
    })
}

fn required_display_string(value: &Value, key: &str, max: usize) -> Result<String, AppraisalError> {
    let value = value
        .get(key)
        .and_then(Value::as_str)
        .ok_or(AppraisalError::InvalidAppraisal)?;
    validate_display_text(value, max, key).map_err(|_| AppraisalError::InvalidAppraisal)
}

fn validate_display_text(value: &str, max: usize, label: &str) -> Result<String, String> {
    if value.is_empty() || value.len() > max || !value.chars().all(|c| c.is_ascii_graphic()) {
        return Err(format!(
            "{label} must contain 1..={max} printable ASCII bytes"
        ));
    }
    Ok(value.to_string())
}

fn required_ar4si_value(value: &Value, key: &str) -> Result<i32, AppraisalError> {
    value
        .get(key)
        .and_then(Value::as_i64)
        .filter(|value| (0..=127).contains(value))
        .and_then(|value| i32::try_from(value).ok())
        .ok_or(AppraisalError::InvalidAppraisal)
}

fn required_hex(value: &Value, key: &str, length: usize) -> Result<String, AppraisalError> {
    let digest = value
        .get(key)
        .and_then(Value::as_str)
        .ok_or(AppraisalError::InvalidAppraisal)?;
    normalize_hex(digest, length).ok_or(AppraisalError::InvalidAppraisal)
}

fn normalize_references(references: ReferenceValues) -> Result<ReferenceValues, String> {
    let mut normalized = BTreeMap::new();
    for (key, values) in references {
        let Some((component, algorithm)) = reference_key_parts(&key) else {
            continue;
        };
        let Some(length) = digest_length(algorithm) else {
            continue;
        };
        let mut normalized_values = Vec::with_capacity(values.len());
        for value in values {
            let digest = normalize_hex(&value, length)
                .ok_or_else(|| format!("invalid reference digest in {key}"))?;
            normalized_values.push(digest);
        }
        normalized.insert(reference_key(component, algorithm), normalized_values);
    }
    Ok(normalized)
}

fn reference_key_parts(key: &str) -> Option<(&str, &str)> {
    let suffix = key.strip_prefix("measurement.")?;
    let (component, algorithm) = suffix.rsplit_once('.')?;
    matches!(
        component,
        "shim" | "grub" | "kernel" | "initrd" | "kernel_cmdline"
    )
    .then_some((component, algorithm))
}

fn digest_length(algorithm: &str) -> Option<usize> {
    match algorithm {
        "SHA-1" => Some(40),
        "SHA-256" => Some(64),
        "SHA-384" => Some(96),
        _ => None,
    }
}

fn normalize_hex(value: &str, length: usize) -> Option<String> {
    (value.len() == length && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| value.to_ascii_lowercase())
}

fn measurements_from_tdx(
    tdx: &Value,
    references: &ReferenceValues,
) -> Result<Vec<SandboxAttestationMeasurement>, AppraisalError> {
    let events = match tdx.get("uefi_event_logs") {
        None => &[][..],
        Some(Value::Array(events)) => events.as_slice(),
        Some(_) => return Err(AppraisalError::InvalidAppraisal),
    };
    ["shim", "grub", "kernel", "initrd", "kernel_cmdline"]
        .into_iter()
        .map(|component| measurement_for_component(component, events, references))
        .collect()
}

fn measurement_for_component(
    component: &str,
    events: &[Value],
    references: &ReferenceValues,
) -> Result<SandboxAttestationMeasurement, AppraisalError> {
    let candidates = events
        .iter()
        .filter(|event| event_matches_component(event, component))
        .map(validated_first_digest)
        .collect::<Result<Vec<_>, _>>()?;
    if candidates.is_empty() {
        return Ok(measurement_without_event(component, references));
    }
    let selected = candidates
        .iter()
        .find(|(algorithm, digest)| {
            references
                .get(&reference_key(component, algorithm))
                .is_some_and(|values| values.iter().any(|value| value == digest))
        })
        .unwrap_or(&candidates[0]);
    Ok(SandboxAttestationMeasurement {
        component: component.to_string(),
        algorithm: selected.0.clone(),
        measurement: selected.1.clone(),
        references: references
            .get(&reference_key(component, &selected.0))
            .cloned()
            .unwrap_or_default(),
    })
}

fn event_matches_component(event: &Value, component: &str) -> bool {
    let event_type = event.get("type_name").and_then(Value::as_str);
    let details = event.get("details");
    match component {
        "shim" | "grub" => {
            event_type == Some("EV_EFI_BOOT_SERVICES_APPLICATION")
                && device_path_contains(details, component)
        }
        "kernel" => {
            (event_type == Some("EV_IPL")
                && detail_string(details).is_some_and(|value| value.contains("Kernel")))
                || (event_type == Some("EV_EFI_BOOT_SERVICES_APPLICATION")
                    && device_path_contains(details, "File(kernel)"))
        }
        "initrd" => {
            event_type == Some("EV_IPL")
                && detail_string(details).is_some_and(|value| value.contains("Initrd"))
        }
        "kernel_cmdline" => {
            (event_type == Some("EV_IPL")
                && detail_string(details).is_some_and(|value| {
                    ["grub_cmd linux", "kernel_cmdline", "grub_kernel_cmdline"]
                        .iter()
                        .any(|prefix| value.starts_with(prefix))
                }))
                || (event_type == Some("EV_EVENT_TAG")
                    && detail_string(details) == Some("LOADED_IMAGE::LoadOptions"))
        }
        _ => false,
    }
}

fn device_path_contains(details: Option<&Value>, fragment: &str) -> bool {
    details
        .and_then(|value| value.get("device_paths"))
        .and_then(Value::as_array)
        .is_some_and(|paths| {
            paths
                .iter()
                .any(|path| path.as_str().is_some_and(|path| path.contains(fragment)))
        })
}

fn detail_string(details: Option<&Value>) -> Option<&str> {
    details
        .and_then(|value| value.get("string"))
        .and_then(Value::as_str)
}

fn validated_first_digest(event: &Value) -> Result<(String, String), AppraisalError> {
    let digest = event
        .get("digests")
        .and_then(Value::as_array)
        .and_then(|digests| digests.first())
        .ok_or(AppraisalError::InvalidAppraisal)?;
    let algorithm = digest
        .get("alg")
        .and_then(Value::as_str)
        .ok_or(AppraisalError::InvalidAppraisal)?;
    let length = digest_length(algorithm).ok_or(AppraisalError::InvalidAppraisal)?;
    let value = digest
        .get("digest")
        .and_then(Value::as_str)
        .and_then(|value| normalize_hex(value, length))
        .ok_or(AppraisalError::InvalidAppraisal)?;
    Ok((algorithm.to_string(), value))
}

fn measurement_without_event(
    component: &str,
    references: &ReferenceValues,
) -> SandboxAttestationMeasurement {
    let configured = ["SHA-384", "SHA-256", "SHA-1"]
        .into_iter()
        .find_map(|algorithm| {
            references
                .get(&reference_key(component, algorithm))
                .map(|values| (algorithm, values))
        });
    let (algorithm, references) = configured.map_or_else(
        || (String::new(), Vec::new()),
        |(algorithm, values)| (algorithm.to_string(), values.clone()),
    );
    SandboxAttestationMeasurement {
        component: component.to_string(),
        algorithm,
        measurement: String::new(),
        references,
    }
}

fn reference_key(component: &str, algorithm: &str) -> String {
    format!("measurement.{component}.{algorithm}")
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use jsonwebtoken::{EncodingKey, Header, encode};
    use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};
    use serde_json::Map;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    const POLICY_ID: &str = "default";

    fn references() -> ReferenceValues {
        BTreeMap::from([
            (
                "measurement.shim.SHA-384".to_string(),
                vec!["aa".repeat(48)],
            ),
            (
                "measurement.grub.SHA-384".to_string(),
                vec!["bb".repeat(48)],
            ),
            (
                "measurement.kernel.SHA-384".to_string(),
                vec!["cc".repeat(48)],
            ),
            (
                "measurement.initrd.SHA-384".to_string(),
                vec!["dd".repeat(48)],
            ),
            (
                "measurement.kernel_cmdline.SHA-384".to_string(),
                vec!["ee".repeat(48)],
            ),
        ])
    }

    fn event(event_type: &str, details: Value, digest: String) -> Value {
        json!({
            "type_name": event_type,
            "details": details,
            "digests": [{"alg": "SHA-384", "digest": digest}]
        })
    }

    fn matching_events() -> Vec<Value> {
        vec![
            event(
                "EV_EFI_BOOT_SERVICES_APPLICATION",
                json!({"device_paths": ["/EFI/alinux/shimx64.efi"]}),
                "aa".repeat(48),
            ),
            event(
                "EV_EFI_BOOT_SERVICES_APPLICATION",
                json!({"device_paths": ["/EFI/alinux/grubx64.efi"]}),
                "bb".repeat(48),
            ),
            event(
                "EV_IPL",
                json!({"string": "grub_linuxefi Kernel"}),
                "cc".repeat(48),
            ),
            event(
                "EV_IPL",
                json!({"string": "grub_linuxefi Initrd"}),
                "dd".repeat(48),
            ),
            event(
                "EV_IPL",
                json!({"string": "grub_kernel_cmdline root=/dev/vda"}),
                "ee".repeat(48),
            ),
        ]
    }

    fn claims(nonce: &[u8; 32], events: Vec<Value>) -> Value {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        json!({
            "iat": now,
            "exp": now + 300,
            "submods": {"cpu0": {
                "ear.status": "affirming",
                "ear.appraisal-policy-id": POLICY_ID,
                "ear.trustworthiness-vector": {
                    "hardware": 2,
                    "executables": 3,
                    "configuration": 2,
                    "file-system": 2
                },
                "ear.veraison.annotated-evidence": {
                    "report_data": format!("{}{}", hex::encode(nonce), "0".repeat(64)),
                    "tdx": {"uefi_event_logs": events}
                }
            }}
        })
    }

    fn signed_token(claims: &Value) -> (String, Vec<u8>) {
        crate::install_jsonwebtoken_crypto_provider();
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("key");
        let private_pem = key.serialize_pem();
        let public_pem = key.public_key_pem().into_bytes();
        let token = encode(
            &Header::new(Algorithm::ES256),
            claims,
            &EncodingKey::from_ec_pem(private_pem.as_bytes()).expect("encoding key"),
        )
        .expect("token");
        (token, public_pem)
    }

    #[test]
    fn signed_ear_binds_nonce_policy_and_measurements() {
        let nonce = [7_u8; 32];
        let (token, public_key) = signed_token(&claims(&nonce, matching_events()));
        let appraisal = verify_ear(
            &token,
            &nonce,
            &DecodingKey::from_ec_pem(&public_key).expect("decoding key"),
            &references(),
            POLICY_ID,
        )
        .expect("valid appraisal");

        assert_eq!(appraisal.ear_status, "affirming");
        assert_eq!(appraisal.policy_id, POLICY_ID);
        assert_eq!(appraisal.measurements.len(), 5);
        assert!(appraisal.measurements.iter().all(|measurement| {
            !measurement.measurement.is_empty()
                && measurement.references.contains(&measurement.measurement)
        }));
    }

    #[test]
    fn signed_ear_rejects_wrong_nonce_and_policy() {
        let nonce = [7_u8; 32];
        let (token, public_key) = signed_token(&claims(&nonce, matching_events()));
        let key = DecodingKey::from_ec_pem(&public_key).expect("decoding key");
        assert!(matches!(
            verify_ear(&token, &[8_u8; 32], &key, &references(), POLICY_ID),
            Err(AppraisalError::InvalidAppraisal)
        ));
        assert!(matches!(
            verify_ear(&token, &nonce, &key, &references(), "another-policy"),
            Err(AppraisalError::InvalidAppraisal)
        ));
    }

    #[test]
    fn signed_ear_rejects_invalid_signature_and_expiry() {
        let nonce = [5_u8; 32];
        let (token, _) = signed_token(&claims(&nonce, matching_events()));
        let (_, other_public_key) = signed_token(&claims(&nonce, matching_events()));
        assert!(matches!(
            verify_ear(
                &token,
                &nonce,
                &DecodingKey::from_ec_pem(&other_public_key).expect("decoding key"),
                &references(),
                POLICY_ID,
            ),
            Err(AppraisalError::InvalidAppraisal)
        ));

        let mut expired = claims(&nonce, matching_events());
        expired["exp"] = json!(1);
        let (expired_token, public_key) = signed_token(&expired);
        assert!(matches!(
            verify_ear(
                &expired_token,
                &nonce,
                &DecodingKey::from_ec_pem(&public_key).expect("decoding key"),
                &references(),
                POLICY_ID,
            ),
            Err(AppraisalError::InvalidAppraisal)
        ));
    }

    #[test]
    fn direct_boot_events_expose_kernel_and_load_options() {
        let nonce = [6_u8; 32];
        let events = vec![
            event(
                "EV_EFI_BOOT_SERVICES_APPLICATION",
                json!({"device_paths": ["VenMedia(...)", "File(kernel)"]}),
                "cc".repeat(48),
            ),
            event(
                "EV_EVENT_TAG",
                json!({"string": "LOADED_IMAGE::LoadOptions"}),
                "ee".repeat(48),
            ),
        ];
        let appraisal =
            appraisal_from_claims(&claims(&nonce, events), &nonce, &references(), POLICY_ID)
                .expect("direct-boot appraisal");
        assert_eq!(
            appraisal
                .measurements
                .iter()
                .find(|measurement| measurement.component == "kernel")
                .expect("kernel")
                .measurement,
            "cc".repeat(48)
        );
        assert_eq!(
            appraisal
                .measurements
                .iter()
                .find(|measurement| measurement.component == "kernel_cmdline")
                .expect("kernel cmdline")
                .measurement,
            "ee".repeat(48)
        );
    }

    #[test]
    fn absent_event_log_keeps_only_normalized_references() {
        let nonce = [9_u8; 32];
        let mut value = claims(&nonce, Vec::new());
        value["submods"]["cpu0"]["ear.veraison.annotated-evidence"]["tdx"] = json!({});
        let appraisal = appraisal_from_claims(&value, &nonce, &references(), POLICY_ID)
            .expect("appraisal without event log");
        assert!(appraisal.measurements.iter().all(|measurement| {
            measurement.measurement.is_empty() && !measurement.references.is_empty()
        }));
    }

    #[test]
    fn malformed_vector_and_terminal_control_data_are_rejected() {
        let nonce = [4_u8; 32];
        let mut value = claims(&nonce, matching_events());
        value["submods"]["cpu0"]["ear.trustworthiness-vector"] = Value::Object(Map::new());
        assert!(matches!(
            appraisal_from_claims(&value, &nonce, &references(), POLICY_ID),
            Err(AppraisalError::InvalidAppraisal)
        ));

        let mut value = claims(&nonce, matching_events());
        value["submods"]["cpu0"]["ear.status"] = json!("affirming\u{1b}[2J");
        assert!(matches!(
            appraisal_from_claims(&value, &nonce, &references(), POLICY_ID),
            Err(AppraisalError::InvalidAppraisal)
        ));
    }

    #[test]
    fn reference_measurements_require_supported_normalized_hex() {
        let invalid = BTreeMap::from([(
            "measurement.kernel.SHA-384".to_string(),
            vec!["not-a-digest\u{1b}[2J".to_string()],
        )]);
        assert!(normalize_references(invalid).is_err());

        let uppercase = BTreeMap::from([(
            "measurement.kernel.SHA-384".to_string(),
            vec!["AB".repeat(48)],
        )]);
        assert_eq!(
            normalize_references(uppercase).expect("valid references")["measurement.kernel.SHA-384"]
                [0],
            "ab".repeat(48)
        );

        let untrusted = BTreeMap::from([
            (
                "measurement.kernel.attacker.SHA-384".to_string(),
                vec!["value\u{1b}[2J".to_string()],
            ),
            (
                "measurement.kernel.SHA-512".to_string(),
                vec!["value\u{1b}[2J".to_string()],
            ),
            ("tdx.xfam".to_string(), vec!["value\u{1b}[2J".to_string()]),
        ]);
        assert!(
            normalize_references(untrusted)
                .expect("unrelated reference keys are ignored")
                .is_empty()
        );
    }

    #[test]
    fn absent_event_log_uses_only_exact_supported_reference_keys() {
        let references = normalize_references(BTreeMap::from([
            (
                "measurement.kernel.attacker.SHA-384".to_string(),
                vec!["value\u{1b}[2J".to_string()],
            ),
            (
                "measurement.kernel.SHA-256".to_string(),
                vec!["ab".repeat(32)],
            ),
        ]))
        .expect("normalized references");

        let measurement = measurement_without_event("kernel", &references);
        assert_eq!(measurement.algorithm, "SHA-256");
        assert_eq!(measurement.references, vec!["ab".repeat(32)]);
    }

    #[test]
    fn trustee_url_is_loopback_and_has_no_credentials() {
        assert!(trustee_attestation_url("http://127.0.0.1:50005").is_ok());
        assert!(trustee_attestation_url("http://localhost:8081/api/").is_ok());
        assert!(trustee_attestation_url("https://10.0.0.2:8081/api").is_err());
        assert!(trustee_attestation_url("http://user@127.0.0.1:8081/api").is_err());
        assert!(trustee_attestation_url("file:///run/trustee.sock").is_err());
    }

    #[tokio::test]
    async fn asr_request_uses_raw_nonce_and_caps_response() {
        let nonce = [0x5a_u8; 32];
        let expected_nonce = URL_SAFE_NO_PAD.encode(nonce);
        let (client, mut server) = tokio::io::duplex(16 * 1024);
        let server_task = tokio::spawn(async move {
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                server.read_exact(&mut byte).await.expect("request byte");
                request.push(byte[0]);
            }
            let request = String::from_utf8(request).expect("HTTP request");
            assert!(request.contains(&format!("runtime_data={expected_nonce}&encoding=base64")));
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                .await
                .expect("response");
        });

        assert_eq!(
            request_asr_evidence(client, &nonce)
                .await
                .expect("evidence"),
            b"{}"
        );
        server_task.await.expect("server task");
    }

    #[tokio::test]
    async fn trustee_request_carries_the_same_raw_nonce_and_selected_policy() {
        let server = MockServer::start().await;
        let nonce = [0x31_u8; 32];
        let evidence = b"fresh-tdx-evidence";
        let expected = json!({
            "verification_requests": [{
                "tee": "tdx",
                "evidence": URL_SAFE_NO_PAD.encode(evidence),
                "runtime_data": {"raw": URL_SAFE_NO_PAD.encode(nonce)}
            }],
            "policy_ids": [POLICY_ID]
        });
        Mock::given(method("POST"))
            .and(path("/attestation"))
            .and(header("content-type", "application/json"))
            .and(body_json(expected))
            .respond_with(ResponseTemplate::new(200).set_body_string("signed.ear.token"))
            .expect(1)
            .mount(&server)
            .await;

        let (_, public_key) = signed_token(&claims(&nonce, matching_events()));
        let reporter = AttestationReporter {
            trustee_attestation_url: trustee_attestation_url(&server.uri()).expect("loopback URL"),
            policy_id: POLICY_ID.to_string(),
            references: references(),
            decoding_key: DecodingKey::from_ec_pem(&public_key).expect("decoding key"),
            http: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("HTTP client"),
        };

        assert_eq!(
            reporter
                .request_trustee(evidence, &nonce)
                .await
                .expect("Trustee request"),
            "signed.ear.token"
        );
    }
}
