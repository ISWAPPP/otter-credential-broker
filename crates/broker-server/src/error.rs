//! Mapping of [`BrokerError`] to HTTP responses. Bodies never contain secret
//! material; internal errors are logged and answered generically.

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, Request};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use broker_core::BrokerError;
use broker_core::limits::LimitKind;
use broker_core::llm::ProviderKind;
use serde_json::json;

/// HTTP status and stable machine-readable code for an error.
pub fn classify(e: &BrokerError) -> (StatusCode, &'static str) {
    match e {
        BrokerError::NotFound(_) => (StatusCode::NOT_FOUND, "not_found"),
        BrokerError::Conflict(_) => (StatusCode::CONFLICT, "conflict"),
        BrokerError::Invalid(_) => (StatusCode::BAD_REQUEST, "invalid_request"),
        BrokerError::TooLarge(_) => (StatusCode::PAYLOAD_TOO_LARGE, "too_large"),
        BrokerError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
        BrokerError::Forbidden(_) => (StatusCode::FORBIDDEN, "forbidden"),
        BrokerError::RateLimited { .. } => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
        BrokerError::TooManyInFlight(_) => (StatusCode::TOO_MANY_REQUESTS, "too_many_in_flight"),
        // 402: not retried by the common SDKs, unlike 429.
        BrokerError::BudgetExceeded(_) => (StatusCode::PAYMENT_REQUIRED, "budget_exceeded"),
        BrokerError::Limit(r) => match r.kind {
            LimitKind::Rate => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            LimitKind::InFlight => (StatusCode::TOO_MANY_REQUESTS, "too_many_in_flight"),
            LimitKind::Budget => (StatusCode::PAYMENT_REQUIRED, "budget_exceeded"),
        },
        BrokerError::Crypto(_) | BrokerError::Storage(_) | BrokerError::Migrate(_) | BrokerError::Internal(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "internal")
        }
    }
}

fn public_message(e: &BrokerError, status: StatusCode) -> String {
    if status == StatusCode::INTERNAL_SERVER_ERROR {
        tracing::error!(error = %e, "internal error");
        "internal error".to_owned()
    } else {
        e.to_string()
    }
}

fn retry_after(e: &BrokerError, resp: &mut Response) {
    let secs = match e {
        BrokerError::RateLimited { retry_after_secs } => *retry_after_secs,
        BrokerError::TooManyInFlight(_) => 1,
        BrokerError::Limit(r) => match (r.kind, r.retry_after_secs) {
            (_, Some(secs)) => secs,
            (LimitKind::InFlight, None) => 1,
            _ => return,
        },
        _ => return,
    };
    if let Ok(v) = HeaderValue::from_str(&secs.to_string()) {
        resp.headers_mut().insert(header::RETRY_AFTER, v);
    }
}

/// Error of the admin API and the worker endpoint:
/// `{"error": "<code>", "message": "..."}`.
#[derive(Debug)]
pub struct ApiError(pub BrokerError);

impl From<BrokerError> for ApiError {
    fn from(e: BrokerError) -> Self {
        Self(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = classify(&self.0);
        let message = public_message(&self.0, status);
        let mut resp = (status, Json(json!({ "error": code, "message": message }))).into_response();
        if status == StatusCode::UNAUTHORIZED {
            resp.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        retry_after(&self.0, &mut resp);
        resp
    }
}

/// JSON body extractor for the admin API. Its rejections never echo the
/// submitted body: serde messages can contain values (e.g. `invalid type:
/// string "..."`), and a misplaced secret must not come back in an error.
pub struct JsonBody<T>(pub T);

impl<T, S> FromRequest<S> for JsonBody<T>
where
    Json<T>: FromRequest<S, Rejection = JsonRejection>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(v)) => Ok(Self(v)),
            Err(r) => Err(ApiError(match r {
                JsonRejection::BytesRejection(b) if b.status() == StatusCode::PAYLOAD_TOO_LARGE => {
                    BrokerError::TooLarge("request body too large".into())
                }
                JsonRejection::MissingJsonContentType(_) => {
                    BrokerError::Invalid("expected content-type: application/json".into())
                }
                JsonRejection::JsonSyntaxError(_) => BrokerError::Invalid("request body is not valid JSON".into()),
                JsonRejection::JsonDataError(_) => {
                    BrokerError::Invalid("request body has unknown fields or fields of the wrong type".into())
                }
                _ => BrokerError::Invalid("could not read the request body".into()),
            })),
        }
    }
}

/// Error produced by the proxy itself on `/llm/*`, shaped like the
/// provider's own errors so SDKs surface the message:
/// Anthropic `{"type":"error","error":{"type","message"}}`, OpenAI
/// `{"error":{"message","type","code"}}`.
pub fn llm_error(kind: ProviderKind, e: &BrokerError) -> Response {
    let (status, code) = classify(e);
    let message = public_message(e, status);
    llm_error_response(kind, status, code, &message, e)
}

pub fn llm_error_response(
    kind: ProviderKind,
    status: StatusCode,
    code: &str,
    message: &str,
    source: &BrokerError,
) -> Response {
    let body = match kind {
        ProviderKind::Anthropic => {
            let t = match status.as_u16() {
                400 => "invalid_request_error",
                401 => "authentication_error",
                402 => "billing_error",
                403 => "permission_error",
                404 => "not_found_error",
                413 => "request_too_large",
                429 => "rate_limit_error",
                504 => "timeout_error",
                _ => "api_error",
            };
            json!({ "type": "error", "error": { "type": t, "message": message, "code": code } })
        }
        ProviderKind::Openai => {
            let t = match status.as_u16() {
                400 | 404 | 413 => "invalid_request_error",
                401 => "authentication_error",
                402 => "insufficient_quota",
                403 => "permission_error",
                429 => "rate_limit_exceeded",
                _ => "api_error",
            };
            json!({ "error": { "message": message, "type": t, "code": code, "param": null } })
        }
    };
    let mut resp = (status, Json(body)).into_response();
    if status == StatusCode::UNAUTHORIZED {
        resp.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    }
    retry_after(source, &mut resp);
    resp
}
