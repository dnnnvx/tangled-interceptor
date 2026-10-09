//! Tekton Triggers `ClusterInterceptor` that verifies Tangled webhook signatures.
//!
//! Tangled signs the raw request body as `X-Tangled-Signature-256: sha256=<hex hmac>`,
//! the same scheme as GitHub, but Tekton's built-in `github` interceptor only reads
//! `X-Hub-Signature-256`. The EventListener POSTs an `InterceptorRequest`
//! (`{"body": <raw body string>, "header": {name: [values]}, ..}`) and expects an
//! `InterceptorResponse` (`{"continue": bool, "status": {..}}`) back.

use std::{collections::HashMap, env, fs, net::SocketAddr};

use axum::{
    Json, Router,
    routing::{get, post},
};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

// google.golang.org/grpc/codes, which Tekton uses for status.code
const INVALID_ARGUMENT: i32 = 3;
const UNAUTHENTICATED: i32 = 16;

#[derive(Deserialize)]
struct InterceptorRequest {
    #[serde(default)]
    body: String,
    #[serde(default)]
    header: HashMap<String, Vec<String>>,
}

#[derive(Serialize)]
struct InterceptorResponse {
    r#continue: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<Status>,
}

#[derive(Serialize)]
struct Status {
    code: i32,
    message: String,
}

#[derive(Clone)]
struct Config {
    secret: Vec<u8>,
    /// Lower-cased name of the header carrying `sha256=<hex hmac>`.
    header: String,
}

fn verify(cfg: &Config, req: &InterceptorRequest) -> Result<(), (i32, String)> {
    let signature = req
        .header
        .iter()
        .find(|(name, _)| name.to_ascii_lowercase() == cfg.header)
        .and_then(|(_, values)| values.first())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| (INVALID_ARGUMENT, format!("missing {} header", cfg.header)))?;

    let mismatch = || (UNAUTHENTICATED, format!("{} does not match", cfg.header));
    let expected = signature
        .strip_prefix("sha256=")
        .and_then(|hex| hex::decode(hex).ok())
        .ok_or_else(mismatch)?;

    let mut mac = Hmac::<Sha256>::new_from_slice(&cfg.secret).expect("HMAC accepts any key length");
    mac.update(req.body.as_bytes());
    // verify_slice compares in constant time
    mac.verify_slice(&expected).map_err(|_| mismatch())
}

async fn intercept(cfg: Config, body: axum::body::Bytes) -> Json<InterceptorResponse> {
    let result = serde_json::from_slice::<InterceptorRequest>(&body)
        .map_err(|e| (INVALID_ARGUMENT, format!("bad interceptor request: {e}")))
        .and_then(|req| verify(&cfg, &req));
    Json(match result {
        Ok(()) => InterceptorResponse {
            r#continue: true,
            status: None,
        },
        Err((code, message)) => InterceptorResponse {
            r#continue: false,
            status: Some(Status { code, message }),
        },
    })
}

fn app(cfg: Config) -> Router {
    Router::new()
        .route("/", post(move |body| intercept(cfg.clone(), body)))
        // readiness/liveness
        .route("/healthz", get(|| async { "ok" }))
}

#[tokio::main]
async fn main() {
    let secret_file = env::var("WEBHOOK_SECRET_FILE").expect("WEBHOOK_SECRET_FILE is required");
    let secret = fs::read(&secret_file).unwrap_or_else(|e| panic!("reading {secret_file}: {e}"));
    let cfg = Config {
        secret: secret.trim_ascii().to_vec(),
        header: env::var("SIGNATURE_HEADER")
            .unwrap_or_else(|_| "x-tangled-signature-256".into())
            .to_ascii_lowercase(),
    };
    let addr: SocketAddr = env::var("LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8080".into())
        .parse()
        .expect("LISTEN_ADDR must be host:port");

    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    axum::serve(listener, app(cfg))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .expect("serve");
}

#[cfg(test)]
mod tests {
    use super::*;

    const BODY: &str = r#"{"ref":"refs/heads/main"}"#;

    fn cfg() -> Config {
        Config {
            secret: b"s3cret".to_vec(),
            header: "x-tangled-signature-256".into(),
        }
    }

    fn sign(body: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(b"s3cret").unwrap();
        mac.update(body.as_bytes());
        format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
    }

    fn request(header: Option<(&str, String)>, body: &str) -> InterceptorRequest {
        InterceptorRequest {
            body: body.into(),
            header: header
                .into_iter()
                .map(|(k, v)| (k.into(), vec![v]))
                .collect(),
        }
    }

    #[test]
    fn accepts_valid_signature_any_header_case() {
        let req = request(Some(("X-Tangled-Signature-256", sign(BODY))), BODY);
        assert!(verify(&cfg(), &req).is_ok());
    }

    #[test]
    fn rejects_missing_header() {
        assert_eq!(
            verify(&cfg(), &request(None, BODY)).unwrap_err().0,
            INVALID_ARGUMENT
        );
    }

    #[test]
    fn rejects_tampered_body() {
        let req = request(
            Some(("X-Tangled-Signature-256", sign(BODY))),
            r#"{"ref":"x"}"#,
        );
        assert_eq!(verify(&cfg(), &req).unwrap_err().0, UNAUTHENTICATED);
    }

    #[test]
    fn rejects_malformed_signature() {
        for bad in ["", "sha256=", "sha256=zz", "md5=abcd", "abcd"] {
            let req = request(Some(("X-Tangled-Signature-256", bad.into())), BODY);
            assert!(verify(&cfg(), &req).is_err(), "{bad:?} accepted");
        }
    }
}
