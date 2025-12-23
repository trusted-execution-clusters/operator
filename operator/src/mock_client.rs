// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use compute_pcrs_lib::Pcr;
use http::{Method, Request, Response, StatusCode};
use k8s_openapi::{api::core::v1::ConfigMap, chrono::Utc};
use kube::{Client, client::Body, error::ErrorResponse};
use operator::RvContextData;
use serde::Serialize;
use std::sync::atomic::{AtomicU32, Ordering};
use std::{collections::BTreeMap, convert::Infallible, sync::Arc};
use tower::service_fn;

use crate::trustee;
use trusted_cluster_operator_lib::reference_values::{ImagePcr, ImagePcrs, PCR_CONFIG_FILE};

macro_rules! assert_kube_api_error {
    ($err:expr, $code:expr, $reason:expr, $message:expr, $status:expr) => {{
        let kube_error = $err
            .downcast_ref::<kube::Error>()
            .expect(&format!("Expected kube::Error, got: {:?}", $err));

        if let kube::Error::Api(error_response) = kube_error {
            assert_eq!(error_response.code, $code);
            assert_eq!(error_response.reason, $reason);
            assert_eq!(error_response.message, $message);
            assert_eq!(error_response.status, $status);
        } else {
            assert!(false, "Expected kube::Error::Api, got: {:?}", kube_error);
        }
    }};
}

macro_rules! count_check {
    ($expected:literal, $closure:ident, |$client:ident| $body:block) => {
        use std::sync::atomic;
        let count = std::sync::Arc::new(atomic::AtomicU32::new(0));
        let $client = MockClient::new($closure, "test".to_string(), count.clone()).into_client();
        $body
        assert_eq!(count.load(atomic::Ordering::Acquire), $expected, "Endpoint call count mismatch");
    }
}

pub(crate) use assert_kube_api_error;
pub(crate) use count_check;

async fn create_response<T: Future<Output = Result<String, StatusCode>>>(
    response: T,
) -> Result<Response<Body>, Infallible> {
    let (body, status_code) = match response.await {
        Ok(response_data) => (Body::from(response_data.into_bytes()), StatusCode::OK),
        Err(status_code) => {
            let unknown_msg = format!("error with status code {status_code}");
            let (message, reason) = match status_code {
                StatusCode::CONFLICT => ("resource already exists", "AlreadyExists"),
                StatusCode::INTERNAL_SERVER_ERROR => ("internal server error", "ServerTimeout"),
                StatusCode::NOT_FOUND => ("resource not found", "NotFound"),
                StatusCode::BAD_REQUEST => ("bad request", "BadRequest"),
                _ => (unknown_msg.as_str(), "Unknown"),
            };
            let error_response = ErrorResponse {
                status: "Failure".to_string(),
                message: message.to_string(),
                reason: reason.to_string(),
                code: status_code.as_u16(),
            };
            let error_json = serde_json::to_string(&error_response).unwrap();
            (Body::from(error_json.into_bytes()), status_code)
        }
    };
    Ok(Response::builder().status(status_code).body(body).unwrap())
}

pub struct MockClient<F, T>
where
    F: Fn(Request<Body>, u32) -> T + Send + Sync + 'static,
    T: Future<Output = Result<String, StatusCode>> + Send + 'static,
{
    response_closure: F,
    namespace: String,
    request_count: Arc<AtomicU32>,
}

impl<F, T> MockClient<F, T>
where
    F: Fn(Request<Body>, u32) -> T + Send + Sync + 'static,
    T: Future<Output = Result<String, StatusCode>> + Send + 'static,
{
    pub fn new(response_closure: F, namespace: String, request_count: Arc<AtomicU32>) -> Self {
        Self {
            response_closure,
            namespace,
            request_count,
        }
    }

    pub fn into_client(self) -> Client {
        let namespace = self.namespace.clone();
        let mock_svc = service_fn(move |req: Request<Body>| {
            let response = (self.response_closure)(req, self.request_count.load(Ordering::Acquire));
            self.request_count.fetch_add(1, Ordering::AcqRel);
            create_response(response)
        });
        Client::new(mock_svc, namespace)
    }
}

pub async fn test_create_success<
    F: Fn(Client) -> S,
    S: Future<Output = anyhow::Result<()>>,
    T: Default + Serialize,
>(
    create: F,
) {
    let clos = async |_, _| Ok(serde_json::to_string(&T::default()).unwrap());
    count_check!(1, clos, |client| {
        assert!(create(client).await.is_ok());
    });
}

pub async fn test_create_already_exists<
    F: Fn(Client) -> S,
    S: Future<Output = anyhow::Result<()>>,
>(
    create: F,
) {
    let clos = async |req: Request<_>, _| match req {
        r if r.method() == Method::POST => Err(StatusCode::CONFLICT),
        _ => panic!("unexpected API interaction: {req:?}"),
    };
    count_check!(1, clos, |client| {
        assert!(create(client).await.is_ok());
    });
}

pub async fn test_create_error<F: Fn(Client) -> S, S: Future<Output = anyhow::Result<()>>>(
    create: F,
) {
    let clos = async |req: Request<_>, _| match req.method() {
        &Method::POST => Err(StatusCode::INTERNAL_SERVER_ERROR),
        _ => panic!("unexpected API interaction: {req:?}"),
    };
    count_check!(1, clos, |client| {
        let err = create(client).await.unwrap_err();
        let msg = "internal server error";
        assert_kube_api_error!(err, 500, "ServerTimeout", msg, "Failure");
    });
}

pub fn dummy_pcrs() -> ImagePcrs {
    ImagePcrs(BTreeMap::from([(
        "cos".to_string(),
        ImagePcr {
            first_seen: Utc::now(),
            pcrs: vec![
                Pcr {
                    id: 0,
                    value: "pcr0_val".into(),
                    events: vec![],
                },
                Pcr {
                    id: 1,
                    value: "pcr1_val".into(),
                    events: vec![],
                },
            ],
            reference: "ref".to_string(),
        },
    )]))
}

pub fn dummy_trustee_map() -> ConfigMap {
    ConfigMap {
        data: Some(BTreeMap::from([(
            trustee::REFERENCE_VALUES_FILE.to_string(),
            "[]".to_string(),
        )])),
        ..Default::default()
    }
}

pub fn dummy_pcrs_map() -> ConfigMap {
    let data = BTreeMap::from([(
        PCR_CONFIG_FILE.to_string(),
        serde_json::to_string(&dummy_pcrs()).unwrap(),
    )]);
    ConfigMap {
        data: Some(data),
        ..Default::default()
    }
}

pub fn generate_rv_ctx(client: Client) -> RvContextData {
    RvContextData {
        client,
        owner_reference: Default::default(),
        pcrs_compute_image: String::new(),
    }
}
