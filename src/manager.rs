pub use crate::acm;
use crate::{telemetry, Error, Result};
use chrono::prelude::*;
use futures::{future::BoxFuture, FutureExt, StreamExt};
use k8s_openapi::{
    api::{
        self,
        core::v1::{ObjectReference, Secret},
        networking::v1::Ingress,
        networking::v1::IngressSpec,
    },
    ByteString,
};
use kube::{
    api::{Api, ListParams, Patch, PatchParams, PostParams, ResourceExt},
    client::Client,
    runtime::{
        controller::{Action, Controller},
        events::{Event, EventType, Recorder, Reporter},
        finalizer,
        reflector::{ObjectRef, Store},
    },
    CustomResource, Resource,
};
use prometheus::{
    default_registry, proto::MetricFamily, register_histogram_vec, register_int_counter,
    HistogramOpts, HistogramVec, IntCounter,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tokio::{
    sync::RwLock,
    time::{Duration, Instant},
};
use tracing::{debug, error, event, field, info, instrument, trace, warn, Level, Span};

pub const ALB_ARN_ANNOTATION: &str = "alb.ingress.kubernetes.io/certificate-arn";
pub const ACM_MANAGER_NAME: &str = "acm-sync-manager";
const FINALIZER_NAME: &str = "acm-sync-manager.io/finalizer";

// Context for our reconciler
#[derive(Clone)]
struct Data {
    /// kubernetes client
    client: Client,
    /// AWS ACM client
    aws_client: aws_sdk_acm::Client,
    /// In memory state
    state: Arc<RwLock<State>>,
    /// Various prometheus metrics
    metrics: Metrics,
    /// Owner tag value name
    owner_tag_value: String,
}

#[instrument(skip(ctx), fields(trace_id))]
async fn apply(ingress: Arc<Ingress>, ctx: Arc<Data>) -> Result<Action> {
    let trace_id = telemetry::get_trace_id();
    Span::current().record("trace_id", &field::display(&trace_id));
    let start = Instant::now();

    let client = ctx.client.clone();
    ctx.state.write().await.last_event = Utc::now();
    let reporter = ctx.state.read().await.reporter.clone();
    let recorder = Recorder::new(client.clone(), reporter, ingress.object_ref(&()));
    let name = ingress.name_any();
    let ns = ingress.namespace().expect("ingress is namespaced");
    let arn = ingress
        .annotations()
        .get_key_value(ALB_ARN_ANNOTATION)
        .map(|e| e.1.to_owned());

    let secret_names: Vec<&String> = ingress
        .spec
        .as_ref()
        .and_then(|spec| {
            spec.tls.as_ref().map(|itls| {
                itls.iter()
                    .filter(|tls| tls.secret_name.is_some())
                    .map(|tls| tls.secret_name.as_ref().unwrap())
                    .collect()
            })
        })
        .unwrap_or_else(|| [].to_vec());

    let secrets: Api<Secret> = Api::namespaced(client.clone(), &ns);
    for sec in secret_names.iter() {
        info!(
            "ingress name: {} namespace: {} secretName: {}",
            &name, &ns, &sec
        );
        let secret = secrets.get(sec).await.map_err(Error::KubeError)?;

        if let Some(data) = secret.data {
            let (cert, chain) = extract_cert_and_chain(
                data.get("tls.crt").map(|d| d.0.clone()).unwrap_or_default(),
                data.get("ca.crt").map(|d| d.0.clone()).unwrap_or_default(),
            );

            let cs = acm::CertificateService::new(ctx.aws_client.clone());
            let mut ct = acm::Certificate::default();
            ct.name(&name)
                .namespace(&ns)
                .ingress_name(&name)
                .set_arn(arn.clone())
                .set_key(data.get("tls.key").map(|d| d.0.clone()))
                .set_cert(Some(cert))
                .set_chain(Some(chain));

            let cert_result = cs.update_certificate(&ct, &ctx.owner_tag_value).await;

            match cert_result {
                Err(Error::NotOwnerError) => {
                    return Ok(Action::requeue(Duration::from_secs(3600 / 2)))
                }
                Err(err) => {
                    recorder
                        .publish(Event {
                            action: "Import".into(),
                            reason: "ImportError".into(),
                            note: Some(format!(
                                "Unable to import certificate for ingress {}",
                                &err
                            )),
                            type_: EventType::Warning,
                            secondary: None,
                        })
                        .await
                        .map_err(Error::KubeError)?;
                    return Err(err);
                }
                Ok(cert_result) => {
                    let cert = cert_result.cert;
                    // update LB ARN annotation on ingress resource
                    if arn.is_none() || arn != cert.arn {
                        let ingresses: Api<Ingress> = Api::namespaced(client.clone(), &ns);
                        let ingress = ingress.clone();
                        let patch = serde_json::json!({
                            "apiVersion": "networking.k8s.io/v1",
                            "kind": "Ingress",
                            "metadata": {
                                "name": ingress.name_any(),
                                "namespace": ingress.namespace(),
                                "annotations": {
                                    ALB_ARN_ANNOTATION: cert.arn.as_ref()
                                }
                            }
                        });
                        let params = PatchParams::apply(ACM_MANAGER_NAME).force();
                        let patch = Patch::Apply(&patch);
                        ingresses
                            .patch(&ingress.name_any(), &params, &patch)
                            .await
                            .map_err(Error::KubeError)?;
                    }
                    recorder
                        .publish(Event {
                            action: "Sync".into(),
                            reason: cert_result.state.to_string(),
                            note: Some(format!(
                                "Certificate {} processed successfully",
                                &cert.arn.unwrap()
                            )),
                            type_: EventType::Normal,
                            secondary: None,
                        })
                        .await
                        .map_err(Error::KubeError)?;
                }
            }
        }
    }

    let duration = start.elapsed().as_millis() as f64 / 1000.0;
    //let ex = Exemplar::new_with_labels(duration, HashMap::from([("trace_id".to_string(), trace_id)]);
    ctx.metrics
        .reconcile_duration
        .with_label_values(&[])
        .observe(duration);
    //.observe_with_exemplar(duration, ex);
    ctx.metrics.handled_events.inc();

    // If no events were received, check back every 30 minutes
    Ok(Action::requeue(Duration::from_secs(3600 / 2)))
}

async fn cleanup(ingress: Arc<Ingress>, ctx: Arc<Data>) -> Result<Action> {
    info!(
        "Cleaning up ingress {}/{}",
        &ingress.namespace().unwrap_or_default(),
        &ingress.name_any()
    );

    let arn = ingress
        .annotations()
        .get_key_value(ALB_ARN_ANNOTATION)
        .map(|e| Some(e.1.to_owned()));
    if arn.is_some() {
        let cs = acm::CertificateService::new(ctx.aws_client.clone());
        let mut ct = acm::Certificate::default();
        ct.set_arn(arn.unwrap());
        cs.delete_certificate(&ct).await?;
    }

    Ok(Action::await_change())
}

fn extract_cert_and_chain(chain: Vec<u8>, root: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    let index = chain
        .split(|c| c == &b'\n')
        .position(|l| l.starts_with(b"-----END "));
    let lines = &mut chain.split(|c| c == &b'\n');
    let cert: Vec<&[u8]> = lines.by_ref().take(index.unwrap() + 1).collect();
    let chain: Vec<&[u8]> = if root.is_empty() {
        lines.collect()
    } else {
        lines.chain(root.split(|c| c == &b'\n')).collect()
    };

    (cert.join(&b'\n'), chain.join(&b'\n'))
}

/// Metrics exposed on /metrics
#[derive(Clone)]
pub struct Metrics {
    pub handled_events: IntCounter,
    pub reconcile_duration: HistogramVec,
}
impl Metrics {
    fn new() -> Self {
        let reconcile_histogram = register_histogram_vec!(
            "secret_controller_reconcile_duration_seconds",
            "The duration of reconcile to complete in seconds",
            &[],
            vec![0.01, 0.1, 0.25, 0.5, 1., 5., 15., 60.]
        )
        .unwrap();

        Metrics {
            handled_events: register_int_counter!(
                "secret_controller_handled_events",
                "handled events"
            )
            .unwrap(),
            reconcile_duration: reconcile_histogram,
        }
    }
}

/// In-memory reconciler state exposed on /
#[derive(Clone, Serialize)]
pub struct State {
    #[serde(deserialize_with = "from_ts")]
    pub last_event: DateTime<Utc>,
    #[serde(skip)]
    pub reporter: Reporter,
}
impl State {
    fn new() -> Self {
        State {
            last_event: Utc::now(),
            reporter: "secret-controller".into(),
        }
    }
}

fn secret_mapper_func(
    secret: Secret,
    cache: &Store<Ingress>,
    _client: &Client,
) -> Vec<ObjectRef<Ingress>> {
    cache
        .state()
        .iter()
        .filter_map(|i| {
            if i.namespace() == secret.namespace() {
                if let Some(spec) = &i.spec {
                    if let Some(tls) = &spec.tls {
                        for tls in tls.iter() {
                            if tls.secret_name == Some(secret.name_any()) {
                                debug!(
                                    "found secret {}/{} matching ingress {}",
                                    secret.namespace().unwrap_or_else(|| "unknown".into()),
                                    secret.name_any(),
                                    i.name_any(),
                                );
                                return Some(ObjectRef::from_obj(i.as_ref()));
                            }
                        }
                    }
                }
            }
            None
        })
        .collect()
}

/// Data owned by the Manager
#[derive(Clone)]
pub struct Manager {
    /// In memory state
    state: Arc<RwLock<State>>,
}

/// Example Manager that owns a Controller for ingresses
impl Manager {
    /// Lifecycle initialization interface for app
    ///
    /// This returns a `Manager` that drives a `Controller` + a future to be awaited
    /// It is up to `main` to wait for the controller stream.
    pub async fn new(owner_tag_value: String) -> (Self, BoxFuture<'static, ()>) {
        let shared_config = aws_config::load_from_env().await;
        let aws_client = aws_sdk_acm::Client::new(&shared_config);
        let client = Client::try_default().await.expect("create client");
        let metrics = Metrics::new();
        let state = Arc::new(RwLock::new(State::new()));
        let context = Arc::new(Data {
            client: client.clone(),
            aws_client: aws_client.clone(),
            metrics,
            state: state.clone(),
            owner_tag_value,
        });

        let secrets = Api::<Secret>::all(client.clone());
        let ingresses = Api::<Ingress>::all(client.clone());

        let controller = Controller::new(ingresses, ListParams::default());
        let store = controller.store();
        let secret_mapper = {
            let client = client.clone();
            move |secret: Secret| secret_mapper_func(secret, &store, &client)
        };

        // All good. Start controller and return its future.
        let drainer = controller
            .watches(secrets, ListParams::default(), secret_mapper)
            // .run(reconcile, error_policy, context)
            .run(
                move |ing, ctx| {
                    let ns = ing.meta().namespace.as_deref().unwrap();
                    let ingresses = Api::<Ingress>::namespaced(client.clone(), ns);
                    async move {
                        finalizer(&ingresses, FINALIZER_NAME, ing, |event| async {
                            match event {
                                finalizer::Event::Apply(ing) => apply(ing, ctx).await,
                                finalizer::Event::Cleanup(ing) => cleanup(ing, ctx).await,
                            }
                        })
                        .await
                    }
                },
                |err, _| {
                    warn!("reconcile failed: {:?}", err);
                    Action::requeue(Duration::from_secs(120))
                },
                context,
            )
            .filter_map(|x| async move { std::result::Result::ok(x) })
            .for_each(|_| futures::future::ready(()))
            .boxed();

        (Self { state }, drainer)
    }

    /// Metrics getter
    pub fn metrics(&self) -> Vec<MetricFamily> {
        default_registry().gather()
    }

    /// State getter
    pub async fn state(&self) -> State {
        self.state.read().await.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_cert_and_chain_test() {
        let cert_chain_input: &[u8] = "-----BEGIN CERTIFICATE
this is the cert
-----END CERTIFICATE"
            .as_bytes();

        let (cert, chain) = extract_cert_and_chain(cert_chain_input.to_vec(), vec![]);

        assert_eq!(&cert, &cert_chain_input);
        assert_eq!(&chain, b"");

        let cert_input: &[u8] = "-----BEGIN CERTIFICATE -----
this is the cert entry
-----END CERTIFICATE -----"
            .as_bytes();
        let chain_input: &[u8] = "-----BEGIN CERTIFICATE -----
this is the chain entry
-----END CERTIFICATE -----"
            .as_bytes();
        let cert_chain_input: &[u8] = &[cert_input, chain_input].join(&b'\n');

        let (cert, chain) = extract_cert_and_chain(cert_chain_input.to_vec(), vec![]);

        assert_eq!(cert, cert_input);
        assert_eq!(chain, chain_input);

        let cert_input: &[u8] = "-----BEGIN CERTIFICATE -----
this is the cert entry
-----END CERTIFICATE -----"
            .as_bytes();
        let chain_input: &[u8] = "-----BEGIN CERTIFICATE -----
this is the chain entry
-----END CERTIFICATE -----"
            .as_bytes();
        let root_input: &[u8] = "-----BEGIN CERTIFICATE -----
this is the root entry
-----END CERTIFICATE -----"
            .as_bytes();
        let cert_chain_input: &[u8] = &[cert_input, chain_input].join(&b'\n');

        let (cert, chain) = extract_cert_and_chain(cert_chain_input.to_vec(), root_input.to_vec());

        assert_eq!(cert, cert_input);
        assert_eq!(chain, [chain_input, root_input].join(&b'\n'));
    }
}
