use acm_sync_manager::{acm, manager};
use aws_sdk_acm::{
    error::{self, GetCertificateErrorKind},
    types,
};
use std::{collections::HashMap, time::Duration};
use tokio::time::Instant;

use k8s_openapi::api::networking::v1::{
    HTTPIngressPath, HTTPIngressRuleValue, Ingress, IngressBackend, IngressRule,
    IngressServiceBackend, IngressSpec, IngressTLS, ServiceBackendPort,
};
use kube::{
    api::{DeleteParams, PostParams},
    runtime::wait::{self, Condition},
    Api, Client, ResourceExt,
};

#[tokio::test]
async fn test_certificate_import() -> anyhow::Result<()> {
    let client = Client::try_default().await?;

    // Create a Ingress resource referencing a secret
    // uses that cert-manager annotations to provision automatically certificate
    // and secret that is referenced in the ingress.
    let ing_name = "test-e2e";
    let ingress: Api<Ingress> = Api::namespaced(client, "default");
    let ing: Ingress = serde_json::from_value(serde_json::json!({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "Ingress",
        "metadata": {
            "name": ing_name,
            "annotations": {
                "cert-manager.io/issuer": "e2e-ca-issuer"
            }
        },
        "spec": {
            "rules": [
            {
                "host": "e2e-test.acm-sync-manager.kubestack.io",
                "http": {
                    "paths": [
                    {
                        "path": "/",
                        "pathType": "Prefix",
                        "backend": {
                            "service": {
                                "name": "service1",
                                "port": {
                                    "number": 80
                                }
                            }
                        }
                    }
                    ]
                }
            }
            ],
            "tls": [
            {
                "hosts": [
                    "e2e-test.acm-sync-manager.kubestack.io"
                ],
                "secretName": "e2e-test-tls"
            }
            ]
        }
    }))?;

    ingress.create(&PostParams::default(), &ing).await?;

    wait_for_arn(ingress.clone(), ing_name).await?;

    // fetch ARN to be able to check if it exists in ACM
    let ing = ingress.get(ing_name).await?;
    let arn = ing
        .annotations()
        .get_key_value(manager::ALB_ARN_ANNOTATION)
        .map_or(None, |kv| Some(kv.1));
    assert!(arn.is_some());

    let shared_config = aws_config::load_from_env().await;
    let aws_client = aws_sdk_acm::Client::new(&shared_config);

    // check in ACM if certificate exists and has the right tags
    check_tags(&aws_client, arn.unwrap()).await?;

    // test certificate update. for this will need to compare ACM
    // previous content and after the update.
    let cert = fetch_acm_certificate(&aws_client, arn.unwrap()).await?;
    update_ingress(&ingress, ing_name).await?;
    wait_for_certificate_update(&aws_client, &cert, arn.unwrap()).await?;

    ingress.delete(ing_name, &DeleteParams::default()).await?;

    // check after deletion that the certificate was deleted in ACM
    wait_for_certificate_not_found(&aws_client, arn.unwrap()).await?;

    Ok(())
}

async fn fetch_acm_certificate(client: &aws_sdk_acm::Client, arn: &str) -> anyhow::Result<String> {
    let cert = client.get_certificate().certificate_arn(arn).send().await?;
    Ok(cert.certificate().unwrap().into())
}

async fn wait_for_certificate_update(
    client: &aws_sdk_acm::Client,
    cert: &String,
    arn: &str,
) -> anyhow::Result<()> {
    for _i in 0..20 {
        tokio::time::sleep_until(Instant::now() + Duration::from_millis(1000)).await;
        let cert_acm = fetch_acm_certificate(client, arn).await?;
        if cert_acm != *cert {
            return Ok(());
        }
    }

    Err(anyhow::anyhow!("certificate was never updated in ACM"))
}

async fn update_ingress(ingress: &Api<Ingress>, ing_name: &str) -> anyhow::Result<()> {
    let mut ing = ingress.get(ing_name).await?;
    ing.spec = Some(IngressSpec {
        rules: Some(vec![IngressRule {
            host: Some("e2e-test-up.acm-sync-manager.kubestack.io".into()),
            http: Some(HTTPIngressRuleValue {
                paths: vec![HTTPIngressPath {
                    path: Some("/".into()),
                    path_type: "ImplementationSpecific".into(),
                    backend: IngressBackend {
                        resource: None,
                        service: Some(IngressServiceBackend {
                            name: "svc".into(),
                            port: Some(ServiceBackendPort {
                                name: Some("http".into()),
                                number: None,
                            }),
                        }),
                    },
                }],
            }),
        }]),
        tls: Some(vec![IngressTLS {
            hosts: Some(vec!["e2e-test-up.acm-sync-manager.kubestack.io".into()]),
            secret_name: Some("e2e-test-tls".into()),
        }]),
        ..IngressSpec::default()
    });
    ingress
        .replace(ing_name, &PostParams::default(), &ing)
        .await
        .map(|_| Ok(()))?
}

async fn wait_for_certificate_not_found(
    client: &aws_sdk_acm::Client,
    arn: &str,
) -> anyhow::Result<()> {
    for _i in 0..10 {
        tokio::time::sleep_until(Instant::now() + Duration::from_millis(1000)).await;
        let result = check_certificate_not_found(client, arn).await;
        if let Ok(_) = result {
            return Ok(());
        }
    }

    Err(anyhow::anyhow!("certificate is found in ACM"))
}

async fn check_certificate_not_found(
    client: &aws_sdk_acm::Client,
    arn: &str,
) -> anyhow::Result<()> {
    let result = client.get_certificate().certificate_arn(arn).send().await;
    match result {
        Err(types::SdkError::ServiceError {
            err:
                error::GetCertificateError {
                    kind: GetCertificateErrorKind::ResourceNotFoundException(..),
                    ..
                },
            ..
        }) => return Ok(()),
        Err(err) => return Err(err.into()),
        Ok(_) => return Err(anyhow::anyhow!("still defined in ACM")),
    }
}

async fn check_tags(client: &aws_sdk_acm::Client, arn: &str) -> anyhow::Result<()> {
    let resp = client
        .list_tags_for_certificate()
        .certificate_arn(arn)
        .send()
        .await?;

    let tags: HashMap<_, _> = resp
        .tags()
        .unwrap()
        .into_iter()
        .map(|t| (t.key().unwrap(), t.value().unwrap()))
        .collect();
    assert!(
        tags.contains_key(acm::TAG_OWNER)
            && tags.contains_key(acm::TAG_NAMESPACE)
            && tags.contains_key(acm::TAG_SECRET_NAME)
            && tags.contains_key(acm::TAG_INGRESS_NAME),
    );

    Ok(())
}

async fn wait_for_arn(ingress: Api<Ingress>, name: &str) -> anyhow::Result<()> {
    let arn = wait::await_condition(ingress, name, is_ingress_has_arn());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(15), arn).await?;

    Ok(())
}

fn is_ingress_has_arn() -> impl Condition<Ingress> {
    |obj: Option<&Ingress>| {
        if let Some(ing) = &obj {
            return ing
                .annotations()
                .get_key_value(manager::ALB_ARN_ANNOTATION)
                .is_some();
        }
        false
    }
}
