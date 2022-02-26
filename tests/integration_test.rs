use k8s_openapi::api::networking::v1::Ingress;
use kube::{
    api::{DeleteParams, PostParams},
    runtime::wait::{self, Condition},
    Api, Client, ResourceExt,
};

const ALB_ARN_ANNOTATION: &str = "alb.ingress.kubernetes.io/certificate-arn";

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
        .get_key_value(ALB_ARN_ANNOTATION)
        .map_or(None, |kv| Some(kv.1));
    assert!(arn.is_some());

    // TODO: check in ACM if certificate exists and has the right tags

    ingress.delete(ing_name, &DeleteParams::default()).await?;

    // TODO: check after deletion that the certificate was deleted in ACM

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
                .get_key_value(ALB_ARN_ANNOTATION)
                .is_some();
        }
        false
    }
}
