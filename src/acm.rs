use std::{collections::HashMap, fmt::Display, str::FromStr};

use crate::Error;
use aws_sdk_acm::{
    error::{self, SdkError},
    operation::{
        delete_certificate::DeleteCertificateError, delete_certificate::DeleteCertificateOutput,
        get_certificate::GetCertificateError, get_certificate::GetCertificateOutput,
    },
    primitives::Blob,
    types::{self, Tag},
    Client,
};
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, event, field, info, instrument, trace, warn, Level, Span};

pub const TAG_SECRET_NAME: &str = "acm-sync-manager/secret-name";
pub const TAG_NAMESPACE: &str = "acm-sync-manager/namespace";
pub const TAG_INGRESS_NAME: &str = "acm-sync-manager/ingress-name";
pub const TAG_OWNER: &str = "acm-sync-manager/owner";

#[derive(
    CustomResource, Deserialize, Serialize, Clone, Debug, PartialEq, Eq, JsonSchema, Default,
)]
#[kube(
    kind = "Certificate",
    group = "acm-sync-manager.io",
    version = "v1",
    namespaced
)]
pub struct CertificateSpec {
    pub arn: Option<String>,
    pub name: Option<String>,
    pub namespace: Option<String>,
    pub ingress_name: Option<String>,
    pub key: Option<Vec<u8>>,
    pub cert: Option<Vec<u8>>,
    pub chain: Option<Vec<u8>>,
}

impl Certificate {
    pub fn name(&mut self, name: &str) -> &mut Certificate {
        self.set_name(Some(name.into()));
        self
    }

    pub fn namespace(&mut self, namespace: &str) -> &mut Certificate {
        self.set_namespace(Some(namespace.into()));
        self
    }

    pub fn ingress_name(&mut self, name: &str) -> &mut Certificate {
        self.set_ingress_name(Some(name.into()));
        self
    }

    pub fn set_name(&mut self, name: Option<String>) -> &mut Certificate {
        self.spec.name = name;
        self
    }

    pub fn set_namespace(&mut self, namespace: Option<String>) -> &mut Certificate {
        self.spec.namespace = namespace;
        self
    }

    pub fn set_key(&mut self, key: Option<Vec<u8>>) -> &mut Certificate {
        self.spec.key = key;
        self
    }

    pub fn set_cert(&mut self, cert: Option<Vec<u8>>) -> &mut Certificate {
        if let Some(c) = cert {
            self.spec.cert = Some(trim_ascii_whitespace(&c).to_vec());
        } else {
            self.spec.cert = cert;
        }
        self
    }

    pub fn set_chain(&mut self, chain: Option<Vec<u8>>) -> &mut Certificate {
        if let Some(c) = chain {
            self.spec.chain = Some(trim_ascii_whitespace(&c).to_vec());
        } else {
            self.spec.chain = chain;
        }
        self
    }

    pub fn set_arn(&mut self, arn: Option<String>) -> &mut Certificate {
        self.spec.arn = arn;
        self
    }

    pub fn set_ingress_name(&mut self, name: Option<String>) -> &mut Certificate {
        self.spec.ingress_name = name;
        self
    }
}

impl From<GetCertificateOutput> for Certificate {
    fn from(cert: GetCertificateOutput) -> Self {
        let mut c = Certificate::new("", CertificateSpec::default());
        c.set_cert(cert.certificate().map(|ce| ce.as_bytes().to_vec()))
            .set_chain(cert.certificate_chain().map(|ch| ch.as_bytes().to_vec()));
        c
    }
}

#[derive(Debug)]
pub enum CertificateUpdateState {
    UpToDate,
    Imported,
    Updated,
}

impl Display for CertificateUpdateState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl Default for CertificateUpdateState {
    fn default() -> Self {
        Self::UpToDate
    }
}

pub struct CertificateUpdateResult {
    pub cert: Certificate,
    pub state: CertificateUpdateState,
}

impl CertificateUpdateResult {
    pub fn new(cert: Certificate, state: CertificateUpdateState) -> Self {
        Self { cert, state }
    }
}

pub struct CertificateService {
    client: Client,
}

impl CertificateService {
    pub fn new(client: Client) -> CertificateService {
        CertificateService { client }
    }

    pub async fn update_certificate(
        &self,
        cert: &Certificate,
        owner_tag_value: &str,
    ) -> Result<CertificateUpdateResult, Error> {
        let acm_cert = self.find_certificate(cert, owner_tag_value).await?;
        let mut import_builder = self.client.import_certificate();
        let state;

        // TODO: we should also compare if tags are not what we expect. if so
        // we we'll need to update them. Since we cannot update tags on re-import
        // we'll need to use add/remove tags methods
        if let Some(c) = acm_cert {
            info!(
                "found certificate match in ACM with ARN {}",
                c.spec.arn.clone().unwrap()
            );
            if c.spec.cert != cert.spec.cert {
                info!("certificate data does not match ACM");
                import_builder = import_builder.set_certificate_arn(c.spec.arn);
                state = CertificateUpdateState::Updated;
            } else {
                info!(message = "certificate match ACM");
                return Ok(CertificateUpdateResult {
                    cert: cert.to_owned(),
                    state: CertificateUpdateState::UpToDate,
                });
            }
        } else {
            import_builder = import_builder
                .tags(
                    Tag::builder()
                        .key(TAG_INGRESS_NAME)
                        .value(cert.spec.ingress_name.clone().unwrap())
                        .build()
                        .map_err(|e| Error::SdkError(e.into()))?,
                )
                .tags(
                    Tag::builder()
                        .key(TAG_SECRET_NAME)
                        .value(cert.spec.name.clone().unwrap())
                        .build()
                        .map_err(|e| Error::SdkError(e.into()))?,
                )
                .tags(
                    Tag::builder()
                        .key(TAG_NAMESPACE)
                        .value(cert.spec.namespace.clone().unwrap())
                        .build()
                        .map_err(|e| Error::SdkError(e.into()))?,
                )
                .tags(
                    Tag::builder()
                        .key(TAG_OWNER)
                        .value(owner_tag_value)
                        .build()
                        .map_err(|e| Error::SdkError(e.into()))?,
                );
            state = CertificateUpdateState::Imported;
        }

        let import_result = import_builder
            .set_certificate(cert.spec.cert.as_ref().map(|v| Blob::new(v.clone())))
            .set_certificate_chain(cert.spec.chain.as_ref().map(|v| Blob::new(v.clone())))
            .set_private_key(cert.spec.key.as_ref().map(|v| Blob::new(v.clone())))
            .send()
            .await
            .map_err(|e| Error::SdkError(e.into()))?;

        info!(message = "certificate data imported into ACM");
        let mut acm_cert = cert.clone();
        acm_cert.spec.arn = import_result.certificate_arn;
        let result = CertificateUpdateResult::new(acm_cert, state);

        Ok(result)
    }

    pub async fn find_certificate(
        &self,
        certificate: &Certificate,
        owner_tag_value: &str,
    ) -> Result<Option<Certificate>, Error> {
        let acm_cert_result = if let Some(arn) = &certificate.spec.arn {
            let co = self
                .client
                .get_certificate()
                .set_certificate_arn(Some(arn.clone()))
                .send()
                .await;

            match co {
                Err(SdkError::ServiceError(err)) if err.err().is_resource_not_found_exception() => {
                    Ok(None)
                }
                Err(err) => Err(Error::SdkError(err.into())),
                Ok(ct) => {
                    let mut result: Certificate = ct.into();
                    Ok(Some(
                        result
                            .set_arn(certificate.spec.arn.clone())
                            .set_ingress_name(certificate.spec.ingress_name.clone())
                            .set_name(certificate.spec.name.clone())
                            .set_namespace(certificate.spec.namespace.clone())
                            .to_owned(),
                    ))
                }
            }?
        } else {
            // TODO: should we try to scan all certificates in ACM for a match (tags and content)
            return Ok(None);
        };

        let acm_cert = match acm_cert_result {
            Some(c) => c,
            _ => return Ok(None),
        };

        // check if the certificate found is own by us.
        // if it is, we return it for updating if neccessary.
        // if not we return NotOwnerError to notify the caller that we cannot synchronize
        // it.
        let cert_tags = self
            .client
            .list_tags_for_certificate()
            .set_certificate_arn(acm_cert.spec.arn.to_owned())
            .send()
            .await
            .map_err(|e| Error::SdkError(e.into()))?;

        // build tag lookup table
        let mut tags_lookup = HashMap::new();
        let tags = cert_tags.tags();
        tags.iter().for_each(|t| {
            tags_lookup.insert(t.key(), t.value());
        });

        // compare tags for match
        if tags_lookup.get(&TAG_OWNER) == Some(&Some(owner_tag_value)) {
            return Ok(Some(acm_cert));
        }

        Err(Error::NotOwnerError)
    }

    pub async fn delete_certificate(&self, cert: &Certificate) -> Result<(), Error> {
        let result = self
            .client
            .delete_certificate()
            .certificate_arn(cert.spec.arn.clone().unwrap())
            .send()
            .await;

        match result {
            Err(SdkError::ServiceError(err)) if err.err().is_resource_not_found_exception() => {
                Ok(())
            }
            Err(err) => Err(Error::SdkError(err.into())),
            Ok(_) => Ok(()),
        }
    }
}

pub fn trim_ascii_whitespace(x: &[u8]) -> &[u8] {
    let from = match x.iter().position(|x| !x.is_ascii_whitespace()) {
        Some(i) => i,
        None => return &x[0..0],
    };
    let to = x.iter().rposition(|x| !x.is_ascii_whitespace()).unwrap();
    &x[from..=to]
}
