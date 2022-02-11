use std::{collections::HashMap, str::FromStr};

use crate::Error;
use aws_sdk_acm::{
    error::{self, DeleteCertificateErrorKind, GetCertificateError, GetCertificateErrorKind},
    model::{self, Tag},
    output::GetCertificateOutput,
    Blob, Client,
};
use tracing::{debug, error, event, field, info, instrument, trace, warn, Level, Span};

const TAG_SECRET_NAME: &str = "acm-sync-manager/secret-name";
const TAG_NAMESPACE: &str = "acm-sync-manager/namespace";
const TAG_INGRESS_NAME: &str = "acm-sync-manager/ingress-name";
const TAG_OWNER: &str = "acm-sync-manager/owner";
const TAG_DEFAULT_OWNER_VALUE: &str = "acm-sync-manager";

#[derive(Default, Clone, Debug, PartialEq)]
pub struct Certificate {
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
        self.name = Some(name.into());
        self
    }

    pub fn namespace(&mut self, namespace: &str) -> &mut Certificate {
        self.namespace = Some(namespace.into());
        self
    }

    pub fn ingress_name(&mut self, name: &str) -> &mut Certificate {
        self.ingress_name = Some(name.into());
        self
    }

    pub fn set_name(&mut self, name: Option<String>) -> &mut Certificate {
        self.name = name;
        self
    }

    pub fn set_namespace(&mut self, namespace: Option<String>) -> &mut Certificate {
        self.namespace = namespace;
        self
    }

    pub fn set_key(&mut self, key: Option<Vec<u8>>) -> &mut Certificate {
        self.key = key;
        self
    }

    pub fn set_cert(&mut self, cert: Option<Vec<u8>>) -> &mut Certificate {
        self.cert = cert;
        self
    }

    pub fn set_chain(&mut self, chain: Option<Vec<u8>>) -> &mut Certificate {
        self.chain = chain;
        self
    }

    pub fn set_arn(&mut self, arn: Option<String>) -> &mut Certificate {
        self.arn = arn;
        self
    }

    pub fn set_ingress_name(&mut self, name: Option<String>) -> &mut Certificate {
        self.ingress_name = name;
        self
    }
}

impl From<GetCertificateOutput> for Certificate {
    fn from(cert: GetCertificateOutput) -> Self {
        let mut c = Certificate::default();
        c.set_cert(
            cert.certificate()
                .and_then(|ce| Some(ce.as_bytes().to_vec())),
        )
        .set_chain(
            cert.certificate_chain()
                .and_then(|ch| Some(ch.as_bytes().to_vec())),
        );
        c
    }
}

pub struct CertificateService {
    client: Client,
}

impl CertificateService {
    pub fn new(client: Client) -> CertificateService {
        CertificateService { client }
    }

    pub async fn update_certificate(&self, cert: &Certificate) -> Result<Certificate, Error> {
        let acm_cert = self.find_certificate(&cert).await?;
        let mut import_builder = self.client.import_certificate();

        // TODO: we should also compare if tags are not what we expect. if so
        // we we'll need to update them.
        if let Some(c) = acm_cert {
            info!(
                "found certificate match in ACM with ARN {}",
                c.arn.clone().unwrap()
            );
            if c.cert != cert.cert {
                info!(message = "certificate data does not match ACM");
                import_builder = import_builder.set_certificate_arn(c.arn.clone());
            } else {
                info!(message = "certificate match ACM");
                return Ok(cert.to_owned());
            }
        }

        let result = import_builder
            .set_certificate(cert.cert.as_ref().and_then(|v| Some(Blob::new(v.clone()))))
            .set_certificate_chain(cert.chain.as_ref().and_then(|v| Some(Blob::new(v.clone()))))
            .set_private_key(cert.key.as_ref().and_then(|v| Some(Blob::new(v.clone()))))
            .tags(
                Tag::builder()
                    .key(TAG_INGRESS_NAME)
                    .value(cert.ingress_name.clone().unwrap())
                    .build(),
            )
            .tags(
                Tag::builder()
                    .key(TAG_SECRET_NAME)
                    .value(cert.name.clone().unwrap())
                    .build(),
            )
            .tags(
                Tag::builder()
                    .key(TAG_NAMESPACE)
                    .value(cert.namespace.clone().unwrap())
                    .build(),
            )
            .tags(
                Tag::builder()
                    .key(TAG_OWNER)
                    .value(TAG_DEFAULT_OWNER_VALUE)
                    .build(),
            )
            .send()
            .await
            .map_err(|e| Error::SdkError(e.into()))?;

        info!(message = "certificate data imported into ACM");
        let mut acm_cert = cert.clone();
        acm_cert.arn = result.certificate_arn;
        Ok(acm_cert)
    }

    pub async fn find_certificate(
        &self,
        certificate: &Certificate,
    ) -> Result<Option<Certificate>, Error> {
        let acm_cert = if let Some(arn) = &certificate.arn {
            let co = self
                .client
                .get_certificate()
                .set_certificate_arn(Some(arn.clone()))
                .send()
                .await;

            match co {
                Err(aws_sdk_acm::SdkError::ServiceError {
                    err:
                        error::GetCertificateError {
                            kind: GetCertificateErrorKind::ResourceNotFoundException(..),
                            ..
                        },
                    ..
                }) => return Ok(None),
                Err(err) => return Err(Error::SdkError(err.into())),
                Ok(ct) => {
                    let mut result: Certificate = ct.into();
                    result
                        .set_arn(certificate.arn.clone())
                        .set_ingress_name(certificate.ingress_name.clone())
                        .set_name(certificate.name.clone())
                        .set_namespace(certificate.namespace.clone())
                        .to_owned()
                }
            }
        } else {
            return Ok(None);
        };

        // check if the certificate found is own by us.
        // if it is, fine we return it for updating if neccessary.
        // if not we need a way to notify the caller that we cannot synchronize
        // it. NotOwnerError is returned in that case.
        // need to check all tags from certificate.
        let cert_tags = self
            .client
            .list_tags_for_certificate()
            .set_certificate_arn(acm_cert.arn.to_owned())
            .send()
            .await
            .map_err(|e| Error::SdkError(e.into()))?;

        // build tag lookup table
        let mut tags_lookup = HashMap::new();
        if let Some(tags) = cert_tags.tags() {
            tags.into_iter().for_each(|t| {
                tags_lookup.insert(t.key(), t.value());
            });
        }

        // compare tags for match
        if tags_lookup.get(&Some(TAG_OWNER)) == Some(&Some(&*TAG_DEFAULT_OWNER_VALUE)) {
            return Ok(Some(acm_cert));
        }

        Err(Error::NotOwnerError)
    }

    pub async fn delete_certificate(&self, cert: &Certificate) -> Result<(), Error> {
        let result = self
            .client
            .delete_certificate()
            .certificate_arn(cert.arn.clone().unwrap())
            .send()
            .await;

        match result {
            Err(aws_sdk_acm::SdkError::ServiceError {
                err:
                    error::DeleteCertificateError {
                        kind: DeleteCertificateErrorKind::ResourceNotFoundException(..),
                        ..
                    },
                ..
            }) => return Ok(()),
            Err(err) => return Err(Error::SdkError(err.into())),
            Ok(_) => Ok(()),
        }
    }
}
