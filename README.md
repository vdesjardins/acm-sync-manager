# Introduction
This kubernetes controller synchronizes certificates referenced into Ingress resources to AWS ACM.
After successful synchronization the ALB annotation *alb.ingress.kubernetes.io/certificate-arn* is
updated with the corresponding certificate ARN.

## Configuration
The prefered authentication method is with [IAM roles for Service Accounts](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html). Alternative authentication methods with this controller are surely possible but not tested at this time.

An example of policy to use that will give required access to ACM:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "acmmanager",
      "Action": [
        "acm:DescribeCertificate",
        "acm:GetCertificate",
        "acm:ListTagsForCertificate",
        "acm:AddTagsToCertificate",
        "acm:RemoveTagsFromCertificate",
        "acm:DeleteCertificate",
        "acm:ImportCertificate"
      ],
      "Effect": "Allow",
      "Resource": [
        "arn:aws:acm:*:<AWS_ACCOUNT>:certificate/*"
      ]
    },
    {
      "Sid": "acmmanagerAllResources",
      "Action": [
        "acm:ListCertificates",
        "acm:ImportCertificate"
      ],
      "Effect": "Allow",
      "Resource": [
        "*"
      ]
    }
  ]
}
```

## Installation
To install acm-sync-manager using Helm:

```bash
helm repo add acm-sync-manager https://vdesjardins.github.io/acm-sync-manager
helm install acm-sync-manager/acm-sync-manager --generate-name
```

## Testing

We need to export those variables and run the AWS setup:
```sh
export OIDC_S3_BUCKET_NAME=<your s3 bucket name>
export AWS_REGION=ca-central-1
make setup-aws
```

After we need to create our kind test cluster:

```sh
make cluster
```

Install the controller:

```sh
make install-local
```

Running tests:

```sh
make test
```
