#!/usr/bin/env bash

set -e

OIDC_S3_BUCKET_NAME=${1}
if [[ $OIDC_S3_BUCKET_NAME == "" ]]; then
	echo 1>&1 "OIDC bucket name parameter is mandatory."
	exit 1
fi

AWS_ACCOUNT=$(aws sts get-caller-identity | jq '.Account' -Mr)
policy_arn="arn:aws:iam::$AWS_ACCOUNT:policy/acm-sync-manager"

# policy for acm-sync-manager
##################################################
aws iam detach-role-policy --role-name acm-sync-manager --policy-arn "$policy_arn"
aws iam delete-role --role-name acm-sync-manager
aws iam delete-policy --policy-arn "arn:aws:iam::$AWS_ACCOUNT:policy/acm-sync-manager"

# delete OIDC provider configuration
##################################################
aws iam delete-open-id-connect-provider --open-id-connect-provider-arn "arn:aws:iam::$AWS_ACCOUNT:oidc-provider/$OIDC_S3_BUCKET_NAME.s3.$AWS_REGION.amazonaws.com/cluster/acm-sync-cluster"

# clean OIDC bucket
##################################################
aws s3 rm "s3://$OIDC_S3_BUCKET_NAME/cluster" --recursive
aws s3api delete-bucket --bucket "$OIDC_S3_BUCKET_NAME"
