#!/usr/bin/env bash

# set -e

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)

AWS_ACCOUNT=$(aws sts get-caller-identity | jq '.Account' -Mr)
AWS_REGION=$(aws configure get region)
OIDC_S3_BUCKET_NAME=${1}

if [[ $OIDC_S3_BUCKET_NAME == "" ]]; then
	echo 1>&1 "OIDC bucket name parameter is mandatory."
	exit 1
fi

export AWS_ACCOUNT AWS_REGION OIDC_S3_BUCKET_NAME

policy_file=$(mktemp)
assume_policy_file=$(mktemp)

trap cleanup EXIT

function cleanup() {
	rm "$policy_file" 2>/dev/null
	rm "$assume_policy_file" 2>/dev/null
}

# create bucket for OIDC provider configuration
##################################################
aws s3api create-bucket --bucket "$OIDC_S3_BUCKET_NAME" --create-bucket-configuration="{\"LocationConstraint\":\"$AWS_REGION\"}"

# create OIDC provider. Uses a fake thumbprint since it's no longer validated when using an S3 bucket
##################################################
aws iam create-open-id-connect-provider --url "https://$OIDC_S3_BUCKET_NAME.s3.$AWS_REGION.amazonaws.com/cluster/acm-sync-cluster" --client-id-list 'sts.amazonaws.com' --thumbprint-list "0000000000000000000000000000000000000000"

# policy for acm-sync-manager
##################################################
envsubst -i "$SCRIPT_DIR/acm-sync-manager-policy.json" >"$policy_file"
envsubst -i "$SCRIPT_DIR/acm-sync-manager-assume-policy.json" >"$assume_policy_file"

policy=$(aws iam create-policy --policy-name acm-sync-manager --policy-document "file://$policy_file")
policy_arn=$(echo "$policy" | jq .Policy.Arn -Mr)
aws iam create-role --role-name acm-sync-manager --assume-role-policy-document "file://$assume_policy_file"
aws iam attach-role-policy --role-name acm-sync-manager --policy-arn "$policy_arn"
