docker_build('localhost:5000/acm-sync-manager:latest', '.', dockerfile='Dockerfile')
load('ext://namespace', 'namespace_create', 'namespace_inject')
namespace_create('acm-sync-manager')
aws_account = str(local('aws sts get-caller-identity | jq \'.Account\' -Mr')).rstrip()
if aws_account == "":
    fail('AWS session invalid.')
sa_annotation = 'serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn=arn:aws:iam::%s:role/acm-sync-manager' % aws_account
k8s_yaml(helm('./charts/acm-sync-manager', name = 'acm-sync-manager', namespace = 'acm-sync-manager',
  set = [
	'serviceAccount.name=acm-sync-manager-sa',
	'image.repository=localhost:5000/acm-sync-manager',
	'image.tag=latest',
    'image.pullPolicy=Always',
    'fullNameOverride=acm-sync-manager',
    sa_annotation,
  ]
))

k8s_resource('acm-sync-manager', port_forwards=8080)
