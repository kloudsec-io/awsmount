"""CollectionRef constants shared by providers (avoids import cycles)."""

from __future__ import annotations

from awsmount.providers.base import CollectionRef

__all__ = [
    "ACM_CERTIFICATES",
    "AMIS",
    "APIGW_REST_APIS",
    "AUTOSCALING_GROUPS",
    "CFN_STACKS",
    "CFN_STACK_RESOURCES",
    "CLOUDFRONT_DISTRIBUTIONS",
    "CLOUDWATCH_ALARMS",
    "DHCP_OPTIONS",
    "DYNAMODB_TABLES",
    "ECR_REPOSITORIES",
    "ECS_CLUSTERS",
    "ECS_SERVICES",
    "ECS_TASK_DEFINITIONS",
    "EKS_CLUSTERS",
    "ELASTIC_IPS",
    "EVENTBRIDGE_BUSES",
    "FLOW_LOGS",
    "IAM_GROUPS",
    "IAM_POLICIES",
    "IAM_ROLES",
    "IAM_USERS",
    "INSTANCES",
    "INTERNET_GATEWAYS",
    "KEY_PAIRS",
    "KMS_ALIASES",
    "KMS_KEYS",
    "LAMBDA_FUNCTIONS",
    "LAUNCH_TEMPLATES",
    "LOAD_BALANCERS",
    "LOG_GROUPS",
    "NAT_GATEWAYS",
    "NETWORK_ACLS",
    "NETWORK_INTERFACES",
    "ORG_ACCOUNTS",
    "ORG_POLICIES",
    "ORG_ROOTS",
    "PEERING_CONNECTIONS",
    "RDS_CLUSTERS",
    "RDS_INSTANCES",
    "REDSHIFT_CLUSTERS",
    "ROUTE53_HOSTED_ZONES",
    "ROUTE_TABLES",
    "S3_BUCKETS",
    "SECRETS",
    "SECURITY_GROUPS",
    "SNAPSHOTS",
    "SNS_TOPICS",
    "SQS_QUEUES",
    "SSM_PARAMETERS",
    "STEPFUNCTIONS_STATE_MACHINES",
    "SUBNETS",
    "TARGET_GROUPS",
    "TRANSIT_GATEWAYS",
    "VOLUMES",
    "VPCS",
    "VPC_ENDPOINTS",
]

# EC2
INSTANCES = CollectionRef("region", "ec2", "instances")
VOLUMES = CollectionRef("region", "ec2", "volumes")
SNAPSHOTS = CollectionRef("region", "ec2", "snapshots")
KEY_PAIRS = CollectionRef("region", "ec2", "key-pairs")
ELASTIC_IPS = CollectionRef("region", "ec2", "elastic-ips")
NETWORK_INTERFACES = CollectionRef("region", "ec2", "network-interfaces")
AMIS = CollectionRef("region", "ec2", "amis")

# VPC family
VPCS = CollectionRef("region", "vpc", "vpcs")
SUBNETS = CollectionRef("region", "vpc", "subnets")
SECURITY_GROUPS = CollectionRef("region", "vpc", "security-groups")
ROUTE_TABLES = CollectionRef("region", "vpc", "route-tables")
INTERNET_GATEWAYS = CollectionRef("region", "vpc", "internet-gateways")
NAT_GATEWAYS = CollectionRef("region", "vpc", "nat-gateways")
NETWORK_ACLS = CollectionRef("region", "vpc", "network-acls")
VPC_ENDPOINTS = CollectionRef("region", "vpc", "endpoints")
PEERING_CONNECTIONS = CollectionRef("region", "vpc", "peering-connections")
DHCP_OPTIONS = CollectionRef("region", "vpc", "dhcp-options")
TRANSIT_GATEWAYS = CollectionRef("region", "vpc", "transit-gateways")
FLOW_LOGS = CollectionRef("region", "vpc", "flow-logs")

# Compute and containers
LOAD_BALANCERS = CollectionRef("region", "elbv2", "load-balancers")
TARGET_GROUPS = CollectionRef("region", "elbv2", "target-groups")
LAMBDA_FUNCTIONS = CollectionRef("region", "lambda", "functions")
RDS_INSTANCES = CollectionRef("region", "rds", "instances")
RDS_CLUSTERS = CollectionRef("region", "rds", "clusters")
ECS_CLUSTERS = CollectionRef("region", "ecs", "clusters")
ECS_SERVICES = CollectionRef("region", "ecs", "clusters/services")
ECS_TASK_DEFINITIONS = CollectionRef("region", "ecs", "task-definitions")
EKS_CLUSTERS = CollectionRef("region", "eks", "clusters")

# Storage, data and messaging
S3_BUCKETS = CollectionRef("region", "s3", "buckets")
DYNAMODB_TABLES = CollectionRef("region", "dynamodb", "tables")
SQS_QUEUES = CollectionRef("region", "sqs", "queues")
SNS_TOPICS = CollectionRef("region", "sns", "topics")
KMS_KEYS = CollectionRef("region", "kms", "keys")
KMS_ALIASES = CollectionRef("region", "kms", "aliases")
LOG_GROUPS = CollectionRef("region", "logs", "log-groups")
SECRETS = CollectionRef("region", "secretsmanager", "secrets")
SSM_PARAMETERS = CollectionRef("region", "ssm", "parameters")

# Management, edge and identity
ACM_CERTIFICATES = CollectionRef("region", "acm", "certificates")
CFN_STACKS = CollectionRef("region", "cloudformation", "stacks")
CFN_STACK_RESOURCES = CollectionRef("region", "cloudformation",
                                    "stacks/resources")
APIGW_REST_APIS = CollectionRef("region", "apigateway", "rest-apis")
ROUTE53_HOSTED_ZONES = CollectionRef("global", "route53", "hosted-zones")
IAM_USERS = CollectionRef("global", "iam", "users")
IAM_ROLES = CollectionRef("global", "iam", "roles")
IAM_GROUPS = CollectionRef("global", "iam", "groups")
IAM_POLICIES = CollectionRef("global", "iam", "policies")
CLOUDFRONT_DISTRIBUTIONS = CollectionRef("global", "cloudfront",
                                         "distributions")
ORG_ACCOUNTS = CollectionRef("global", "organizations", "accounts")
ORG_ROOTS = CollectionRef("global", "organizations", "roots")
ORG_POLICIES = CollectionRef("global", "organizations", "policies")

# Added services
LAUNCH_TEMPLATES = CollectionRef("region", "ec2", "launch-templates")
AUTOSCALING_GROUPS = CollectionRef("region", "autoscaling", "groups")
CLOUDWATCH_ALARMS = CollectionRef("region", "cloudwatch", "alarms")
ECR_REPOSITORIES = CollectionRef("region", "ecr", "repositories")
STEPFUNCTIONS_STATE_MACHINES = CollectionRef("region", "stepfunctions",
                                             "state-machines")
REDSHIFT_CLUSTERS = CollectionRef("region", "redshift", "clusters")
EVENTBRIDGE_BUSES = CollectionRef("region", "eventbridge", "event-buses")
