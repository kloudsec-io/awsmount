"""Deterministic, idempotent moto seeding for the provider tests.

The module exposes one function per provider group plus
:func:`seed_all`, which calls every group that exists:

* :func:`seed_ec2_vpc` builds a rich EC2/VPC estate. It has two VPCs
  (peered), three subnets, and four security groups (three reference
  each other through their rules, one is unreferenced). It also has a
  key pair and an owned AMI. There are three instances with tags and
  user-data that contains :data:`FAKE_SECRET`, a data volume with a
  snapshot, a secondary ENI and Elastic IPs. Finally there is an
  internet gateway, a NAT gateway, a custom network ACL, public and
  private route tables, and gateway and interface endpoints.
* :func:`seed_compute` builds the compute and container estate on top
  of the EC2/VPC one. It has IAM roles for every consumer, two Lambda
  functions (one in the VPC, with environment variables holding
  :data:`FAKE_SECRET`, tags, a resource policy, an alias and a log
  group), an application load balancer with a listener and a target
  group holding the web instance, an RDS PostgreSQL instance and an
  Aurora cluster with one member (master passwords are
  :data:`FAKE_SECRET`), an ECS cluster with a Fargate service behind
  the target group and a task definition whose environment holds
  :data:`FAKE_SECRET`, and an EKS cluster with a node group.
* :func:`seed_management` builds a CloudFormation stack (security
  group, log group and a wait-condition handle) whose ``DbPassword``
  parameter is :data:`FAKE_SECRET`.
* :func:`seed_data` builds the storage, data and messaging estate. It
  has a customer-managed KMS key (alias, rotation, tags, custom key
  policy), an S3 bucket with policy, KMS encryption, public access
  block, versioning, tags and three objects whose bodies hold
  :data:`FAKE_SECRET`, an unconfigured bucket and a bucket in
  ``eu-west-1``. It also has a KMS-encrypted DynamoDB table with TTL,
  point-in-time recovery, tags and one item holding
  :data:`FAKE_SECRET`, an SQS queue (policy, KMS key, redrive policy
  to a dead-letter queue, tags, one message holding
  :data:`FAKE_SECRET`), an SNS topic (KMS key, tags, HTTP and HTTPS
  subscriptions whose endpoints embed :data:`FAKE_SECRET`, plus an SQS
  subscription) and two CloudWatch log groups (one with retention, KMS
  key, tags and a metric filter).
* :func:`seed_secrets` builds the secrets estate. It has a Secrets
  Manager secret whose name contains ``/`` (KMS data key, tags,
  resource policy, value holding :data:`FAKE_SECRET`) and a plain
  secret whose value is :data:`FAKE_SECRET`. It also has four SSM
  parameters: a tagged String, a SecureString encrypted with the data
  key, a SecureString using the default ``alias/aws/ssm`` key (both
  SecureStrings hold :data:`FAKE_SECRET`) and a StringList whose name
  has no leading slash. SSM reserves parameter names that begin with
  ``aws`` or ``ssm`` (with or without a leading ``/``), so the
  parameter names deliberately avoid those prefixes.
* :func:`seed_edge` builds ACM certificates and Route 53 zones on top
  of the EC2/VPC estate. One tagged certificate has subject alternative
  names, and two certificates share one domain name (collision rule).
  A public zone (tags, A/CNAME/TXT records) and a private zone share
  the name ``awsmount.example.`` (collision rule); the private zone is
  associated with the main VPC and with a VPC in ``eu-west-1``. A third
  public zone has no tags.
* :func:`seed_iam` builds the identity estate. Two users (one tagged,
  with an inline policy, an access key and a virtual MFA device), a
  group holding both users, a role trusted by a same-account role, a
  same-account user, a foreign account and EC2, plus an instance
  profile. A customer-managed policy has two versions (the second is
  the default) and is attached to the user, the group and the role.
* :func:`seed_cloudfront` builds a tagged CloudFront distribution
  with two aliases, an ACM viewer certificate and three origins: the
  S3 data bucket (``us-east-1``), the ``eu-west-1`` bucket and a
  custom origin whose custom header value is :data:`FAKE_SECRET`.
* :func:`seed_apigateway` builds a tagged REGIONAL REST API with two
  nested resources, a mocked GET method, a TOKEN authorizer, one
  deployment and a ``prod`` stage whose variables hold
  :data:`FAKE_SECRET`, plus two untagged APIs sharing one name
  (collision rule).
* :func:`seed_organizations` creates an organization (all features), a
  member account and a service control policy.

Determinism: names, CIDRs, tags, rules and contents are fixed.
Resource ids are chosen by the backend and returned in a dataclass.

Idempotency: every ``_ensure_*`` helper first looks for the resource it
would create, matching on CIDR, name, description, tag or association.
It reuses that resource instead of creating a duplicate, so running a
seed function twice against the same backend leaves the estate
unchanged.
"""

from __future__ import annotations

import base64
import io
import json
import zipfile
from dataclasses import dataclass
from typing import Any

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError

__all__ = [
    "ALB_NAME",
    "ALB_TAGS",
    "API_AUTHORIZER",
    "API_DEPLOYMENT_DESCRIPTION",
    "API_DESCRIPTION",
    "API_DUP_COUNT",
    "API_DUP_DESCRIPTION",
    "API_DUP_NAME",
    "API_NAME",
    "API_RECORD",
    "API_RESOURCE_PATHS",
    "API_STAGE",
    "API_STAGE_VARIABLES",
    "API_TAGS",
    "API_TARGET",
    "APP_TAGS",
    "AllSeed",
    "ApiGatewaySeed",
    "BUCKET_EU",
    "BUCKET_EU_REGION",
    "BUCKET_NAME",
    "BUCKET_PLAIN",
    "BUCKET_POLICY_SID",
    "BUCKET_TAGS",
    "BUILDER_TAGS",
    "CERT_DOMAIN",
    "CERT_DUP_COUNT",
    "CERT_DUP_DOMAIN",
    "CERT_SANS",
    "CERT_TAGS",
    "CFN_ROLE_NAME",
    "CF_ALIASES",
    "CF_API_DOMAIN",
    "CF_CALLER_REFERENCE",
    "CF_COMMENT",
    "CF_EU_DOMAIN",
    "CF_HEADER_NAME",
    "CF_HEADER_VALUE",
    "CF_ORIGIN_API",
    "CF_ORIGIN_EU",
    "CF_ORIGIN_S3",
    "CF_REGION",
    "CF_S3_DOMAIN",
    "CF_TAGS",
    "CloudFrontSeed",
    "ComputeSeed",
    "DATA_KEY_SID",
    "DATA_KMS_ALIAS",
    "DATA_KMS_DESCRIPTION",
    "DATA_KMS_TAGS",
    "DATA_VOLUME_NAME",
    "DATA_VOLUME_SIZE",
    "DB_SUBNET_GROUP",
    "DLQ_NAME",
    "DataSeed",
    "ECS_CLUSTER",
    "ECS_CONTAINER",
    "ECS_ENV",
    "ECS_EXECUTION_ROLE_NAME",
    "ECS_FAMILY",
    "ECS_SECRET_NAME",
    "ECS_SERVICE",
    "ECS_TAGS",
    "ECS_TASK_ROLE_NAME",
    "EKS_CLUSTER",
    "EKS_NODEGROUP",
    "EKS_NODE_ROLE_NAME",
    "EKS_ROLE_NAME",
    "EKS_TAGS",
    "EKS_VERSION",
    "ENDPOINT_POLICY",
    "ENI_DESCRIPTION",
    "ENI_NAME",
    "EU_VPC_CIDR",
    "EU_VPC_NAME",
    "EU_VPC_REGION",
    "Ec2VpcSeed",
    "EdgeSeed",
    "FAKE_SECRET",
    "GOLDEN_IMAGE_NAME",
    "HTTPS_ENDPOINT",
    "HTTP_ENDPOINT",
    "IAM_FOREIGN_ACCOUNT",
    "IAM_GROUP",
    "IAM_GROUP_INLINE",
    "IAM_INLINE_ACTIONS",
    "IAM_INSTANCE_PROFILE",
    "IAM_MFA_NAME",
    "IAM_POLICY",
    "IAM_POLICY_DESCRIPTION",
    "IAM_POLICY_TAGS",
    "IAM_ROLE",
    "IAM_ROLE_INLINE",
    "IAM_ROLE_TAGS",
    "IAM_TRUSTED_ROLE",
    "IAM_USER",
    "IAM_USER_INLINE",
    "IAM_USER_PLAIN",
    "IAM_USER_TAGS",
    "INSTANCE_TYPE",
    "IamSeed",
    "KEY_NAME",
    "LAMBDA_ALIAS",
    "LAMBDA_API",
    "LAMBDA_ENV",
    "LAMBDA_LOG_GROUP",
    "LAMBDA_PERMISSION_SID",
    "LAMBDA_ROLE_NAME",
    "LAMBDA_RUNTIME",
    "LAMBDA_TAGS",
    "LAMBDA_WORKER",
    "LOG_GROUP",
    "LOG_GROUP_PLAIN",
    "LOG_RETENTION",
    "LOG_TAGS",
    "MAIN_VPC_CIDR",
    "MAIN_VPC_NAME",
    "MESSAGE_BODY",
    "METRIC_FILTER",
    "METRIC_PATTERN",
    "ManagementSeed",
    "NACL_NAME",
    "OBJECT_BODY",
    "OBJECT_KEYS",
    "ORG_ACCOUNT_EMAIL",
    "ORG_ACCOUNT_NAME",
    "ORG_POLICY_DESCRIPTION",
    "ORG_POLICY_NAME",
    "ORG_POLICY_TYPE",
    "OrganizationsSeed",
    "PARAM_API_KEY",
    "PARAM_DB_PASSWORD",
    "PARAM_DESCRIPTION",
    "PARAM_HOSTS",
    "PARAM_HOSTS_VALUE",
    "PARAM_LOG_LEVEL",
    "PARAM_LOG_LEVEL_VALUE",
    "PARAM_TAGS",
    "PEER_SUBNET_CIDR",
    "PEER_VPC_CIDR",
    "PEER_VPC_NAME",
    "PRIVATE_RT_NAME",
    "PRIVATE_SUBNET_CIDR",
    "PUBLIC_ACCESS_BLOCK",
    "PUBLIC_RT_NAME",
    "PUBLIC_SUBNET_CIDR",
    "QUEUE_MAX_RECEIVE",
    "QUEUE_NAME",
    "QUEUE_TAGS",
    "QUEUE_VISIBILITY",
    "RDS_CLUSTER",
    "RDS_CLUSTER_MEMBER",
    "RDS_INSTANCE",
    "RDS_MASTER_USER",
    "RDS_TAGS",
    "REGION",
    "SECRET_DB_DESCRIPTION",
    "SECRET_DB_NAME",
    "SECRET_DB_TAGS",
    "SECRET_DB_VALUE",
    "SECRET_PLAIN_NAME",
    "SECRET_PLAIN_VALUE",
    "SECRET_POLICY_SID",
    "SEED_TAG",
    "SG_APP",
    "SG_DB",
    "SG_LONELY",
    "SG_WEB",
    "SNAPSHOT_DESCRIPTION",
    "STACK_ENVIRONMENT",
    "STACK_LOG_GROUP",
    "STACK_NAME",
    "STACK_OUTPUT_SG",
    "STACK_TAGS",
    "STACK_TEMPLATE",
    "SERVICES_LT_NAME",
    "SecretsSeed",
    "ServicesSeed",
    "TABLE_ITEM",
    "TABLE_NAME",
    "TABLE_TAGS",
    "TABLE_TTL_ATTRIBUTE",
    "TAG_SECRET_VALUE",
    "TG_NAME",
    "TG_TAGS",
    "TOPIC_DISPLAY",
    "TOPIC_NAME",
    "TOPIC_TAGS",
    "TXT_VALUE",
    "USER_DATA",
    "WEB_TAGS",
    "WWW_IP",
    "WWW_RECORD",
    "ZONE_NAME",
    "ZONE_PRIVATE_COMMENT",
    "ZONE_PUBLIC_COMMENT",
    "ZONE_SOLO_COMMENT",
    "ZONE_SOLO_NAME",
    "ZONE_TAGS",
    "authorizer_uri",
    "base_image_id",
    "bucket_policy",
    "cloudfront_config",
    "data_key_policy",
    "iam_inline_document",
    "iam_policy_document",
    "iam_trust_policy",
    "org_policy_document",
    "queue_policy",
    "secret_policy",
    "seed_all",
    "seed_services",
    "seed_apigateway",
    "seed_cloudfront",
    "seed_compute",
    "seed_data",
    "seed_ec2_vpc",
    "seed_edge",
    "seed_iam",
    "seed_management",
    "seed_organizations",
    "seed_secrets",
]

REGION = "us-east-1"
SEED_TAG = "awsmount-seed"

SERVICES_LT_NAME = "awsmount-lt"
SERVICES_ASG = "awsmount-asg"
SERVICES_ALARM = "awsmount-high-cpu"
SERVICES_ECR = "awsmount/app"
SERVICES_ECR_PLAIN = "awsmount-plain"
SERVICES_SFN = "awsmount-machine"
SERVICES_SFN_ROLE = "awsmount-sfn-role"
SERVICES_REDSHIFT = "awsmount-redshift"
SERVICES_BUS = "awsmount-bus"
SERVICES_RULE = "awsmount-rule"
SERVICES_SCHEDULE = "awsmount-schedule"
SERVICES_TAGS: dict[str, str] = {"team": "platform", SEED_TAG: "true"}

FAKE_SECRET = "FAKE-S3CR3T-awsmount-0000-do-not-leak"
USER_DATA = ("#!/bin/bash\n"
             f"export DB_PASSWORD={FAKE_SECRET}\n"
             "systemctl start app\n")
TAG_SECRET_VALUE = "tag-values-are-not-redacted"

MAIN_VPC_CIDR = "10.10.0.0/16"
PEER_VPC_CIDR = "10.20.0.0/16"
PUBLIC_SUBNET_CIDR = "10.10.1.0/24"
PRIVATE_SUBNET_CIDR = "10.10.2.0/24"
PEER_SUBNET_CIDR = "10.20.1.0/24"
MAIN_VPC_NAME = "awsmount-main"
PEER_VPC_NAME = "awsmount-peer"

SG_WEB = "awsmount-web"
SG_APP = "awsmount-app"
SG_DB = "awsmount-db"
SG_LONELY = "awsmount-lonely"

KEY_NAME = "awsmount-seed-deploy"
GOLDEN_IMAGE_NAME = "awsmount-seed-golden"
FALLBACK_AMI = "ami-12c6146b"
INSTANCE_TYPE = "t3.micro"

WEB_TAGS: dict[str, str] = {
    "Name": "web-1",
    "Environment": "prod",
    "Owner": "platform",
    "team/owner": "alice",
    "DbPassword": TAG_SECRET_VALUE,
    SEED_TAG: "true",
}
APP_TAGS: dict[str, str] = {
    "Name": "app-1",
    "Environment": "prod",
    SEED_TAG: "true",
}
BUILDER_TAGS: dict[str, str] = {
    "Name": "ami-builder",
    SEED_TAG: "true",
}

DATA_VOLUME_NAME = "awsmount-data"
DATA_VOLUME_SIZE = 20
SNAPSHOT_DESCRIPTION = "awsmount-seed data snapshot"
ENI_DESCRIPTION = "awsmount-seed secondary interface"
ENI_NAME = "app-secondary"
PUBLIC_RT_NAME = "awsmount-public-rt"
PRIVATE_RT_NAME = "awsmount-private-rt"
NACL_NAME = "awsmount-public-acl"

ENDPOINT_POLICY: dict[str, Any] = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": "*",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::awsmount-seed-bucket/*",
    }],
}

_LIVE_INSTANCE = frozenset({"pending", "running", "stopping", "stopped"})
_DEAD_STATES = frozenset({"deleted", "deleting", "failed", "rejected",
                          "expired"})

# -- compute and containers -------------------------------------------

LAMBDA_ROLE_NAME = "awsmount-lambda-role"
ECS_TASK_ROLE_NAME = "awsmount-ecs-task-role"
ECS_EXECUTION_ROLE_NAME = "awsmount-ecs-exec-role"
EKS_ROLE_NAME = "awsmount-eks-role"
EKS_NODE_ROLE_NAME = "awsmount-eks-node-role"

LAMBDA_API = "awsmount-api"
LAMBDA_WORKER = "awsmount-worker"
LAMBDA_RUNTIME = "python3.12"
LAMBDA_ENV: dict[str, str] = {
    "DB_PASSWORD": FAKE_SECRET,
    "FEATURE_FLAGS": "beta",
    "LOG_LEVEL": "info",
}
LAMBDA_TAGS: dict[str, str] = {
    "team": "payments",
    "Environment": "prod",
    SEED_TAG: "true",
}
LAMBDA_ALIAS = "live"
LAMBDA_PERMISSION_SID = "AllowS3Invoke"
LAMBDA_LOG_GROUP = f"/aws/lambda/{LAMBDA_API}"
LAMBDA_CODE = "def handler(event, context):\n    return {'ok': True}\n"

ALB_NAME = "awsmount-alb"
ALB_TAGS: dict[str, str] = {
    "Name": ALB_NAME,
    "Environment": "prod",
    SEED_TAG: "true",
}
TG_NAME = "awsmount-tg"
TG_TAGS: dict[str, str] = {
    "Environment": "prod",
    SEED_TAG: "true",
}

DB_SUBNET_GROUP = "awsmount-db-subnets"
RDS_INSTANCE = "awsmount-pg"
RDS_CLUSTER = "awsmount-aurora"
RDS_CLUSTER_MEMBER = "awsmount-aurora-1"
RDS_MASTER_USER = "awsadmin"
RDS_TAGS: dict[str, str] = {
    "Environment": "prod",
    "team": "data",
    SEED_TAG: "true",
}

ECS_CLUSTER = "awsmount-cluster"
ECS_FAMILY = "awsmount-web"
ECS_SERVICE = "awsmount-web-svc"
ECS_CONTAINER = "web"
ECS_SECRET_NAME = "awsmount-api-key-AbCdEf"
ECS_ENV: dict[str, str] = {
    "DB_PASSWORD": FAKE_SECRET,
    "LOG_LEVEL": "debug",
}
ECS_TAGS: dict[str, str] = {
    "team": "payments",
    SEED_TAG: "true",
}

EKS_CLUSTER = "awsmount-eks"
EKS_NODEGROUP = "awsmount-ng"
EKS_VERSION = "1.29"
EKS_TAGS: dict[str, str] = {
    "team": "platform",
    SEED_TAG: "true",
}

# -- management (CloudFormation) --------------------------------------

CFN_ROLE_NAME = "awsmount-cfn-role"
STACK_NAME = "awsmount-stack"
STACK_ENVIRONMENT = "prod"
STACK_LOG_GROUP = "/awsmount/cfn/app"
STACK_OUTPUT_SG = "WebSGId"
STACK_TAGS: dict[str, str] = {
    "Environment": "prod",
    SEED_TAG: "true",
}
STACK_TEMPLATE: dict[str, Any] = {
    "AWSTemplateFormatVersion": "2010-09-09",
    "Description": "awsmount seed stack",
    "Parameters": {
        "VpcId": {"Type": "String"},
        "DbPassword": {"Type": "String"},
        "Environment": {"Type": "String", "Default": "dev"},
    },
    "Resources": {
        "WebSG": {
            "Type": "AWS::EC2::SecurityGroup",
            "Properties": {
                "GroupDescription": "awsmount cfn web",
                "VpcId": {"Ref": "VpcId"},
            },
        },
        "AppLogs": {
            "Type": "AWS::Logs::LogGroup",
            "Properties": {
                "LogGroupName": STACK_LOG_GROUP,
                "RetentionInDays": 7,
            },
        },
        "Handle": {
            "Type": "AWS::CloudFormation::WaitConditionHandle",
        },
    },
    "Outputs": {
        STACK_OUTPUT_SG: {"Value": {"Ref": "WebSG"}},
    },
}

# -- storage, data and messaging --------------------------------------

DATA_KMS_ALIAS = "alias/awsmount-data"
DATA_KMS_DESCRIPTION = "awsmount seed data key"
DATA_KMS_TAGS: dict[str, str] = {
    "Environment": "prod",
    SEED_TAG: "true",
}
DATA_KEY_SID = "awsmount-seed-root"

BUCKET_NAME = "awsmount-seed-data"
BUCKET_PLAIN = "awsmount-seed-plain"
BUCKET_EU = "awsmount-seed-eu"
BUCKET_EU_REGION = "eu-west-1"
BUCKET_TAGS: dict[str, str] = {
    "Environment": "prod",
    "DbPassword": TAG_SECRET_VALUE,
    SEED_TAG: "true",
}
BUCKET_POLICY_SID = "awsmount-seed-read"
PUBLIC_ACCESS_BLOCK: dict[str, bool] = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}
OBJECT_KEYS: tuple[str, ...] = ("a.txt", "dir/b.txt", "z.txt")
OBJECT_BODY = f"password={FAKE_SECRET}\n"

TABLE_NAME = "awsmount-orders"
TABLE_TAGS: dict[str, str] = {
    "Environment": "prod",
    "team": "orders",
    SEED_TAG: "true",
}
TABLE_TTL_ATTRIBUTE = "expires_at"
TABLE_ITEM: dict[str, Any] = {
    "pk": {"S": "order-1"},
    "card": {"S": FAKE_SECRET},
}

QUEUE_NAME = "awsmount-jobs"
DLQ_NAME = "awsmount-jobs-dlq"
QUEUE_VISIBILITY = "45"
QUEUE_MAX_RECEIVE = "5"
QUEUE_TAGS: dict[str, str] = {
    "team": "jobs",
    "DbPassword": TAG_SECRET_VALUE,
    SEED_TAG: "true",
}
MESSAGE_BODY = json.dumps({"card": FAKE_SECRET}, sort_keys=True)

TOPIC_NAME = "awsmount-events"
TOPIC_DISPLAY = "awsmount events"
TOPIC_TAGS: dict[str, str] = {
    "team": "events",
    SEED_TAG: "true",
}
HTTPS_ENDPOINT = f"https://hook:{FAKE_SECRET}@hooks.example.com/sns"
HTTP_ENDPOINT = f"http://hooks.example.com/sns?token={FAKE_SECRET}"

LOG_GROUP = "/awsmount/app"
LOG_GROUP_PLAIN = "/awsmount/audit"
LOG_RETENTION = 14
LOG_TAGS: dict[str, str] = {
    "team": "platform",
    SEED_TAG: "true",
}
METRIC_FILTER = "awsmount-errors"
METRIC_PATTERN = "ERROR"

_NO_QUEUE = frozenset({"AWS.SimpleQueueService.NonExistentQueue",
                       "QueueDoesNotExist"})

# -- secrets (Secrets Manager, SSM Parameter Store) -------------------

SECRET_DB_NAME = "awsmount/db/password"
SECRET_DB_DESCRIPTION = "awsmount seed database credentials"
SECRET_DB_VALUE = json.dumps({"password": FAKE_SECRET,
                              "username": RDS_MASTER_USER},
                             sort_keys=True)
SECRET_DB_TAGS: dict[str, str] = {
    "Environment": "prod",
    "DbPassword": TAG_SECRET_VALUE,
    "team/owner": "security",
    SEED_TAG: "true",
}
SECRET_POLICY_SID = "awsmount-seed-secret-describe"
SECRET_PLAIN_NAME = "awsmount-api-token"
SECRET_PLAIN_VALUE = FAKE_SECRET

# SSM rejects names beginning with "aws" or "ssm" (case-insensitive,
# with or without a leading "/"), so these names must not start with
# "/awsmount" or "awsmount".
PARAM_LOG_LEVEL = "/app/awsmount/log-level"
PARAM_LOG_LEVEL_VALUE = "info"
PARAM_DESCRIPTION = "awsmount seed log level"
PARAM_DB_PASSWORD = "/app/awsmount/db-password"
PARAM_API_KEY = "/app/awsmount/api-key"
PARAM_HOSTS = "app-awsmount-hosts"
PARAM_HOSTS_VALUE = "a.internal,b.internal"
PARAM_TAGS: dict[str, str] = {
    "Environment": "prod",
    "ApiToken": TAG_SECRET_VALUE,
    "team/owner": "platform",
    SEED_TAG: "true",
}

# -- edge (ACM, Route 53) ---------------------------------------------

CERT_DOMAIN = "api.awsmount.example"
CERT_SANS: tuple[str, ...] = ("api.awsmount.example",
                              "www.awsmount.example")
CERT_TAGS: dict[str, str] = {
    "Environment": "prod",
    "ApiToken": TAG_SECRET_VALUE,
    SEED_TAG: "true",
}
CERT_DUP_DOMAIN = "dup.awsmount.example"
CERT_DUP_COUNT = 2

EU_VPC_REGION = "eu-west-1"
EU_VPC_CIDR = "10.30.0.0/16"
EU_VPC_NAME = "awsmount-eu"

ZONE_NAME = "awsmount.example."
ZONE_PUBLIC_COMMENT = "awsmount seed public zone"
ZONE_PRIVATE_COMMENT = "awsmount seed private zone"
ZONE_SOLO_NAME = "solo.awsmount.example."
ZONE_SOLO_COMMENT = "awsmount seed solo zone"
ZONE_TAGS: dict[str, str] = {
    "Environment": "prod",
    "ApiToken": TAG_SECRET_VALUE,
    SEED_TAG: "true",
}
WWW_RECORD = "www.awsmount.example."
WWW_IP = "192.0.2.10"
API_RECORD = "api.awsmount.example."
API_TARGET = "lb.awsmount.example.net"
TXT_VALUE = '"v=awsmount1"'
_ZONE_PREFIX = "/hostedzone/"

# -- identity (IAM) ---------------------------------------------------

IAM_USER = "awsmount-alice"
IAM_USER_PLAIN = "awsmount-bob"
IAM_GROUP = "awsmount-devs"
IAM_ROLE = "awsmount-app-role"
IAM_TRUSTED_ROLE = "awsmount-deployer"
IAM_POLICY = "awsmount-read"
IAM_POLICY_DESCRIPTION = "awsmount seed customer-managed read policy"
IAM_INSTANCE_PROFILE = "awsmount-app-profile"
IAM_MFA_NAME = "awsmount-alice-mfa"
IAM_MFA_CODES = ("123456", "654321")
IAM_FOREIGN_ACCOUNT = "999999999999"
IAM_USER_INLINE = "inline-s3"
IAM_ROLE_INLINE = "inline-logs"
IAM_GROUP_INLINE = "inline-ec2"
IAM_INLINE_ACTIONS: dict[str, str] = {
    IAM_USER_INLINE: "s3:ListAllMyBuckets",
    IAM_ROLE_INLINE: "logs:CreateLogStream",
    IAM_GROUP_INLINE: "ec2:DescribeInstances",
}
IAM_USER_TAGS: dict[str, str] = {
    "team": "platform",
    "team/owner": "alice",
    "DbPassword": TAG_SECRET_VALUE,
    SEED_TAG: "true",
}
IAM_ROLE_TAGS: dict[str, str] = {
    "Environment": "prod",
    SEED_TAG: "true",
}
IAM_POLICY_TAGS: dict[str, str] = {
    "Environment": "prod",
    "ApiToken": TAG_SECRET_VALUE,
    SEED_TAG: "true",
}

_IAM_ATTACH: dict[str, tuple[str, str, str]] = {
    "user": ("list_attached_user_policies", "attach_user_policy",
             "UserName"),
    "group": ("list_attached_group_policies", "attach_group_policy",
              "GroupName"),
    "role": ("list_attached_role_policies", "attach_role_policy",
             "RoleName"),
}
_IAM_INLINE: dict[str, tuple[str, str]] = {
    "user": ("put_user_policy", "UserName"),
    "group": ("put_group_policy", "GroupName"),
    "role": ("put_role_policy", "RoleName"),
}

# -- CloudFront -------------------------------------------------------

CF_REGION = "us-east-1"
CF_CALLER_REFERENCE = "awsmount-seed-distribution"
CF_COMMENT = "awsmount seed distribution"
CF_ALIASES: tuple[str, ...] = ("cdn.awsmount.example",
                               "static.awsmount.example")
CF_ORIGIN_S3 = "s3-data"
CF_ORIGIN_EU = "s3-eu"
CF_ORIGIN_API = "api-origin"
CF_S3_DOMAIN = f"{BUCKET_NAME}.s3.amazonaws.com"
CF_EU_DOMAIN = f"{BUCKET_EU}.s3.{BUCKET_EU_REGION}.amazonaws.com"
CF_API_DOMAIN = "origin.awsmount.example"
CF_HEADER_NAME = "X-Origin-Verify"
CF_HEADER_VALUE = FAKE_SECRET
CF_TAGS: dict[str, str] = {
    "Environment": "prod",
    "ApiToken": TAG_SECRET_VALUE,
    SEED_TAG: "true",
}

# -- API Gateway ------------------------------------------------------

API_NAME = "awsmount-rest"
API_DESCRIPTION = "awsmount seed REST api"
API_DUP_NAME = "awsmount-dup"
API_DUP_DESCRIPTION = "awsmount seed duplicate api"
API_DUP_COUNT = 2
API_TAGS: dict[str, str] = {
    "team": "api",
    "ApiToken": TAG_SECRET_VALUE,
    SEED_TAG: "true",
}
API_STAGE = "prod"
API_STAGE_VARIABLES: dict[str, str] = {
    "backendHost": "orders.internal",
    "backendKey": FAKE_SECRET,
}
API_RESOURCE_PATHS: tuple[str, ...] = ("/orders", "/orders/{id}")
API_AUTHORIZER = "awsmount-token-auth"
API_DEPLOYMENT_DESCRIPTION = "awsmount seed deployment"

# -- Organizations ----------------------------------------------------

ORG_ACCOUNT_NAME = "awsmount-sandbox"
ORG_ACCOUNT_EMAIL = "sandbox@awsmount.example"
ORG_POLICY_NAME = "awsmount-deny-leave"
ORG_POLICY_DESCRIPTION = "awsmount seed service control policy"
ORG_POLICY_TYPE = "SERVICE_CONTROL_POLICY"


@dataclass(frozen=True)
class Ec2VpcSeed:
    """Ids of the EC2/VPC estate created by :func:`seed_ec2_vpc`."""

    region: str
    account_id: str
    vpc_main: str
    vpc_peer: str
    subnet_public: str
    subnet_private: str
    subnet_peer: str
    sg_web: str
    sg_app: str
    sg_db: str
    sg_lonely: str
    key_name: str
    base_image: str
    image_golden: str
    instance_builder: str
    instance_web: str
    instance_app: str
    volume_data: str
    snapshot_data: str
    eni_extra: str
    eip_web: str
    eip_web_ip: str
    eip_nat: str
    igw: str
    nat: str
    peering: str
    rtb_public: str
    rtb_private: str
    nacl: str
    vpce_gateway: str
    vpce_interface: str

    @property
    def instances(self) -> tuple[str, ...]:
        """Every seeded instance (all of them carry user-data)."""
        return (self.instance_builder, self.instance_web,
                self.instance_app)


@dataclass(frozen=True)
class ComputeSeed:
    """Ids of the compute estate created by :func:`seed_compute`."""

    region: str
    account_id: str
    network: Ec2VpcSeed
    lambda_role_arn: str
    lambda_api_arn: str
    lambda_worker_arn: str
    lambda_log_group: str
    alb_arn: str
    alb_dns: str
    target_group_arn: str
    listener_arn: str
    listener_rule_arn: str
    db_subnet_group: str
    rds_instance: str
    rds_cluster: str
    rds_cluster_member: str
    ecs_cluster_arn: str
    ecs_task_role_arn: str
    ecs_execution_role_arn: str
    ecs_secret_arn: str
    task_definition_arn: str
    ecs_service_arn: str
    eks_role_arn: str
    eks_node_role_arn: str
    eks_cluster: str
    eks_nodegroup: str


@dataclass(frozen=True)
class ManagementSeed:
    """Ids of the CloudFormation estate from :func:`seed_management`."""

    region: str
    account_id: str
    network: Ec2VpcSeed
    cfn_role_arn: str
    stack_name: str
    stack_id: str
    stack_sg_id: str
    stack_log_group: str


@dataclass(frozen=True)
class DataSeed:
    """Ids of the storage/data/messaging estate from :func:`seed_data`."""

    region: str
    account_id: str
    kms_key_id: str
    kms_key_arn: str
    kms_alias: str
    bucket: str
    bucket_plain: str
    bucket_eu: str
    table: str
    table_arn: str
    queue_url: str
    queue_arn: str
    dlq_url: str
    dlq_arn: str
    topic_arn: str
    log_group: str
    log_group_plain: str


@dataclass(frozen=True)
class ServicesSeed:
    """Ids from :func:`seed_services` (Auto Scaling, CloudWatch, ECR, ...)."""

    region: str
    account_id: str
    launch_template_id: str
    launch_template_name: str
    asg_name: str
    eks_asg_name: str
    alarm_name: str
    ecr_repo: str
    ecr_repo_plain: str
    sfn_name: str
    sfn_arn: str
    sfn_role_arn: str
    redshift_cluster: str
    bus_name: str
    rule_name: str
    schedule_rule_name: str


@dataclass(frozen=True)
class SecretsSeed:
    """Ids of the secrets estate created by :func:`seed_secrets`."""

    region: str
    account_id: str
    kms_key_id: str
    kms_key_arn: str
    secret_db_arn: str
    secret_plain_arn: str
    parameters: tuple[str, ...]


@dataclass(frozen=True)
class EdgeSeed:
    """Ids of the ACM/Route 53 estate created by :func:`seed_edge`."""

    region: str
    account_id: str
    network: Ec2VpcSeed
    certificate_arn: str
    dup_certificate_arns: tuple[str, ...]
    vpc_eu: str
    zone_public: str
    zone_private: str
    zone_solo: str


@dataclass(frozen=True)
class IamSeed:
    """ARNs and ids of the identity estate created by :func:`seed_iam`."""

    region: str
    account_id: str
    user_arn: str
    user_plain_arn: str
    group_arn: str
    role_arn: str
    trusted_role_arn: str
    policy_arn: str
    instance_profile_arn: str
    access_key_id: str
    mfa_serial: str


@dataclass(frozen=True)
class CloudFrontSeed:
    """Ids of the CloudFront estate created by :func:`seed_cloudfront`."""

    region: str
    account_id: str
    distribution_id: str
    distribution_arn: str
    domain_name: str
    certificate_arn: str
    bucket: str
    bucket_eu: str


@dataclass(frozen=True)
class ApiGatewaySeed:
    """Ids of the API Gateway estate from :func:`seed_apigateway`."""

    region: str
    account_id: str
    api_id: str
    dup_api_ids: tuple[str, ...]
    resources: tuple[tuple[str, str], ...]
    stage: str
    deployment_id: str
    authorizer_id: str


@dataclass(frozen=True)
class OrganizationsSeed:
    """Ids of the organization created by :func:`seed_organizations`."""

    region: str
    account_id: str
    organization_id: str
    root_id: str
    member_account_id: str
    policy_id: str


@dataclass(frozen=True)
class AllSeed:
    """Result of :func:`seed_all`, one field per provider group."""

    ec2_vpc: Ec2VpcSeed
    compute: ComputeSeed
    management: ManagementSeed
    data: DataSeed
    secrets: SecretsSeed
    edge: EdgeSeed
    iam: IamSeed
    cloudfront: CloudFrontSeed
    apigateway: ApiGatewaySeed
    organizations: OrganizationsSeed
    services: ServicesSeed


# ---------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------


def _client(session: boto3.Session, service: str, region: str,
            endpoint_url: str | None) -> Any:
    kwargs: dict[str, Any] = {"region_name": region}
    if endpoint_url:
        kwargs["endpoint_url"] = endpoint_url
    return session.client(service, **kwargs)


def _s3_client(session: boto3.Session, region: str,
               endpoint_url: str | None) -> Any:
    kwargs: dict[str, Any] = {"region_name": region}
    if endpoint_url:
        kwargs["endpoint_url"] = endpoint_url
        kwargs["config"] = BotoConfig(s3={"addressing_style": "path"})
    return session.client("s3", **kwargs)


def _all(client: Any, op: str, key: str,
         **params: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for page in client.get_paginator(op).paginate(**params):
        out.extend(i for i in page.get(key, []) if isinstance(i, dict))
    return out


def _tag_list(tags: dict[str, str]) -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in sorted(tags.items())]


def _tags_of(item: dict[str, Any], field: str = "Tags") -> dict[str, str]:
    return {str(t["Key"]): str(t.get("Value", ""))
            for t in item.get(field) or [] if "Key" in t}


def _tag(ec2: Any, resource_id: str, name: str) -> None:
    ec2.create_tags(Resources=[resource_id],
                    Tags=_tag_list({"Name": name, SEED_TAG: "true"}))


def base_image_id(ec2: Any) -> str:
    """A backend-provided public AMI (smallest id), for launches."""
    images = ec2.describe_images(Owners=["amazon"]).get("Images", [])
    ids = sorted(str(i["ImageId"]) for i in images if i.get("ImageId"))
    return ids[0] if ids else FALLBACK_AMI


# ---------------------------------------------------------------------
# find-or-create helpers
# ---------------------------------------------------------------------


def _ensure_vpc(ec2: Any, cidr: str, name: str) -> str:
    for vpc in _all(ec2, "describe_vpcs", "Vpcs"):
        if vpc.get("CidrBlock") == cidr:
            return str(vpc["VpcId"])
    vpc_id = str(ec2.create_vpc(CidrBlock=cidr)["Vpc"]["VpcId"])
    _tag(ec2, vpc_id, name)
    return vpc_id


def _ensure_subnet(ec2: Any, vpc_id: str, cidr: str, zone: str,
                   name: str) -> str:
    for subnet in _all(ec2, "describe_subnets", "Subnets"):
        if subnet.get("VpcId") == vpc_id and \
                subnet.get("CidrBlock") == cidr:
            return str(subnet["SubnetId"])
    subnet_id = str(ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=cidr,
        AvailabilityZone=zone)["Subnet"]["SubnetId"])
    _tag(ec2, subnet_id, name)
    return subnet_id


def _ensure_sg(ec2: Any, vpc_id: str, name: str) -> tuple[str, bool]:
    for group in _all(ec2, "describe_security_groups", "SecurityGroups"):
        if group.get("VpcId") == vpc_id and group.get("GroupName") == name:
            return str(group["GroupId"]), False
    group_id = str(ec2.create_security_group(
        GroupName=name, Description=f"{name} (awsmount seed)",
        VpcId=vpc_id)["GroupId"])
    _tag(ec2, group_id, name)
    return group_id, True


def _allow_group(ec2: Any, group_id: str, source_id: str, port: int,
                 description: str) -> None:
    ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": port, "ToPort": port,
            "UserIdGroupPairs": [{"GroupId": source_id,
                                  "Description": description}],
        }])


def _allow_cidr(ec2: Any, group_id: str, cidr: str, port: int,
                description: str) -> None:
    ec2.authorize_security_group_ingress(
        GroupId=group_id,
        IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": port, "ToPort": port,
            "IpRanges": [{"CidrIp": cidr, "Description": description}],
        }])


def _ensure_key_pair(ec2: Any, name: str) -> str:
    pairs = ec2.describe_key_pairs().get("KeyPairs", [])
    if not any(p.get("KeyName") == name for p in pairs):
        ec2.create_key_pair(KeyName=name)
    return name


def _find_instance(ec2: Any, name: str) -> str | None:
    for reservation in _all(ec2, "describe_instances", "Reservations"):
        for inst in reservation.get("Instances", []):
            state = (inst.get("State") or {}).get("Name")
            if state in _LIVE_INSTANCE and \
                    _tags_of(inst).get("Name") == name:
                return str(inst["InstanceId"])
    return None


def _ensure_instance(ec2: Any, tags: dict[str, str], image_id: str,
                     subnet_id: str, group_id: str, key_name: str) -> str:
    found = _find_instance(ec2, tags["Name"])
    if found is not None:
        return found
    resp = ec2.run_instances(
        ImageId=image_id, InstanceType=INSTANCE_TYPE, MinCount=1,
        MaxCount=1, SubnetId=subnet_id, SecurityGroupIds=[group_id],
        KeyName=key_name, UserData=USER_DATA,
        TagSpecifications=[{"ResourceType": "instance",
                            "Tags": _tag_list(tags)}])
    return str(resp["Instances"][0]["InstanceId"])


def _ensure_image(ec2: Any, instance_id: str) -> str:
    for image in ec2.describe_images(Owners=["self"]).get("Images", []):
        if image.get("Name") == GOLDEN_IMAGE_NAME:
            return str(image["ImageId"])
    image_id = str(ec2.create_image(
        InstanceId=instance_id, Name=GOLDEN_IMAGE_NAME,
        Description="awsmount seed golden image")["ImageId"])
    _tag(ec2, image_id, GOLDEN_IMAGE_NAME)
    return image_id


def _ensure_volume(ec2: Any, zone: str) -> tuple[str, bool]:
    for volume in _all(ec2, "describe_volumes", "Volumes"):
        if _tags_of(volume).get("Name") == DATA_VOLUME_NAME and \
                volume.get("State") not in ("deleting", "deleted"):
            return str(volume["VolumeId"]), False
    volume_id = str(ec2.create_volume(
        AvailabilityZone=zone, Size=DATA_VOLUME_SIZE,
        VolumeType="gp3")["VolumeId"])
    _tag(ec2, volume_id, DATA_VOLUME_NAME)
    return volume_id, True


def _ensure_snapshot(ec2: Any, volume_id: str) -> str:
    for snap in _all(ec2, "describe_snapshots", "Snapshots",
                     OwnerIds=["self"]):
        if snap.get("Description") == SNAPSHOT_DESCRIPTION:
            return str(snap["SnapshotId"])
    snap_id = str(ec2.create_snapshot(
        VolumeId=volume_id, Description=SNAPSHOT_DESCRIPTION)["SnapshotId"])
    _tag(ec2, snap_id, "awsmount-data-snapshot")
    return snap_id


def _ensure_eni(ec2: Any, subnet_id: str, group_id: str,
                instance_id: str) -> str:
    for eni in _all(ec2, "describe_network_interfaces",
                    "NetworkInterfaces"):
        if eni.get("Description") == ENI_DESCRIPTION:
            return str(eni["NetworkInterfaceId"])
    eni_id = str(ec2.create_network_interface(
        SubnetId=subnet_id, Groups=[group_id],
        Description=ENI_DESCRIPTION)["NetworkInterface"]
        ["NetworkInterfaceId"])
    _tag(ec2, eni_id, ENI_NAME)
    ec2.attach_network_interface(NetworkInterfaceId=eni_id,
                                 InstanceId=instance_id, DeviceIndex=1)
    return eni_id


def _ensure_instance_eip(ec2: Any, instance_id: str) -> tuple[str, str]:
    for addr in ec2.describe_addresses().get("Addresses", []):
        if addr.get("InstanceId") == instance_id and \
                addr.get("AllocationId"):
            return str(addr["AllocationId"]), str(addr["PublicIp"])
    resp = ec2.allocate_address(Domain="vpc")
    ec2.associate_address(AllocationId=resp["AllocationId"],
                          InstanceId=instance_id)
    return str(resp["AllocationId"]), str(resp["PublicIp"])


def _ensure_igw(ec2: Any, vpc_id: str) -> str:
    for igw in _all(ec2, "describe_internet_gateways", "InternetGateways"):
        if any(a.get("VpcId") == vpc_id
               for a in igw.get("Attachments", [])):
            return str(igw["InternetGatewayId"])
    igw_id = str(ec2.create_internet_gateway()["InternetGateway"]
                 ["InternetGatewayId"])
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    _tag(ec2, igw_id, "awsmount-igw")
    return igw_id


def _ensure_peering(ec2: Any, requester: str, accepter: str) -> str:
    for pcx in _all(ec2, "describe_vpc_peering_connections",
                    "VpcPeeringConnections"):
        req = (pcx.get("RequesterVpcInfo") or {}).get("VpcId")
        acc = (pcx.get("AccepterVpcInfo") or {}).get("VpcId")
        code = str((pcx.get("Status") or {}).get("Code", ""))
        if req == requester and acc == accepter and \
                code not in _DEAD_STATES:
            return str(pcx["VpcPeeringConnectionId"])
    pcx_id = str(ec2.create_vpc_peering_connection(
        VpcId=requester, PeerVpcId=accepter)["VpcPeeringConnection"]
        ["VpcPeeringConnectionId"])
    ec2.accept_vpc_peering_connection(VpcPeeringConnectionId=pcx_id)
    return pcx_id


def _ensure_nat(ec2: Any, subnet_id: str) -> tuple[str, str]:
    for nat in _all(ec2, "describe_nat_gateways", "NatGateways"):
        if nat.get("SubnetId") == subnet_id and \
                nat.get("State") in ("pending", "available"):
            addresses = nat.get("NatGatewayAddresses") or [{}]
            return (str(nat["NatGatewayId"]),
                    str(addresses[0].get("AllocationId", "")))
    allocation = str(ec2.allocate_address(Domain="vpc")["AllocationId"])
    nat_id = str(ec2.create_nat_gateway(
        SubnetId=subnet_id, AllocationId=allocation)["NatGateway"]
        ["NatGatewayId"])
    return nat_id, allocation


def _ensure_route_table(ec2: Any, vpc_id: str,
                        name: str) -> tuple[str, bool]:
    for rtb in _all(ec2, "describe_route_tables", "RouteTables"):
        if rtb.get("VpcId") == vpc_id and \
                _tags_of(rtb).get("Name") == name:
            return str(rtb["RouteTableId"]), False
    rtb_id = str(ec2.create_route_table(VpcId=vpc_id)["RouteTable"]
                 ["RouteTableId"])
    _tag(ec2, rtb_id, name)
    return rtb_id, True


def _ensure_nacl(ec2: Any, vpc_id: str, subnet_id: str) -> str:
    acls = _all(ec2, "describe_network_acls", "NetworkAcls")
    for acl in acls:
        if acl.get("VpcId") == vpc_id and not acl.get("IsDefault") and \
                _tags_of(acl).get("Name") == NACL_NAME:
            return str(acl["NetworkAclId"])
    acl_id = str(ec2.create_network_acl(VpcId=vpc_id)["NetworkAcl"]
                 ["NetworkAclId"])
    _tag(ec2, acl_id, NACL_NAME)
    ec2.create_network_acl_entry(
        NetworkAclId=acl_id, RuleNumber=100, Protocol="6",
        RuleAction="allow", Egress=False, CidrBlock="0.0.0.0/0",
        PortRange={"From": 443, "To": 443})
    ec2.create_network_acl_entry(
        NetworkAclId=acl_id, RuleNumber=100, Protocol="-1",
        RuleAction="allow", Egress=True, CidrBlock="0.0.0.0/0")
    for acl in acls:
        for assoc in acl.get("Associations", []):
            if assoc.get("SubnetId") == subnet_id and \
                    assoc.get("NetworkAclAssociationId"):
                ec2.replace_network_acl_association(
                    AssociationId=assoc["NetworkAclAssociationId"],
                    NetworkAclId=acl_id)
                return acl_id
    return acl_id


def _ensure_endpoint(ec2: Any, vpc_id: str, service_name: str,
                     **create: Any) -> str:
    for ep in _all(ec2, "describe_vpc_endpoints", "VpcEndpoints"):
        state = str(ep.get("State", "")).lower()
        if ep.get("VpcId") == vpc_id and \
                ep.get("ServiceName") == service_name and \
                state not in _DEAD_STATES:
            return str(ep["VpcEndpointId"])
    resp = ec2.create_vpc_endpoint(VpcId=vpc_id, ServiceName=service_name,
                                   **create)
    return str(resp["VpcEndpoint"]["VpcEndpointId"])


# ---------------------------------------------------------------------
# compute find-or-create helpers
# ---------------------------------------------------------------------


def _error_code(exc: ClientError) -> str:
    return str(exc.response.get("Error", {}).get("Code", ""))


def _trust_policy(principal: str) -> str:
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": principal},
            "Action": "sts:AssumeRole",
        }],
    }, sort_keys=True)


def _ensure_role(iam: Any, name: str, principal: str) -> str:
    try:
        return str(iam.get_role(RoleName=name)["Role"]["Arn"])
    except ClientError as exc:
        if _error_code(exc) != "NoSuchEntity":
            raise
    resp = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_trust_policy(principal),
        Description=f"{name} (awsmount seed)",
        Tags=_tag_list({SEED_TAG: "true"}))
    return str(resp["Role"]["Arn"])


def _lambda_zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        info = zipfile.ZipInfo("handler.py",
                               date_time=(2024, 1, 1, 0, 0, 0))
        info.external_attr = 0o644 << 16
        archive.writestr(info, LAMBDA_CODE)
    return buffer.getvalue()


def _ensure_function(lam: Any, name: str, **create: Any) -> str:
    for fn in _all(lam, "list_functions", "Functions"):
        if fn.get("FunctionName") == name:
            return str(fn["FunctionArn"])
    resp = lam.create_function(FunctionName=name, **create)
    return str(resp["FunctionArn"])


def _ensure_permission(lam: Any, name: str) -> None:
    try:
        raw = lam.get_policy(FunctionName=name).get("Policy") or "{}"
        policy = json.loads(raw)
        statements = policy.get("Statement") or []
        if any(s.get("Sid") == LAMBDA_PERMISSION_SID
               for s in statements if isinstance(s, dict)):
            return
    except ClientError as exc:
        if _error_code(exc) != "ResourceNotFoundException":
            raise
    lam.add_permission(
        FunctionName=name, StatementId=LAMBDA_PERMISSION_SID,
        Action="lambda:InvokeFunction", Principal="s3.amazonaws.com",
        SourceArn="arn:aws:s3:::awsmount-seed-bucket")


def _ensure_alias(lam: Any, name: str) -> None:
    aliases = lam.list_aliases(FunctionName=name).get("Aliases", [])
    if any(a.get("Name") == LAMBDA_ALIAS for a in aliases):
        return
    lam.create_alias(FunctionName=name, Name=LAMBDA_ALIAS,
                     FunctionVersion="$LATEST",
                     Description="awsmount seed alias")


def _ensure_log_group(logs: Any, name: str) -> str:
    groups = logs.describe_log_groups(
        logGroupNamePrefix=name).get("logGroups", [])
    if not any(g.get("logGroupName") == name for g in groups):
        logs.create_log_group(logGroupName=name,
                              tags={SEED_TAG: "true"})
    return name


def _ensure_load_balancer(elb: Any, subnets: list[str],
                          groups: list[str]) -> tuple[str, str]:
    for lb in _all(elb, "describe_load_balancers", "LoadBalancers"):
        if lb.get("LoadBalancerName") == ALB_NAME:
            return str(lb["LoadBalancerArn"]), str(lb.get("DNSName", ""))
    resp = elb.create_load_balancer(
        Name=ALB_NAME, Subnets=subnets, SecurityGroups=groups,
        Scheme="internet-facing", Type="application",
        IpAddressType="ipv4", Tags=_tag_list(ALB_TAGS))
    lb = resp["LoadBalancers"][0]
    return str(lb["LoadBalancerArn"]), str(lb.get("DNSName", ""))


def _ensure_target_group(elb: Any, vpc_id: str) -> str:
    for tg in _all(elb, "describe_target_groups", "TargetGroups"):
        if tg.get("TargetGroupName") == TG_NAME:
            return str(tg["TargetGroupArn"])
    resp = elb.create_target_group(
        Name=TG_NAME, Protocol="HTTP", Port=80, VpcId=vpc_id,
        TargetType="instance", HealthCheckPath="/health",
        Tags=_tag_list(TG_TAGS))
    return str(resp["TargetGroups"][0]["TargetGroupArn"])


def _ensure_listener(elb: Any, lb_arn: str, tg_arn: str) -> str:
    listeners = elb.describe_listeners(
        LoadBalancerArn=lb_arn).get("Listeners", [])
    for listener in listeners:
        if listener.get("Port") == 80:
            return str(listener["ListenerArn"])
    resp = elb.create_listener(
        LoadBalancerArn=lb_arn, Protocol="HTTP", Port=80,
        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg_arn}])
    return str(resp["Listeners"][0]["ListenerArn"])


def _ensure_listener_rule(elb: Any, listener_arn: str, tg_arn: str) -> str:
    """A rule forwarding ``/api/*`` to the target group (priority 10)."""
    rules = elb.describe_rules(ListenerArn=listener_arn).get("Rules", [])
    for rule in rules:
        if not rule.get("IsDefault"):
            return str(rule["RuleArn"])
    resp = elb.create_rule(
        ListenerArn=listener_arn, Priority=10,
        Conditions=[{"Field": "path-pattern", "Values": ["/api/*"]}],
        Actions=[{"Type": "forward", "TargetGroupArn": tg_arn}])
    return str(resp["Rules"][0]["RuleArn"])


def _ensure_db_subnet_group(rds: Any, subnets: list[str]) -> str:
    for group in _all(rds, "describe_db_subnet_groups", "DBSubnetGroups"):
        if group.get("DBSubnetGroupName") == DB_SUBNET_GROUP:
            return DB_SUBNET_GROUP
    rds.create_db_subnet_group(
        DBSubnetGroupName=DB_SUBNET_GROUP,
        DBSubnetGroupDescription="awsmount seed database subnets",
        SubnetIds=subnets, Tags=_tag_list({SEED_TAG: "true"}))
    return DB_SUBNET_GROUP


def _ensure_db_cluster(rds: Any, group_id: str, subnet_group: str) -> str:
    for cluster in _all(rds, "describe_db_clusters", "DBClusters"):
        if cluster.get("DBClusterIdentifier") == RDS_CLUSTER:
            return RDS_CLUSTER
    rds.create_db_cluster(
        DBClusterIdentifier=RDS_CLUSTER, Engine="aurora-postgresql",
        MasterUsername=RDS_MASTER_USER, MasterUserPassword=FAKE_SECRET,
        DatabaseName="appdb", VpcSecurityGroupIds=[group_id],
        DBSubnetGroupName=subnet_group, Tags=_tag_list(RDS_TAGS))
    return RDS_CLUSTER


def _ensure_db_instance(rds: Any, ident: str, **create: Any) -> str:
    for db in _all(rds, "describe_db_instances", "DBInstances"):
        if db.get("DBInstanceIdentifier") == ident:
            return ident
    rds.create_db_instance(DBInstanceIdentifier=ident, **create)
    return ident


def _ecs_tags(tags: dict[str, str]) -> list[dict[str, str]]:
    return [{"key": k, "value": v} for k, v in sorted(tags.items())]


def _ensure_ecs_cluster(ecs: Any) -> str:
    resp = ecs.describe_clusters(clusters=[ECS_CLUSTER])
    for cluster in resp.get("clusters", []):
        if cluster.get("status") == "ACTIVE":
            return str(cluster["clusterArn"])
    created = ecs.create_cluster(
        clusterName=ECS_CLUSTER, tags=_ecs_tags(ECS_TAGS),
        settings=[{"name": "containerInsights", "value": "enabled"}])
    return str(created["cluster"]["clusterArn"])


def _container_definitions(secret_arn: str) -> list[dict[str, Any]]:
    return [{
        "name": ECS_CONTAINER,
        "image": "public.ecr.aws/nginx/nginx:1.25",
        "essential": True,
        "cpu": 256,
        "memory": 512,
        "portMappings": [{"containerPort": 8080, "protocol": "tcp"}],
        "environment": [{"name": k, "value": v}
                        for k, v in sorted(ECS_ENV.items())],
        "secrets": [{"name": "API_KEY", "valueFrom": secret_arn}],
    }]


def _ensure_task_definition(ecs: Any, task_role: str, exec_role: str,
                            secret_arn: str) -> str:
    arns = ecs.list_task_definitions(
        familyPrefix=ECS_FAMILY, status="ACTIVE").get(
            "taskDefinitionArns", [])
    if arns:
        return str(sorted(arns)[0])
    resp = ecs.register_task_definition(
        family=ECS_FAMILY, taskRoleArn=task_role,
        executionRoleArn=exec_role, networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"], cpu="256", memory="512",
        containerDefinitions=_container_definitions(secret_arn),
        tags=_ecs_tags(ECS_TAGS))
    return str(resp["taskDefinition"]["taskDefinitionArn"])


def _ensure_ecs_service(ecs: Any, cluster_arn: str, task_def: str,
                        tg_arn: str, subnet_id: str,
                        group_id: str) -> str:
    resp = ecs.describe_services(cluster=cluster_arn,
                                 services=[ECS_SERVICE])
    for service in resp.get("services", []):
        if service.get("status") == "ACTIVE":
            return str(service["serviceArn"])
    created = ecs.create_service(
        cluster=cluster_arn, serviceName=ECS_SERVICE,
        taskDefinition=task_def, desiredCount=2, launchType="FARGATE",
        loadBalancers=[{"targetGroupArn": tg_arn,
                        "containerName": ECS_CONTAINER,
                        "containerPort": 8080}],
        networkConfiguration={"awsvpcConfiguration": {
            "subnets": [subnet_id], "securityGroups": [group_id],
            "assignPublicIp": "DISABLED"}},
        tags=_ecs_tags(ECS_TAGS))
    return str(created["service"]["serviceArn"])


def _ensure_eks_cluster(eks: Any, role_arn: str, subnets: list[str],
                        group_id: str) -> str:
    if EKS_CLUSTER in eks.list_clusters().get("clusters", []):
        return EKS_CLUSTER
    eks.create_cluster(
        name=EKS_CLUSTER, version=EKS_VERSION, roleArn=role_arn,
        resourcesVpcConfig={"subnetIds": subnets,
                            "securityGroupIds": [group_id],
                            "endpointPublicAccess": True,
                            "endpointPrivateAccess": False},
        tags=dict(EKS_TAGS))
    return EKS_CLUSTER


def _ensure_nodegroup(eks: Any, node_role: str, subnet_id: str) -> str:
    groups = eks.list_nodegroups(clusterName=EKS_CLUSTER).get(
        "nodegroups", [])
    if EKS_NODEGROUP in groups:
        return EKS_NODEGROUP
    eks.create_nodegroup(
        clusterName=EKS_CLUSTER, nodegroupName=EKS_NODEGROUP,
        subnets=[subnet_id], nodeRole=node_role,
        scalingConfig={"minSize": 1, "maxSize": 2, "desiredSize": 1},
        instanceTypes=["t3.medium"], tags=dict(EKS_TAGS))
    return EKS_NODEGROUP


def _ensure_stack(cfn: Any, vpc_id: str, role_arn: str) -> str:
    for stack in _all(cfn, "describe_stacks", "Stacks"):
        if stack.get("StackName") == STACK_NAME and \
                stack.get("StackStatus") != "DELETE_COMPLETE":
            return str(stack["StackId"])
    params = {"VpcId": vpc_id, "DbPassword": FAKE_SECRET,
              "Environment": STACK_ENVIRONMENT}
    resp = cfn.create_stack(
        StackName=STACK_NAME,
        TemplateBody=json.dumps(STACK_TEMPLATE, sort_keys=True),
        Parameters=[{"ParameterKey": k, "ParameterValue": v}
                    for k, v in sorted(params.items())],
        Tags=_tag_list(STACK_TAGS), RoleARN=role_arn)
    return str(resp["StackId"])


# ---------------------------------------------------------------------
# data find-or-create helpers
# ---------------------------------------------------------------------


def data_key_policy(account_id: str) -> dict[str, Any]:
    """Key policy of the seeded data key (root of the account)."""
    return {
        "Version": "2012-10-17",
        "Id": "awsmount-seed-key-policy",
        "Statement": [{
            "Sid": DATA_KEY_SID,
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "kms:*",
            "Resource": "*",
        }],
    }


def bucket_policy(account_id: str) -> dict[str, Any]:
    """Bucket policy of :data:`BUCKET_NAME`."""
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": BUCKET_POLICY_SID,
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{BUCKET_NAME}/*",
        }],
    }


def queue_policy(account_id: str, region: str) -> dict[str, Any]:
    """Queue policy of :data:`QUEUE_NAME` (SNS may send messages)."""
    return {
        "Version": "2012-10-17",
        "Id": "awsmount-seed-queue-policy",
        "Statement": [{
            "Sid": "AllowSnsPublish",
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": f"arn:aws:sqs:{region}:{account_id}:{QUEUE_NAME}",
        }],
    }


def _ensure_data_key(kms: Any, account_id: str) -> tuple[str, str]:
    for alias in _all(kms, "list_aliases", "Aliases"):
        target = alias.get("TargetKeyId")
        if alias.get("AliasName") == DATA_KMS_ALIAS and target:
            meta = kms.describe_key(KeyId=str(target))["KeyMetadata"]
            return str(meta["KeyId"]), str(meta["Arn"])
    meta = kms.create_key(
        Description=DATA_KMS_DESCRIPTION, KeyUsage="ENCRYPT_DECRYPT",
        Policy=json.dumps(data_key_policy(account_id), sort_keys=True),
        Tags=[{"TagKey": k, "TagValue": v}
              for k, v in sorted(DATA_KMS_TAGS.items())])["KeyMetadata"]
    key_id = str(meta["KeyId"])
    kms.create_alias(AliasName=DATA_KMS_ALIAS, TargetKeyId=key_id)
    kms.enable_key_rotation(KeyId=key_id)
    return key_id, str(meta["Arn"])


def _ensure_bucket(s3: Any, name: str, region: str) -> None:
    names = {str(b.get("Name"))
             for b in s3.list_buckets().get("Buckets", [])}
    if name in names:
        return
    if region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name,
            CreateBucketConfiguration={"LocationConstraint": region})


def _seed_buckets(s3: Any, s3_eu: Any, region: str, account_id: str,
                  key_arn: str) -> None:
    _ensure_bucket(s3, BUCKET_NAME, region)
    existing = {str(o.get("Key")) for o in _all(
        s3, "list_objects_v2", "Contents", Bucket=BUCKET_NAME)}
    for key in OBJECT_KEYS:
        if key not in existing:
            s3.put_object(Bucket=BUCKET_NAME, Key=key,
                          Body=OBJECT_BODY.encode("utf-8"))
    s3.put_bucket_policy(
        Bucket=BUCKET_NAME,
        Policy=json.dumps(bucket_policy(account_id), sort_keys=True))
    s3.put_bucket_encryption(
        Bucket=BUCKET_NAME,
        ServerSideEncryptionConfiguration={"Rules": [{
            "ApplyServerSideEncryptionByDefault": {
                "SSEAlgorithm": "aws:kms", "KMSMasterKeyID": key_arn},
            "BucketKeyEnabled": True}]})
    s3.put_public_access_block(
        Bucket=BUCKET_NAME,
        PublicAccessBlockConfiguration=dict(PUBLIC_ACCESS_BLOCK))
    s3.put_bucket_versioning(
        Bucket=BUCKET_NAME, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_tagging(Bucket=BUCKET_NAME,
                          Tagging={"TagSet": _tag_list(BUCKET_TAGS)})
    _ensure_bucket(s3, BUCKET_PLAIN, region)
    _ensure_bucket(s3_eu, BUCKET_EU, BUCKET_EU_REGION)


def _ensure_table(ddb: Any, key_arn: str) -> str:
    try:
        table = ddb.describe_table(TableName=TABLE_NAME)["Table"]
    except ClientError as exc:
        if _error_code(exc) != "ResourceNotFoundException":
            raise
        table = ddb.create_table(
            TableName=TABLE_NAME,
            AttributeDefinitions=[{"AttributeName": "pk",
                                   "AttributeType": "S"}],
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
            BillingMode="PAY_PER_REQUEST",
            SSESpecification={"Enabled": True, "SSEType": "KMS",
                              "KMSMasterKeyId": key_arn},
            Tags=_tag_list(TABLE_TAGS))["TableDescription"]
    ttl = ddb.describe_time_to_live(TableName=TABLE_NAME).get(
        "TimeToLiveDescription", {})
    if ttl.get("TimeToLiveStatus") != "ENABLED":
        ddb.update_time_to_live(
            TableName=TABLE_NAME,
            TimeToLiveSpecification={"Enabled": True,
                                     "AttributeName": TABLE_TTL_ATTRIBUTE})
    ddb.update_continuous_backups(
        TableName=TABLE_NAME,
        PointInTimeRecoverySpecification={
            "PointInTimeRecoveryEnabled": True})
    ddb.put_item(TableName=TABLE_NAME, Item=TABLE_ITEM)
    return str(table["TableArn"])


def _ensure_queue(sqs: Any, name: str, attributes: dict[str, str],
                  tags: dict[str, str]) -> tuple[str, bool]:
    try:
        return str(sqs.get_queue_url(QueueName=name)["QueueUrl"]), False
    except ClientError as exc:
        if _error_code(exc) not in _NO_QUEUE:
            raise
    kwargs: dict[str, Any] = {"QueueName": name}
    if attributes:
        kwargs["Attributes"] = attributes
    if tags:
        kwargs["tags"] = tags
    return str(sqs.create_queue(**kwargs)["QueueUrl"]), True


def _queue_arn(sqs: Any, url: str) -> str:
    attrs = sqs.get_queue_attributes(QueueUrl=url,
                                     AttributeNames=["QueueArn"])
    return str(attrs["Attributes"]["QueueArn"])


def _ensure_topic(sns: Any, key_id: str) -> str:
    for topic in _all(sns, "list_topics", "Topics"):
        arn = str(topic.get("TopicArn", ""))
        if arn.rsplit(":", 1)[-1] == TOPIC_NAME:
            return arn
    resp = sns.create_topic(
        Name=TOPIC_NAME,
        Attributes={"DisplayName": TOPIC_DISPLAY,
                    "KmsMasterKeyId": key_id},
        Tags=_tag_list(TOPIC_TAGS))
    return str(resp["TopicArn"])


def _ensure_subscription(sns: Any, topic_arn: str, protocol: str,
                         endpoint: str) -> None:
    for sub in _all(sns, "list_subscriptions_by_topic", "Subscriptions",
                    TopicArn=topic_arn):
        if sub.get("Protocol") == protocol and \
                sub.get("Endpoint") == endpoint:
            return
    sns.subscribe(TopicArn=topic_arn, Protocol=protocol,
                  Endpoint=endpoint)


def _ensure_data_log_group(logs: Any, name: str, *,
                           key_arn: str | None = None,
                           tags: dict[str, str] | None = None,
                           retention: int | None = None) -> str:
    groups = logs.describe_log_groups(
        logGroupNamePrefix=name).get("logGroups", [])
    if not any(g.get("logGroupName") == name for g in groups):
        kwargs: dict[str, Any] = {"logGroupName": name}
        if key_arn:
            kwargs["kmsKeyId"] = key_arn
        if tags:
            kwargs["tags"] = dict(tags)
        logs.create_log_group(**kwargs)
    if retention:
        logs.put_retention_policy(logGroupName=name,
                                  retentionInDays=retention)
    return name


# ---------------------------------------------------------------------
# secrets find-or-create helpers
# ---------------------------------------------------------------------


def secret_policy(account_id: str) -> dict[str, Any]:
    """Resource policy of :data:`SECRET_DB_NAME`."""
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": SECRET_POLICY_SID,
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "secretsmanager:DescribeSecret",
            "Resource": "*",
        }],
    }


def _ensure_secret(sm: Any, name: str, **create: Any) -> str:
    for secret in _all(sm, "list_secrets", "SecretList"):
        if secret.get("Name") == name:
            return str(secret["ARN"])
    return str(sm.create_secret(Name=name, **create)["ARN"])


def _ensure_parameters(ssm: Any, key_id: str) -> tuple[str, ...]:
    existing = {str(p.get("Name")) for p in _all(
        ssm, "describe_parameters", "Parameters")}
    wanted: tuple[tuple[str, dict[str, Any]], ...] = (
        (PARAM_LOG_LEVEL, {"Type": "String",
                           "Value": PARAM_LOG_LEVEL_VALUE,
                           "Description": PARAM_DESCRIPTION,
                           "Tags": _tag_list(PARAM_TAGS)}),
        (PARAM_DB_PASSWORD, {"Type": "SecureString",
                             "Value": FAKE_SECRET, "KeyId": key_id}),
        (PARAM_API_KEY, {"Type": "SecureString", "Value": FAKE_SECRET}),
        (PARAM_HOSTS, {"Type": "StringList",
                       "Value": PARAM_HOSTS_VALUE}),
    )
    for name, put in wanted:
        if name not in existing:
            ssm.put_parameter(Name=name, **put)
    return tuple(sorted(name for name, _put in wanted))


# ---------------------------------------------------------------------
# edge find-or-create helpers
# ---------------------------------------------------------------------


def _ensure_certificates(acm: Any, domain: str, count: int,
                         sans: tuple[str, ...]) -> tuple[str, ...]:
    arns = [str(c["CertificateArn"]) for c in _all(
        acm, "list_certificates", "CertificateSummaryList")
        if c.get("DomainName") == domain and c.get("CertificateArn")]
    while len(arns) < count:
        kwargs: dict[str, Any] = {"DomainName": domain,
                                  "ValidationMethod": "DNS"}
        if sans:
            kwargs["SubjectAlternativeNames"] = list(sans)
        arns.append(str(acm.request_certificate(**kwargs)
                        ["CertificateArn"]))
    return tuple(sorted(arns))[:count]


def _strip_zone(value: str) -> str:
    if value.startswith(_ZONE_PREFIX):
        return value[len(_ZONE_PREFIX):]
    return value


def _ensure_zone(r53: Any, name: str, comment: str, *,
                 vpc: dict[str, str] | None = None) -> str:
    for zone in _all(r53, "list_hosted_zones", "HostedZones"):
        config = zone.get("Config") or {}
        if zone.get("Name") == name and config.get("Comment") == comment:
            return _strip_zone(str(zone["Id"]))
    kwargs: dict[str, Any] = {
        "Name": name,
        "CallerReference": "awsmount-seed-" + comment.replace(" ", "-"),
        "HostedZoneConfig": {"Comment": comment,
                             "PrivateZone": vpc is not None},
    }
    if vpc is not None:
        kwargs["VPC"] = dict(vpc)
    resp = r53.create_hosted_zone(**kwargs)
    return _strip_zone(str(resp["HostedZone"]["Id"]))


def _rrset(name: str, rtype: str, value: str) -> dict[str, Any]:
    return {"Name": name, "Type": rtype, "TTL": 300,
            "ResourceRecords": [{"Value": value}]}


def _upsert_records(r53: Any, zone_id: str) -> None:
    records = (_rrset(WWW_RECORD, "A", WWW_IP),
               _rrset(API_RECORD, "CNAME", API_TARGET),
               _rrset(ZONE_NAME, "TXT", TXT_VALUE))
    r53.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={"Comment": "awsmount seed",
                     "Changes": [{"Action": "UPSERT",
                                  "ResourceRecordSet": rr}
                                 for rr in records]})


def _ensure_zone_vpc(r53: Any, zone_id: str, vpc_id: str,
                     region: str) -> None:
    vpcs = r53.get_hosted_zone(Id=zone_id).get("VPCs", []) or []
    if any(v.get("VPCId") == vpc_id for v in vpcs):
        return
    r53.associate_vpc_with_hosted_zone(
        HostedZoneId=zone_id, VPC={"VPCRegion": region, "VPCId": vpc_id})


# ---------------------------------------------------------------------
# identity (IAM) find-or-create helpers
# ---------------------------------------------------------------------


def iam_policy_document(version: int) -> dict[str, Any]:
    """Document of version ``version`` of :data:`IAM_POLICY`."""
    actions = ["s3:GetObject", "s3:ListBucket"]
    if version >= 2:
        actions.append("s3:GetBucketLocation")
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": f"AwsmountReadV{version}",
            "Effect": "Allow",
            "Action": actions,
            "Resource": "*",
        }],
    }


def iam_inline_document(name: str) -> dict[str, Any]:
    """Document of the inline policy ``name``."""
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": IAM_INLINE_ACTIONS[name],
            "Resource": "*",
        }],
    }


def iam_trust_policy(account_id: str) -> dict[str, Any]:
    """Trust policy of :data:`IAM_ROLE`.

    It trusts a same-account role and user (both become ``trusts``
    links), a foreign account root and the EC2 service (neither does).
    """
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "TrustPrincipals",
                "Effect": "Allow",
                "Principal": {"AWS": [
                    f"arn:aws:iam::{account_id}:role/{IAM_TRUSTED_ROLE}",
                    f"arn:aws:iam::{account_id}:user/{IAM_USER}",
                    f"arn:aws:iam::{IAM_FOREIGN_ACCOUNT}:root",
                ]},
                "Action": "sts:AssumeRole",
            },
            {
                "Sid": "TrustEc2",
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            },
        ],
    }


def _ensure_user(iam: Any, name: str, tags: dict[str, str]) -> str:
    try:
        return str(iam.get_user(UserName=name)["User"]["Arn"])
    except ClientError as exc:
        if _error_code(exc) != "NoSuchEntity":
            raise
    resp = iam.create_user(UserName=name, Tags=_tag_list(tags))
    return str(resp["User"]["Arn"])


def _ensure_group(iam: Any, name: str) -> str:
    try:
        return str(iam.get_group(GroupName=name)["Group"]["Arn"])
    except ClientError as exc:
        if _error_code(exc) != "NoSuchEntity":
            raise
    return str(iam.create_group(GroupName=name)["Group"]["Arn"])


def _ensure_member(iam: Any, group: str, user: str) -> None:
    users = _all(iam, "get_group", "Users", GroupName=group)
    if not any(u.get("UserName") == user for u in users):
        iam.add_user_to_group(GroupName=group, UserName=user)


def _ensure_iam_role(iam: Any, name: str, document: str,
                     tags: dict[str, str]) -> str:
    try:
        return str(iam.get_role(RoleName=name)["Role"]["Arn"])
    except ClientError as exc:
        if _error_code(exc) != "NoSuchEntity":
            raise
    resp = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=document,
        Description=f"{name} (awsmount seed)", Tags=_tag_list(tags))
    return str(resp["Role"]["Arn"])


def _find_managed_policy(iam: Any) -> str | None:
    for policy in _all(iam, "list_policies", "Policies", Scope="Local"):
        if policy.get("PolicyName") == IAM_POLICY:
            return str(policy["Arn"])
    return None


def _ensure_managed_policy(iam: Any) -> str:
    arn = _find_managed_policy(iam)
    if arn is None:
        resp = iam.create_policy(
            PolicyName=IAM_POLICY,
            PolicyDocument=json.dumps(iam_policy_document(1),
                                      sort_keys=True),
            Description=IAM_POLICY_DESCRIPTION,
            Tags=_tag_list(IAM_POLICY_TAGS))
        arn = str(resp["Policy"]["Arn"])
    versions = _all(iam, "list_policy_versions", "Versions",
                    PolicyArn=arn)
    if len(versions) < 2:
        iam.create_policy_version(
            PolicyArn=arn,
            PolicyDocument=json.dumps(iam_policy_document(2),
                                      sort_keys=True),
            SetAsDefault=True)
    return arn


def _ensure_attached(iam: Any, kind: str, name: str, arn: str) -> None:
    list_op, attach_op, field = _IAM_ATTACH[kind]
    attached = _all(iam, list_op, "AttachedPolicies", **{field: name})
    if not any(p.get("PolicyArn") == arn for p in attached):
        getattr(iam, attach_op)(**{field: name, "PolicyArn": arn})


def _put_inline(iam: Any, kind: str, name: str, policy: str) -> None:
    op, field = _IAM_INLINE[kind]
    getattr(iam, op)(**{
        field: name,
        "PolicyName": policy,
        "PolicyDocument": json.dumps(iam_inline_document(policy),
                                     sort_keys=True),
    })


def _ensure_access_key(iam: Any, user: str) -> str:
    keys = _all(iam, "list_access_keys", "AccessKeyMetadata",
                UserName=user)
    if keys:
        return str(sorted(k["AccessKeyId"] for k in keys)[0])
    resp = iam.create_access_key(UserName=user)
    return str(resp["AccessKey"]["AccessKeyId"])


def _ensure_mfa(iam: Any, user: str, account_id: str) -> str:
    devices = _all(iam, "list_mfa_devices", "MFADevices", UserName=user)
    if devices:
        return str(devices[0]["SerialNumber"])
    try:
        resp = iam.create_virtual_mfa_device(
            VirtualMFADeviceName=IAM_MFA_NAME)
        serial = str(resp["VirtualMFADevice"]["SerialNumber"])
    except ClientError as exc:
        if _error_code(exc) != "EntityAlreadyExists":
            raise
        serial = f"arn:aws:iam::{account_id}:mfa/{IAM_MFA_NAME}"
    iam.enable_mfa_device(UserName=user, SerialNumber=serial,
                          AuthenticationCode1=IAM_MFA_CODES[0],
                          AuthenticationCode2=IAM_MFA_CODES[1])
    return serial


def _ensure_instance_profile(iam: Any, name: str, role: str) -> str:
    try:
        profile = iam.get_instance_profile(
            InstanceProfileName=name)["InstanceProfile"]
    except ClientError as exc:
        if _error_code(exc) != "NoSuchEntity":
            raise
        profile = iam.create_instance_profile(
            InstanceProfileName=name)["InstanceProfile"]
    roles = profile.get("Roles") or []
    if not any(r.get("RoleName") == role for r in roles):
        iam.add_role_to_instance_profile(InstanceProfileName=name,
                                         RoleName=role)
    return str(profile["Arn"])


# ---------------------------------------------------------------------
# CloudFront find-or-create helpers
# ---------------------------------------------------------------------


def cloudfront_config(certificate_arn: str) -> dict[str, Any]:
    """DistributionConfig of the seeded distribution."""
    s3_origin = {"OriginAccessIdentity": ""}
    return {
        "CallerReference": CF_CALLER_REFERENCE,
        "Aliases": {"Quantity": len(CF_ALIASES),
                    "Items": list(CF_ALIASES)},
        "DefaultRootObject": "index.html",
        "Origins": {"Quantity": 3, "Items": [
            {"Id": CF_ORIGIN_S3, "DomainName": CF_S3_DOMAIN,
             "S3OriginConfig": dict(s3_origin)},
            {"Id": CF_ORIGIN_EU, "DomainName": CF_EU_DOMAIN,
             "S3OriginConfig": dict(s3_origin)},
            {"Id": CF_ORIGIN_API, "DomainName": CF_API_DOMAIN,
             "CustomHeaders": {"Quantity": 1, "Items": [
                 {"HeaderName": CF_HEADER_NAME,
                  "HeaderValue": CF_HEADER_VALUE}]},
             "CustomOriginConfig": {"HTTPPort": 80, "HTTPSPort": 443,
                                    "OriginProtocolPolicy":
                                        "https-only"}},
        ]},
        "DefaultCacheBehavior": {
            "TargetOriginId": CF_ORIGIN_S3,
            "ViewerProtocolPolicy": "redirect-to-https",
            "ForwardedValues": {"QueryString": False,
                                "Cookies": {"Forward": "none"}},
            "MinTTL": 0,
        },
        "Comment": CF_COMMENT,
        "Enabled": True,
        "ViewerCertificate": {
            "ACMCertificateArn": certificate_arn,
            "SSLSupportMethod": "sni-only",
            "MinimumProtocolVersion": "TLSv1.2_2021",
        },
    }


def _distributions(cf: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for page in cf.get_paginator("list_distributions").paginate():
        dist_list = page.get("DistributionList") or {}
        out.extend(i for i in dist_list.get("Items", []) or []
                   if isinstance(i, dict))
    return out


def _ensure_distribution(cf: Any,
                         certificate_arn: str) -> tuple[str, str, str]:
    for dist in _distributions(cf):
        config = cf.get_distribution_config(
            Id=dist["Id"])["DistributionConfig"]
        if config.get("CallerReference") == CF_CALLER_REFERENCE:
            return (str(dist["Id"]), str(dist["ARN"]),
                    str(dist["DomainName"]))
    resp = cf.create_distribution_with_tags(DistributionConfigWithTags={
        "DistributionConfig": cloudfront_config(certificate_arn),
        "Tags": {"Items": _tag_list(CF_TAGS)},
    })
    dist = resp["Distribution"]
    return str(dist["Id"]), str(dist["ARN"]), str(dist["DomainName"])


# ---------------------------------------------------------------------
# API Gateway find-or-create helpers
# ---------------------------------------------------------------------


def authorizer_uri(region: str, account_id: str) -> str:
    """Lambda invocation URI of the seeded TOKEN authorizer."""
    return (f"arn:aws:apigateway:{region}:lambda:path/2015-03-31/"
            f"functions/arn:aws:lambda:{region}:{account_id}:function:"
            "awsmount-authorizer/invocations")


def _ensure_rest_api(apigw: Any) -> str:
    for api in _all(apigw, "get_rest_apis", "items"):
        if api.get("name") == API_NAME and \
                api.get("description") == API_DESCRIPTION:
            return str(api["id"])
    resp = apigw.create_rest_api(
        name=API_NAME, description=API_DESCRIPTION,
        endpointConfiguration={"types": ["REGIONAL"]},
        tags=dict(API_TAGS))
    return str(resp["id"])


def _ensure_dup_apis(apigw: Any) -> tuple[str, ...]:
    ids = [str(a["id"]) for a in _all(apigw, "get_rest_apis", "items")
           if a.get("name") == API_DUP_NAME]
    while len(ids) < API_DUP_COUNT:
        resp = apigw.create_rest_api(
            name=API_DUP_NAME, description=API_DUP_DESCRIPTION,
            endpointConfiguration={"types": ["EDGE"]})
        ids.append(str(resp["id"]))
    return tuple(sorted(ids))[:API_DUP_COUNT]


def _ensure_api_resources(apigw: Any, api_id: str) -> dict[str, str]:
    by_path = {str(r["path"]): str(r["id"]) for r in _all(
        apigw, "get_resources", "items", restApiId=api_id)}
    for path in API_RESOURCE_PATHS:
        if path in by_path:
            continue
        parent, part = path.rsplit("/", 1)
        resp = apigw.create_resource(restApiId=api_id,
                                     parentId=by_path[parent or "/"],
                                     pathPart=part)
        by_path[path] = str(resp["id"])
    return by_path


def _ensure_api_method(apigw: Any, api_id: str, resource_id: str) -> None:
    resource = apigw.get_resource(restApiId=api_id,
                                  resourceId=resource_id)
    if "GET" in (resource.get("resourceMethods") or {}):
        return
    apigw.put_method(restApiId=api_id, resourceId=resource_id,
                     httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'})


def _ensure_api_stage(apigw: Any, api_id: str) -> str:
    for stage in apigw.get_stages(restApiId=api_id).get("item", []):
        if stage.get("stageName") == API_STAGE:
            return str(stage["deploymentId"])
    resp = apigw.create_deployment(
        restApiId=api_id, stageName=API_STAGE,
        description=API_DEPLOYMENT_DESCRIPTION,
        variables=dict(API_STAGE_VARIABLES))
    return str(resp["id"])


def _ensure_authorizer(apigw: Any, api_id: str, region: str,
                       account_id: str) -> str:
    items = apigw.get_authorizers(restApiId=api_id).get("items", [])
    for auth in items:
        if auth.get("name") == API_AUTHORIZER:
            return str(auth["id"])
    resp = apigw.create_authorizer(
        restApiId=api_id, name=API_AUTHORIZER, type="TOKEN",
        authorizerUri=authorizer_uri(region, account_id),
        identitySource="method.request.header.Authorization",
        authorizerResultTtlInSeconds=300)
    return str(resp["id"])


# ---------------------------------------------------------------------
# Organizations find-or-create helpers
# ---------------------------------------------------------------------


def org_policy_document() -> dict[str, Any]:
    """Content of the seeded service control policy."""
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "DenyLeaveOrganization",
            "Effect": "Deny",
            "Action": "organizations:LeaveOrganization",
            "Resource": "*",
        }],
    }


def _ensure_organization(org: Any) -> str:
    try:
        return str(org.describe_organization()["Organization"]["Id"])
    except ClientError as exc:
        if _error_code(exc) != "AWSOrganizationsNotInUseException":
            raise
    resp = org.create_organization(FeatureSet="ALL")
    return str(resp["Organization"]["Id"])


def _ensure_org_account(org: Any) -> str:
    for account in _all(org, "list_accounts", "Accounts"):
        if account.get("Name") == ORG_ACCOUNT_NAME:
            return str(account["Id"])
    status = org.create_account(Email=ORG_ACCOUNT_EMAIL,
                                AccountName=ORG_ACCOUNT_NAME)[
                                    "CreateAccountStatus"]
    if status.get("AccountId"):
        return str(status["AccountId"])
    desc = org.describe_create_account_status(
        CreateAccountRequestId=status["Id"])
    return str(desc["CreateAccountStatus"]["AccountId"])


def _ensure_org_policy(org: Any) -> str:
    for policy in _all(org, "list_policies", "Policies",
                       Filter=ORG_POLICY_TYPE):
        if policy.get("Name") == ORG_POLICY_NAME:
            return str(policy["Id"])
    resp = org.create_policy(
        Content=json.dumps(org_policy_document(), sort_keys=True),
        Description=ORG_POLICY_DESCRIPTION, Name=ORG_POLICY_NAME,
        Type=ORG_POLICY_TYPE)
    return str(resp["Policy"]["PolicySummary"]["Id"])


# ---------------------------------------------------------------------
# provider groups
# ---------------------------------------------------------------------


def seed_ec2_vpc(session: boto3.Session, *, region: str = REGION,
                 endpoint_url: str | None = None) -> Ec2VpcSeed:
    """Seed (or find) the EC2 + VPC estate described in the module doc."""
    ec2 = _client(session, "ec2", region, endpoint_url)
    sts = _client(session, "sts", region, endpoint_url)
    account_id = str(sts.get_caller_identity()["Account"])
    zone_a, zone_b = f"{region}a", f"{region}b"

    vpc_main = _ensure_vpc(ec2, MAIN_VPC_CIDR, MAIN_VPC_NAME)
    vpc_peer = _ensure_vpc(ec2, PEER_VPC_CIDR, PEER_VPC_NAME)
    subnet_public = _ensure_subnet(ec2, vpc_main, PUBLIC_SUBNET_CIDR,
                                   zone_a, "awsmount-public")
    subnet_private = _ensure_subnet(ec2, vpc_main, PRIVATE_SUBNET_CIDR,
                                    zone_b, "awsmount-private")
    subnet_peer = _ensure_subnet(ec2, vpc_peer, PEER_SUBNET_CIDR, zone_a,
                                 "awsmount-peer-subnet")

    sg_web, new_web = _ensure_sg(ec2, vpc_main, SG_WEB)
    sg_app, new_app = _ensure_sg(ec2, vpc_main, SG_APP)
    sg_db, new_db = _ensure_sg(ec2, vpc_main, SG_DB)
    sg_lonely, _new_lonely = _ensure_sg(ec2, vpc_peer, SG_LONELY)
    if new_web:
        _allow_cidr(ec2, sg_web, "0.0.0.0/0", 443, "public https")
        _allow_group(ec2, sg_web, sg_app, 9100, "metrics from app")
    if new_app:
        _allow_group(ec2, sg_app, sg_web, 8080, "http from web")
    if new_db:
        _allow_group(ec2, sg_db, sg_app, 5432, "postgres from app")

    key_name = _ensure_key_pair(ec2, KEY_NAME)
    base_image = base_image_id(ec2)
    builder = _ensure_instance(ec2, BUILDER_TAGS, base_image,
                               subnet_public, sg_web, key_name)
    golden = _ensure_image(ec2, builder)
    web = _ensure_instance(ec2, WEB_TAGS, golden, subnet_public, sg_web,
                           key_name)
    app = _ensure_instance(ec2, APP_TAGS, golden, subnet_private, sg_app,
                           key_name)

    volume, new_volume = _ensure_volume(ec2, zone_a)
    if new_volume:
        ec2.attach_volume(VolumeId=volume, InstanceId=web,
                          Device="/dev/sdf")
    snapshot = _ensure_snapshot(ec2, volume)
    eni = _ensure_eni(ec2, subnet_private, sg_app, app)
    eip_web, eip_web_ip = _ensure_instance_eip(ec2, web)

    igw = _ensure_igw(ec2, vpc_main)
    peering = _ensure_peering(ec2, vpc_main, vpc_peer)
    nat, eip_nat = _ensure_nat(ec2, subnet_public)

    rtb_public, new_public = _ensure_route_table(ec2, vpc_main,
                                                 PUBLIC_RT_NAME)
    if new_public:
        ec2.create_route(RouteTableId=rtb_public,
                         DestinationCidrBlock="0.0.0.0/0",
                         GatewayId=igw)
        ec2.create_route(RouteTableId=rtb_public,
                         DestinationCidrBlock=PEER_VPC_CIDR,
                         VpcPeeringConnectionId=peering)
        ec2.associate_route_table(RouteTableId=rtb_public,
                                  SubnetId=subnet_public)
    rtb_private, new_private = _ensure_route_table(ec2, vpc_main,
                                                   PRIVATE_RT_NAME)
    if new_private:
        ec2.create_route(RouteTableId=rtb_private,
                         DestinationCidrBlock="0.0.0.0/0",
                         NatGatewayId=nat)
        ec2.associate_route_table(RouteTableId=rtb_private,
                                  SubnetId=subnet_private)

    nacl = _ensure_nacl(ec2, vpc_main, subnet_public)
    vpce_gateway = _ensure_endpoint(
        ec2, vpc_main, f"com.amazonaws.{region}.s3",
        VpcEndpointType="Gateway", RouteTableIds=[rtb_private],
        PolicyDocument=json.dumps(ENDPOINT_POLICY, sort_keys=True))
    vpce_interface = _ensure_endpoint(
        ec2, vpc_main, f"com.amazonaws.{region}.sqs",
        VpcEndpointType="Interface", SubnetIds=[subnet_private],
        SecurityGroupIds=[sg_db], PrivateDnsEnabled=False)

    return Ec2VpcSeed(
        region=region, account_id=account_id, vpc_main=vpc_main,
        vpc_peer=vpc_peer, subnet_public=subnet_public,
        subnet_private=subnet_private, subnet_peer=subnet_peer,
        sg_web=sg_web, sg_app=sg_app, sg_db=sg_db, sg_lonely=sg_lonely,
        key_name=key_name, base_image=base_image, image_golden=golden,
        instance_builder=builder, instance_web=web, instance_app=app,
        volume_data=volume, snapshot_data=snapshot, eni_extra=eni,
        eip_web=eip_web, eip_web_ip=eip_web_ip, eip_nat=eip_nat, igw=igw,
        nat=nat, peering=peering, rtb_public=rtb_public,
        rtb_private=rtb_private, nacl=nacl, vpce_gateway=vpce_gateway,
        vpce_interface=vpce_interface)


def seed_compute(session: boto3.Session, *, region: str = REGION,
                 endpoint_url: str | None = None,
                 ec2_vpc: Ec2VpcSeed | None = None) -> ComputeSeed:
    """Seed (or find) ELBv2, Lambda, RDS, ECS and EKS resources.

    The EC2/VPC estate is seeded first (idempotently) unless it is
    passed in as ``ec2_vpc``.
    """
    net = ec2_vpc if ec2_vpc is not None else seed_ec2_vpc(
        session, region=region, endpoint_url=endpoint_url)
    iam = _client(session, "iam", region, endpoint_url)
    lam = _client(session, "lambda", region, endpoint_url)
    logs = _client(session, "logs", region, endpoint_url)
    elb = _client(session, "elbv2", region, endpoint_url)
    rds = _client(session, "rds", region, endpoint_url)
    ecs = _client(session, "ecs", region, endpoint_url)
    eks = _client(session, "eks", region, endpoint_url)
    subnets = [net.subnet_public, net.subnet_private]

    lambda_role = _ensure_role(iam, LAMBDA_ROLE_NAME,
                               "lambda.amazonaws.com")
    task_role = _ensure_role(iam, ECS_TASK_ROLE_NAME,
                             "ecs-tasks.amazonaws.com")
    exec_role = _ensure_role(iam, ECS_EXECUTION_ROLE_NAME,
                             "ecs-tasks.amazonaws.com")
    eks_role = _ensure_role(iam, EKS_ROLE_NAME, "eks.amazonaws.com")
    node_role = _ensure_role(iam, EKS_NODE_ROLE_NAME, "ec2.amazonaws.com")

    code = {"ZipFile": _lambda_zip()}
    api_arn = _ensure_function(
        lam, LAMBDA_API, Runtime=LAMBDA_RUNTIME, Role=lambda_role,
        Handler="handler.handler", Code=code, Timeout=30, MemorySize=256,
        Description="awsmount seed api function",
        Environment={"Variables": dict(LAMBDA_ENV)},
        VpcConfig={"SubnetIds": subnets,
                   "SecurityGroupIds": [net.sg_app]},
        Tags=dict(LAMBDA_TAGS))
    worker_arn = _ensure_function(
        lam, LAMBDA_WORKER, Runtime=LAMBDA_RUNTIME, Role=lambda_role,
        Handler="handler.handler", Code=code, Timeout=60, MemorySize=128,
        Description="awsmount seed worker function",
        Tags={SEED_TAG: "true"})
    _ensure_permission(lam, LAMBDA_API)
    _ensure_alias(lam, LAMBDA_API)
    log_group = _ensure_log_group(logs, LAMBDA_LOG_GROUP)

    alb_arn, alb_dns = _ensure_load_balancer(elb, subnets, [net.sg_web])
    tg_arn = _ensure_target_group(elb, net.vpc_main)
    elb.register_targets(TargetGroupArn=tg_arn,
                         Targets=[{"Id": net.instance_web, "Port": 80}])
    listener = _ensure_listener(elb, alb_arn, tg_arn)
    listener_rule = _ensure_listener_rule(elb, listener, tg_arn)

    subnet_group = _ensure_db_subnet_group(rds, subnets)
    cluster = _ensure_db_cluster(rds, net.sg_db, subnet_group)
    instance = _ensure_db_instance(
        rds, RDS_INSTANCE, DBInstanceClass="db.t3.micro",
        Engine="postgres", MasterUsername=RDS_MASTER_USER,
        MasterUserPassword=FAKE_SECRET, AllocatedStorage=20,
        VpcSecurityGroupIds=[net.sg_db], DBSubnetGroupName=subnet_group,
        Tags=_tag_list(RDS_TAGS))
    member = _ensure_db_instance(
        rds, RDS_CLUSTER_MEMBER, DBInstanceClass="db.r5.large",
        Engine="aurora-postgresql", DBClusterIdentifier=cluster,
        DBSubnetGroupName=subnet_group, Tags=_tag_list(RDS_TAGS))

    secret_arn = (f"arn:aws:secretsmanager:{region}:{net.account_id}"
                  f":secret:{ECS_SECRET_NAME}")
    cluster_arn = _ensure_ecs_cluster(ecs)
    task_def = _ensure_task_definition(ecs, task_role, exec_role,
                                       secret_arn)
    service_arn = _ensure_ecs_service(ecs, cluster_arn, task_def, tg_arn,
                                      net.subnet_private, net.sg_app)

    eks_cluster = _ensure_eks_cluster(eks, eks_role, subnets, net.sg_app)
    nodegroup = _ensure_nodegroup(eks, node_role, net.subnet_private)

    return ComputeSeed(
        region=region, account_id=net.account_id, network=net,
        lambda_role_arn=lambda_role, lambda_api_arn=api_arn,
        lambda_worker_arn=worker_arn, lambda_log_group=log_group,
        alb_arn=alb_arn, alb_dns=alb_dns, target_group_arn=tg_arn,
        listener_arn=listener, listener_rule_arn=listener_rule,
        db_subnet_group=subnet_group,
        rds_instance=instance, rds_cluster=cluster,
        rds_cluster_member=member, ecs_cluster_arn=cluster_arn,
        ecs_task_role_arn=task_role, ecs_execution_role_arn=exec_role,
        ecs_secret_arn=secret_arn, task_definition_arn=task_def,
        ecs_service_arn=service_arn, eks_role_arn=eks_role,
        eks_node_role_arn=node_role, eks_cluster=eks_cluster,
        eks_nodegroup=nodegroup)


def seed_management(session: boto3.Session, *, region: str = REGION,
                    endpoint_url: str | None = None,
                    ec2_vpc: Ec2VpcSeed | None = None) -> ManagementSeed:
    """Seed (or find) the CloudFormation stack of the module doc."""
    net = ec2_vpc if ec2_vpc is not None else seed_ec2_vpc(
        session, region=region, endpoint_url=endpoint_url)
    iam = _client(session, "iam", region, endpoint_url)
    cfn = _client(session, "cloudformation", region, endpoint_url)
    role = _ensure_role(iam, CFN_ROLE_NAME, "cloudformation.amazonaws.com")
    stack_id = _ensure_stack(cfn, net.vpc_main, role)
    stack = cfn.describe_stacks(StackName=STACK_NAME)["Stacks"][0]
    outputs = {str(o["OutputKey"]): str(o.get("OutputValue", ""))
               for o in stack.get("Outputs", []) if "OutputKey" in o}
    return ManagementSeed(
        region=region, account_id=net.account_id, network=net,
        cfn_role_arn=role, stack_name=STACK_NAME, stack_id=stack_id,
        stack_sg_id=outputs.get(STACK_OUTPUT_SG, ""),
        stack_log_group=STACK_LOG_GROUP)


def seed_data(session: boto3.Session, *, region: str = REGION,
              endpoint_url: str | None = None) -> DataSeed:
    """Seed (or find) S3, DynamoDB, SQS, SNS, KMS and Logs resources."""
    sts = _client(session, "sts", region, endpoint_url)
    account_id = str(sts.get_caller_identity()["Account"])

    kms = _client(session, "kms", region, endpoint_url)
    key_id, key_arn = _ensure_data_key(kms, account_id)

    s3 = _s3_client(session, region, endpoint_url)
    s3_eu = _s3_client(session, BUCKET_EU_REGION, endpoint_url)
    _seed_buckets(s3, s3_eu, region, account_id, key_arn)

    ddb = _client(session, "dynamodb", region, endpoint_url)
    table_arn = _ensure_table(ddb, key_arn)

    sqs = _client(session, "sqs", region, endpoint_url)
    dlq_url, _dlq_new = _ensure_queue(sqs, DLQ_NAME, {},
                                      {SEED_TAG: "true"})
    dlq_arn = _queue_arn(sqs, dlq_url)
    redrive = json.dumps({"deadLetterTargetArn": dlq_arn,
                          "maxReceiveCount": QUEUE_MAX_RECEIVE},
                         sort_keys=True)
    queue_url, created = _ensure_queue(
        sqs, QUEUE_NAME,
        {"VisibilityTimeout": QUEUE_VISIBILITY,
         "KmsMasterKeyId": key_id,
         "Policy": json.dumps(queue_policy(account_id, region),
                              sort_keys=True),
         "RedrivePolicy": redrive},
        dict(QUEUE_TAGS))
    if created:
        sqs.send_message(QueueUrl=queue_url, MessageBody=MESSAGE_BODY)
    queue_arn = _queue_arn(sqs, queue_url)

    sns = _client(session, "sns", region, endpoint_url)
    topic_arn = _ensure_topic(sns, key_id)
    for protocol, endpoint in (("https", HTTPS_ENDPOINT),
                               ("http", HTTP_ENDPOINT),
                               ("sqs", queue_arn)):
        _ensure_subscription(sns, topic_arn, protocol, endpoint)

    logs = _client(session, "logs", region, endpoint_url)
    _ensure_data_log_group(logs, LOG_GROUP, key_arn=key_arn,
                           tags=LOG_TAGS, retention=LOG_RETENTION)
    _ensure_data_log_group(logs, LOG_GROUP_PLAIN)
    logs.put_metric_filter(
        logGroupName=LOG_GROUP, filterName=METRIC_FILTER,
        filterPattern=METRIC_PATTERN,
        metricTransformations=[{"metricName": "AppErrors",
                                "metricNamespace": "awsmount",
                                "metricValue": "1"}])

    return DataSeed(
        region=region, account_id=account_id, kms_key_id=key_id,
        kms_key_arn=key_arn, kms_alias=DATA_KMS_ALIAS,
        bucket=BUCKET_NAME, bucket_plain=BUCKET_PLAIN,
        bucket_eu=BUCKET_EU, table=TABLE_NAME, table_arn=table_arn,
        queue_url=queue_url, queue_arn=queue_arn, dlq_url=dlq_url,
        dlq_arn=dlq_arn, topic_arn=topic_arn, log_group=LOG_GROUP,
        log_group_plain=LOG_GROUP_PLAIN)


def seed_secrets(session: boto3.Session, *, region: str = REGION,
                 endpoint_url: str | None = None) -> SecretsSeed:
    """Seed (or find) Secrets Manager secrets and SSM parameters.

    The KMS data key of :func:`seed_data` is reused (or created) so
    that the secret and one SecureString parameter link to it.
    """
    sts = _client(session, "sts", region, endpoint_url)
    account_id = str(sts.get_caller_identity()["Account"])
    kms = _client(session, "kms", region, endpoint_url)
    key_id, key_arn = _ensure_data_key(kms, account_id)

    sm = _client(session, "secretsmanager", region, endpoint_url)
    db_arn = _ensure_secret(
        sm, SECRET_DB_NAME, Description=SECRET_DB_DESCRIPTION,
        KmsKeyId=key_arn, SecretString=SECRET_DB_VALUE,
        Tags=_tag_list(SECRET_DB_TAGS))
    sm.put_resource_policy(
        SecretId=db_arn,
        ResourcePolicy=json.dumps(secret_policy(account_id),
                                  sort_keys=True))
    plain_arn = _ensure_secret(sm, SECRET_PLAIN_NAME,
                               SecretString=SECRET_PLAIN_VALUE)

    ssm = _client(session, "ssm", region, endpoint_url)
    parameters = _ensure_parameters(ssm, key_id)

    return SecretsSeed(
        region=region, account_id=account_id, kms_key_id=key_id,
        kms_key_arn=key_arn, secret_db_arn=db_arn,
        secret_plain_arn=plain_arn, parameters=parameters)


def seed_edge(session: boto3.Session, *, region: str = REGION,
              endpoint_url: str | None = None,
              ec2_vpc: Ec2VpcSeed | None = None) -> EdgeSeed:
    """Seed (or find) ACM certificates and Route 53 hosted zones.

    The EC2/VPC estate is seeded first (idempotently) unless it is
    passed in as ``ec2_vpc``; the private zone uses its main VPC.
    """
    net = ec2_vpc if ec2_vpc is not None else seed_ec2_vpc(
        session, region=region, endpoint_url=endpoint_url)

    acm = _client(session, "acm", region, endpoint_url)
    cert = _ensure_certificates(acm, CERT_DOMAIN, 1, CERT_SANS)[0]
    acm.add_tags_to_certificate(CertificateArn=cert,
                                Tags=_tag_list(CERT_TAGS))
    dups = _ensure_certificates(acm, CERT_DUP_DOMAIN, CERT_DUP_COUNT, ())

    ec2_eu = _client(session, "ec2", EU_VPC_REGION, endpoint_url)
    vpc_eu = _ensure_vpc(ec2_eu, EU_VPC_CIDR, EU_VPC_NAME)

    r53 = _client(session, "route53", region, endpoint_url)
    public = _ensure_zone(r53, ZONE_NAME, ZONE_PUBLIC_COMMENT)
    _upsert_records(r53, public)
    r53.change_tags_for_resource(ResourceType="hostedzone",
                                 ResourceId=public,
                                 AddTags=_tag_list(ZONE_TAGS))
    private = _ensure_zone(r53, ZONE_NAME, ZONE_PRIVATE_COMMENT,
                           vpc={"VPCRegion": region,
                                "VPCId": net.vpc_main})
    _ensure_zone_vpc(r53, private, vpc_eu, EU_VPC_REGION)
    solo = _ensure_zone(r53, ZONE_SOLO_NAME, ZONE_SOLO_COMMENT)

    return EdgeSeed(
        region=region, account_id=net.account_id, network=net,
        certificate_arn=cert, dup_certificate_arns=dups, vpc_eu=vpc_eu,
        zone_public=public, zone_private=private, zone_solo=solo)


def seed_iam(session: boto3.Session, *, region: str = REGION,
             endpoint_url: str | None = None) -> IamSeed:
    """Seed (or find) the IAM users, group, roles and policy."""
    sts = _client(session, "sts", region, endpoint_url)
    account_id = str(sts.get_caller_identity()["Account"])
    iam = _client(session, "iam", region, endpoint_url)

    user_arn = _ensure_user(iam, IAM_USER, IAM_USER_TAGS)
    plain_arn = _ensure_user(iam, IAM_USER_PLAIN, {SEED_TAG: "true"})
    group_arn = _ensure_group(iam, IAM_GROUP)
    for user in (IAM_USER, IAM_USER_PLAIN):
        _ensure_member(iam, IAM_GROUP, user)

    trusted_arn = _ensure_iam_role(
        iam, IAM_TRUSTED_ROLE, _trust_policy("ec2.amazonaws.com"),
        {SEED_TAG: "true"})
    role_arn = _ensure_iam_role(
        iam, IAM_ROLE,
        json.dumps(iam_trust_policy(account_id), sort_keys=True),
        IAM_ROLE_TAGS)

    policy_arn = _ensure_managed_policy(iam)
    _ensure_attached(iam, "user", IAM_USER, policy_arn)
    _ensure_attached(iam, "group", IAM_GROUP, policy_arn)
    _ensure_attached(iam, "role", IAM_ROLE, policy_arn)
    _put_inline(iam, "user", IAM_USER, IAM_USER_INLINE)
    _put_inline(iam, "group", IAM_GROUP, IAM_GROUP_INLINE)
    _put_inline(iam, "role", IAM_ROLE, IAM_ROLE_INLINE)

    key_id = _ensure_access_key(iam, IAM_USER)
    serial = _ensure_mfa(iam, IAM_USER, account_id)
    profile_arn = _ensure_instance_profile(iam, IAM_INSTANCE_PROFILE,
                                           IAM_ROLE)

    return IamSeed(
        region=region, account_id=account_id, user_arn=user_arn,
        user_plain_arn=plain_arn, group_arn=group_arn,
        role_arn=role_arn, trusted_role_arn=trusted_arn,
        policy_arn=policy_arn, instance_profile_arn=profile_arn,
        access_key_id=key_id, mfa_serial=serial)


def seed_cloudfront(session: boto3.Session, *, region: str = REGION,
                    endpoint_url: str | None = None) -> CloudFrontSeed:
    """Seed (or find) the CloudFront distribution of the module doc.

    The origin buckets and the viewer certificate (always in
    :data:`CF_REGION`, as CloudFront requires) are found or created
    with the same helpers as :func:`seed_data` and :func:`seed_edge`.
    """
    sts = _client(session, "sts", region, endpoint_url)
    account_id = str(sts.get_caller_identity()["Account"])

    s3 = _s3_client(session, region, endpoint_url)
    s3_eu = _s3_client(session, BUCKET_EU_REGION, endpoint_url)
    _ensure_bucket(s3, BUCKET_NAME, region)
    _ensure_bucket(s3_eu, BUCKET_EU, BUCKET_EU_REGION)

    acm = _client(session, "acm", CF_REGION, endpoint_url)
    cert = _ensure_certificates(acm, CERT_DOMAIN, 1, CERT_SANS)[0]

    cf = _client(session, "cloudfront", CF_REGION, endpoint_url)
    dist_id, dist_arn, domain = _ensure_distribution(cf, cert)

    return CloudFrontSeed(
        region=region, account_id=account_id, distribution_id=dist_id,
        distribution_arn=dist_arn, domain_name=domain,
        certificate_arn=cert, bucket=BUCKET_NAME, bucket_eu=BUCKET_EU)


def seed_apigateway(session: boto3.Session, *, region: str = REGION,
                    endpoint_url: str | None = None) -> ApiGatewaySeed:
    """Seed (or find) the REST APIs of the module doc."""
    sts = _client(session, "sts", region, endpoint_url)
    account_id = str(sts.get_caller_identity()["Account"])
    apigw = _client(session, "apigateway", region, endpoint_url)

    api_id = _ensure_rest_api(apigw)
    dups = _ensure_dup_apis(apigw)
    resources = _ensure_api_resources(apigw, api_id)
    _ensure_api_method(apigw, api_id, resources[API_RESOURCE_PATHS[0]])
    authorizer = _ensure_authorizer(apigw, api_id, region, account_id)
    deployment = _ensure_api_stage(apigw, api_id)

    return ApiGatewaySeed(
        region=region, account_id=account_id, api_id=api_id,
        dup_api_ids=dups,
        resources=tuple(sorted(resources.items())),
        stage=API_STAGE, deployment_id=deployment,
        authorizer_id=authorizer)


def seed_organizations(session: boto3.Session, *, region: str = REGION,
                       endpoint_url: str | None = None
                       ) -> OrganizationsSeed:
    """Seed (or find) the organization, member account and SCP."""
    sts = _client(session, "sts", region, endpoint_url)
    account_id = str(sts.get_caller_identity()["Account"])
    org = _client(session, "organizations", region, endpoint_url)

    organization_id = _ensure_organization(org)
    roots = sorted(str(r["Id"]) for r in _all(org, "list_roots", "Roots"))
    member = _ensure_org_account(org)
    policy = _ensure_org_policy(org)

    return OrganizationsSeed(
        region=region, account_id=account_id,
        organization_id=organization_id, root_id=roots[0],
        member_account_id=member, policy_id=policy)


def seed_services(session: boto3.Session, *, region: str = REGION,
                  endpoint_url: str | None = None,
                  compute: ComputeSeed | None = None,
                  data: DataSeed | None = None) -> ServicesSeed:
    """Seed (or find) launch template, Auto Scaling, CloudWatch, ECR,
    Step Functions, Redshift and EventBridge resources. It needs the
    compute and data estates.
    """
    net_seed = compute.network if compute is not None else seed_ec2_vpc(
        session, region=region, endpoint_url=endpoint_url)
    comp = compute if compute is not None else seed_compute(
        session, region=region, endpoint_url=endpoint_url,
        ec2_vpc=net_seed)
    dat = data if data is not None else seed_data(
        session, region=region, endpoint_url=endpoint_url)
    account = net_seed.account_id
    ec2 = _client(session, "ec2", region, endpoint_url)
    asg = _client(session, "autoscaling", region, endpoint_url)
    cw = _client(session, "cloudwatch", region, endpoint_url)
    ecr = _client(session, "ecr", region, endpoint_url)
    sfn = _client(session, "stepfunctions", region, endpoint_url)
    rs = _client(session, "redshift", region, endpoint_url)
    events = _client(session, "events", region, endpoint_url)
    eks = _client(session, "eks", region, endpoint_url)
    iam = _client(session, "iam", region, endpoint_url)

    # launch template (its user data holds the fake secret) + groups
    found = [t for t in _all(ec2, "describe_launch_templates",
                             "LaunchTemplates")
             if t.get("LaunchTemplateName") == SERVICES_LT_NAME]
    if found:
        lt_id = str(found[0]["LaunchTemplateId"])
    else:
        lt_id = str(ec2.create_launch_template(
            LaunchTemplateName=SERVICES_LT_NAME,
            LaunchTemplateData={
                "InstanceType": "t3.micro",
                "UserData": base64.b64encode(
                    USER_DATA.encode()).decode()},
            TagSpecifications=[{
                "ResourceType": "launch-template",
                "Tags": _tag_list(SERVICES_TAGS)}],
        )["LaunchTemplate"]["LaunchTemplateId"])
    groups = {g["AutoScalingGroupName"]
              for g in _all(asg, "describe_auto_scaling_groups",
                            "AutoScalingGroups")}
    if SERVICES_ASG not in groups:
        asg.create_auto_scaling_group(
            AutoScalingGroupName=SERVICES_ASG, MinSize=0, MaxSize=1,
            LaunchTemplate={"LaunchTemplateId": lt_id,
                            "Version": "$Latest"},
            VPCZoneIdentifier=net_seed.subnet_private,
            TargetGroupARNs=[comp.target_group_arn],
            Tags=[{"Key": k, "Value": v, "PropagateAtLaunch": False}
                  for k, v in sorted(SERVICES_TAGS.items())])
    nodegroup = eks.describe_nodegroup(
        clusterName=EKS_CLUSTER, nodegroupName=EKS_NODEGROUP)["nodegroup"]
    eks_asgs = nodegroup.get("resources", {}).get("autoScalingGroups", [])
    eks_asg = str(eks_asgs[0]["name"]) if eks_asgs else ""
    if eks_asg and eks_asg not in groups:
        asg.create_auto_scaling_group(
            AutoScalingGroupName=eks_asg, MinSize=0, MaxSize=1,
            LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "1"},
            VPCZoneIdentifier=net_seed.subnet_private)

    # CloudWatch alarms
    cw.put_metric_alarm(
        AlarmName=SERVICES_ALARM, MetricName="CPUUtilization",
        Namespace="AWS/EC2", Statistic="Average", Period=60,
        EvaluationPeriods=1, Threshold=80,
        ComparisonOperator="GreaterThanThreshold",
        AlarmActions=[dat.topic_arn],
        Dimensions=[{"Name": "InstanceId",
                     "Value": net_seed.instance_web}],
        Tags=_tag_list(SERVICES_TAGS))

    # ECR: one repository with both policies, one without
    existing = {r["repositoryName"] for r in
                _all(ecr, "describe_repositories", "repositories")}
    if SERVICES_ECR not in existing:
        ecr.create_repository(repositoryName=SERVICES_ECR,
                              tags=_tag_list(SERVICES_TAGS))
        ecr.set_repository_policy(
            repositoryName=SERVICES_ECR,
            policyText=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Sid": "AllowPull", "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                    "Action": ["ecr:GetDownloadUrlForLayer",
                               "ecr:BatchGetImage"]}]}, sort_keys=True))
        ecr.put_lifecycle_policy(
            repositoryName=SERVICES_ECR,
            lifecyclePolicyText=json.dumps({"rules": [{
                "rulePriority": 1, "description": "keep 5 untagged",
                "selection": {"tagStatus": "untagged",
                              "countType": "imageCountMoreThan",
                              "countNumber": 5},
                "action": {"type": "expire"}}]}, sort_keys=True))
    if SERVICES_ECR_PLAIN not in existing:
        ecr.create_repository(repositoryName=SERVICES_ECR_PLAIN)

    # Step Functions: the definition holds the fake secret and a Lambda
    sfn_role = _ensure_role(iam, SERVICES_SFN_ROLE,
                            "states.amazonaws.com")
    definition = json.dumps({
        "StartAt": "Call",
        "States": {"Call": {
            "Type": "Task", "Resource": comp.lambda_api_arn, "End": True,
            "Parameters": {"ApiKey": FAKE_SECRET, "mode": "visible"}}},
    }, sort_keys=True)
    machines = {m["name"]: m["stateMachineArn"] for m in
                _all(sfn, "list_state_machines", "stateMachines")}
    sfn_arn = machines.get(SERVICES_SFN) or str(
        sfn.create_state_machine(
            name=SERVICES_SFN, definition=definition, roleArn=sfn_role,
            tags=[{"key": k, "value": v}
                  for k, v in sorted(SERVICES_TAGS.items())]
        )["stateMachineArn"])

    # Redshift
    clusters = {c["ClusterIdentifier"] for c in
                _all(rs, "describe_clusters", "Clusters")}
    if SERVICES_REDSHIFT not in clusters:
        rs.create_cluster(
            ClusterIdentifier=SERVICES_REDSHIFT, NodeType="dc2.large",
            MasterUsername="awsmount", MasterUserPassword=FAKE_SECRET,
            VpcSecurityGroupIds=[net_seed.sg_db],
            Tags=_tag_list(SERVICES_TAGS))

    # EventBridge: a custom bus with a rule and two targets, plus a
    # scheduled rule on the default bus
    buses = {b["Name"] for b in events.list_event_buses()["EventBuses"]}
    if SERVICES_BUS not in buses:
        events.create_event_bus(Name=SERVICES_BUS,
                                Tags=_tag_list(SERVICES_TAGS))
    events.put_rule(
        Name=SERVICES_RULE, EventBusName=SERVICES_BUS,
        EventPattern=json.dumps({"source": ["awsmount.test"]}),
        State="ENABLED", RoleArn=sfn_role, Tags=_tag_list(SERVICES_TAGS))
    events.put_targets(
        Rule=SERVICES_RULE, EventBusName=SERVICES_BUS,
        Targets=[
            {"Id": "notify", "Arn": dat.topic_arn,
             "Input": json.dumps({"password": FAKE_SECRET,
                                  "note": "static input"})},
            {"Id": "workflow", "Arn": sfn_arn, "RoleArn": sfn_role}])
    events.put_rule(Name=SERVICES_SCHEDULE,
                    ScheduleExpression="rate(1 hour)", State="DISABLED")

    return ServicesSeed(
        region=region, account_id=account, launch_template_id=lt_id,
        launch_template_name=SERVICES_LT_NAME, asg_name=SERVICES_ASG,
        eks_asg_name=eks_asg,
        alarm_name=SERVICES_ALARM,
        ecr_repo=SERVICES_ECR, ecr_repo_plain=SERVICES_ECR_PLAIN,
        sfn_name=SERVICES_SFN, sfn_arn=sfn_arn, sfn_role_arn=sfn_role,
        redshift_cluster=SERVICES_REDSHIFT, bus_name=SERVICES_BUS,
        rule_name=SERVICES_RULE, schedule_rule_name=SERVICES_SCHEDULE)


def seed_all(session: boto3.Session, *, region: str = REGION,
             endpoint_url: str | None = None) -> AllSeed:
    """Run every provider group's seed function, in a fixed order."""
    network = seed_ec2_vpc(session, region=region,
                           endpoint_url=endpoint_url)
    compute = seed_compute(session, region=region,
                           endpoint_url=endpoint_url, ec2_vpc=network)
    data = seed_data(session, region=region, endpoint_url=endpoint_url)
    return AllSeed(
        ec2_vpc=network,
        compute=compute,
        management=seed_management(session, region=region,
                                   endpoint_url=endpoint_url,
                                   ec2_vpc=network),
        data=data,
        secrets=seed_secrets(session, region=region,
                             endpoint_url=endpoint_url),
        edge=seed_edge(session, region=region, endpoint_url=endpoint_url,
                       ec2_vpc=network),
        iam=seed_iam(session, region=region, endpoint_url=endpoint_url),
        cloudfront=seed_cloudfront(session, region=region,
                                   endpoint_url=endpoint_url),
        apigateway=seed_apigateway(session, region=region,
                                   endpoint_url=endpoint_url),
        organizations=seed_organizations(session, region=region,
                                         endpoint_url=endpoint_url),
        services=seed_services(session, region=region,
                               endpoint_url=endpoint_url, compute=compute,
                               data=data),
    )
