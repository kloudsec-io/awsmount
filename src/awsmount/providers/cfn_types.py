"""CloudFormation resource type -> CollectionRef map (docs/coverage.md).

Stack resources link to the collection that holds their physical
resource. Types that are not listed here get no ``target`` link.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Literal

from awsmount.providers import refs
from awsmount.providers.base import CollectionRef

__all__ = ["ARN_PHYSICAL_IDS", "CFN_TYPES", "lookup_by", "target_of"]

CFN_TYPES: Mapping[str, CollectionRef] = {
    "AWS::EC2::Instance": refs.INSTANCES,
    "AWS::EC2::NetworkInterface": refs.NETWORK_INTERFACES,
    "AWS::EC2::SecurityGroup": refs.SECURITY_GROUPS,
    "AWS::EC2::Subnet": refs.SUBNETS,
    "AWS::EC2::VPC": refs.VPCS,
    "AWS::EC2::VPCEndpoint": refs.VPC_ENDPOINTS,
    "AWS::ECS::Cluster": refs.ECS_CLUSTERS,
    "AWS::ElasticLoadBalancingV2::LoadBalancer": refs.LOAD_BALANCERS,
    "AWS::IAM::Role": refs.IAM_ROLES,
    "AWS::KMS::Key": refs.KMS_KEYS,
    "AWS::Lambda::Function": refs.LAMBDA_FUNCTIONS,
    "AWS::Logs::LogGroup": refs.LOG_GROUPS,
    "AWS::RDS::DBInstance": refs.RDS_INSTANCES,
}

ARN_PHYSICAL_IDS: frozenset[str] = frozenset({
    "AWS::ElasticLoadBalancingV2::LoadBalancer",
})


def target_of(resource_type: str) -> CollectionRef | None:
    """Collection holding resources of ``resource_type``, if mapped."""
    return CFN_TYPES.get(resource_type)


def lookup_by(resource_type: str) -> Literal["key", "arn"]:
    """How the physical id of ``resource_type`` identifies the target."""
    return "arn" if resource_type in ARN_PHYSICAL_IDS else "key"
