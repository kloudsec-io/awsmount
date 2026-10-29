# awsmount coverage

28 services, 63 resource types

| Service | Scope | Resource types |
|---|---|---|
| ec2 | region | instances, volumes, snapshots, key-pairs, elastic-ips, network-interfaces, amis, launch-templates |
| vpc | region | vpcs, subnets, security-groups, route-tables, internet-gateways, nat-gateways, network-acls, endpoints, peering-connections, dhcp-options, transit-gateways, flow-logs |
| elbv2 | region | load-balancers, load-balancers/listeners, load-balancers/listeners/rules, target-groups |
| lambda | region | functions |
| rds | region | instances, clusters, clusters/members |
| ecs | region | clusters, clusters/services, task-definitions |
| eks | region | clusters, clusters/nodegroups, clusters/addons |
| autoscaling | region | groups |
| s3 | region | buckets |
| dynamodb | region | tables |
| sqs | region | queues |
| sns | region | topics |
| kms | region | keys, aliases |
| logs | region | log-groups |
| cloudwatch | region | alarms |
| ecr | region | repositories |
| stepfunctions | region | state-machines |
| redshift | region | clusters |
| eventbridge | region | event-buses, event-buses/rules |
| cloudformation | region | stacks, stacks/resources |
| secretsmanager | region | secrets |
| ssm | region | parameters |
| acm | region | certificates |
| route53 | global | hosted-zones |
| iam | global | users, roles, groups, policies |
| cloudfront | global | distributions |
| apigateway | region | rest-apis |
| organizations | global | accounts, roots, policies |

## Files and links of each resource directory

\* = fetched on first read (an API call), ? = only when the resource has one, / = directory.

| Resource type | Files | Links |
|---|---|---|
| ec2/instances | describe.json, arn, name?, tags.json, tags/, state, instance-type, private-ip, user-data\*, links/ | subnet, vpc, image, key-pair, security-groups/, volumes/, network-interfaces/ |
| ec2/volumes | describe.json, arn, name?, tags.json, tags/, state, size-gib, links/ | instances/, snapshot, kms-key |
| ec2/snapshots | describe.json, arn, name?, tags.json, tags/, state, links/ | volume, kms-key |
| ec2/key-pairs | describe.json, arn, name?, tags.json, tags/, fingerprint, public-key | - |
| ec2/elastic-ips | describe.json, arn, name?, tags.json, tags/, public-ip, links/ | instance, network-interface |
| ec2/network-interfaces | describe.json, arn, name?, tags.json, tags/, status, private-ip, interface-type, links/ | subnet, vpc, instance, security-groups/ |
| ec2/amis | describe.json, arn, name, tags.json, tags/, state, links/ | snapshots/ |
| ec2/launch-templates | describe.json, arn, name?, tags.json, tags/, default-version, latest-version | - |
| vpc/vpcs | describe.json, arn, name?, tags.json, tags/, cidr, links/ | dhcp-options |
| vpc/subnets | describe.json, arn, name?, tags.json, tags/, cidr, availability-zone, links/ | vpc |
| vpc/security-groups | describe.json, arn, name, tags.json, tags/, rules.json, group-name, vpc-id, links/, referenced-by/ | vpc, references/ |
| vpc/route-tables | describe.json, arn, name?, tags.json, tags/, routes.json, links/ | vpc, subnets/, internet-gateways/, nat-gateways/, peering-connections/ |
| vpc/internet-gateways | describe.json, arn, name?, tags.json, tags/, links/ | vpcs/ |
| vpc/nat-gateways | describe.json, arn, name?, tags.json, tags/, state, links/ | vpc, subnet, network-interfaces/, elastic-ips/ |
| vpc/network-acls | describe.json, arn, name?, tags.json, tags/, entries.json, links/ | vpc, subnets/ |
| vpc/endpoints | describe.json, arn, name?, tags.json, tags/, policy.json, links/ | vpc, subnets/, route-tables/, security-groups/, network-interfaces/ |
| vpc/peering-connections | describe.json, arn, name?, tags.json, tags/, status, links/ | requester-vpc, accepter-vpc |
| vpc/dhcp-options | describe.json, arn, name?, tags.json, tags/ | - |
| vpc/transit-gateways | describe.json, arn, name?, tags.json, tags/, state | - |
| vpc/flow-logs | describe.json, arn, name?, tags.json, tags/, links/ | resource, log-group |
| elbv2/load-balancers | describe.json, arn, tags.json\*, tags/\*, dns-name, type, scheme, listeners.json\*, attributes.json\*, links/, listeners/ | vpc, subnets/, security-groups/, target-groups/ |
| elbv2/load-balancers/listeners | describe.json, arn, protocol, port, links/, rules/ | load-balancer, target-groups/, certificates/ |
| elbv2/load-balancers/listeners/rules | describe.json, arn, priority, links/ | target-groups/ |
| elbv2/target-groups | describe.json, arn, tags.json\*, tags/\*, protocol, port, target-type, health.json\*, attributes.json\*, links/ | vpc, load-balancers/ |
| lambda/functions | describe.json, arn, tags.json\*, tags/\*, runtime, policy.json\*, aliases.json\*, event-source-mappings.json\*, url-config.json\*, links/ | role, vpc, subnets/, security-groups/, kms-key, log-group |
| rds/instances | describe.json, arn, name?, tags.json, tags/, engine, status, endpoint, links/ | cluster, vpc, subnets/, security-groups/, kms-key |
| rds/clusters | describe.json, arn, name?, tags.json, tags/, engine, status, endpoint, links/, members/ | instances/, security-groups/, kms-key |
| rds/clusters/members | describe.json, role, promotion-tier, links/ | instance, cluster |
| ecs/clusters | describe.json, arn, name?, tags.json, tags/, status, services/ | - |
| ecs/clusters/services | describe.json, arn, name?, tags.json, tags/, status, desired-count, links/ | cluster, task-definition, target-groups/, subnets/, security-groups/, role |
| ecs/task-definitions | describe.json\*, arn, tags.json\*, tags/\*, links/ | role, execution-role |
| eks/clusters | describe.json\*, arn, tags.json\*, tags/\*, nodegroups.json\*, addons.json\*, links/, nodegroups/, addons/ | role, vpc, subnets/, security-groups/ |
| eks/clusters/nodegroups | describe.json\*, tags.json\*, tags/\*, links/ | cluster, role, subnets/, launch-template, autoscaling-groups/ |
| eks/clusters/addons | describe.json\*, tags.json\*, tags/\*, links/ | cluster, role |
| autoscaling/groups | describe.json, arn, name?, tags.json, tags/, min-size, max-size, desired-capacity, links/ | launch-template, subnets/, target-groups/, instances/ |
| s3/buckets | describe.json, arn, tags.json\*, tags/\*, region, policy.json\*, encryption.json\*, public-access-block.json\*, versioning.json\*, objects-listing.json\*, objects/ | - |
| dynamodb/tables | describe.json\*, arn, tags.json\*, tags/\*, ttl.json\*, continuous-backups.json\*, links/ | kms-key |
| sqs/queues | describe.json\*, arn, tags.json\*, tags/\*, url, policy.json\*, links/ | dead-letter-queue, kms-key |
| sns/topics | describe.json\*, arn, name, tags.json\*, tags/\*, policy.json\*, subscriptions.json\*, links/ | kms-key |
| kms/keys | describe.json\*, arn, tags.json\*, tags/\*, policy.json\*, rotation.json\*, links/ | aliases/ |
| kms/aliases | describe.json, arn, links/ | target-key |
| logs/log-groups | describe.json, arn, tags.json\*, tags/\*, retention, stored-bytes, metric-filters.json\*, subscription-filters.json\*, links/ | kms-key |
| cloudwatch/alarms | describe.json, arn, tags.json\*, tags/\*, state, metric, links/ | sns-topics/, instances/ |
| ecr/repositories | describe.json, arn, tags.json\*, tags/\*, uri, policy.json\*, lifecycle-policy.json\*, links/ | kms-key |
| stepfunctions/state-machines | describe.json\*, arn, tags.json\*, tags/\*, definition.json\*, links/ | role, lambda-functions/, log-groups/ |
| redshift/clusters | describe.json, arn, name?, tags.json, tags/, status, node-type, endpoint, links/ | vpc, security-groups/, roles/, kms-key |
| eventbridge/event-buses | describe.json, arn, tags.json\*, tags/\*, rules/ | - |
| eventbridge/event-buses/rules | describe.json, arn, tags.json\*, tags/\*, state, schedule, targets.json\*, links/ | role |
| cloudformation/stacks | describe.json, arn, name, tags.json, tags/, status, outputs.json, parameters.json, template\*, links/, resources/ | role |
| cloudformation/stacks/resources | describe.json, type, physical-id, status, links/ | target |
| secretsmanager/secrets | describe.json, arn, name, tags.json, tags/, rotation-enabled, policy.json\*, links/ | kms-key, rotation-lambda |
| ssm/parameters | describe.json, arn, name, tags.json\*, tags/\*, type, version, links/ | kms-key |
| acm/certificates | describe.json, arn, name, tags.json\*, tags/\*, status, details.json\* | - |
| route53/hosted-zones | describe.json, arn, name, tags.json\*, tags/\*, private, record-count, records.json\*, links/ | vpcs/ |
| iam/users | describe.json, arn, name, tags.json\*, tags/\*, attached-policies.json\*, inline-policies/\*, groups.json\*, access-keys.json\*, mfa-devices.json\*, links/ | groups/, policies/ |
| iam/roles | describe.json, arn, name, tags.json\*, tags/\*, trust-policy.json, attached-policies.json\*, inline-policies/\*, instance-profiles.json\*, last-used.json\*, links/ | policies/, trusts/, trusts-users/ |
| iam/groups | describe.json, arn, name, attached-policies.json\*, inline-policies/\*, links/ | members/, policies/ |
| iam/policies | describe.json, arn, name, tags.json\*, tags/\*, document.json\*, versions.json\*, entities.json\*, links/ | attached-to-users/, attached-to-groups/, attached-to-roles/ |
| cloudfront/distributions | describe.json, arn, tags.json\*, tags/\*, domain-name, status, aliases, config.json\*, links/ | certificate, origins-s3/ |
| apigateway/rest-apis | describe.json, arn, name, tags.json, tags/, endpoint-type, resources.json\*, stages.json\*, deployments.json\*, authorizers.json\* | - |
| organizations/accounts | describe.json, arn, name, account-name, status | - |
| organizations/roots | describe.json, arn, name | - |
| organizations/policies | describe.json, arn, name, document.json\* | - |
