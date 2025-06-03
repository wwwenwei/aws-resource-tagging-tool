#!/usr/bin/env python3
import boto3
import json
import os
import logging
import argparse
from botocore.exceptions import ClientError

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 默认配置文件路径
DEFAULT_CONFIG_PATH = 'aws_service_config.json'

# 已知服务的资源类型配置模板
SERVICE_TEMPLATES = {
    'ec2': {
        'resource_types': [
            {
                'type': 'instance',
                'list_method': 'describe_instances',
                'arn_template': 'arn:aws:ec2:{region}:{account_id}:instance/{id}',
                'extract_ids': 'lambda data: [i["InstanceId"] for r in data.get("Reservations", []) for i in r.get("Instances", [])]'
            },
            {
                'type': 'volume',
                'list_method': 'describe_volumes',
                'arn_template': 'arn:aws:ec2:{region}:{account_id}:volume/{id}',
                'extract_ids': 'lambda data: [v["VolumeId"] for v in data.get("Volumes", [])]'
            },
            {
                'type': 'security-group',
                'list_method': 'describe_security_groups',
                'arn_template': 'arn:aws:ec2:{region}:{account_id}:security-group/{id}',
                'extract_ids': 'lambda data: [sg["GroupId"] for sg in data.get("SecurityGroups", [])]'
            },
            {
                'type': 'subnet',
                'list_method': 'describe_subnets',
                'arn_template': 'arn:aws:ec2:{region}:{account_id}:subnet/{id}',
                'extract_ids': 'lambda data: [s["SubnetId"] for s in data.get("Subnets", [])]'
            },
            {
                'type': 'vpc',
                'list_method': 'describe_vpcs',
                'arn_template': 'arn:aws:ec2:{region}:{account_id}:vpc/{id}',
                'extract_ids': 'lambda data: [v["VpcId"] for v in data.get("Vpcs", [])]'
            }
        ]
    },
    's3': {
        'resource_types': [
            {
                'type': 'bucket',
                'list_method': 'list_buckets',
                'arn_template': 'arn:aws:s3:::{id}',
                'extract_ids': 'lambda data: [b["Name"] for b in data.get("Buckets", [])]'
            }
        ]
    },
    'lambda': {
        'resource_types': [
            {
                'type': 'function',
                'list_method': 'list_functions',
                'arn_template': 'arn:aws:lambda:{region}:{account_id}:function:{id}',
                'extract_ids': 'lambda data: [f["FunctionName"] for f in data.get("Functions", [])]'
            }
        ]
    },
    'rds': {
        'resource_types': [
            {
                'type': 'db',
                'list_method': 'describe_db_instances',
                'arn_template': 'arn:aws:rds:{region}:{account_id}:db:{id}',
                'extract_ids': 'lambda data: [db["DBInstanceIdentifier"] for db in data.get("DBInstances", [])]'
            }
        ]
    },
    'dynamodb': {
        'resource_types': [
            {
                'type': 'table',
                'list_method': 'list_tables',
                'arn_template': 'arn:aws:dynamodb:{region}:{account_id}:table/{id}',
                'extract_ids': 'lambda data: data.get("TableNames", [])'
            }
        ]
    },
    'elasticache': {
        'resource_types': [
            {
                'type': 'cluster',
                'list_method': 'describe_cache_clusters',
                'arn_template': 'arn:aws:elasticache:{region}:{account_id}:cluster:{id}',
                'extract_ids': 'lambda data: [c["CacheClusterId"] for c in data.get("CacheClusters", [])]'
            }
        ]
    },
    'elb': {
        'resource_types': [
            {
                'type': 'loadbalancer',
                'list_method': 'describe_load_balancers',
                'arn_template': 'arn:aws:elasticloadbalancing:{region}:{account_id}:loadbalancer/{id}',
                'extract_ids': 'lambda data: [lb["LoadBalancerName"] for lb in data.get("LoadBalancerDescriptions", [])]'
            }
        ]
    },
    'elbv2': {
        'resource_types': [
            {
                'type': 'loadbalancer',
                'list_method': 'describe_load_balancers',
                'arn_template': None,  # ALB/NLB 直接返回ARN
                'extract_ids': 'lambda data: [lb["LoadBalancerArn"] for lb in data.get("LoadBalancers", [])]'
            }
        ]
    },
    # 以下是新增的服务模板
    'apigateway': {
        'resource_types': [
            {
                'type': 'restapi',
                'list_method': 'get_rest_apis',
                'arn_template': 'arn:aws:apigateway:{region}::/restapis/{id}',
                'extract_ids': 'lambda data: [api["id"] for api in data.get("items", [])]'
            }
        ]
    },
    'cloudformation': {
        'resource_types': [
            {
                'type': 'stack',
                'list_method': 'list_stacks',
                'arn_template': 'arn:aws:cloudformation:{region}:{account_id}:stack/{id}',
                'extract_ids': 'lambda data: [stack["StackId"].split("/")[-1] for stack in data.get("StackSummaries", [])]'
            }
        ]
    },
    'cloudfront': {
        'resource_types': [
            {
                'type': 'distribution',
                'list_method': 'list_distributions',
                'arn_template': 'arn:aws:cloudfront::{account_id}:distribution/{id}',
                'extract_ids': 'lambda data: [dist["Id"] for dist in data.get("DistributionList", {}).get("Items", [])]'
            }
        ]
    },
    'cloudwatch': {
        'resource_types': [
            {
                'type': 'alarm',
                'list_method': 'describe_alarms',
                'arn_template': 'arn:aws:cloudwatch:{region}:{account_id}:alarm:{id}',
                'extract_ids': 'lambda data: [alarm["AlarmName"] for alarm in data.get("MetricAlarms", [])]'
            }
        ]
    },
    'codebuild': {
        'resource_types': [
            {
                'type': 'project',
                'list_method': 'list_projects',
                'arn_template': 'arn:aws:codebuild:{region}:{account_id}:project/{id}',
                'extract_ids': 'lambda data: data.get("projects", [])'
            }
        ]
    },
    'codecommit': {
        'resource_types': [
            {
                'type': 'repository',
                'list_method': 'list_repositories',
                'arn_template': 'arn:aws:codecommit:{region}:{account_id}:repository/{id}',
                'extract_ids': 'lambda data: [repo["repositoryName"] for repo in data.get("repositories", [])]'
            }
        ]
    },
    'codedeploy': {
        'resource_types': [
            {
                'type': 'application',
                'list_method': 'list_applications',
                'arn_template': 'arn:aws:codedeploy:{region}:{account_id}:application:{id}',
                'extract_ids': 'lambda data: data.get("applications", [])'
            }
        ]
    },
    'codepipeline': {
        'resource_types': [
            {
                'type': 'pipeline',
                'list_method': 'list_pipelines',
                'arn_template': 'arn:aws:codepipeline:{region}:{account_id}:pipeline/{id}',
                'extract_ids': 'lambda data: [p["name"] for p in data.get("pipelines", [])]'
            }
        ]
    },
    'cognito-identity': {
        'resource_types': [
            {
                'type': 'identitypool',
                'list_method': 'list_identity_pools',
                'arn_template': 'arn:aws:cognito-identity:{region}:{account_id}:identitypool/{id}',
                'extract_ids': 'lambda data: [pool["IdentityPoolId"] for pool in data.get("IdentityPools", [])]'
            }
        ]
    },
    'cognito-idp': {
        'resource_types': [
            {
                'type': 'userpool',
                'list_method': 'list_user_pools',
                'arn_template': 'arn:aws:cognito-idp:{region}:{account_id}:userpool/{id}',
                'extract_ids': 'lambda data: [pool["Id"] for pool in data.get("UserPools", [])]'
            }
        ]
    },
    'dms': {
        'resource_types': [
            {
                'type': 'replication-instance',
                'list_method': 'describe_replication_instances',
                'arn_template': 'arn:aws:dms:{region}:{account_id}:rep:{id}',
                'extract_ids': 'lambda data: [inst["ReplicationInstanceIdentifier"] for inst in data.get("ReplicationInstances", [])]'
            }
        ]
    },
    'docdb': {
        'resource_types': [
            {
                'type': 'db-cluster',
                'list_method': 'describe_db_clusters',
                'arn_template': 'arn:aws:rds:{region}:{account_id}:cluster:{id}',
                'extract_ids': 'lambda data: [cluster["DBClusterIdentifier"] for cluster in data.get("DBClusters", [])]'
            }
        ]
    },
    'ecr': {
        'resource_types': [
            {
                'type': 'repository',
                'list_method': 'describe_repositories',
                'arn_template': 'arn:aws:ecr:{region}:{account_id}:repository/{id}',
                'extract_ids': 'lambda data: [repo["repositoryName"] for repo in data.get("repositories", [])]'
            }
        ]
    },
    'ecs': {
        'resource_types': [
            {
                'type': 'cluster',
                'list_method': 'list_clusters',
                'arn_template': None,  # ECS 直接返回 ARN
                'extract_ids': 'lambda data: data.get("clusterArns", [])'
            }
        ]
    },
    'eks': {
        'resource_types': [
            {
                'type': 'cluster',
                'list_method': 'list_clusters',
                'arn_template': 'arn:aws:eks:{region}:{account_id}:cluster/{id}',
                'extract_ids': 'lambda data: data.get("clusters", [])'
            }
        ]
    },
    'emr': {
        'resource_types': [
            {
                'type': 'cluster',
                'list_method': 'list_clusters',
                'arn_template': 'arn:aws:elasticmapreduce:{region}:{account_id}:cluster/{id}',
                'extract_ids': 'lambda data: [c["Id"] for c in data.get("Clusters", [])]'
            }
        ]
    },
    'es': {
        'resource_types': [
            {
                'type': 'domain',
                'list_method': 'list_domain_names',
                'arn_template': 'arn:aws:es:{region}:{account_id}:domain/{id}',
                'extract_ids': 'lambda data: [domain["DomainName"] for domain in data.get("DomainNames", [])]'
            }
        ]
    },
    'events': {
        'resource_types': [
            {
                'type': 'rule',
                'list_method': 'list_rules',
                'arn_template': 'arn:aws:events:{region}:{account_id}:rule/{id}',
                'extract_ids': 'lambda data: [rule["Name"] for rule in data.get("Rules", [])]'
            }
        ]
    },
    'firehose': {
        'resource_types': [
            {
                'type': 'deliverystream',
                'list_method': 'list_delivery_streams',
                'arn_template': 'arn:aws:firehose:{region}:{account_id}:deliverystream/{id}',
                'extract_ids': 'lambda data: data.get("DeliveryStreamNames", [])'
            }
        ]
    },
    'glacier': {
        'resource_types': [
            {
                'type': 'vault',
                'list_method': 'list_vaults',
                'arn_template': 'arn:aws:glacier:{region}:{account_id}:vaults/{id}',
                'extract_ids': 'lambda data: [vault["VaultName"] for vault in data.get("VaultList", [])]'
            }
        ]
    },
    'glue': {
        'resource_types': [
            {
                'type': 'database',
                'list_method': 'get_databases',
                'arn_template': 'arn:aws:glue:{region}:{account_id}:database/{id}',
                'extract_ids': 'lambda data: [db["Name"] for db in data.get("DatabaseList", [])]'
            }
        ]
    },
    'iam': {
        'resource_types': [
            {
                'type': 'role',
                'list_method': 'list_roles',
                'arn_template': 'arn:aws:iam::{account_id}:role/{id}',
                'extract_ids': 'lambda data: [role["RoleName"] for role in data.get("Roles", [])]'
            }
        ]
    },
    'kinesis': {
        'resource_types': [
            {
                'type': 'stream',
                'list_method': 'list_streams',
                'arn_template': 'arn:aws:kinesis:{region}:{account_id}:stream/{id}',
                'extract_ids': 'lambda data: data.get("StreamNames", [])'
            }
        ]
    },
    'kms': {
        'resource_types': [
            {
                'type': 'key',
                'list_method': 'list_keys',
                'arn_template': None,  # KMS 直接返回 ARN
                'extract_ids': 'lambda data: [key["KeyArn"] for key in data.get("Keys", [])]'
            }
        ]
    },
    'logs': {
        'resource_types': [
            {
                'type': 'log-group',
                'list_method': 'describe_log_groups',
                'arn_template': 'arn:aws:logs:{region}:{account_id}:log-group:{id}',
                'extract_ids': 'lambda data: [group["logGroupName"] for group in data.get("logGroups", [])]'
            }
        ]
    },
    'neptune': {
        'resource_types': [
            {
                'type': 'db-cluster',
                'list_method': 'describe_db_clusters',
                'arn_template': 'arn:aws:rds:{region}:{account_id}:cluster:{id}',
                'extract_ids': 'lambda data: [cluster["DBClusterIdentifier"] for cluster in data.get("DBClusters", []) if cluster.get("Engine") == "neptune"]'
            }
        ]
    },
    'redshift': {
        'resource_types': [
            {
                'type': 'cluster',
                'list_method': 'describe_clusters',
                'arn_template': 'arn:aws:redshift:{region}:{account_id}:cluster:{id}',
                'extract_ids': 'lambda data: [cluster["ClusterIdentifier"] for cluster in data.get("Clusters", [])]'
            }
        ]
    },
    'route53': {
        'resource_types': [
            {
                'type': 'hostedzone',
                'list_method': 'list_hosted_zones',
                'arn_template': 'arn:aws:route53::{account_id}:hostedzone/{id}',
                'extract_ids': 'lambda data: [zone["Id"].split("/")[-1] for zone in data.get("HostedZones", [])]'
            }
        ]
    },
    'sagemaker': {
        'resource_types': [
            {
                'type': 'notebook-instance',
                'list_method': 'list_notebook_instances',
                'arn_template': 'arn:aws:sagemaker:{region}:{account_id}:notebook-instance/{id}',
                'extract_ids': 'lambda data: [nb["NotebookInstanceName"] for nb in data.get("NotebookInstances", [])]'
            }
        ]
    },
    'secretsmanager': {
        'resource_types': [
            {
                'type': 'secret',
                'list_method': 'list_secrets',
                'arn_template': None,  # Secrets Manager 直接返回 ARN
                'extract_ids': 'lambda data: [secret["ARN"] for secret in data.get("SecretList", [])]'
            }
        ]
    },
    'ses': {
        'resource_types': [
            {
                'type': 'identity',
                'list_method': 'list_identities',
                'arn_template': 'arn:aws:ses:{region}:{account_id}:identity/{id}',
                'extract_ids': 'lambda data: data.get("Identities", [])'
            }
        ]
    },
    'sns': {
        'resource_types': [
            {
                'type': 'topic',
                'list_method': 'list_topics',
                'arn_template': None,  # SNS 直接返回 ARN
                'extract_ids': 'lambda data: [topic["TopicArn"] for topic in data.get("Topics", [])]'
            }
        ]
    },
    'sqs': {
        'resource_types': [
            {
                'type': 'queue',
                'list_method': 'list_queues',
                'arn_template': None,  # SQS 直接返回 URL，需要转换为 ARN
                'extract_ids': 'lambda data: [url.split("/")[-1] for url in data.get("QueueUrls", [])]'
            }
        ]
    },
    'ssm': {
        'resource_types': [
            {
                'type': 'parameter',
                'list_method': 'describe_parameters',
                'arn_template': 'arn:aws:ssm:{region}:{account_id}:parameter/{id}',
                'extract_ids': 'lambda data: [param["Name"] for param in data.get("Parameters", [])]'
            }
        ]
    },
    'stepfunctions': {
        'resource_types': [
            {
                'type': 'statemachine',
                'list_method': 'list_state_machines',
                'arn_template': None,  # Step Functions 直接返回 ARN
                'extract_ids': 'lambda data: [sm["stateMachineArn"] for sm in data.get("stateMachines", [])]'
            }
        ]
    }
}

# 可能的AWS服务列表（可以扩展）
POTENTIAL_SERVICES = [
    'ec2', 's3', 'lambda', 'rds', 'dynamodb', 'elasticache', 'elb', 'elbv2',
    'apigateway', 'cloudformation', 'cloudfront', 'cloudwatch', 'codebuild',
    'codecommit', 'codedeploy', 'codepipeline', 'cognito-identity', 'cognito-idp',
    'dms', 'docdb', 'ecr', 'ecs', 'eks', 'emr', 'es', 'events', 'firehose',
    'glacier', 'glue', 'iam', 'kinesis', 'kms', 'logs', 'neptune', 'redshift',
    'route53', 'sagemaker', 'secretsmanager', 'ses', 'sns', 'sqs', 'ssm', 'stepfunctions'
]

def get_account_id():
    """获取当前AWS账号ID"""
    try:
        sts_client = boto3.client('sts')
        return sts_client.get_caller_identity()["Account"]
    except ClientError as e:
        logger.error(f"无法获取AWS账号ID: {str(e)}")
        raise

def get_available_regions():
    """获取可用的AWS区域列表"""
    try:
        ec2_client = boto3.client('ec2')
        regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
        return regions
    except ClientError as e:
        logger.error(f"无法获取AWS区域列表: {str(e)}")
        return ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 
                'ap-south-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3', 
                'ap-southeast-1', 'ap-southeast-2', 'ca-central-1', 'eu-central-1', 
                'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-north-1', 
                'sa-east-1']

def discover_active_services(region):
    """发现指定区域中活跃的AWS服务"""
    active_services = {}
    
    for service_name in POTENTIAL_SERVICES:
        try:
            # 尝试创建服务客户端
            client = boto3.client(service_name, region_name=region)
            
            # 检查是否有资源
            has_resources = False
            
            if service_name in SERVICE_TEMPLATES:
                for resource_type in SERVICE_TEMPLATES[service_name]['resource_types']:
                    try:
                        # 尝试列出资源
                        list_method = resource_type['list_method']
                        response = getattr(client, list_method)()
                        
                        # 使用extract_ids函数提取资源ID
                        extract_ids_str = resource_type['extract_ids']
                        extract_ids = eval(extract_ids_str)
                        resource_ids = extract_ids(response)
                        
                        if resource_ids:
                            has_resources = True
                            logger.info(f"区域 {region} 中的服务 {service_name} 有 {len(resource_ids)} 个 {resource_type['type']} 资源")
                            break
                    except Exception as e:
                        logger.debug(f"无法列出区域 {region} 中服务 {service_name} 的资源 {resource_type['type']}: {str(e)}")
                        continue
            
            # 如果服务有资源或者我们有模板，则添加到活跃服务列表
            if has_resources or service_name in SERVICE_TEMPLATES:
                if service_name in SERVICE_TEMPLATES:
                    active_services[service_name] = SERVICE_TEMPLATES[service_name]
                    logger.info(f"区域 {region} 中发现活跃服务: {service_name}")
                else:
                    # 对于没有模板的服务，我们可以尝试自动发现资源类型
                    # 这部分比较复杂，需要针对每种服务进行定制
                    logger.info(f"区域 {region} 中发现服务 {service_name}，但没有预定义模板")
        
        except (ClientError, boto3.exceptions.UnknownServiceError) as e:
            logger.debug(f"区域 {region} 中未启用服务 {service_name}: {str(e)}")
            continue
    
    return active_services

def discover_services_in_regions(regions=None):
    """在多个区域中发现活跃的AWS服务"""
    if regions is None:
        regions = get_available_regions()
    
    all_services = {}
    
    for region in regions:
        logger.info(f"正在区域 {region} 中发现活跃服务...")
        region_services = discover_active_services(region)
        
        # 合并服务配置
        for service_name, config in region_services.items():
            if service_name not in all_services:
                all_services[service_name] = config
    
    return all_services

def save_service_config(config, output_path):
    """保存服务配置到文件"""
    # 将lambda函数转换为字符串
    serializable_config = {}
    for service_name, service_config in config.items():
        serializable_config[service_name] = {
            'resource_types': []
        }
        
        for resource_type in service_config['resource_types']:
            serializable_resource_type = resource_type.copy()
            if callable(resource_type.get('extract_ids')):
                # 将lambda函数转换为字符串
                extract_ids_str = resource_type['extract_ids'].__code__.co_consts[0]
                serializable_resource_type['extract_ids'] = f"lambda {extract_ids_str}"
            
            serializable_config[service_name]['resource_types'].append(serializable_resource_type)
    
    # 保存到文件
    with open(output_path, 'w') as f:
        json.dump(serializable_config, f, indent=2)
    
    logger.info(f"服务配置已保存到 {output_path}")

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='AWS服务配置生成工具')
    parser.add_argument('--regions', nargs='+', help='要处理的AWS区域列表（默认：所有区域）')
    parser.add_argument('--output', default=DEFAULT_CONFIG_PATH, help=f'输出配置文件路径（默认：{DEFAULT_CONFIG_PATH}）')
    parser.add_argument('--verbose', '-v', action='store_true', help='启用详细日志输出')
    
    args = parser.parse_args()
    
    # 设置日志级别
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    try:
        # 获取当前账号ID
        account_id = get_account_id()
        logger.info(f"当前AWS账号ID: {account_id}")
        
        # 发现活跃的服务
        services = discover_services_in_regions(args.regions)
        
        # 保存服务配置
        save_service_config(services, args.output)
        
        logger.info(f"发现了 {len(services)} 个活跃的AWS服务")
        for service_name in services:
            logger.info(f"  - {service_name}")
        
    except Exception as e:
        logger.error(f"程序执行出错: {str(e)}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
