import boto3
import argparse
import logging
import json
import os
from botocore.exceptions import ClientError
from concurrent.futures import ThreadPoolExecutor, as_completed

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 默认配置文件路径
DEFAULT_CONFIG_PATH = 'aws_service_config.json'
DEFAULT_RESOURCES_PATH = 'untagged_resources.json'

# 默认服务配置（如果配置文件不存在或无法加载）
DEFAULT_SERVICE_CONFIGS = {
    'ec2': {
        'resource_types': [
            {
                'type': 'instance',
                'list_method': 'describe_instances',
                'arn_template': 'arn:aws:ec2:{region}:{account_id}:instance/{id}',
                'extract_ids': lambda data: [i['InstanceId'] for r in data.get('Reservations', []) for i in r.get('Instances', [])]
            },
            {
                'type': 'volume',
                'list_method': 'describe_volumes',
                'arn_template': 'arn:aws:ec2:{region}:{account_id}:volume/{id}',
                'extract_ids': lambda data: [v['VolumeId'] for v in data.get('Volumes', [])]
            }
        ]
    },
    's3': {
        'resource_types': [
            {
                'type': 'bucket',
                'list_method': 'list_buckets',
                'arn_template': 'arn:aws:s3:::{id}',
                'extract_ids': lambda data: [b['Name'] for b in data.get('Buckets', [])]
            }
        ]
    }
}

def load_service_configs(config_path=DEFAULT_CONFIG_PATH):
    """从配置文件加载服务配置"""
    if not os.path.exists(config_path):
        logger.warning(f"配置文件 {config_path} 不存在，使用默认配置")
        return DEFAULT_SERVICE_CONFIGS
    
    try:
        with open(config_path, 'r') as f:
            config_data = json.load(f)
        
        # 将字符串形式的lambda函数转换为实际的lambda函数
        for service_name, service_config in config_data.items():
            for resource_type in service_config.get('resource_types', []):
                if 'extract_ids' in resource_type and isinstance(resource_type['extract_ids'], str):
                    try:
                        # 将字符串形式的lambda函数转换为实际的lambda函数
                        extract_ids_str = resource_type['extract_ids']
                        resource_type['extract_ids'] = eval(extract_ids_str)
                    except Exception as e:
                        logger.error(f"无法解析 {service_name} 服务的 {resource_type['type']} 资源的 extract_ids 函数: {str(e)}")
                        # 使用默认的提取函数
                        resource_type['extract_ids'] = lambda data: []
        
        logger.info(f"从 {config_path} 加载了 {len(config_data)} 个服务配置")
        return config_data
    
    except Exception as e:
        logger.error(f"加载配置文件 {config_path} 时出错: {str(e)}")
        logger.warning("使用默认配置")
        return DEFAULT_SERVICE_CONFIGS

# 加载服务配置
SERVICE_CONFIGS = load_service_configs()

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

def get_enabled_services(region):
    """获取在指定区域启用的AWS服务"""
    enabled_services = {}
    
    for service_name, config in SERVICE_CONFIGS.items():
        try:
            # 尝试创建服务客户端
            client = boto3.client(service_name, region_name=region)
            
            # 如果能成功创建客户端，则认为该服务可用
            enabled_services[service_name] = {
                'client': service_name,
                'resource_types': config['resource_types']
            }
            logger.debug(f"区域 {region} 中启用了服务: {service_name}")
        except (ClientError, boto3.exceptions.UnknownServiceError) as e:
            logger.debug(f"区域 {region} 中未启用服务 {service_name}: {str(e)}")
            continue
    
    return enabled_services

def get_untagged_resources(account_id, regions=None, services=None, tag_key='map-xxx', max_workers=10):
    """
    获取未打指定标签的资源
    
    参数:
        account_id (str): AWS账号ID
        regions (list): 要检查的区域列表，如果为None则检查所有可用区域
        services (list): 要检查的服务列表，如果为None则检查所有支持的服务
        tag_key (str): 要检查的标签键
        max_workers (int): 最大并行工作线程数
    
    返回:
        dict: 按区域和服务分组的未打标签资源列表
    """
    if regions is None:
        regions = get_available_regions()
    
    untagged_resources = {}
    
    # 使用线程池并行处理多个区域
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_region = {
            executor.submit(process_region, account_id, region, services, tag_key): region
            for region in regions
        }
        
        for future in as_completed(future_to_region):
            region = future_to_region[future]
            try:
                region_resources = future.result()
                if region_resources:
                    untagged_resources[region] = region_resources
            except Exception as e:
                logger.error(f"处理区域 {region} 时出错: {str(e)}")
    
    return untagged_resources

def process_region(account_id, region, services=None, tag_key='map-xxx'):
    """处理单个区域的资源"""
    logger.info(f"正在处理区域: {region}")
    region_resources = {}
    
    # 获取该区域启用的服务
    enabled_services = get_enabled_services(region)
    
    # 如果指定了服务列表，则只处理这些服务
    if services:
        enabled_services = {k: v for k, v in enabled_services.items() if k in services}
    
    # 创建资源标签API客户端
    tagging = boto3.client('resourcegroupstaggingapi', region_name=region)
    
    for service_name, service_config in enabled_services.items():
        service_resources = process_service(account_id, region, service_name, service_config, tagging, tag_key)
        if service_resources:
            region_resources[service_name] = service_resources
    
    return region_resources

def process_service(account_id, region, service_name, service_config, tagging, tag_key):
    """处理单个服务的资源"""
    logger.info(f"正在处理服务: {service_name} 在区域 {region}")
    service_resources = {}
    
    try:
        client = boto3.client(service_config['client'], region_name=region)
        
        for resource_type_config in service_config['resource_types']:
            resource_type = resource_type_config['type']
            list_method = resource_type_config['list_method']
            extract_ids = resource_type_config['extract_ids']
            arn_template = resource_type_config['arn_template']
            
            try:
                # 处理特殊服务的参数需求
                paginate_params = {}
                
                # 处理需要MaxResults参数的服务
                if service_name == 'cognito-identity' and list_method == 'list_identity_pools':
                    paginate_params['MaxResults'] = 60  # AWS Cognito Identity 要求提供 MaxResults 参数
                elif service_name == 'cognito-idp' and list_method == 'list_user_pools':
                    paginate_params['MaxResults'] = 60  # Cognito User Pools 也需要 MaxResults
                elif service_name == 'glue' and list_method == 'get_databases':
                    paginate_params['MaxResults'] = 100  # Glue 服务可能需要 MaxResults
                
                # 处理其他可能需要特殊参数的服务
                if service_name == 'ssm' and list_method == 'describe_parameters':
                    paginate_params['ParameterFilters'] = []  # 某些服务可能需要空过滤器
                
                # 分页处理资源列表
                try:
                    paginator = client.get_paginator(list_method)
                    all_resources = []
                    
                    for page in paginator.paginate(**paginate_params):
                        if arn_template is None:
                            # 某些服务（如ALB/NLB）直接返回ARN
                            resource_arns = extract_ids(page)
                            all_resources.extend(resource_arns)
                        else:
                            # 其他服务需要构建ARN
                            resource_ids = extract_ids(page)
                            resource_arns = [
                                arn_template.format(id=resource_id, region=region, account_id=account_id)
                                for resource_id in resource_ids
                            ]
                            all_resources.extend(resource_arns)
                except Exception as e:
                    logger.warning(f"处理服务 {service_name} 的资源类型 {resource_type} 时出错: {str(e)}")
                    continue
                
                if not all_resources:
                    continue
                
                # 批量检查标签（每次最多20个ARN）
                untagged = []
                for i in range(0, len(all_resources), 20):
                    batch = all_resources[i:i+20]
                    try:
                        response = tagging.get_resources(ResourceARNList=batch)
                        
                        # 提取所有资源的标签信息
                        tagged_resources = {
                            res['ResourceARN']: [tag['Key'] for tag in res.get('Tags', [])]
                            for res in response.get('ResourceTagMappingList', [])
                        }
                        
                        # 检查每个ARN是否缺少指定标签
                        for arn in batch:
                            tag_keys = tagged_resources.get(arn, [])
                            if tag_key not in tag_keys:
                                untagged.append(arn)
                    except ClientError as e:
                        logger.warning(f"获取资源标签时出错 {batch}: {str(e)}")
                        # 某些资源可能不支持标签，我们跳过这些错误
                        continue
                
                if untagged:
                    service_resources[resource_type] = untagged
                    
            except ClientError as e:
                logger.warning(f"处理资源类型 {resource_type} 时出错: {str(e)}")
                continue
                
    except ClientError as e:
        logger.error(f"处理服务 {service_name} 时出错: {str(e)}")
    
    return service_resources

def save_resources_to_json(resources, output_path, tag_key, tag_value):
    """
    将未打标签的资源保存到JSON文件
    
    参数:
        resources (dict): 按区域和服务分组的资源列表
        output_path (str): 输出文件路径
        tag_key (str): 标签键
        tag_value (str): 标签值
    """
    # 创建包含元数据的资源对象
    resource_data = {
        'metadata': {
            'timestamp': str(logging.Formatter.converter()),
            'tag_key': tag_key,
            'tag_value': tag_value
        },
        'resources': resources
    }
    
    # 保存到文件
    with open(output_path, 'w') as f:
        json.dump(resource_data, f, indent=2)
    
    logger.info(f"未打标签的资源已保存到 {output_path}")

def load_resources_from_json(input_path):
    """
    从JSON文件加载资源
    
    参数:
        input_path (str): 输入文件路径
    
    返回:
        tuple: (resources, tag_key, tag_value)
    """
    try:
        with open(input_path, 'r') as f:
            data = json.load(f)
        
        resources = data.get('resources', {})
        metadata = data.get('metadata', {})
        tag_key = metadata.get('tag_key', 'map-migrated')
        tag_value = metadata.get('tag_value', 'd-server-01234567')
        
        return resources, tag_key, tag_value
    
    except Exception as e:
        logger.error(f"加载资源文件 {input_path} 时出错: {str(e)}")
        raise

def tag_resources(resources, tag_key, tag_value, dry_run=True):
    """
    为资源添加标签
    
    参数:
        resources (dict): 按区域和服务分组的资源列表
        tag_key (str): 标签键
        tag_value (str): 标签值
        dry_run (bool): 如果为True，则只打印要添加的标签而不实际添加
    
    返回:
        dict: 标签添加结果统计
    """
    results = {
        'success': 0,
        'failed': 0,
        'skipped': 0
    }
    
    for region, region_resources in resources.items():
        tagging = boto3.client('resourcegroupstaggingapi', region_name=region)
        
        for service, service_resources in region_resources.items():
            for resource_type, arns in service_resources.items():
                logger.info(f"为 {region} 区域的 {service} {resource_type} 添加标签")
                
                # 批量添加标签（每次最多20个ARN）
                for i in range(0, len(arns), 20):
                    batch = arns[i:i+20]
                    
                    if dry_run:
                        logger.info(f"[DRY RUN] 将为以下资源添加标签 {tag_key}={tag_value}:")
                        for arn in batch:
                            logger.info(f"  {arn}")
                        results['skipped'] += len(batch)
                        continue
                    
                    try:
                        response = tagging.tag_resources(
                            ResourceARNList=batch,
                            Tags={tag_key: tag_value}
                        )
                        
                        # 检查失败的资源
                        failed = response.get('FailedResourcesMap', {})
                        success_count = len(batch) - len(failed)
                        
                        results['success'] += success_count
                        results['failed'] += len(failed)
                        
                        if failed:
                            logger.warning(f"无法为 {len(failed)} 个资源添加标签:")
                            for arn, failure in failed.items():
                                logger.warning(f"  {arn}: {failure.get('ErrorMessage')}")
                    
                    except ClientError as e:
                        logger.error(f"添加标签时出错: {str(e)}")
                        results['failed'] += len(batch)
    
    return results

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='AWS资源标签管理工具')
    parser.add_argument('--regions', nargs='+', help='要处理的AWS区域列表（默认：所有区域）')
    parser.add_argument('--services', nargs='+', help='要处理的AWS服务列表（默认：所有支持的服务）')
    parser.add_argument('--tag-key', default='map-migrated', help='要检查或添加的标签键（默认：map-migrated）')
    parser.add_argument('--tag-value', default='d-server-01234567', help='添加标签时使用的标签值')
    parser.add_argument('--output', default=DEFAULT_RESOURCES_PATH, help=f'输出资源文件路径（默认：{DEFAULT_RESOURCES_PATH}）')
    parser.add_argument('--input', help='输入资源文件路径（用于应用标签）')
    parser.add_argument('--apply', action='store_true', help='应用标签（如果不指定，则只列出未打标签的资源）')
    parser.add_argument('--verbose', '-v', action='store_true', help='启用详细日志输出')
    
    args = parser.parse_args()
    
    # 设置日志级别
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    try:
        # 如果提供了输入文件，则从文件加载资源并应用标签
        if args.input:
            logger.info(f"从文件 {args.input} 加载资源")
            resources, tag_key, tag_value = load_resources_from_json(args.input)
            
            # 如果命令行参数指定了标签键值，则覆盖文件中的值
            if args.tag_key != 'map-migrated':
                tag_key = args.tag_key
            if args.tag_value != 'd-server-01234567':
                tag_value = args.tag_value
            
            # 统计资源数量
            total_resources = 0
            for region, region_resources in resources.items():
                for service, service_resources in region_resources.items():
                    for resource_type, arns in service_resources.items():
                        total_resources += len(arns)
            
            logger.info(f"从文件加载了 {total_resources} 个资源")
            
            # 打印资源
            for region, region_resources in resources.items():
                print(f"\n区域: {region}")
                for service, service_resources in region_resources.items():
                    print(f"  服务: {service}")
                    for resource_type, arns in service_resources.items():
                        print(f"    {resource_type} ({len(arns)}):")
                        for arn in arns:
                            print(f"      {arn}")
            
            # 如果指定了--apply参数，则添加标签
            if args.apply and total_resources > 0:
                logger.info(f"正在为 {total_resources} 个资源添加标签 {tag_key}={tag_value}")
                results = tag_resources(
                    resources=resources,
                    tag_key=tag_key,
                    tag_value=tag_value,
                    dry_run=False
                )
                
                logger.info(f"标签添加结果: 成功={results['success']}, 失败={results['failed']}, 跳过={results['skipped']}")
            elif total_resources > 0:
                logger.info("使用 --apply 参数来添加标签")
        
        # 否则，扫描资源并保存到文件
        else:
            # 获取当前账号ID
            account_id = get_account_id()
            logger.info(f"当前AWS账号ID: {account_id}")
            
            # 获取未打标签的资源
            untagged = get_untagged_resources(
                account_id=account_id,
                regions=args.regions,
                services=args.services,
                tag_key=args.tag_key
            )
            
            # 统计资源数量
            total_resources = 0
            for region, region_resources in untagged.items():
                for service, service_resources in region_resources.items():
                    for resource_type, arns in service_resources.items():
                        total_resources += len(arns)
            
            logger.info(f"找到 {total_resources} 个未打 '{args.tag_key}' 标签的资源")
            
            # 打印未打标签的资源
            for region, region_resources in untagged.items():
                print(f"\n区域: {region}")
                for service, service_resources in region_resources.items():
                    print(f"  服务: {service}")
                    for resource_type, arns in service_resources.items():
                        print(f"    {resource_type} ({len(arns)}):")
                        for arn in arns:
                            print(f"      {arn}")
            
            # 保存资源到文件
            if total_resources > 0:
                save_resources_to_json(
                    resources=untagged,
                    output_path=args.output,
                    tag_key=args.tag_key,
                    tag_value=args.tag_value
                )
                logger.info(f"资源已保存到 {args.output}，使用 --input {args.output} --apply 来应用标签")
            
    except Exception as e:
        logger.error(f"程序执行出错: {str(e)}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
