# AWS 资源标签管理工具

这个项目提供了一套用于管理 AWS 资源标签的工具。项目主要包含两个核心组件：资源标签添加工具和服务配置生成工具。

## 功能特点

### 资源标签管理 (`add_service_tag.py`)

- **资源发现**：自动扫描 AWS 账户中的资源，支持多区域并行处理
- **标签缺失检测**：识别缺少特定标签（如 `map-xxx`）的资源
- **批量标签应用**：支持对多个资源同时应用标签
- **资源报告**：生成详细的资源清单报告，包括资源类型、ARN 等信息
- **支持多种 AWS 服务**：覆盖 EC2、S3、Lambda、RDS、DynamoDB 等 40+ 种 AWS 服务

### 服务配置生成 (`generate_service_config.py`)

- **服务发现**：自动检测 AWS 账户中启用的服务
- **配置模板**：为各种 AWS 服务提供预定义的资源类型配置模板
- **配置生成**：生成标准化的服务配置 JSON 文件，供标签管理工具使用
- **可扩展性**：支持轻松添加新的服务和资源类型

## 使用场景

- **云迁移项目**：为迁移到 AWS 的资源添加标准化标签（如 `map-xxx`）
- **资源管理**：确保所有 AWS 资源都有适当的标签，便于成本分配和资源组织
- **合规性**：帮助满足组织的标签策略和合规性要求
- **自动化**：作为 CI/CD 流程的一部分，确保新创建的资源都有适当的标签

## 快速开始

### 安装依赖

```bash
pip install boto3
```

### 配置 AWS 凭证

确保您已经配置了 AWS 凭证，可以通过以下方式之一：

- AWS CLI 配置 (`aws configure`)
- 环境变量 (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
- IAM 角色（如果在 EC2 实例上运行）

### 生成服务配置

```bash
python generate_service_config.py --output aws_service_config.json
```

### 扫描未标记的资源

```bash
python add_service_tag.py --tag-key map-migrated --output untagged_resources.json
```

### 应用标签

```bash
python add_service_tag.py --input untagged_resources.json --tag-key map-migrated --tag-value d-server-01234567 --apply
```

## 命令行参数

### `add_service_tag.py`

- `--regions`：要处理的 AWS 区域列表（默认：所有区域）
- `--services`：要处理的 AWS 服务列表（默认：所有支持的服务）
- `--tag-key`：要检查或添加的标签键（默认：map-migrated）
- `--tag-value`：添加标签时使用的标签值（默认：d-server-01234567）
- `--output`：输出资源文件路径（默认：untagged_resources.json）
- `--input`：输入资源文件路径（用于应用标签）
- `--apply`：应用标签（如果不指定，则只列出未打标签的资源）
- `--verbose`：启用详细日志输出

### `generate_service_config.py`

- `--regions`：要处理的 AWS 区域列表（默认：所有区域）
- `--output`：输出配置文件路径（默认：aws_service_config.json）
- `--verbose`：启用详细日志输出

## 项目结构

- `add_service_tag.py`：主要的标签管理工具
- `generate_service_config.py`：服务配置生成工具
- `aws_service_config.json`：服务配置文件，包含各种 AWS 服务的资源类型定义

## 支持的 AWS 服务

项目支持多种 AWS 服务，包括但不限于：

- 计算服务：EC2、Lambda、ECS、EKS
- 存储服务：S3、EBS、EFS
- 数据库服务：RDS、DynamoDB、ElastiCache、Neptune
- 网络服务：ELB、ALB/NLB、API Gateway
- 安全服务：IAM、KMS、Secrets Manager
- 分析服务：EMR、Glue
- 应用集成：SNS、SQS、EventBridge
- 开发者工具：CodeBuild、CodeCommit、CodeDeploy、CodePipeline
- 监控服务：CloudWatch


## 免责声明

**本项目仅供测试和学习使用，不建要直接用于生产环境**

- 本工具会扫描并修改您 AWS 账户中的资源标签，请在使用前充分了解其功能和影响
- 在生产环境中使用前，强烈建议在测试账户或非关键资源上进行测试
- 作者不对使用本工具导致的任何数据丢失、服务中断或其他问题负责
- 使用本工具前，请确保您有适当的 AWS 权限，并了解相关的 AWS 服务和资源
- 本工具不会删除或修改资源本身，仅添加或修改资源标签
- 建议在使用前备份重要数据，并在非高峰时段运行大规模标签操作

## 注意事项

- 工具需要适当的 AWS IAM 权限才能正常工作，包括读取资源和修改标签的权限
- 大规模扫描可能会产生 AWS API 调用费用，请注意控制扫描范围和频率
- 某些 AWS 资源可能不支持标签，工具会自动跳过这些资源
- 工具默认使用 20 个并行线程，可以根据需要调整 `max_workers` 参数


