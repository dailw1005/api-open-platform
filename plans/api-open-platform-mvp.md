# API 开放平台 MVP 整体方案与实施蓝图

> 状态：Approved；Gate 0、FlowValidator、HMAC v1 签名与验证/防重放、Publication Guard、PostgreSQL 基础迁移均已 GREEN。  
> 范围：整体方案、数据模型、编排 DSL、安全基线、技术选型与实施切片。  
> 约束：本阶段不编写业务代码。
> 仓储前提：当前目录尚不是 Git 仓库；方案确认后由 S0 显式初始化，Blueprint 以 direct mode 执行，不自动创建分支或提交。

## 1. 结论摘要

MVP 采用“模块化单体起步、控制面与数据面逻辑隔离、独立编排引擎组件”的路线。控制面负责租户、用户、API 目录、应用、凭据、策略、编排发布和管理台；数据面负责公开请求鉴权、限流、代理、编排执行、计量和审计。两者先共用一个部署单元以降低交付复杂度，但代码边界、数据所有权和运行路径从第一天就分离，后续可按负载和故障域拆成独立服务。

核心原则：

- 先完成“注册 -> 发布 -> 创建应用 -> 获取凭据 -> 签名调用 -> 限流/计量/日志”的闭环。
- 编排只组合已登记 API，使用受限 DSL 与安全表达式，不允许任意 URL、脚本或代码执行。
- 发布版本不可变，运行时使用已发布快照，支持显式回滚。
- 外部 API 的调用计量、限流和审计是强制能力，不提供关闭开关。
- MVP 不做微服务、真实支付、复杂审批和图形化拖拽；这些列入二期。

### 1.1 业务闭环

1. 平台管理员在系统租户中登记上游 API，完成连通性检查、Schema 和策略配置后发布到平台目录。
2. 应用开发者创建租户内应用，选择已发布 API 范围；系统生成 AppKey/Secret，Secret 仅展示一次。
3. 应用开发者编写编排草稿，引用已发布 API，在 sandbox 中测试后提交；平台管理员审核并发布不可变版本。
4. 应用使用 HMAC 签名调用公开 API；网关完成应用认证、签名校验、授权、多层限流和配额检查。
5. 单一 API 请求被代理到登记上游；编排请求由独立引擎执行并传递上下文变量。
6. 平台异步写入请求日志、计量记录和审计事件；开发者查看自己的用量与诊断，查看者读取授权范围内的数据。
7. 发生密钥泄露、异常流量或恶意配置时，管理员可紧急吊销凭据、下线 API 或回滚版本。

### 1.2 租户模型

- 采用“平台级共享 API 目录 + 租户级应用、凭据、用量和日志”模型。
- 平台运营方使用系统租户承载全局 API 目录和上游登记信息；业务租户消费已发布 API。
- 单一 API 默认使用 `PLATFORM_PUBLIC`，对所有活跃租户可见；租户编排生成的公开包装 API 默认使用 `TENANT_PRIVATE`，只有同租户应用可获授和调用。
- `PLATFORM_PUBLIC` 由系统租户中的平台编排发布；普通租户不能把自己的编排提升为平台公开 API。
- 公开 API 路径在全平台唯一，不按租户重复；应用身份决定调用主体，AppKey 所属租户决定数据隔离范围。
- 平台管理员是全局角色；应用开发者和查看者的资源访问始终受 `tenant_id` 约束。

## 2. 角色与权限清单

### 2.1 角色边界

| 角色 | 作用域 | 职责 |
| --- | --- | --- |
| 平台管理员 `PLATFORM_ADMIN` | 全局 | 运营平台、登记上游 API、发布目录、制定策略、处理安全事件 |
| 应用开发者 `APP_DEVELOPER` | 所属租户 | 创建应用、管理自己的凭据、调用已发布 API、编写和测试编排 |
| 查看者 `VIEWER` | 所属租户 | 只读查看文档、编排、使用量与脱敏日志 |

默认假设：平台管理员也是上游 API 的唯一登记与发布者；开发者消费已发布 API。若希望开发者也能登记私有上游 API，应作为二期能力，并增加网络域、审批和租户级出站策略。

账号与角色规则：用户账号全局唯一（邮箱规范化后唯一），一个账号可加入多个租户，但同一租户只允许一个租户角色；平台管理员是额外全局绑定。角色之间没有隐式继承：`APP_DEVELOPER` 可写自己的应用和草稿并读取自己的应用数据；`VIEWER` 可读取本租户全部已发布 API/编排、应用元数据和脱敏用量/日志，但不能写、不能测试、不能读取草稿或任何密钥材料。

### 2.2 权限矩阵

| 能力 | 平台管理员 | 应用开发者 | 查看者 |
| --- | --- | --- | --- |
| 创建/停用租户 | 全量 | 无 | 无 |
| 邀请/停用用户、分配角色 | 全量 | 无 | 无 |
| 查看租户成员 | 全量 | 本租户只读 | 本租户只读 |
| 登记/编辑上游 API 草稿 | 全量 | 无 | 无 |
| 提交/审核/发布/下线 API | 全量 | 无 | 无 |
| 查看已发布 API 文档 | 全量 | 本租户可见范围 | 本租户可见范围 |
| 创建应用 | 全量 | 本租户，限本人创建 | 无 |
| 查看应用基础信息 | 全量 | 自己创建的应用 | 本租户只读，不含密钥和敏感配置 |
| 编辑应用基础信息 | 全量 | 自己创建的应用 | 无 |
| 查看 AppKey | 全量 | 自己的应用 | 无 |
| 查看 Secret 明文 | 永不提供历史回读 | 仅创建/轮换成功时展示一次 | 无 |
| 轮换/吊销凭据 | 全量，含紧急吊销 | 自己的应用 | 无 |
| 授权 API 范围 | 全量 | 仅能在已发布目录中选择 | 只读 |
| 配置限流/配额/价格 | 全量 | 只读 | 只读 |
| 创建/编辑编排草稿 | 全量 | 本租户草稿 | 无 |
| 测试编排 | 全量 | 本租户沙箱 | 无 |
| 提交编排审核 | 全量 | 本租户草稿 | 无 |
| 发布/回滚编排 | 全量 | 无 | 无 |
| 查看编排定义 | 全量 | 本租户已发布版本；自己的草稿 | 本租户已发布版本只读 |
| 查看请求日志 | 全量 | 自己应用、字段脱敏 | 本租户、字段脱敏 |
| 查看调用量与账单明细 | 全量 | 自己应用 | 本租户只读 |
| 查看审计日志 | 全量 | 无 | 无 |
| 执行紧急封禁 | 全量 | 无 | 无 |

权限实现采用服务端 RBAC + 资源级所有权校验 + 租户过滤；前端菜单隐藏不属于安全控制。

## 3. MVP 功能范围

### 3.1 MVP 必做

| 能力域 | MVP 范围 | 验收要点 |
| --- | --- | --- |
| 租户与 IAM | 管理员邀请用户、固定三角色、租户隔离、本地账号 Session、管理员 MFA、CSRF | 跨租户资源不可读写；审计可追溯 |
| API 目录 | 手工登记、受限 OpenAPI 3.x 导入草稿、版本、环境、发布/弃用/下线、健康检查 | 禁止外部 `$ref` 和自动发布；发布版本不可变且可回滚 |
| 应用管理 | 创建应用、选择 API 范围、AppKey/Secret、轮换、吊销 | Secret 只展示一次；旧凭据可短暂重叠后失效 |
| 外部鉴权 | HMAC-SHA256 v1、时间窗、Nonce、请求体哈希、租户/应用/凭据/API/授权状态校验 | 密钥错误、重放、过期、吊销、越权均被拒绝 |
| 限流与配额 | 租户/应用/API 多维限流；日/月调用配额；标准限流响应头 | 多实例下计数一致；超限不触达上游 |
| 计量与账单明细 | 每次上游派发的请求 ID、价格快照、尝试次数和计费状态 | 编排多节点可分别计量；重试与重复投递不重复记账 |
| 日志与审计 | 请求日志、编排节点日志、管理操作审计、脱敏和保留策略 | 不记录 Secret、Signature、敏感正文 |
| 单一 API 代理 | 路由、方法/路径映射、上游超时、响应大小限制、错误归一 | 上游不可用时返回明确错误且不泄露内部地址 |
| API 编排 | 串行、并行、if/else、try/catch、重试、节点/整体超时、上下文变量 | 覆盖分支、串行、并行、异常、重试、超时测试 |
| 编排管理 | JSON DSL 编辑器、服务端校验、sandbox 测试运行、草稿/提交/发布/回滚 | 非法节点、悬空引用、超限配置和嵌套编排无法发布 |
| 管理台与开发者门户 | API 文档、应用与凭据、编排编辑与运行诊断、基本用量页面 | 关键闭环可完全通过界面完成 |
| 可观测性 | Request ID、结构化日志、指标、链路追踪、健康检查 | 可定位一次失败调用及对应上游/节点 |

### 3.2 二期迭代

- 图形化拖拽编排、Vue Flow/React Flow 画布、版本差异对比。
- 循环、子编排、异步长任务、人工审批、补偿事务、Saga、定时触发。
- 真实支付、发票、税务、合同价、优惠券、退款和复杂计费规则。
- OAuth 2.0/OIDC、JWT 换取、mTLS、双向证书、企业 SSO/SCIM。
- API 市场、订阅申请、审核流、租户自定义门户和域名。
- 多环境灰度、流量镜像、金丝雀发布、自动回滚。
- ClickHouse/OpenSearch 大数据量日志分析、异常检测和实时大屏。
- SDK 自动生成、Mock Server、契约测试市场和多语言代码示例。
- 跨地域容灾、单元化、多活、租户级专属集群。

### 3.3 明确不做

- 不允许编排直接填写任意 URL 或任意请求头。
- 不提供脚本节点、插件上传、任意代码执行和自定义函数。
- 不将 Redis 作为账单或审计事实源。
- 不在 MVP 内承诺跨区域强一致和高可用 SLA。

## 4. 整体架构分层

### 4.1 逻辑架构

```text
管理台 / 开发者门户
        |
        v
控制面 Control Plane
  IAM/RBAC | 租户 | API 目录 | 应用/凭据 | 策略/价格
  编排编辑/校验/审批/发布 | 运营查询
        |
        | 发布快照 + Outbox 事件
        v
PostgreSQL | Redis | RabbitMQ | KMS/Secrets | 对象存储
        ^
        | 配置缓存 / 事件消费
        |
数据面 Data Plane
  WAF/反向代理 -> 公开网关 -> 鉴权 -> 限流/配额
  -> 单一 API 代理 或 编排运行时 -> 上游 API
  -> 计量/日志/审计事件
```

### 4.2 模块分层

| 层 | 责任 | 关键约束 |
| --- | --- | --- |
| 接入层 | TLS、WAF、路由、请求大小与超时上限 | 只信任受控代理写入的客户端 IP |
| 控制面 | 管理配置、审批、发布、查询 | 不进入公开请求热路径 |
| 数据面 | 鉴权、限流、代理、编排执行、计量 | 只读取已发布快照和缓存 |
| 编排层 | DSL 校验、编译、执行、节点追踪 | 独立接口，不依赖控制面 UI |
| 异步层 | 计量、审计、缓存失效、聚合 | Outbox + 幂等消费者 |
| 数据层 | PostgreSQL、Redis、对象存储、KMS | 事实源、缓存和密钥职责分离 |
| 运维层 | 指标、日志、追踪、告警、备份 | 一次调用可端到端定位 |

### 4.3 代码模块建议

```text
platform-control       # 控制面 REST、IAM、目录、策略、审批
gateway-runtime        # 外部 API 鉴权、限流、代理入口
orchestration-engine   # DSL 模型、校验器、编译器、执行器
usage-audit            # 计量、账单明细、日志与审计事件
platform-contract      # OpenAPI、事件、错误码、共享 DTO
platform-app           # Spring Boot 启动、配置与装配
platform-web           # 管理台/开发者门户
```

模块依赖方向必须由构建规则约束：`orchestration-engine` 不依赖 Web 管理模块；`gateway-runtime` 不依赖控制面实现；共享模块只放契约，不放业务逻辑。

### 4.4 部署策略

- MVP：一个后端部署单元、一个前端部署单元；Docker Compose 启动 PostgreSQL、Redis、RabbitMQ 和对象存储。
- 公开网关与控制面使用不同的路由前缀、认证机制和网络入口策略。
- 运行实例无状态；已发布配置缓存到 Redis/本地 Caffeine，通过 Outbox 事件失效。
- 数据面不得在每次请求时同步调用控制面。
- 二期按故障域拆为 `control-plane`、`gateway`、`orchestrator` 三个可独立扩缩容服务。

## 5. 数据库核心表结构

所有表使用 UUIDv7/ULID 主键、UTC 时间戳和乐观锁版本号。所有租户级业务表包含 `tenant_id`；平台级共享目录使用 `owner_tenant_id` 标识运营方系统租户。金额使用 `DECIMAL(20,6)` 或最小货币单位。

租户级表使用 `(tenant_id, id)` 复合唯一键和复合外键，例如 `app_credential` 只能引用同一租户的 `app`。这些表默认启用 PostgreSQL RLS；平台管理员跨租户读取使用单独数据库角色、显式平台作用域和审计事件，不使用普通业务连接绕过 RLS。

### 5.1 身份与租户

| 表 | 关键字段 | 约束与用途 |
| --- | --- | --- |
| `iam_tenant` | `id`, `code`, `name`, `status`, `auth_epoch`, `created_at` | `code` 全局唯一；支持 `ACTIVE/SUSPENDED`，状态变更递增 epoch |
| `iam_user` | `id`, `email`, `password_hash`, `mfa_enabled`, `status` | 邮箱规范化后全局唯一；账号可绑定多个租户；密码使用 Argon2id |
| `iam_role_binding` | `id`, `user_id`, `tenant_id`, `role_code`, `scope_type` | 固定角色；同一租户每用户只允许一个角色；平台管理员为全局作用域 |
| `iam_session` | `id`, `user_id`, `token_hash`, `expires_at`, `revoked_at` | 仅保存会话令牌哈希 |

### 5.2 API 目录与接入

| 表 | 关键字段 | 约束与用途 |
| --- | --- | --- |
| `api_definition` | `id`, `owner_tenant_id`, `code`, `name`, `public_method`, `public_path`, `kind`, `visibility`, `active_prod_publication_id`, `status`, `publish_epoch` | `(public_method, public_path)` 全平台唯一；visibility 为 `PLATFORM_PUBLIC/TENANT_PRIVATE`；活动指针是生产公开路由唯一真相 |
| `api_version` | `id`, `api_id`, `version`, `status`, `request_schema`, `response_schema`, `timeout_ms`, `config_json`, `config_checksum`, `created_by` | 已发布版本不可修改；保存完整发布快照 |
| `api_publication` | `id`, `api_id`, `visibility`, `api_version_id`, `environment`, `publication_no`, `status`, `manifest_json`, `manifest_checksum`, `previous_publication_id`, `published_by`, `published_at` | `(api_id, environment, publication_no)` 唯一；MVP 只允许 `environment=PROD`；manifest 固化解析后的上游环境和引用清单 |
| `upstream_endpoint` | `id`, `owner_tenant_id`, `code`, `name`, `method`, `path_template`, `status` | 平台级登记；地址和认证配置在环境表中保存 |
| `upstream_environment` | `id`, `owner_tenant_id`, `endpoint_id`, `environment`, `version`, `base_url`, `auth_ref`, `tls_policy`, `egress_zone`, `status` | `(endpoint_id, environment, version)` 唯一；分别配置 `PROD/SANDBOX` |
| `upstream_credential` | `id`, `owner_tenant_id`, `name`, `auth_type`, `secret_ref`, `status`, `rotated_at` | 默认只存 KMS/Vault 引用；禁止在 DSL 或通用业务表保存明文 |

说明：`api_version.config_json` 对单一 API 保存 `upstream_endpoint_id`、映射和超时；对编排 API 保存 `orchestration_version_id`。运行时按 `environment` 解析对应的 `upstream_environment`，因此 sandbox 与生产使用同一 API 定义但不同的已登记环境配置。PostgreSQL `CHECK` 不能跨表验证目标状态，因此发布由事务服务完成：检查目标已发布、解析 `PROD` 环境、计算引用清单、写入 `api_publication` 的 `manifest_json`，最后原子切换 `api_definition.active_prod_publication_id`。数据库触发器或受限写权限阻止修改已发布版本，防止绕过服务层。

编排草稿测试通过 `/developer/v1/orchestrations/{id}/test-runs` 触发：临时编译草稿 IR，强制 `environment=SANDBOX`，只允许访问 `upstream_environment.environment=SANDBOX` 的目标；生产发布只接受已发布环境配置和不可变 IR。缺少 sandbox 配置的 API 返回明确测试不可用错误，不回退到生产。

### 5.3 应用与凭据

| 表 | 关键字段 | 约束与用途 |
| --- | --- | --- |
| `app` | `id`, `tenant_id`, `name`, `owner_user_id`, `status`, `auth_epoch`, `description` | 名称租户内唯一；吊销后不可恢复；状态变更递增 `auth_epoch` |
| `app_credential` | `id`, `tenant_id`, `app_id`, `app_key`, `secret_ciphertext`, `kms_key_id`, `status`, `auth_epoch`, `expires_at` | `(tenant_id, app_id)` 复合外键；`app_key` 全局唯一；Secret 信封加密 |
| `app_api_grant` | `id`, `tenant_id`, `app_id`, `api_id`, `granted_by`, `status`, `auth_epoch` | `(tenant_id, app_id, api_id)` 唯一；授权状态变更递增 epoch |
| `credential_rotation` | `id`, `tenant_id`, `app_id`, `old_credential_id`, `new_credential_id`, `overlap_until`, `status` | 轮换审计；最多一个重叠凭据 |

说明：HMAC 校验需要可恢复的 Secret，因此不能只存哈希。Secret 创建时展示一次，数据库只保存密文；解密结果短时缓存，轮换/吊销后立即失效。KMS 加密使用租户、应用和凭据 ID 作为 AAD，防止密文被跨对象替换。`last_used_at` 不放在请求热路径逐次更新，改为 Redis 记录后批量回写。

AppKey 至少 128 bit 随机熵，Secret 至少 256 bit 随机熵，均使用不可预测的随机源生成；认证失败响应不区分“AppKey 不存在”和“签名错误”。

### 5.4 策略、计量与审计

| 表 | 关键字段 | 约束与用途 |
| --- | --- | --- |
| `rate_limit_policy` | `id`, `tenant_id`, `scope_type`, `scope_id`, `limit_value`, `window_seconds`, `burst`, `algorithm`, `enabled` | `tenant_id` 对平台/API 规则可空；租户/应用规则必填；作用域组合唯一 |
| `quota_policy` | `id`, `tenant_id`, `scope_type`, `scope_id`, `period`, `limit_value`, `metric`, `enabled` | 日/月调用配额；作用域/周期组合唯一 |
| `price_rule` | `id`, `owner_tenant_id`, `api_id`, `metric`, `unit_price`, `currency`, `billable_status`, `effective_from`, `effective_to` | 平台级定价；同 API/metric 有效期不得重叠，发布时固化快照 |
| `usage_record` | `usage_id`, `root_request_id`, `tenant_id`, `app_id`, `api_id`, `api_version_id`, `environment`, `source_type`, `node_id`, `attempt_no`, `billing_unit_id`, `quantity`, `unit_price`, `amount`, `currency`, `billable`, `occurred_at` | `(root_request_id, billing_unit_id, attempt_no)` 唯一；一次编排可有多次上游计量 |
| `usage_daily` | `tenant_id`, `app_id`, `api_id`, `environment`, `source_type`, `stat_date`, `calls`, `billable_calls`, `amount` | `(tenant_id, app_id, api_id, environment, source_type, stat_date)` 唯一；只聚合生产可计费用量 |
| `request_log` | `request_id`, `client_request_id`, `root_request_id`, `tenant_id`, `app_id`, `api_id`, `environment`, `status_code`, `latency_ms`, `client_ip`, `trace_id`, `error_code`, `started_at` | `request_id` 由服务端生成；按日分区；默认不存正文 |
| `audit_log` | `id`, `tenant_id`, `actor_id`, `action`, `resource_type`, `resource_id`, `result`, `before_json`, `after_json`, `trace_id` | 只追加；字段脱敏；管理端不可修改 |
| `outbox_event` | `id`, `aggregate_type`, `aggregate_id`, `event_type`, `payload`, `status`, `retry_count`, `created_at` | 事务性发布；消费者幂等 |
| `idempotency_record` | `id`, `tenant_id`, `app_id`, `scope`, `root_request_id`, `node_id`, `idempotency_key`, `request_hash`, `state`, `dispatch_state`, `lease_until`, `response_status`, `response_ref`, `expires_at` | `(tenant_id, app_id, scope, idempotency_key)` 唯一；`state=RESERVED/IN_PROGRESS/COMPLETED/FAILED/EXPIRED` |

### 5.5 编排

| 表 | 关键字段 | 约束与用途 |
| --- | --- | --- |
| `orchestration` | `id`, `tenant_id`, `code`, `name`, `owner_user_id`, `status`, `latest_published_version_id` | 编排身份；`latest_published_version_id` 仅作目录展示，公开路由真相在 `api_publication` |
| `orchestration_version` | `id`, `tenant_id`, `orchestration_id`, `version`, `dsl_json`, `compiled_ir_json`, `required_api_set_json`, `checksum`, `status`, `created_by`, `published_at` | `(tenant_id, orchestration_id)` 复合外键；发布时固化引用 API 清单 |
| `orchestration_run` | `run_id`, `tenant_id`, `request_id`, `root_request_id`, `orchestration_version_id`, `api_publication_id`, `app_id`, `environment`, `mode`, `status`, `started_at`, `ended_at`, `error_code` | `mode` 为 `PROD/SANDBOX_TEST`；sandbox 会话测试允许 `app_id` 为空 |
| `orchestration_node_run` | `tenant_id`, `run_id`, `node_id`, `node_type`, `attempt`, `api_id`, `idempotency_key_hash`, `status`, `started_at`, `ended_at`, `error_code`, `input_digest`, `output_digest` | 节点级诊断；不保存明文敏感数据 |

### 5.6 数据不变量

- 所有租户级表查询必须带 `tenant_id`；租户级表默认强制 RLS，平台管理员跨租户访问走独立审计角色。
- 所有租户子表外键使用 `(tenant_id, parent_id)` 复合键，禁止只按全局 ID 关联。
- 凭证、发布版本、用量和审计记录禁止物理级联删除；使用状态迁移和保留策略。
- 计量记录以 `(root_request_id, billing_unit_id, attempt_no)` 幂等；重复事件不得重复生成金额。
- 已发布 `api_version` 和 `orchestration_version` 的任何业务字段不可更新；变更必须生成新版本。
- 同一 `api_id + PROD` 只允许一个活动 publication；`active_prod_publication_id` 与活动 publication 的唯一索引在同一事务内维护。
- `PUBLISHED` 表示不可变制品已经获批，不等于公开路由已生效；只有 `active_prod_publication_id` 指向的 publication 可进入生产运行时。
- `api_definition.active_prod_publication_id` 是生产公开路由的唯一真相源，必须引用同 API、同 visibility 的 `PROD` publication；数据库触发器和服务测试共同保证。`api_version`、`orchestration_version` 自身不表示线上生效。
- `TENANT_PRIVATE` 路由鉴权时必须匹配 AppKey 所属租户与 `owner_tenant_id`；`PLATFORM_PUBLIC` 才能跨租户授权。sandbox 测试不创建 publication。
- 租户、应用、凭据、API 和授权的状态变更必须递增对应 epoch；运行时忽略旧 epoch 事件。
- 租户级缓存键必须包含租户、资源 ID 和版本；全局目录缓存键包含平台作用域、API ID 和版本，禁止只使用可变的 `apiCode`。

## 6. 对外鉴权、限流、计量与日志契约

### 6.1 HMAC 鉴权

请求头：

```text
X-Signature-Version: v1
X-App-Key: ak_xxx
X-Timestamp: 1760000000
X-Nonce: <base64url 16-64 bytes>
X-Signature: <hex hmac sha256>
X-Client-Request-Id: <optional client correlation id>
Idempotency-Key: <optional>
```

签名原文使用 UTF-8 和 `\n` 连接：

```text
AK-HMAC-V1
appKey
canonical_host
UPPERCASE_METHOD
canonical_path
canonical_query
canonical_content_type
timestamp
nonce
hex_sha256(raw_body)
```

规范化约定：

- `canonical_host` 取经过受信代理校验的 ASCII Host，转小写；默认端口省略，非默认端口保留。
- 路径只接受 origin-form，大小写敏感，尾斜杠有意义；拒绝 `%2F`、`%5C`、点段、连续斜杠和非法 UTF-8；已编码字节使用大写十六进制。
- Query 按原始 `name=value` 对解析，严格 UTF-8 解码后按 RFC 3986 重新编码；先按名称、再按值排序，重复参数全部保留，空值规范为 `name=`。重复歧义无法无损规范化时直接拒绝。
- Query 中原始 `+` 视为非法字符，要求客户端用 `%2B` 表示加号、`%20` 表示空格；避免表单编码与 RFC 3986 产生两套签名结果。
- `canonical_content_type` 只保留小写媒体类型，去掉参数，例如 `Application/JSON; charset=utf-8` 规范为 `application/json`；无 Content-Type 时为空串。
- 有正文但没有受支持的 Content-Type 直接拒绝；MVP 只允许 `application/json`、`application/x-www-form-urlencoded` 和 `text/plain`。
- 无请求体时使用空字节串的 SHA-256：`e3b0c442...b855`；JSON 体哈希基于原始请求字节，不重新序列化。
- 时间戳为 UTC Unix 秒；Nonce 只允许 base64url 字符，在应用作用域内单次使用。
- Header 名称不区分大小写，但重复或冲突 Header 一律拒绝；`Host` 和 `Content-Type` 必须与签名值一致。
- 签名输出为小写十六进制；Secret 和签名均不得写入日志。`v1` 规范化规则发布后不可变更，升级必须引入新版本。

服务端按以下顺序处理：

1. 基础 IP 限流与请求大小检查。
2. 校验签名版本、时间窗和规范化规则；同一 Nonce 在 Redis 中只能使用一次。
3. 查询 AppKey；租户必须为 `ACTIVE`，应用必须为 `ACTIVE`，凭据必须为 `ACTIVE/ROTATING` 且未过期。
4. 解密 Secret，使用常量时间比较 HMAC。
5. 校验 API 状态、当前 `active_prod_publication_id`、publication visibility、版本校验和应用授权；`TENANT_PRIVATE` 必须与 AppKey 所属租户一致。
6. 同时校验租户、应用、API 三层限流与配额。
7. 路由到单一 API 或编排；为编排加载发布清单，节点执行时再次校验清单内 API 状态。
8. 记录服务端请求 ID、版本和计量事件。

Secret 永远不放入 URL、Header、Cookie、日志或错误响应。

状态缓存规则：

- 身份与吊销状态最大陈旧时间 5 秒；已发布配置最大陈旧时间 30 秒。
- 租户、应用、凭据、授权、API 发布均带单调递增 epoch；实例只接受更高 epoch 的失效事件。
- 吊销类事件通过 Outbox、Redis 失效标记和本地缓存清理传播；事件乱序时由 epoch 兜底。
- 无法从数据库或缓存确认“未吊销”时按 fail-closed 返回 `503`，不得使用过期状态继续调用。
- 凭据 Secret 解密缓存使用短 TTL，轮换/吊销后主动失效；不缓存超过安全 TTL。

### 6.2 限流

- Redis Lua 原子实现令牌桶；时间使用 Redis 服务端时间，避免多实例时钟偏差。
- 维度为 `tenant -> app -> api`，所有已启用策略都必须通过；不是简单覆盖。
- 同一请求的多维判断和扣减由单个 Lua 脚本原子完成；任一维度失败时不消耗其它维度额度。
- 编排节点调用同样消耗应用、租户和目标 API 的策略额度；编排授权清单不能替代节点级限流。
- 预认证按 IP 做粗粒度防爆破限流；认证后再做业务限流。
- Redis 不可用时默认返回 `503`，禁止静默放行；如需降级必须通过显式安全开关并写审计。
- 日/月配额使用 Redis 原子桶并定期从 `usage_record` 对账；Redis 不可用或对账状态未知时 fail-closed。
- 429 响应返回 `Retry-After`、`X-RateLimit-Limit`、`X-RateLimit-Remaining`、`X-RateLimit-Reset`。

### 6.3 计量与账单

- 只有通过鉴权并实际派发到上游的请求才默认进入计费候选；单一 API 代理和编排中的每个节点分别计量。
- `billing_unit_id` 在单一 API 代理中为 API 定义 ID，在编排中为 `nodeId`；`source_type` 区分 `SINGLE_API/FLOW_NODE`。
- 平台内部错误、鉴权失败和限流拒绝默认不计费；上游 4xx/5xx 的计费策略由 `price_rule.billable_status` 显式配置。
- 计费数量、单价和金额均由服务端生成；价格在派发时快照。
- 使用 Outbox 发布 `usage.recorded` 事件，消费者按 `(root_request_id, billing_unit_id, attempt_no)` 幂等。
- MVP 的“计费”是计量、价格快照和账单明细，不对接支付渠道。
- 客户端携带 `Idempotency-Key` 时，网关以 `(tenant_id, app_id, scope, key)` 查找；`scope` 在公开请求为 `PUBLIC_ROOT`，在编排内部节点为 `FLOW_NODE`。
- 公开编排根调用计入调用配额；每个内部 API 派发计入目标 API 的限流、配额和用量。重试每次派发都有独立 `attempt_no`，是否计费由状态规则决定。
- `billable_status` 在 MVP 仅允许 `SUCCESS_ONLY`（2xx/3xx）和 `ALL_DISPATCHED`；默认 `SUCCESS_ONLY`。请求已派发但结果超时/未知时标记 `UNRECONCILED` 且暂不计费，不做自动补扣。
- 单价与金额使用定点数保存，事件聚合不进行浮点运算；生成账单汇总时才按币种最小单位用 HALF_UP 舍入，并保留舍入审计。

重试幂等规则：

- 公开请求的 `Idempotency-Key` 只作用于根请求；记录保留 24 小时，TTL 可通过策略缩短但不能超过审计要求。
- 编排节点重试使用稳定键 `HMAC(server_pepper, root_request_id + ":" + node_id)`，同一节点的所有尝试使用相同键。
- 仅当 DSL 显式声明 `idempotency.mode=platform` 且目标 API 声明支持该 Header 时，才允许非幂等请求重试；否则发布校验失败。
- 平台不把幂等键当作认证凭据；上游必须自行验证并保证幂等语义。

幂等并发状态机：

1. 首个请求通过唯一键原子插入 `RESERVED`，立刻转为 `IN_PROGRESS` 并获得 30 秒租约。
2. 同键同请求哈希的并发请求最多等待 2 秒；仍未完成返回 `409 IDEMPOTENCY_IN_PROGRESS`，不得再次派发。
3. 同键不同请求哈希立即返回 `409 IDEMPOTENCY_CONFLICT`。
4. 完成后写入 `COMPLETED` 和结果引用；TTL 内重复请求直接返回原结果。
5. 失败时记录 `FAILED` 和 `dispatch_state`；只有 `NOT_DISPATCHED` 且租约过期的记录允许安全重占，`POSSIBLY_DISPATCHED` 记录不得自动重放，需返回可审计错误。
6. `EXPIRED` 只用于清理展示和回收扫描，不改变历史响应或账务事实。

### 6.4 日志与审计

- 请求日志默认记录元数据，不记录 Header、Secret、Signature、Cookie、请求/响应正文。
- 确需正文诊断时，按字段白名单脱敏、限长、加密并设置短期 TTL；普通开发者不可读取敏感正文。
- 管理操作全部写审计：登录、角色变更、API 发布、价格变更、密钥轮换/吊销、编排发布/回滚、策略修改。
- 审计记录只追加，数据库账号不得拥有更新/删除权限；二期可增加 WORM/对象锁和哈希链。

## 7. API 编排引擎与 DSL

### 7.1 设计决策

采用“结构化作者 DSL -> 编译器校验 -> 不可变执行 IR -> 有界执行器”的独立引擎：

- 作者 DSL 面向开发者，支持嵌套 `try/catch`、`if/else` 和显式 `parallel`，容易阅读和测试。
- 编译阶段生成扁平或作用域化的执行 IR，后续可增加图形画布、代码生成和优化。
- 生产运行时只接受已发布版本对应的不可变 IR；开发者测试运行使用独立 sandbox 模式临时编译草稿。
- 引擎是 Java 模块，对外暴露 `validate/compile/execute` 三类接口，可独立测试和后续抽取。

### 7.2 MVP 节点类型

| 节点 | 语义 | 关键限制 |
| --- | --- | --- |
| `api` | 调用已发布的登记 API | 只能使用 `apiRef`；MVP 只能指向单一 API，不能指向编排 API |
| `if` | 条件分支 | 受限 AST，无脚本执行 |
| `parallel` | 并行执行分支并汇合 | 仅支持 `joinMode=all`；默认 fail-fast；最大分支数 8 |
| `try` | 捕获内部未处理异常 | `catch` 接收只读 `error`；不允许任意 goto |
| `set_vars` | 写入命名上下文变量 | 只允许写入 `vars/`；禁止覆盖 `input/`、`sys/` |
| `end` | 提前结束并映射输出 | 仅允许出现在当前作用域内 |

二期可新增 `loop`、`switch`、`subflow`、`delay`、`webhook_wait`、`compensation`；它们不能破坏现有 DSL 版本兼容性。

发布时编译 `requiredApiSet`：解析所有 `apiRef` 并固化 API ID、已发布版本、环境和可见性。应用获授公开编排 API 时即获授该发布清单中的只读调用闭包，但执行每个节点仍必须校验租户、应用、API 状态、版本、限流和配额。编排固定使用发布时清单中的 API 版本，单一 API 发布新版本不会静默改变已发布编排；API 定义 `OFFLINE` 或版本被安全下线时，引用它的编排节点立即失败。MVP 不允许编排嵌套，因此不存在递归编排；API 调用总数和尝试总数仍受执行预算限制。

### 7.3 上下文模型

| 命名空间 | 可变性 | 内容 |
| --- | --- | --- |
| `sys` | 只读 | `requestId`, `tenantId`, `appId`, `apiId`, `deadline`, `locale` |
| `input` | 只读 | 已通过 JSON Schema 校验的外部输入 |
| `vars` | 可写 | 开发者显式赋值、作用域隔离的变量 |
| `steps` | 只读 | 已完成节点的输出，键为全局唯一 `nodeId` |
| `error` | 只读 | `code`, `message`, `status`, `nodeId`, `attempt`, `retryable` |
| `secrets` | 只读且隔离 | DSL 不可引用或映射；仅由上游认证适配器注入 |

并行分支使用子上下文读取父上下文，分支内写入只在本地可见；汇合时必须通过显式 `outputMapping` 合并到父上下文，禁止隐式竞争写。

变量语义：

- 根级 `defaults` 在输入 Schema 校验后初始化 `vars`；用于保证输出映射中引用的变量有确定值。
- 每个步骤的变量写入原子提交；步骤失败时该步骤的写入全部回滚，之前已完成步骤的写入保留。
- `try` 的 `catch` 可以读取父上下文和已完成步骤提交的变量，以及只读 `error`；失败步骤不留下部分变量。
- 并行分支基于父上下文快照执行，分支结果在 join 后由 `outputMapping` 原子合并；重复写入同一路径视为发布校验错误。
- fail-fast 取消分支时丢弃所有未提交的本地写入；join 失败不会部分合并 `vars`，已完成分支结果仅保留在诊断记录中。
- 引用缺失默认是执行错误；不做隐式字符串/数字类型转换。输出映射必须满足平台定义的 JSON 兼容类型约束。
- `end` 只结束当前作用域并冻结该作用域输出；父作用域可继续执行或直接返回。MVP 不允许跨作用域 `goto`。

### 7.4 表达式与映射

不采用字符串脚本或通用表达式执行器。条件使用结构化 AST：

```json
{
  "op": "and",
  "args": [
    { "op": "eq", "left": { "$ref": "steps/getUser/body/status" }, "right": "ACTIVE" },
    { "op": "gte", "left": { "$ref": "steps/getUser/body/level" }, "right": 3 }
  ]
}
```

支持操作符：`eq/ne/gt/gte/lt/lte/in/contains/exists/and/or/not`。变量引用格式为 `{ "$ref": "<namespace>/<pointer>" }`，pointer 使用 RFC 6901：`/` 分隔，键中的 `~` 写为 `~0`、`/` 写为 `~1`，数组使用零基索引。例如 `steps/getUser/body/level`、`vars/orders/items/0`。解析器不支持函数调用、反射、模板执行和网络访问。

输出映射示例：

```json
{
  "user": { "$ref": "steps/getUser/body" },
  "orders": { "$ref": "vars/orders/items" },
  "degraded": { "$ref": "vars/degraded" }
}
```

### 7.5 DSL v1 示例

```json
{
  "dslVersion": "1.0",
  "name": "user-profile-summary",
  "timeoutMs": 6000,
  "defaults": {
    "vars/orders": { "items": [] },
    "vars/points": 0,
    "vars/degraded": false
  },
  "inputSchema": {
    "type": "object",
    "required": ["userId"],
    "properties": {
      "userId": { "type": "string", "format": "uuid" }
    }
  },
  "steps": [
    {
      "id": "enrich",
      "type": "try",
      "timeoutMs": 5000,
      "steps": [
        {
          "id": "getUser",
          "type": "api",
          "apiRef": "user-service/get-user@1",
          "request": {
            "pathParams": { "id": { "$ref": "input/userId" } },
            "query": {},
            "headers": {},
            "body": null
          },
          "timeoutMs": 1500,
          "retry": {
            "maxAttempts": 3,
            "backoff": {
              "strategy": "exponential",
              "initialMs": 200,
              "multiplier": 2,
              "maxMs": 1000,
              "jitter": true
            },
            "retryOn": ["TIMEOUT", "HTTP_502", "HTTP_503", "HTTP_504"]
          }
        },
        {
          "id": "membership",
          "type": "if",
          "condition": {
            "op": "gte",
            "left": { "$ref": "steps/getUser/body/level" },
            "right": 3
          },
          "then": [
            {
              "id": "loadDetails",
              "type": "parallel",
              "joinMode": "all",
              "failureMode": "fail_fast",
              "timeoutMs": 2500,
              "branches": [
                {
                  "id": "ordersBranch",
                  "steps": [
                    {
                      "id": "getOrders",
                      "type": "api",
                      "apiRef": "order-service/list-by-user@1",
                      "request": {
                        "pathParams": { "id": { "$ref": "input/userId" } },
                        "query": {},
                        "headers": {},
                        "body": null
                      },
                      "timeoutMs": 2000
                    }
                  ]
                },
                {
                  "id": "pointsBranch",
                  "steps": [
                    {
                      "id": "getPoints",
                      "type": "api",
                      "apiRef": "points-service/get-balance@1",
                      "request": {
                        "pathParams": { "userId": { "$ref": "input/userId" } },
                        "query": {},
                        "headers": {},
                        "body": null
                      },
                      "timeoutMs": 2000
                    }
                  ]
                }
              ],
              "outputMapping": {
                "vars/orders": { "$ref": "steps/getOrders/body" },
                "vars/points": { "$ref": "steps/getPoints/body/value" }
              }
            }
          ],
          "else": [
            {
              "id": "resetDetails",
              "type": "set_vars",
              "assign": {
                "vars/orders": { "items": [] },
                "vars/points": 0
              }
            }
          ]
        },
        {
          "id": "markHealthy",
          "type": "set_vars",
          "assign": {
            "vars/degraded": false
          }
        }
      ],
      "catch": [
        {
          "id": "fallback",
          "type": "set_vars",
          "assign": {
            "vars/orders": { "items": [] },
            "vars/points": 0,
            "vars/degraded": true
          }
        }
      ]
    }
  ],
  "outputMapping": {
    "orders": { "$ref": "vars/orders/items" },
    "points": { "$ref": "vars/points" },
    "degraded": { "$ref": "vars/degraded" }
  }
}
```

### 7.6 校验规则

发布前必须通过两层校验：

1. **结构校验：** JSON Schema、未知字段、类型、必填项、版本号。
2. **语义校验：** 节点 ID 全局唯一、引用可解析、`apiRef` 已发布且租户可见、输出映射类型可推断、分支/节点/深度/并行度/超时/重试不超上限。

额外静态检查：

- 禁止字面量 Secret、认证 Header 和任意 URL。
- `apiRef` 必须指向已发布单一 API；指向 `ORCHESTRATION` 或跨越可见性边界时拒绝发布。
- 禁止写入 `sys/`、`input/`、`steps/` 命名空间。
- 非幂等 HTTP 方法默认禁止自动重试；必须显式配置 `idempotency.mode=platform`，且目标 API 声明支持平台生成的幂等键。
- 子节点超时不得超过父作用域截止时间。
- 并行分支不得写入相同父级 `vars/` 路径；必须通过显式合并。
- 发布时生成必需 API 清单和清单校验和；清单必须全部处于可调用状态。

### 7.7 执行语义

执行器按以下规则运行：

1. 解析公开请求或开发者测试请求并生成全局截止时间；生产总超时默认 30 秒，sandbox 默认 10 秒。
2. 生产模式加载 `api_definition.active_prod_publication_id` 对应的不可变 IR；sandbox 模式临时编译当前草稿，并强制 `environment=SANDBOX`。
3. 校验输入 Schema、请求大小和租户并发配额。
4. 顺序执行步骤；`if` 只执行一个分支；`parallel` 使用有界虚拟线程执行器并发运行。
5. 每个 API 节点继承剩余截止时间，并使用连接、读取和整体超时。
6. 重试仅针对配置的可重试错误，且累计执行时间不得超过节点和全局截止时间。
7. 并行默认 fail-fast；任一分支失败时取消其它分支并等待清理，再把异常交给最近的 `try/catch`。
8. `try/catch` 捕获重试耗尽后的异常；`catch` 完成后可继续后续步骤或映射降级输出。
9. 输出映射失败、响应超限、表达式非法、上下文缺失均视为可审计的编排错误。
10. 记录节点级状态、尝试次数、耗时和错误码；正文默认不记录。

`maxAttempts` 表示包含首次调用在内的总尝试次数，例如 `3` 表示首次调用加最多两次重试。非幂等请求只有显式配置幂等键并通过静态校验后才允许重试。

Sandbox 约束：只允许已登记且在 `SANDBOX` 环境中启用的上游；使用平台测试凭据而非生产应用 Secret；禁止写入生产账单；所有测试运行标记 `mode=SANDBOX_TEST` 并写审计。sandbox 上游仍可能产生副作用，因此上线前必须由管理员确认其安全性，非幂等测试默认需要显式确认。

### 7.8 执行器接口

建议的内部契约（仅在 TDD 阶段细化，不在此阶段编码）：

- `FlowValidator.validate(dsl, tenantContext) -> ValidationResult`
- `FlowCompiler.compile(validatedDsl, apiSnapshotResolver) -> CompiledFlow + checksum`
- `FlowExecutor.execute(compiledFlow, ExecutionContext, ExecutionMode) -> FlowResult`
- `FlowExecutor.cancel(runId)`：MVP 仅用于本地超时/并行取消，不承诺跨进程恢复。

`FlowExecutor` 不依赖 HTTP Controller、数据库实体或管理台 DTO；通过端口接口解析 API 快照、计量和追踪。

`ExecutionMode.PRODUCTION` 要求已发布 publication、不可变 IR 和 `PROD` 上游；`ExecutionMode.SANDBOX_TEST` 只允许草稿编译结果、`SANDBOX` 上游、10 秒硬超时和测试配额，禁止回退生产依赖。

### 7.9 运行规模硬上限

| 项目 | 默认上限 |
| --- | --- |
| 单编排节点数 | 100 |
| 嵌套深度 | 10 |
| 并行分支数 | 8 |
| 单节点重试次数 | 3 |
| DSL 字节数 | 256 KiB |
| 单请求总超时 | 30 秒 |
| 单上游响应大小 | 1 MiB |
| 请求正文大小 | 1 MiB |
| 编排输出大小 | 1 MiB |
| 单次运行累计上游响应 | 2 MiB |
| 单次运行上下文总大小 | 2 MiB |
| 单次运行上游调用数 | 100 |
| 单次运行累计尝试数 | 150 |
| 单租户并发编排数 | 可配置，MVP 默认 50 |

执行器使用全局有界队列、全局与租户级信号量、每上游连接池和舱壁隔离；虚拟线程只降低阻塞成本，不替代背压、连接上限和取消传播。

## 8. 安全风险清单与应对

| 风险 | 攻击路径 | 级别 | MVP 应对 |
| --- | --- | --- | --- |
| 越权访问 | 修改资源 ID 读取他租户 API/应用/日志 | 严重 | RBAC + 资源所有权 + 复合外键 + `tenant_id` 强制过滤 + 默认 RLS + 跨租户测试 |
| Secret 泄露 | 日志、错误页、数据库、前端历史回读 | 严重 | Secret 仅创建时展示；KMS 信封加密；日志白名单；前端不缓存；轮换/吊销 |
| 重放攻击 | 截获请求后重复调用 | 高 | 时间窗、Nonce 单次消费、请求体哈希、HTTPS、常量时间比较 |
| 限流绕过/嵌套绕过 | 路径变体、编排节点跳过 API 策略、伪造代理头 | 高 | 路由规范化；编排发布固化 API 清单；节点级鉴权、限流和配额；只信任受控代理 IP；Redis 原子计数 |
| 密钥枚举/爆破 | 批量尝试 AppKey | 高 | 高熵 AppKey/Secret、IP 限流、失败审计、异常告警、应用封禁 |
| SSRF/编排恶意请求 | OpenAPI 外部引用、脚本节点、重定向诱导访问内网或云元数据 | 严重 | 只允许 `apiRef`；导入禁用外部 `$ref`；上游允许列表；阻断私网/回环/链路本地地址；DNS 固定与重绑定防护；禁止自动重定向 |
| 表达式/注入 | 条件或映射执行任意代码、SQL 注入 | 严重 | 结构化 AST、无通用脚本、参数化 SQL、JSON Schema、Header 白名单、控制字符拒绝 |
| 租户串读 | 共享缓存键或聚合查询遗漏租户条件 | 严重 | 缓存键含租户；查询构造器强制租户；RLS；敏感操作二次校验 |
| 重试放大/重复扣费 | 上游超时后重复 POST，事件重投 | 高 | 仅幂等请求重试；稳定的节点幂等键；持久化幂等表；usage 复合唯一键 |
| 编排资源耗尽 | 大量并行、超大响应、深层嵌套、累计调用过多 | 高 | DSL/节点/分支/深度/响应/上下文/调用/尝试硬上限；有界队列；租户并发配额；失败快速取消 |
| 计费篡改 | 客户端伪造调用量或价格 | 高 | 服务端生成用量与价格快照；客户端只传请求参数；账单事实只追加 |
| 日志泄露 | 记录 Token、Signature、敏感正文 | 高 | 默认不记录 Header/正文；字段脱敏；权限隔离；保留期和访问审计 |
| 管理端劫持 | 管理员账号被盗后发布恶意配置 | 高 | MFA、最小权限、发布前静态检查、高风险操作审计；二期双人审批 |
| 管理端 Web 攻击 | CSRF、Session 固定、Cookie 窃取 | 高 | 服务端 Session；登录后轮换 Session ID；HttpOnly/Secure/SameSite Cookie；CSRF Token；登录限速 |
| 撤销传播延迟 | API/凭据/授权已吊销但缓存仍放行 | 严重 | epoch 单调版本；5 秒身份状态上限；主动失效；无法确认状态时 fail-closed |
| 发布绕过 | 修改已发布版本或绕过清单引用未发布 API | 严重 | `api_publication` 唯一真相源；事务发布；不可变版本；数据库触发器/受限写权限；清单校验和 |
| Sandbox 越界 | 草稿测试访问生产上游或产生未授权副作用 | 严重 | sandbox 只允许 `SANDBOX` 配置；平台测试凭据；测试审计；非幂等测试显式确认；禁止回退生产 |
| 上游认证泄露 | DSL 中硬编码 Token、输出映射或响应 Header 泄露 | 严重 | 只允许 `secret_ref/auth_ref`；密钥适配器隔离；输出禁止 `secrets`；响应 Header 白名单 |
| 依赖与镜像漏洞 | 供应链攻击 | 中高 | 锁定依赖、SBOM、镜像扫描、最小运行镜像、定期升级 |
| DDoS 与级联故障 | 大量请求拖垮网关或上游 | 高 | WAF、IP/租户/API 限流、连接池、熔断、舱壁隔离、超时和最大响应 |

### 8.1 信任边界

1. Internet/客户端 -> WAF/反向代理：不可信输入，必须验证大小、编码和代理头。
2. 数据面 -> 上游 API：受控出站，仅访问登记地址和允许的网络区域。
3. 管理台 -> 控制面：独立认证，高风险操作要求 MFA/二次确认。
4. 控制面 -> 数据面：只通过不可变发布快照和事件，不传递未验证的用户输入。
5. 应用进程 -> 数据层：Secret 与业务数据使用不同访问策略，审计账号只追加。

### 8.2 上游接入与响应边界

- OpenAPI 导入只解析本地文档和本地 `$ref`；外部 `$ref`、非 HTTP(S) `servers`、URL 用户信息、片段和未登记端口一律拒绝或需管理员显式重建。
- 上游连接前校验协议、Host、端口、解析后的 IP 和 egress zone；连接使用已校验地址并禁止自动重定向。
- 上游响应 Header 使用白名单，剥离 `Set-Cookie`、`Location`、CORS 策略、`Transfer-Encoding`、`Connection` 等 hop-by-hop 或浏览器控制 Header。
- 上游响应正文受大小上限；压缩响应先限制解压大小；错误响应归一化，不转发上游堆栈和内部地址。
- 管理端 Session Cookie 使用 `HttpOnly`、`Secure`、`SameSite=Lax`；登录成功轮换 Session ID，登出/吊销立即失效，登录和 MFA 验证均有限速。
- `/platform-admin/**` 和 `/developer/**` 默认同源访问，只允许配置的 CORS 白名单；公开 API 不默认开放浏览器跨域。

## 9. 技术栈选型建议与对比

### 9.1 推荐栈

| 层 | 推荐 | 原因 |
| --- | --- | --- |
| 后端 | Java 21 LTS + Spring Boot 3.x | 成熟的事务、安全、并发和可观测生态；适合长期演进的 API 平台 |
| 架构 | Maven 多模块、模块化单体 | MVP 交付快，同时保留拆分边界；避免过早分布式复杂度 |
| 网关/Web | Spring MVC + 自定义 Filter/RestClient 起步 | 与业务模块一致，调试简单；高吞吐阶段再评估 Spring Cloud Gateway 或 APISIX |
| 编排执行 | Java 21 虚拟线程 + 有界 Executor | 阻塞式上游调用可读性好；通过信号量/队列限制并发 |
| 数据库 | PostgreSQL 16+ | JSONB、事务、分区、RLS、索引和可扩展性适合本场景 |
| 数据访问 | Spring Data JPA + Flyway；日志/聚合用 JdbcClient | 领域 CRUD 可维护；复杂查询保持显式 SQL |
| 缓存 | Redis 7+ + Lettuce | 限流 Lua、Nonce、缓存和短时状态的标准方案 |
| 消息 | RabbitMQ | MVP 异步事件与重试简单；规模上来后评估 Kafka |
| 前端 | Vue 3 + TypeScript + Vite + Element Plus | 管理台表格/表单效率高；Monaco 编辑器承载 DSL 编辑 |
| API 契约 | OpenAPI 3.1 + springdoc + networknt JSON Schema | 自动文档、请求校验和 DSL Schema 校验 |
| 观测 | OpenTelemetry + Micrometer + Prometheus/Grafana + Loki/Tempo | 统一 Request ID、指标、日志和链路 |
| 测试 | JUnit 5 + Testcontainers + WireMock + k6 | 覆盖单测、集成、上游故障和并发压测 |
| 部署 | Docker Compose（开发/小规模）、容器化生产 | MVP 低运维成本；生产再按模块扩缩容 |

### 9.2 关键方案对比

| 决策 | 推荐方案 | 优点 | 代价/缺点 | 不选原因 |
| --- | --- | --- | --- | --- |
| 后端语言/框架 | Java 21 + Spring Boot | 安全/事务/可观测生态完整，适合平台型系统 | 启动和内存成本高于 Go/Node；团队需熟悉 | 不是纯高并发代理，业务与编排复杂度更重要 |
| 架构 | 模块化单体 | 开发、部署、事务简单；边界清晰 | 单进程故障域较大；需严格模块依赖规则 | 微服务会让 MVP 的发布、调试和一致性成本过高 |
| 网关 | 自研 Spring 入口，二期评估 APISIX | 鉴权/计量/编排自定义最灵活 | 需要自己承担代理性能和协议边界 | Kong/APISIX 自定义 HMAC/计量插件仍要开发，且多语言栈 |
| 编排 | 自研受限 DSL 引擎 | 完全匹配业务；可测试、可控安全边界 | 引擎正确性、超时/重试/并发成本高 | Temporal 更适合长任务与持久化工作流；Camunda/Flowable 对同步 API 编排偏重 |
| 数据库 | PostgreSQL | JSONB、RLS、分区、事务强 | 超大规模日志需外部分析库 | MySQL JSON/RLS/分区能力弱于目标；MongoDB 跨实体事务和隔离成本高 |
| 消息 | RabbitMQ | 路由/重试简单，MVP 运维成本低 | 超大规模吞吐和回放能力不如 Kafka | Kafka 对 MVP 偏重；可保留事件契约便于后续迁移 |
| 前端 | Vue 3 + Element Plus | 管理台开发速度快，表格表单生态成熟 | 复杂状态和大规模设计系统需治理 | React 也适合，但没有现成偏好时 Vue 更轻 |
| ORM | JPA + JdbcClient | 领域模型清晰，统计查询可控 | JPA 误用可能产生隐式查询；需审查 SQL | 全量 MyBatis 更显式，但 CRUD 样板更多 |

### 9.3 选型结论

推荐以“Java 模块化单体 + 受限 DSL 自研引擎”为 MVP 主线。若后续出现以下信号，再重新评估拆分：

- 公开网关 QPS 或连接数超过单体扩容边界，拆分网关并使用 APISIX/Envoy。
- 编排需要跨小时/跨天、断点续跑、人工介入，评估 Temporal。
- 日志查询量进入亿级，迁移到 ClickHouse/OpenSearch。
- 多个团队独立发布，出现明显故障域和所有权冲突，再拆控制面、网关、编排器和计量服务。

## 10. API 与状态契约

### 10.1 错误码

| HTTP | 错误码示例 | 含义 |
| --- | --- | --- |
| 400 | `INVALID_ARGUMENT` | 参数、Schema、编码非法 |
| 401 | `INVALID_SIGNATURE` | 签名、时间、Nonce 或凭据无效 |
| 403 | `TENANT_SUSPENDED` / `APP_DISABLED` / `CREDENTIAL_REVOKED` / `API_NOT_GRANTED` | 主体、凭据或授权状态不足 |
| 404 | `API_NOT_FOUND` | 规范化路径不存在 |
| 409 | `IDEMPOTENCY_CONFLICT` / `IDEMPOTENCY_IN_PROGRESS` | 相同幂等键参数不一致或首个请求仍在执行 |
| 422 | `FLOW_BUDGET_EXCEEDED` / `SANDBOX_UNAVAILABLE` | 编排超出预算或缺少安全 sandbox 配置 |
| 429 | `RATE_LIMITED` / `QUOTA_EXCEEDED` | 限流或配额超限 |
| 502 | `UPSTREAM_ERROR` | 上游返回不可接受结果 |
| 504 | `UPSTREAM_TIMEOUT` / `FLOW_TIMEOUT` | 上游或编排超时 |
| 503 | `AUTH_STATE_STALE` / `PLATFORM_DEGRADED` | 无法确认安全状态，或 Redis/配置快照等关键依赖不可用 |

错误体不返回上游真实地址、密钥、堆栈或内部 SQL。

### 10.2 管理、开发者与公开接口边界

| 接口组 | 认证/授权 | 主要资源与规则 |
| --- | --- | --- |
| `/platform-admin/v1/**` | 服务端 Session + Admin MFA + CSRF；仅 `PLATFORM_ADMIN` | 租户、用户、上游 endpoint/environment/credential、API、publication、策略、审核、审计 |
| `/developer/v1/**` | 服务端 Session + CSRF；`APP_DEVELOPER` 或只读 `VIEWER` | 应用、凭据、授权、编排草稿、sandbox test-run、用量与脱敏日志 |
| `/open/v1/**` | AppKey/Secret HMAC v1 | 生产公开 API；强制限流、计量、日志和审计 |
| `/platform-admin/health/**` | 内网或独立探针认证 | 仅运维健康检查，不属于对外业务 API |

管理接口清单在 TDD 第一切分中落实为 OpenAPI：

- `POST /platform-admin/v1/sessions`、`DELETE /platform-admin/v1/sessions/current`
- `POST|PATCH /platform-admin/v1/tenants`、`POST|PATCH /platform-admin/v1/users/{id}/role-bindings`
- `POST|PATCH /platform-admin/v1/upstream-endpoints`、`POST /platform-admin/v1/upstream-endpoints/{id}/environments`
- `POST|PATCH /platform-admin/v1/apis`、`POST /platform-admin/v1/apis/{id}/versions`
- `POST /platform-admin/v1/apis/{id}/deprecate`、`POST /platform-admin/v1/apis/{id}/offline`
- `POST /platform-admin/v1/api-publications`、`POST /platform-admin/v1/api-publications/{id}/rollback`
- `POST|PATCH /platform-admin/v1/policies/rate-limits|quotas|prices`
- `POST /platform-admin/v1/orchestrations/{id}/review`
- `POST /platform-admin/v1/orchestrations/{id}/publish`
- `POST /platform-admin/v1/apps/{id}/suspend`、`POST /platform-admin/v1/apps/{id}/revoke`
- `GET /platform-admin/v1/audit-logs`
- `POST|PATCH /developer/v1/apps`、`POST /developer/v1/apps/{id}/credentials`
- `POST /developer/v1/apps/{id}/credentials/{credentialId}/rotate`
- `POST /developer/v1/apps/{id}/credentials/{credentialId}/revoke`
- `POST /developer/v1/apps/{id}/grants`
- `POST|PATCH /developer/v1/orchestrations`、`POST /developer/v1/orchestrations/{id}/test-runs`
- `GET /developer/v1/apps/{id}/usage`、`GET /developer/v1/apps/{id}/logs`

接口规则：

- 写操作必须带 CSRF Token；创建凭据、轮换、发布、回滚等可重试管理操作必须支持幂等键。
- 开发者只能编辑 `DRAFT` 编排并提交 `IN_REVIEW`；审核、发布、弃用、回滚属于平台管理员。
- 查看者通过同一 `/developer/**` 认证面访问，但所有写接口由服务端权限码拒绝，不能依赖菜单隐藏。
- 所有资源路由在服务端解析当前租户上下文；普通用户请求体中的 `tenant_id` 不作为授权依据。平台管理员访问租户资源时必须通过显式租户路径参数或查询条件选择目标租户，并写入审计。
- 测试运行必须携带幂等键，记录 `SANDBOX_TEST`，不对应公开路由，不允许传入生产上游地址。

TDD Gate 0：先将上述接口固化为 OpenAPI 3.1，补充每个操作的请求/响应 Schema、错误码、权限码、租户作用域、允许状态迁移、CSRF 与幂等要求。未通过该契约评审前，不写 Controller、Service 或数据库迁移。

### 10.3 发布与回滚

1. 草稿保存不改变线上版本。
2. 校验、sandbox 测试和审核通过后生成不可变版本与必需 API 清单。
3. 发布事务验证所有目标已发布、写入 `api_publication`、切换 `active_prod_publication_id`、递增 `publish_epoch` 并写 `outbox_event`。
4. 数据面消费事件后失效缓存；未收到事件的实例通过 epoch 和最长 TTL 自愈，无法确认时拒绝请求。
5. 回滚只把 `active_prod_publication_id` 切回历史 production publication，不修改 `api_version`、`orchestration_version` 或历史审计。
6. 发布和回滚接口必须幂等；重复提交返回同一 publication 或明确冲突，不重复生成线上切换。

## 11. 安全与质量门禁

进入 TDD 前必须确认以下门禁：

- 每个公开接口都有鉴权、授权、租户、输入校验、审计和限流策略。
- 管理端与开发者接口必须逐项验证 Session、CSRF、角色、租户、资源所有权和状态迁移守卫。
- 每个编排 DSL 变更都有 JSON Schema、语义校验和非法样例测试。
- 编排引擎单元测试必须覆盖：串行、if true/false、并行成功、并行失败、fail-fast、重试成功、重试耗尽、节点超时、整体超时、catch、变量提交/回滚、默认值、并行变量隔离、输出映射失败、取消清理和预算耗尽。
- HMAC v1 必须有黄金测试向量，覆盖空正文、UTF-8、`%2F`、重复 Query、Content-Type 参数、时间窗和 Nonce 重放。
- 数据库安全测试必须覆盖复合外键、RLS 默认拒绝、平台管理员审计角色、跨租户 IDOR 和缓存键隔离。
- 可见性测试必须证明 `TENANT_PRIVATE` 编排不能被其它租户授权或调用，`PLATFORM_PUBLIC` 才能跨租户发现。
- 鉴权集成测试必须覆盖租户停用、API 下线、授权吊销、凭据轮换、epoch 乱序和缓存不可用。
- 编排授权测试必须验证发布清单闭包、节点级 API 状态/限流/配额，以及禁止 `apiRef` 指向编排。
- Sandbox 测试必须证明无法访问生产上游、生产 Secret 或产生生产账单。
- 发布测试必须证明已发布版本不可修改、只能通过 `active_prod_publication_id` 切换、重复发布幂等，且非 `PROD` publication 不能成为活动生产指针。
- 幂等状态机测试必须覆盖并发抢占、等待超时、哈希冲突、租约回收、`NOT_DISPATCHED` 重占和 `POSSIBLY_DISPATCHED` 禁止重放。
- 接口契约测试覆盖 401/403/404/409/429/502/503/504。
- 集成测试使用真实 PostgreSQL/Redis/RabbitMQ 容器和 WireMock 上游。
- 安全测试至少覆盖跨租户 IDOR、重放、路径变体绕过、SSRF、Header 注入、超大响应、重复计量、重复计费和上游 Header 清洗。
- 性能测试验证单实例目标 QPS、p95/p99、限流准确性和上游超时行为；具体数字在环境确认后补齐。
- 上线前补齐数据库备份 RPO/RTO、KMS 不可用策略、Redis/消息故障演练、WAF 规则责任人和日志保留期。

## 12. 实施切片与依赖图

以下步骤按 PR 大小切分。每步在实现前先补对应测试与契约。

| 步骤 | 内容 | 依赖 | 可并行 | 退出标准 |
| --- | --- | --- | --- | --- |
| S0 | 工程基线、OpenAPI Gate 0、Maven 模块、Docker Compose、Flyway、健康检查、CI | 无 | 否 | 接口契约评审通过；空应用可启动；基础测试可运行 |
| S1 | IAM、租户、三角色、Session/CSRF、RLS、审计骨架 | S0 | 否 | 登录、RBAC、RLS、跨租户测试通过 |
| S2 | API 目录、上游环境、受限 OpenAPI 导入、publication 与回滚 | S1 | 可与 S3 并行 | 发布不可变、唯一真相源和回滚测试通过 |
| S3 | 应用、AppKey/Secret、轮换、授权范围、epoch | S1 | 可与 S2 并行 | Secret 加密、一次性展示和吊销测试通过 |
| S4 | HMAC v1 黄金向量、Nonce、生命周期校验、单一 API 代理 | S2, S3 | 否 | 401/403/404/502/504 与撤销传播测试通过 |
| S5 | 多层限流、配额、标准响应头 | S4 | 否 | 多实例限流准确；超限不触达上游 |
| S6 | 请求日志、审计、Outbox、按派发计量、幂等消费 | S4 | 可与 S7 并行 | 多节点计量、重复事件和重复计费测试通过 |
| S7 | DSL Schema、IR、校验器、编译器、必需 API 清单 | S2 | 可与 S4-S6 并行 | 非法 DSL、嵌套编排和清单闭包测试通过 |
| S8 | 编排串行、if、变量默认值/提交语义、try/catch | S7 | 否 | 分支/异常/变量测试通过 |
| S9 | 并行、超时、稳定幂等键、取消、资源预算 | S8 | 否 | 并行/超时/重试/预算/清理测试通过 |
| S10 | 编排 publication、sandbox 测试、节点追踪、门户 | S6, S9 | 否 | 生产闭环、sandbox 隔离和回滚通过 |
| S11 | 安全加固、负载测试、恢复演练、文档收尾 | S10 | 可按风险并行 | OWASP 检查、压测、灾备演练通过 |

关键路径：`S0 -> S1 -> S3 -> S4 -> S6 -> S10 -> S11`；编排能力从 `S2 -> S7 -> S8 -> S9 -> S10` 独立推进。

## 13. 待确认决策

建议按以下默认值进入 TDD，确认后才能开始写业务代码：

1. **多租户与可见性：** MVP 默认采用平台级共享单一 API 目录，租户级应用、凭据、用量、日志和编排；租户编排包装 API 默认 `TENANT_PRIVATE`，只有平台系统租户可发布 `PLATFORM_PUBLIC`。
2. **API 登记权限：** MVP 仅平台管理员登记和发布上游 API；开发者只消费已发布 API。
3. **计费范围：** 本期只做调用计量、价格快照和账单明细，不接支付/发票。
4. **Secret 方案：** 使用 HMAC-SHA256 签名，Secret 不出现在请求中，不提供历史明文回读。
5. **编排发布：** 开发者提交、平台管理员审核并发布；开发者可在隔离 sandbox 运行草稿，租户编排默认不跨租户。
6. **运行模式：** 同步 HTTP 编排，总超时默认 30 秒；异步/长任务留到二期。
7. **技术栈：** Java 21 + Spring Boot 3.x + PostgreSQL + Redis + RabbitMQ + Vue 3。
8. **性能目标：** 需要补充目标 QPS、p95/p99、租户上限和日志保留期，才能确定容量与 SLA。
9. **运维目标：** 需要确认 RPO/RTO、KMS/Redis/RabbitMQ 故障策略、备份恢复演练频率和 WAF 责任人。
10. **Sandbox 范围：** MVP 的草稿测试只允许登记过的 `SANDBOX` 上游；缺少 sandbox 配置的 API 不允许测试，不自动回退生产。

## 14. Handoff

- 当前状态：方案已完成并通过架构/安全对抗性评审，无 P0/P1 阻断，等待用户确认。
- 下一 ECC 阶段：`tdd-workflow`。
- TDD 顺序：OpenAPI Gate 0 与 DSL Schema -> 契约测试/单元测试 -> 引擎分支/异常测试 -> 集成测试 -> 实现 -> Code Review -> Security Audit -> Docs -> ECC Memory。
- 在确认前不编写业务代码、不创建数据库迁移、不实现接口。
