# API 开放平台能力契约

## Capability

- **Capability name:** API 开放平台 MVP
- **Source:** 用户需求、`AGENTS.md`
- **Primary actor:** 平台管理员、应用开发者、查看者
- **Outcome after ship:** 管理员可注册并发布 API；开发者可创建应用、保管凭据、调用或编排 API；平台统一完成鉴权、限流、计量、日志与审计。
- **Success signal:** 一条公开 API 可从注册、发布、授权、调用到计量与审计完整闭环；编排支持串行、并行、条件、异常捕获、重试和上下文变量传递。

## Product Intent

提供一个可运营的 API 开放平台 MVP，让上游 API 以统一、安全、可计量的方式开放给应用，并允许应用开发者通过受控编排组合多个 API，而不是直接暴露任意脚本或任意网络调用能力。

## Fixed Constraints

- 平台角色固定为：`PLATFORM_ADMIN`、`APP_DEVELOPER`、`VIEWER`。
- 平台管理员是全局角色；应用开发者和查看者默认按租户隔离。
- 所有对外 API 必须先鉴权，再路由或执行编排。
- 外部调用使用 `AppKey + Secret` 体系。`AppKey` 可公开传输；`Secret` 不随请求传输，仅用于 HMAC-SHA256 签名。
- 调用计量、限流、请求日志和审计日志是全局强制能力，不能由单个 API 或编排关闭。
- 编排引擎是独立领域组件，支持串行、并行、条件分支、异常捕获、有界重试、超时和上下文变量传递。
- 编排节点只能引用已登记并发布的上游 API；MVP 不允许任意 URL、脚本或动态代码执行。
- 编排发布时固化其引用的 API 清单；调用编排 API 不得绕过清单内每个 API 的状态、限流和配额检查。
- MVP 禁止编排节点再引用编排 API，避免递归和隐式授权扩散。
- 已发布配置不可原地修改；发布与回滚必须基于不可变版本。
- 租户数据隔离是数据库、服务层、缓存层和测试的共同约束；租户级表默认启用 RLS，不依赖前端隐藏。

## Actors and Surfaces

- **平台管理员：** 管理租户、用户、平台级上游 API、发布审批、限流、配额、价格、全量日志与审计。
- **应用开发者：** 管理自己创建的应用、凭据、授权范围和编排草稿，执行沙箱测试并提交发布。
- **查看者：** 只读访问已发布 API 文档、编排定义和授权范围内的使用数据，不可读取 Secret 或执行变更。
- **管理台：** IAM、租户、API 目录、应用、策略、编排、账单和审计页面。
- **开发者门户：** API 文档、应用与凭据、调用示例、编排编辑器和运行诊断。
- **公开 API：** `/open/v1/**`，统一 AppKey/Secret 签名、限流、路由和错误契约。
- **平台管理 API：** `/platform-admin/**`，MVP 使用本地账号服务端 Session、管理员 MFA 和 CSRF 防护；OIDC 留到二期。
- **开发者 API：** `/developer/**`，使用本地账号服务端 Session 和 CSRF 防护，承载应用、编排草稿与用量管理。
- **沙箱测试：** 通过 `/developer/**` 的测试运行接口执行草稿，只允许访问登记过的 sandbox 上游，不暴露生产凭据。

## State Transitions

- API 定义：`DRAFT -> IN_REVIEW -> PUBLISHED -> DEPRECATED -> OFFLINE`
- API 审核：`IN_REVIEW -> DRAFT`（驳回）
- 应用：`ACTIVE -> SUSPENDED -> ACTIVE | REVOKED`
- 凭据：`ACTIVE -> ROTATING -> REVOKED | EXPIRED`
- 编排：`DRAFT -> VALIDATED -> IN_REVIEW -> PUBLISHED -> DEPRECATED -> ARCHIVED`
- 编排审核：`IN_REVIEW -> DRAFT`（驳回）
- 运行：`QUEUED -> RUNNING -> SUCCEEDED | FAILED | TIMED_OUT | CANCELLED`

迁移触发者：平台管理员负责 API/编排审核、发布、弃用、下线和回滚；应用开发者只能编辑自己的草稿、测试、提交和吊销自己的凭据；查看者不能触发状态迁移。`PUBLISHED` 仅表示不可变制品获批，公开路由生效以 `active_prod_publication_id` 为准。

## Interface Contract

- 外部请求必须包含 `X-Signature-Version`、`X-App-Key`、`X-Timestamp`、`X-Nonce`、`X-Signature`。
- 服务端校验时间窗、Nonce 唯一性、规范化请求、请求体哈希、租户/应用/凭据/API/授权状态、限流和配额后才可派发。
- 可重试请求应携带 `Idempotency-Key`；非幂等请求默认不自动重试。
- 服务端生成不可伪造的 `requestId`；客户端关联 ID 仅作为审计字段保存，不作为计费或幂等主键。
- 统一错误体：`requestId`、`code`、`message`、`retryable`，不得返回密钥、上游地址、堆栈或内部表结构。
- 统一响应头：`X-Request-Id`、限流剩余额度及重置时间。
- 计量记录由服务端生成，客户端参数不得决定计费价格或数量。

## Data Implications

- 系统事实源为 PostgreSQL；Redis 仅用于短期缓存、限流计数和 Nonce，不作为最终账务事实源。
- 所有租户级业务表必须包含 `tenant_id`，唯一键和索引包含 `tenant_id`。
- API 目录和上游接入默认是平台级共享资源，由平台管理员维护；应用、凭据、用量、日志和审计按租户隔离。
- 单一 API 默认平台公开；租户编排包装 API 默认租户私有，只有同租户应用可授权调用。
- 租户级子表使用 `(tenant_id, id)` 复合唯一键和复合外键；RLS 默认开启，平台管理员跨租户读取使用单独审计角色。
- 应用 Secret 使用 KMS/主密钥信封加密保存；禁止明文存储和日志输出，创建后仅展示一次。
- 已发布 API 和编排版本不可变；运行记录保存实际版本引用。
- 公开路由是否生效以活动 production publication 为准；`PUBLISHED` 制品本身不等于已上线。
- 请求/响应正文默认不落日志；确需排障时按字段脱敏、限长并设置短期保留。
- 金额使用定点数或最小货币单位，禁止浮点数。

## Security and Policy

- 输入、输出、请求大小、节点数量、并行度、超时、重试次数均须有服务端硬上限。
- 表达式采用受限 AST，不使用 SpEL、Groovy、JavaScript 等通用动态执行。
- 上游目标来自已登记 `apiRef`，并受出站白名单、私有地址阻断、DNS 重绑定防护和禁止自动重定向约束。
- 管理端高风险操作使用 MFA 或二次确认；所有变更写入不可覆盖的审计日志。
- 速率和配额按租户、应用、API 多维同时校验，任一维度超限即拒绝。
- 吊销类状态变更必须主动失效缓存，并设置最大陈旧时间；无法确认安全状态时拒绝请求。
- 审计和计量事件采用可靠事件表与幂等消费，避免重试导致重复计费。
- 沙箱草稿执行只使用 sandbox 上游配置和受限测试凭据；生产发布必须引用不可变已发布 IR。

## Non-Goals

- MVP 不实现真实支付、发票、复杂优惠券和合同计费。
- MVP 不实现图形化拖拽编排、循环、子编排、长时间异步任务、补偿事务和人工审批节点。
- MVP 不开放任意 URL 调用、脚本节点、插件市场或自定义代码上传。
- MVP 不实现跨地域多活、租户自定义域名和完整 API 市场。

## Open Decisions

以下默认决策需要在进入 TDD 前确认，详见 `plans/api-open-platform-mvp.md`：

1. MVP 是否采用“平台级共享单一 API + 租户私有编排 + 租户级应用/用量”的多租户模型。
2. 上游 API 是否仅由平台管理员登记。
3. 本期“计费”是否为计量与账单明细，不接真实支付。
4. 外部时钟只接受 UTC 时间戳。
5. 单次同步编排总超时默认 30 秒。

## Handoff

- **Ready for implementation?** 需用户确认默认决策与方案。
- **Needs architecture review?** 已完成对抗性架构与安全评审；无 P0/P1 阻断。
- **Needs product clarification?** 需要确认上述五个默认决策。
- **Next ECC lane:** `tdd-workflow`，先写单元测试、接口契约和编排引擎分支测试，再进入实现。
