# GuardDuty 批量开通 + 批量委派

GuardDuty 是区域级服务，开通和委派都要每个区域单独做。这个脚本在组织管理账号里一次处理所有区域。

## 用法

```bash
# 所有区域开通
./enable-all-regions.sh --profile <管理账号> --enable

# 所有区域委派给安全账号
./enable-all-regions.sh --profile <管理账号> --delegate 123456789012

# 所有区域把组织所有账号加为成员（在安全账号里做，要先委派）
./enable-all-regions.sh --profile <管理账号> --members --admin-profile <安全账号>

# 两个一起做，先 dry-run 看一下
./enable-all-regions.sh --profile <管理账号> --enable --delegate 123456789012 --dry-run
```

| 参数 | 说明 |
|---|---|
| `--profile` | AWS CLI profile，必填 |
| `--enable` | 没开 GuardDuty 的区域新建 detector；已开的区域不动 |
| `--delegate <账号ID>` | 委派给这个账号；已委派给它的跳过，已委派给别人的不覆盖 |
| `--features base\|default` | 配合 `--enable`：新建 detector 的保护功能。`base`（默认）只开基础检测，付费功能全关；`default` 用 AWS 默认 |
| `--with F1,F2` | 配合 `base`：列出的付费功能开启，其余关闭。例：`--with LAMBDA_NETWORK_LOGS,EKS_AUDIT_LOGS` 只开 Lambda Protection 和 EKS 审计日志。可选值见下文 |
| `--members` | 在安全账号里：组织所有 ACTIVE 账号（含管理账号）加为成员，成员自动启用设为 `ALL`。成员的付费功能和 `--with` 一致，没列的为 `NONE` |
| `--admin-profile` | 安全账号（委派管理员）的 profile，配合 `--members`。`--profile` 仍用管理账号，用来读组织账号清单 |
| `--regions a,b` | 只处理这些区域，默认所有已启用区域 |
| `--dry-run` | 只打印要做什么 |
| `--yes` | 跳过确认 |

## `--with` 可选功能

`base` 模式下这些付费功能默认全关，`--with` 里列出的才开，多个用逗号分隔。

| 值 | 功能 | 说明 |
|---|---|---|
| `S3_DATA_EVENTS` | S3 Protection | 监控 S3 数据事件 |
| `EKS_AUDIT_LOGS` | EKS Protection | 分析 EKS 审计日志 |
| `EBS_MALWARE_PROTECTION` | Malware Protection for EC2 | 有可疑发现时扫描 EBS 卷 |
| `RDS_LOGIN_EVENTS` | RDS Protection（登录活动） | 监控 Aurora、RDS PostgreSQL/MySQL/MariaDB 的登录 |
| `RDS_DATA_RISK` | RDS Protection（数据活动） | 检测数据外泄和删库，只支持 Aurora PostgreSQL 和 RDS for PostgreSQL。必须和 `RDS_LOGIN_EVENTS` 一起写 |
| `LAMBDA_NETWORK_LOGS` | Lambda Protection | 分析 Lambda 网络活动 |
| `RUNTIME_MONITORING` | Runtime Monitoring | EC2/ECS/EKS 运行时监控，需要安装代理 |
| `AI_PROTECTION` | AI Protection | 监控 AI 工作负载 |

例：
```bash
--with LAMBDA_NETWORK_LOGS,EKS_AUDIT_LOGS                                 # Lambda + EKS 审计日志
--with RDS_LOGIN_EVENTS                                                   # 只开 RDS 登录监控，数据活动监控关闭
--with LAMBDA_NETWORK_LOGS,EKS_AUDIT_LOGS,RDS_LOGIN_EVENTS,RDS_DATA_RISK  # 再加 RDS 登录和数据活动监控
```

`--with` 只作用于脚本新建的 detector 和 `--members` 新加入的成员。已开通区域的保护功能脚本不改，需要调整在控制台按区域操作。

## 其他说明

可重复运行，已完成的区域会自动跳过。

`--members` 可以和 `--delegate` 一起用：同一区域先委派，再加成员。成员付费功能设成 `NONE` 只影响新开通的账号，已经开着的不会被关掉。
