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
| `--with F1,F2` | 配合 `base`：列出的付费功能开启，其余关闭。例：`--with LAMBDA_NETWORK_LOGS,EKS_AUDIT_LOGS` 只开 Lambda Protection 和 EKS 审计日志。RDS 数据活动监控写 `RDS_DATA_RISK`，要和 `RDS_LOGIN_EVENTS` 一起写 |
| `--members` | 在安全账号里：组织所有 ACTIVE 账号（含管理账号）加为成员，成员自动启用设为 `ALL`。成员的付费功能和 `--with` 一致，没列的为 `NONE` |
| `--admin-profile` | 安全账号（委派管理员）的 profile，配合 `--members`。`--profile` 仍用管理账号，用来读组织账号清单 |
| `--regions a,b` | 只处理这些区域，默认所有已启用区域 |
| `--dry-run` | 只打印要做什么 |
| `--yes` | 跳过确认 |

`base` 关闭的付费功能：S3 Protection、EKS 审计日志、EBS 恶意软件扫描、RDS 登录监控、Lambda 网络日志、Runtime Monitoring、AI Protection。已开通区域的保护功能脚本不改，需要调整在控制台按区域操作。

可重复运行，已完成的区域会自动跳过。

`--members` 可以和 `--delegate` 一起用：同一区域先委派，再加成员。成员付费功能设成 `NONE` 只影响新开通的账号，已经开着的不会被关掉。

RDS 数据活动监控（`RDS_DATA_RISK`，检测 PostgreSQL 数据外泄和删库）是 `RDS_LOGIN_EVENTS` 的子配置：`--with RDS_LOGIN_EVENTS` 只开登录监控，数据活动监控明确关闭；要一起开写 `--with RDS_LOGIN_EVENTS,RDS_DATA_RISK`。
