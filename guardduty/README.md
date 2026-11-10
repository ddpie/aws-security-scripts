# GuardDuty 全区域开通

GuardDuty 是区域级服务。只在部分区域开启时，攻击者拿到凭证后可以去没开的区域操作（比如起实例挖矿），不会产生任何告警。没有资源的区域基本不产生费用，所以全区域开通几乎不增加成本。

`enable-all-regions.sh` 一次完成：

1. 在所有已启用区域开通 GuardDuty **基础检测**（CloudTrail 管理事件、VPC Flow Logs、DNS 日志）
2. 显式关闭付费保护：S3 Protection、EKS 审计日志、EBS 恶意软件扫描、RDS 登录监控、Lambda 网络日志、Runtime Monitoring（含旧版 EKS Runtime Monitoring）、AI Protection
3. 组织模式下：每个区域把安全账号设为委派管理员、打开组织成员自动启用（`ALL`）、把管理账号加为成员、关闭已有成员的付费保护
4. 告警外发：每个区域一条 EventBridge 规则，转发到汇总区域，再发到一个 SNS 主题（EventBridge 的 SNS 目标必须同区域，所以跨区域走事件总线）

## 用法

```bash
# 单账号模式（还没有安全账号）
./enable-all-regions.sh --account-profile <profile> --email sec@example.com

# 组织模式（已有安全账号）
./enable-all-regions.sh --mgmt-profile <管理账号> --sec-profile <安全账号> --email sec@example.com
```

| 参数 | 说明 |
|---|---|
| `--home-region` | 告警汇总区域，默认 `us-west-2` |
| `--min-severity` | 告警门槛，默认 `4`（中危及以上） |
| `--dry-run` | 只打印计划，不做任何修改 |
| `--yes` | 跳过确认提示 |

脚本先做只读预检：发现已有别的委派管理员会直接停止；会列出哪些现有 detector 的 S3 Protection 将被关闭，确认后才执行。单个区域失败不影响其他区域，最后汇总失败区域和警告。

## 创建的资源

均带 `gd-allregion-` 前缀，不会覆盖已有配置：

- SNS 主题 `gd-allregion-findings`（汇总区域）
- 每个区域的 EventBridge 规则 `gd-allregion-findings`
- IAM 角色 `gd-allregion-forward`（仅允许向汇总区域默认事件总线 `PutEvents`）

## 什么时候需要重跑

- 组织模式首次运行后 **24 小时**：成员账号是异步加入的，重跑才能关掉后加入成员的付费保护
- 以后**新开了区域**（或者用 SCP 禁止未使用的区域）
- 组织里加了新账号，想立即检查状态

## 验证

```bash
aws guardduty create-sample-findings --region <非汇总区域> \
  --detector-id <该区域 detector> --finding-types 'Backdoor:EC2/C&CActivity.B!DNS'
```

几分钟内应收到邮件（首次需先点确认订阅邮件）。

## 已知取舍

- SNS 主题未加密。告警内容敏感度低，且邮件本身是明文；如需加密，要用客户自管 KMS 密钥并在密钥策略里授权 `events.amazonaws.com`。
- 告警转发未配置死信队列，依赖 EventBridge 默认的 24 小时重试。
