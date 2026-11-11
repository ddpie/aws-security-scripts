# aws-security-scripts

AWS 安全服务的一次性开通/配置脚本。每个脚本都可重复运行，并支持 `--dry-run` 预览。

| 目录 | 内容 |
|---|---|
| [guardduty/](guardduty/) | 所有区域批量开通 GuardDuty、批量委派给安全账号 |

## 前提

- AWS CLI v2，已配置好对应账号的 profile
- bash 3.2+（macOS 自带即可）

脚本按"能用就好"的原则提供，生产使用前请先在测试账号验证。
