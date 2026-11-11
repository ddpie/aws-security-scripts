# GuardDuty 批量开通 + 批量委派

GuardDuty 是区域级服务，开通和委派都要每个区域单独做。这个脚本在组织管理账号里一次处理所有区域。

## 用法

```bash
# 所有区域开通
./enable-all-regions.sh --profile <管理账号> --enable

# 所有区域委派给安全账号
./enable-all-regions.sh --profile <管理账号> --delegate 123456789012

# 两个一起做，先 dry-run 看一下
./enable-all-regions.sh --profile <管理账号> --enable --delegate 123456789012 --dry-run
```

| 参数 | 说明 |
|---|---|
| `--profile` | AWS CLI profile，必填 |
| `--enable` | 没开 GuardDuty 的区域新建 detector；已开的区域不动 |
| `--delegate <账号ID>` | 委派给这个账号；已委派给它的跳过，已委派给别人的不覆盖 |
| `--features base\|default` | 配合 `--enable`：新建 detector 的保护功能。`base`（默认）只开基础检测，付费功能全关；`default` 用 AWS 默认 |
| `--regions a,b` | 只处理这些区域，默认所有已启用区域 |
| `--dry-run` | 只打印要做什么 |
| `--yes` | 跳过确认 |

`base` 关闭的付费功能：S3 Protection、EKS 审计日志、EBS 恶意软件扫描、RDS 登录监控、Lambda 网络日志、Runtime Monitoring、AI Protection。已开通区域的保护功能脚本不改，需要调整在控制台按区域操作。

可重复运行，已完成的区域会自动跳过。
