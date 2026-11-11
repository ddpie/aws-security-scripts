#!/usr/bin/env bash
# GuardDuty 批量开通 + 批量委派（在组织管理账号里执行）
#
# 用法：
#   ./enable-all-regions.sh --profile <管理账号> --enable                    # 所有区域开通
#   ./enable-all-regions.sh --profile <管理账号> --delegate 123456789012     # 所有区域委派给安全账号
#   ./enable-all-regions.sh --profile <管理账号> --enable --delegate 123456789012
#
# 参数：
#   --profile <名称>        AWS CLI profile（必填）
#   --enable                没开 GuardDuty 的区域新建 detector；已开的区域不动
#   --delegate <账号ID>     把 GuardDuty 委派给这个账号；已委派给它的区域跳过，委派给别人的区域不覆盖
#   --features base|default 新建 detector 的保护功能：base=只开基础检测、付费功能全关（默认）；default=AWS 默认
#   --regions <a,b,...>     只处理这些区域（默认：所有已启用区域）
#   --dry-run               只打印要做什么，不做修改
#   --yes                   跳过确认
set -uo pipefail

PROFILE=""; ENABLE=0; DELEGATE=""; FEATURES=base; ONLY=""; DRY=0; YES=0
PAID=(S3_DATA_EVENTS EKS_AUDIT_LOGS EBS_MALWARE_PROTECTION RDS_LOGIN_EVENTS LAMBDA_NETWORK_LOGS RUNTIME_MONITORING AI_PROTECTION)

die() { echo "错误: $*" >&2; exit 1; }
val() { [[ $# -ge 2 && -n $2 && $2 != --* ]] || die "$1 需要一个值"; }
while [[ $# -gt 0 ]]; do
  case $1 in
    --profile)  val "$@"; PROFILE=$2; shift 2;;
    --enable)   ENABLE=1; shift;;
    --delegate) val "$@"; DELEGATE=$2; shift 2;;
    --features) val "$@"; FEATURES=$2; shift 2;;
    --regions)  val "$@"; ONLY=$2; shift 2;;
    --dry-run)  DRY=1; shift;;
    --yes)      YES=1; shift;;
    -h|--help)  sed -n '2,16p' "$0"; exit 0;;
    *) die "未知参数 $1";;
  esac
done
[[ -n $PROFILE ]] || die "缺少 --profile"
[[ $ENABLE == 1 || -n $DELEGATE ]] || die "至少要用 --enable 或 --delegate 其中一个"
[[ -z $DELEGATE || $DELEGATE =~ ^[0-9]{12}$ ]] || die "--delegate 必须是 12 位账号 ID"
[[ $FEATURES == base || $FEATURES == default ]] || die "--features 只能是 base 或 default"

command -v aws >/dev/null || die "没找到 aws 命令，请先安装 AWS CLI v2"
gd() { aws --profile "$PROFILE" guardduty "$@"; }
# 当前委派：输出 "账号ID 状态"，没有委派时输出 "None None"
admin_of() {
  gd list-organization-admin-accounts --region "$1" \
    --query 'AdminAccounts[0].[AdminAccountId,AdminStatus]' --output text
}
ME=$(aws --profile "$PROFILE" sts get-caller-identity --query Account --output text) || die "无法用 profile ${PROFILE} 登录"
[[ $DELEGATE != "$ME" ]] || die "不能委派给当前账号自己"

if [[ -n $ONLY ]]; then
  IFS=, read -ra REGIONS <<<"${ONLY// /}"
else
  RLIST=$(aws --profile "$PROFILE" ec2 describe-regions --region us-east-1 \
    --filters Name=opt-in-status,Values=opt-in-not-required,opted-in \
    --query 'Regions[].RegionName' --output text) || die "查询区域列表失败"
  read -ra REGIONS <<<"$RLIST"
fi
[[ ${#REGIONS[@]} -gt 0 ]] || die "区域列表为空"
for R in "${REGIONS[@]}"; do
  [[ $R =~ ^[a-z]{2}(-[a-z]+)+-[0-9]+$ ]] || die "区域名不对: '${R}'（--regions 用逗号分隔，比如 us-west-2,ap-northeast-1）"
done

# ---------- 预检：只读 ----------
echo "账号: ${ME}   区域(${#REGIONS[@]}个): ${REGIONS[*]}"
[[ $ENABLE == 1 ]] && echo "开通: 是（新建 detector 的保护功能: ${FEATURES}）"
[[ -n $DELEGATE ]] && echo "委派给: ${DELEGATE}"
echo
for R in "${REGIONS[@]}"; do
  line="  ${R}:"
  if [[ $ENABLE == 1 ]]; then
    det=$(gd list-detectors --region "$R" --query 'DetectorIds[0]' --output text 2>/dev/null) || det=ERR
    case $det in
      None) line+=" 未开通 → 新建";;
      ERR)  line+=" 查询失败（权限/SCP？）";;
      *)    line+=" 已开通，不动";;
    esac
  fi
  if [[ -n $DELEGATE ]]; then
    read -r cur st <<<"$(admin_of "$R" 2>/dev/null || echo ERR)"
    if   [[ $cur == ERR ]];                  then line+=" | 委派查询失败（不是管理账号？）"
    elif [[ $cur == None ]];                 then line+=" | 未委派 → 委派"
    elif [[ $st != ENABLED ]];               then line+=" | 委派给 ${cur} 正在撤销中，稍后重跑"
    elif [[ $cur == "$DELEGATE" ]];          then line+=" | 已委派，不动"
    else                                          line+=" | 已委派给 ${cur}，不覆盖"; fi
  fi
  echo "$line"
done
echo
[[ $DRY == 1 ]] && { echo "（dry-run，未做任何修改）"; exit 0; }
if [[ $YES == 0 ]]; then
  [[ -t 0 ]] || die "非交互环境请加 --yes"
  read -rp "确认执行? [y/N] " a; [[ $a == y || $a == Y ]] || exit 1
fi

# ---------- 执行 ----------
OFF=(); for f in "${PAID[@]}"; do OFF+=("Name=${f},Status=DISABLED"); done
FAILED=(); OTHER=()
ERR=$(mktemp); trap 'rm -f "$ERR"' EXIT
lasterr() { grep -v '^[[:space:]]*$' "$ERR" | tail -n1; }   # AWS CLI 报错末尾有空行
for R in "${REGIONS[@]}"; do
  ok=1
  if [[ $ENABLE == 1 ]]; then
    det=$(gd list-detectors --region "$R" --query 'DetectorIds[0]' --output text) || det=ERR
    if [[ $det == None ]]; then
      args=(create-detector --region "$R" --enable --finding-publishing-frequency FIFTEEN_MINUTES)
      if [[ $FEATURES == base ]] && gd "${args[@]}" --features "${OFF[@]}" >/dev/null 2>"$ERR"; then
        echo "  ${R}: 已开通（只开基础检测）"
      elif [[ $FEATURES == base ]]; then
        # 一次性关闭失败（多半是该区域不支持某项功能）：先按默认建，再逐项关
        echo "  ${R}: 建时关闭付费功能失败，改为建好后逐项关闭。原因: $(lasterr)"
        if det=$(gd "${args[@]}" --query DetectorId --output text); then
          for f in "${PAID[@]}"; do
            # 刚建好的 detector 第一次修改偶尔失败，重试几次
            done_f=0
            for try in 1 2 3; do
              gd update-detector --region "$R" --detector-id "$det" \
                --features "Name=${f},Status=DISABLED" >/dev/null 2>"$ERR" && { done_f=1; break; }
              sleep 5
            done
            if [[ $done_f == 0 ]]; then
              # 该区域没有这个功能就不算失败；其他原因（权限等）算失败，避免付费功能开着却显示成功
              if grep -qiE 'not supported|not available|invalid.*feature' "$ERR"; then
                echo "  ${R}: ${f} 该区域不支持，跳过"
              else
                echo "  ${R}: 关闭 ${f} 失败: $(lasterr)"; ok=0
              fi
            fi
          done
          echo "  ${R}: 已开通"
        else
          echo "  ${R}: 开通失败"; ok=0
        fi
      elif gd "${args[@]}" >/dev/null; then
        echo "  ${R}: 已开通（AWS 默认功能）"
      else
        echo "  ${R}: 开通失败"; ok=0
      fi
    elif [[ $det == ERR ]]; then
      echo "  ${R}: 查询失败"; ok=0
    fi
  fi
  if [[ -n $DELEGATE ]]; then
    read -r cur st <<<"$(admin_of "$R" || echo ERR)"
    if [[ $cur == None ]]; then
      if gd enable-organization-admin-account --region "$R" --admin-account-id "$DELEGATE" >/dev/null; then
        echo "  ${R}: 已委派给 ${DELEGATE}"
      else
        echo "  ${R}: 委派失败"; ok=0
      fi
    elif [[ $cur == ERR ]]; then
      echo "  ${R}: 委派查询失败"; ok=0
    elif [[ $st != ENABLED ]]; then
      echo "  ${R}: 委派给 ${cur} 正在撤销中，稍后重跑"; ok=0
    elif [[ $cur != "$DELEGATE" ]]; then
      OTHER+=("${R}(${cur})")
    fi
  fi
  [[ $ok == 1 ]] || FAILED+=("$R")
done

echo
[[ ${#OTHER[@]} -eq 0 ]] || echo "已委派给别的账号、未改动: ${OTHER[*]}"
if [[ ${#FAILED[@]} -gt 0 ]]; then echo "失败区域（修好后重跑即可）: ${FAILED[*]}"; exit 1; fi
echo "完成。"
