#!/usr/bin/env bash
# GuardDuty 批量开通 + 批量委派（在组织管理账号里执行）
#
# 用法：
#   ./enable-all-regions.sh --profile <管理账号> --enable                    # 所有区域开通
#   ./enable-all-regions.sh --profile <管理账号> --delegate 123456789012     # 所有区域委派给安全账号
#   ./enable-all-regions.sh --profile <管理账号> --enable --delegate 123456789012
#   ./enable-all-regions.sh --profile <管理账号> --members --admin-profile <安全账号>  # 所有区域把组织所有账号加为成员
#
# 参数：
#   --profile <名称>        AWS CLI profile（必填）
#   --enable                没开 GuardDuty 的区域新建 detector；已开的区域不动
#   --delegate <账号ID>     把 GuardDuty 委派给这个账号；已委派给它的区域跳过，委派给别人的区域不覆盖
#   --features base|default 新建 detector 的保护功能：base=只开基础检测、付费功能全关（默认）；default=AWS 默认
#   --with <F1,F2>          配合 base：这些付费功能开启，其余仍关闭（如 LAMBDA_NETWORK_LOGS,EKS_AUDIT_LOGS）
#   --members               在安全账号里：安全账号自身和所有组织账号的付费功能按 --with 设置，组织账号加为成员，成员自动启用设为 ALL
#   --admin-profile <名称>  安全账号（委派管理员）的 profile，配合 --members
#   --regions <a,b,...>     只处理这些区域（默认：所有已启用区域）
#   --dry-run               只打印要做什么，不做修改
#   --yes                   跳过确认
set -uo pipefail

PROFILE=""; ENABLE=0; DELEGATE=""; FEATURES=base; WITH=""; ONLY=""; DRY=0; YES=0; MEMBERS=0; APROFILE=""
PAID=(S3_DATA_EVENTS EKS_AUDIT_LOGS EBS_MALWARE_PROTECTION RDS_LOGIN_EVENTS LAMBDA_NETWORK_LOGS RUNTIME_MONITORING AI_PROTECTION)

die() { echo "错误: $*" >&2; exit 1; }
val() { [[ $# -ge 2 && -n $2 && $2 != --* ]] || die "$1 需要一个值"; }
while [[ $# -gt 0 ]]; do
  case $1 in
    --profile)  val "$@"; PROFILE=$2; shift 2;;
    --enable)   ENABLE=1; shift;;
    --delegate) val "$@"; DELEGATE=$2; shift 2;;
    --features) val "$@"; FEATURES=$2; shift 2;;
    --with)     val "$@"; WITH=$2; shift 2;;
    --regions)  val "$@"; ONLY=$2; shift 2;;
    --dry-run)  DRY=1; shift;;
    --yes)      YES=1; shift;;
    --members)  MEMBERS=1; shift;;
    --admin-profile) val "$@"; APROFILE=$2; shift 2;;
    -h|--help)  sed -n '2,20p' "$0"; exit 0;;
    *) die "未知参数 $1";;
  esac
done
[[ -n $PROFILE ]] || die "缺少 --profile"
[[ $ENABLE == 1 || -n $DELEGATE || $MEMBERS == 1 ]] || die "至少要用 --enable、--delegate、--members 其中一个"
[[ $MEMBERS == 0 || -n $APROFILE ]] || die "--members 需要 --admin-profile <安全账号>"
[[ -z $DELEGATE || $DELEGATE =~ ^[0-9]{12}$ ]] || die "--delegate 必须是 12 位账号 ID"
[[ $FEATURES == base || $FEATURES == default ]] || die "--features 只能是 base 或 default"
IFS=, read -ra ON <<<"${WITH// /}"
[[ ${#ON[@]} -eq 0 || $FEATURES == base ]] || die "--with 只能配合 --features base"
if [[ ${#ON[@]} -gt 0 ]]; then
  for f in "${ON[@]}"; do [[ " ${PAID[*]} RDS_DATA_RISK " == *" $f "* ]] || die "--with 不认识的功能: ${f}（可选: ${PAID[*]} RDS_DATA_RISK）"; done
  [[ " ${ON[*]} " != *" RDS_DATA_RISK "* || " ${ON[*]} " == *" RDS_LOGIN_EVENTS "* ]] || die "RDS_DATA_RISK 要和 RDS_LOGIN_EVENTS 一起开"
fi
status_of() {
  if [[ ${#ON[@]} -gt 0 && " ${ON[*]} " == *" $1 "* ]]; then echo ENABLED; else echo DISABLED; fi
}

command -v aws >/dev/null || die "没找到 aws 命令，请先安装 AWS CLI v2"
gd() { aws --profile "$PROFILE" guardduty "$@"; }
# 当前委派：输出 "账号ID 状态"，没有委派时输出 "None None"
admin_of() {
  gd list-organization-admin-accounts --region "$1" \
    --query 'AdminAccounts[0].[AdminAccountId,AdminStatus]' --output text
}
ME=$(aws --profile "$PROFILE" sts get-caller-identity --query Account --output text) || die "无法用 profile ${PROFILE} 登录"
[[ $DELEGATE != "$ME" ]] || die "不能委派给当前账号自己"
gda() { aws --profile "$APROFILE" guardduty "$@"; }
ADMIN=""; ACC=()   # ACC: "AccountId=x,Email=y"，组织里除安全账号外的所有 ACTIVE 账号
if [[ $MEMBERS == 1 ]]; then
  ADMIN=$(aws --profile "$APROFILE" sts get-caller-identity --query Account --output text) || die "无法用 profile ${APROFILE} 登录"
  [[ -z $DELEGATE || $DELEGATE == "$ADMIN" ]] || die "--admin-profile 的账号(${ADMIN})和 --delegate(${DELEGATE})不一致"
  [[ $ADMIN != "$ME" ]] || die "--admin-profile 不能是管理账号自己"
  LIST=$(aws --profile "$PROFILE" organizations list-accounts \
    --query "Accounts[?Status=='ACTIVE'].[Id,Email]" --output text) || die "查询组织账号失败（--profile 要用管理账号）"
  while read -r id em; do
    [[ -n $id && $id != "$ADMIN" ]] && ACC+=("AccountId=${id},Email=${em}")
  done <<<"$LIST"
  [[ ${#ACC[@]} -gt 0 ]] || die "组织里没有可加入的账号"
fi

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
[[ $ENABLE == 1 ]] && echo "开通: 是（新建 detector 的保护功能: ${FEATURES}${WITH:+，另开 ${WITH}}）"
[[ -n $DELEGATE ]] && echo "委派给: ${DELEGATE}"
[[ $MEMBERS == 1 ]] && echo "加成员: 安全账号 ${ADMIN}，组织账号 ${#ACC[@]} 个（成员付费功能: ${WITH:-全关}）"
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
  if [[ $MEMBERS == 1 ]]; then
    adet=$(gda list-detectors --region "$R" --query 'DetectorIds[0]' --output text 2>/dev/null) || adet=ERR
    if   [[ $adet == ERR ]];  then line+=" | 安全账号查询失败"
    elif [[ $adet == None ]]; then line+=" | 安全账号未开通（委派后自动开通）→ 加成员"
    else
      n=$(gda list-members --region "$R" --detector-id "$adet" --only-associated false \
        --query 'length(Members)' --output text 2>/dev/null) || n="?"
      line+=" | 现有成员 ${n} 个 → 加入全部 ${#ACC[@]} 个"
      if [[ $FEATURES == base ]]; then
        en=$(gda get-detector --region "$R" --detector-id "$adet" \
          --query "Features[?Status=='ENABLED'].Name" --output text 2>/dev/null) || en="?"
        paid_on=""; for f in $en; do [[ " ${PAID[*]} " == *" $f "* ]] && paid_on+="${f} "; done
        paid_on=${paid_on% }; [[ $en == "?" ]] && paid_on="查询失败"
        line+=" | 安全账号自身付费功能: ${paid_on:-无} → ${WITH:-全关}"
      fi
    fi
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
# RDS 数据活动监控(RDS_DATA_RISK)是 RDS_LOGIN_EVENTS 的子配置，登录监控开着时明确设置它
feat_arg() {   # detector 用：Name=..,Status=..
  local a="Name=${1},Status=$(status_of "$1")"
  [[ $1 == RDS_LOGIN_EVENTS && $(status_of "$1") == ENABLED ]] && a+=",AdditionalConfiguration=[{Name=RDS_DATA_RISK,Status=$(status_of RDS_DATA_RISK)}]"
  echo "$a"
}
auto_of() { [[ $(status_of "$1") == ENABLED ]] && echo ALL || echo NONE; }
org_arg() {    # 组织配置用：--with 里的 ALL，其余 NONE
  local a="Name=${1},AutoEnable=$(auto_of "$1")"
  [[ $1 == RDS_LOGIN_EVENTS && $(status_of "$1") == ENABLED ]] && a+=",AdditionalConfiguration=[{Name=RDS_DATA_RISK,AutoEnable=$(auto_of RDS_DATA_RISK)}]"
  echo "$a"
}
OFF=(); OCF=()
for f in "${PAID[@]}"; do OFF+=("$(feat_arg "$f")"); OCF+=("$(org_arg "$f")"); done
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
        echo "  ${R}: 已开通（基础检测${WITH:+ + ${WITH}}）"
      elif [[ $FEATURES == base ]]; then
        # 一次性关闭失败（多半是该区域不支持某项功能）：先按默认建，再逐项关
        echo "  ${R}: 建时关闭付费功能失败，改为建好后逐项关闭。原因: $(lasterr)"
        if det=$(gd "${args[@]}" --query DetectorId --output text); then
          for f in "${PAID[@]}"; do
            # 刚建好的 detector 第一次修改偶尔失败，重试几次
            done_f=0
            for try in 1 2 3; do
              gd update-detector --region "$R" --detector-id "$det" \
                --features "$(feat_arg "$f")" >/dev/null 2>"$ERR" && { done_f=1; break; }
              sleep 5
            done
            if [[ $done_f == 0 ]]; then
              # 该区域没有这个功能就不算失败；其他原因（权限等）算失败，避免付费功能开着却显示成功
              if grep -qiE 'not supported|not available|invalid.*feature' "$ERR"; then
                echo "  ${R}: ${f} 该区域不支持，跳过"
              else
                echo "  ${R}: 设置 ${f} 失败: $(lasterr)"; ok=0
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
  if [[ $MEMBERS == 1 ]]; then
    # 刚委派时安全账号的 detector 可能还没建好，等一会
    adet=None
    for try in 1 2 3 4 5 6 7 8 9 10 11 12; do
      adet=$(gda list-detectors --region "$R" --query 'DetectorIds[0]' --output text) || adet=ERR
      [[ $adet == None ]] || break; sleep 5
    done
    if [[ $adet == None || $adet == ERR ]]; then
      echo "  ${R}: 安全账号没有 detector（还没委派？），跳过加成员"; ok=0
    else
      # 安全账号自己的 detector 是委派时 AWS 自动开的，付费功能可能是默认全开，这里按 --with 统一
      if [[ $FEATURES == base ]]; then
        if gda update-detector --region "$R" --detector-id "$adet" --features "${OFF[@]}" >/dev/null 2>"$ERR"; then
          echo "  ${R}: 安全账号自身付费功能已设为: ${WITH:-全关}"
        else
          echo "  ${R}: 安全账号自身功能一次性设置失败，改为逐项设置。原因: $(lasterr)"
          for f in "${PAID[@]}"; do
            gda update-detector --region "$R" --detector-id "$adet" --features "$(feat_arg "$f")" >/dev/null 2>"$ERR" && continue
            if grep -qiE 'not supported|not available|invalid.*feature' "$ERR"; then
              echo "  ${R}: ${f} 该区域不支持，跳过"
            else
              echo "  ${R}: 设置安全账号 ${f} 失败: $(lasterr)"; ok=0
            fi
          done
        fi
      fi
      if gda update-organization-configuration --region "$R" --detector-id "$adet" \
           --auto-enable-organization-members ALL --features "${OCF[@]}" >/dev/null 2>"$ERR"; then
        echo "  ${R}: 成员自动启用=ALL"
      else
        # 多半是该区域不支持某项功能：先只设 ALL，再逐项设置
        echo "  ${R}: 一次性设置失败，改为逐项设置。原因: $(lasterr)"
        if gda update-organization-configuration --region "$R" --detector-id "$adet" \
             --auto-enable-organization-members ALL >/dev/null; then
          echo "  ${R}: 成员自动启用=ALL"
          for x in "${OCF[@]}"; do
            gda update-organization-configuration --region "$R" --detector-id "$adet" \
              --auto-enable-organization-members ALL --features "$x" >/dev/null 2>"$ERR" && continue
            if grep -qiE 'not supported|not available|invalid.*feature' "$ERR"; then
              echo "  ${R}: ${x%%,*} 该区域不支持，跳过"
            else
              echo "  ${R}: 设置成员功能 ${x} 失败: $(lasterr)"; ok=0
            fi
          done
        else
          echo "  ${R}: 设置成员自动启用失败"; ok=0
        fi
      fi
      # create-members 每次最多 50 个；已是成员的账号会被跳过，不算失败
      bad=0; i=0
      while [[ $i -lt ${#ACC[@]} ]]; do
        un=$(gda create-members --region "$R" --detector-id "$adet" --account-details "${ACC[@]:$i:50}" \
          --query 'UnprocessedAccounts[].[AccountId,Result]' --output text 2>"$ERR") || { echo "  ${R}: 加成员失败: $(lasterr)"; bad=1; }
        while IFS= read -r l; do
          [[ -z $l ]] && continue
          echo "$l" | grep -qi 'already' || { echo "  ${R}: 账号未加入: ${l}"; bad=1; }
        done <<<"$un"
        i=$((i + 50))
      done
      if [[ $bad == 0 ]]; then echo "  ${R}: 已加入 ${#ACC[@]} 个组织账号"; else ok=0; fi
    fi
  fi
  [[ $ok == 1 ]] || FAILED+=("$R")
done

echo
[[ ${#OTHER[@]} -eq 0 ]] || echo "已委派给别的账号、未改动: ${OTHER[*]}"
if [[ ${#FAILED[@]} -gt 0 ]]; then echo "失败区域（修好后重跑即可）: ${FAILED[*]}"; exit 1; fi
echo "完成。"
