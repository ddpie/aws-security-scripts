#!/usr/bin/env bash
# 在所有已启用区域开通 GuardDuty 基础检测，并把告警汇总到一个区域的 SNS。
# 只开基础检测（CloudTrail 管理事件 / VPC Flow Logs / DNS 日志）；
# S3 Protection 以及 EKS / 恶意软件扫描 / RDS / Lambda / Runtime Monitoring 全部显式关闭。
#
# 用法：
#   单账号模式（还没有安全账号）：
#     ./enable-all-regions.sh --account-profile <profile> --email sec@example.com
#   组织模式（已建好安全账号）：
#     ./enable-all-regions.sh --mgmt-profile <管理账号> --sec-profile <安全账号> --email sec@example.com
# 可选：
#   --home-region us-west-2   告警汇总区域（默认俄勒冈）
#   --min-severity 4          告警门槛（默认 4 = 中危及以上）
#   --dry-run                 只打印计划，不做任何修改
#   --yes                     跳过确认提示
# 可重复运行。以后新开了区域，或组织里加了新账号，再跑一次即可。
set -uo pipefail

HOME_REGION=us-west-2
MIN_SEV=4
DRY=0; YES=0
MGMT=""; SEC=""; SINGLE=""; EMAIL=""
PREFIX=gd-allregion
# 要关闭的付费保护（GuardDuty 新建 detector 时默认会打开这些）
FEATURES=(S3_DATA_EVENTS EKS_AUDIT_LOGS EBS_MALWARE_PROTECTION RDS_LOGIN_EVENTS LAMBDA_NETWORK_LOGS RUNTIME_MONITORING EKS_RUNTIME_MONITORING AI_PROTECTION)

die()  { echo "错误: $*" >&2; exit 1; }
need() { [[ $# -ge 2 && -n $2 && $2 != --* ]] || die "$1 需要一个值"; }
while [[ $# -gt 0 ]]; do
  case $1 in
    --mgmt-profile)    need "$@"; MGMT=$2; shift 2;;
    --sec-profile)     need "$@"; SEC=$2; shift 2;;
    --account-profile) need "$@"; SINGLE=$2; shift 2;;
    --email)           need "$@"; EMAIL=$2; shift 2;;
    --home-region)     need "$@"; HOME_REGION=$2; shift 2;;
    --min-severity)    need "$@"; MIN_SEV=$2; shift 2;;
    --dry-run) DRY=1; shift;;
    --yes)     YES=1; shift;;
    -h|--help) sed -n '2,17p' "$0"; exit 0;;
    *) die "未知参数 $1";;
  esac
done
[[ $MIN_SEV =~ ^[0-9]+(\.[0-9]+)?$ ]] || die "--min-severity 必须是数字"
if   [[ -n $SINGLE && -z $MGMT && -z $SEC ]]; then MODE=single; TARGET=$SINGLE
elif [[ -z $SINGLE && -n $MGMT && -n $SEC ]]; then MODE=org;    TARGET=$SEC
else die "用 --account-profile，或同时用 --mgmt-profile 和 --sec-profile"; fi

# run：打印并执行修改类命令；打印走 stderr，不会混进 $(...) 的结果
exec 3>&2   # 命令回显固定走 fd3，即使 stderr 被重定向也能看到
run()   { echo "+ $*" >&3; [[ $DRY == 1 ]] || "$@"; }
aws_t() { aws --profile "$TARGET" "$@"; }
aws_m() { aws --profile "$MGMT" "$@"; }

TARGET_ID=$(aws_t sts get-caller-identity --query Account --output text) || die "无法用 $TARGET 登录"
MGMT_ID=""
if [[ $MODE == org ]]; then
  MGMT_ID=$(aws_m sts get-caller-identity --query Account --output text) || die "无法用 $MGMT 登录"
  [[ $MGMT_ID != "$TARGET_ID" ]] || die "安全账号不能是管理账号本身"
  ORG_N=$(aws_m organizations list-accounts --query 'length(Accounts[?Status==`ACTIVE`])' --output text) \
    || die "无法列出组织账号"
fi

# us-east-1 永远是启用状态，用它查区域列表
read -ra REGIONS <<<"$(aws_t ec2 describe-regions --region us-east-1 \
  --filters Name=opt-in-status,Values=opt-in-not-required,opted-in \
  --query 'Regions[].RegionName' --output text)" || die "查询区域列表失败"
[[ ${#REGIONS[@]} -gt 0 ]] || die "区域列表为空"
if [[ $MODE == org ]]; then   # 组织模式：只处理管理账号和安全账号都启用的区域
  read -ra MREG <<<"$(aws_m ec2 describe-regions --region us-east-1 \
    --filters Name=opt-in-status,Values=opt-in-not-required,opted-in \
    --query 'Regions[].RegionName' --output text)" || die "查询管理账号区域失败"
  BOTH=(); SKIPPED=()
  for r in "${REGIONS[@]}"; do
    if [[ " ${MREG[*]} " == *" $r "* ]]; then BOTH+=("$r"); else SKIPPED+=("$r"); fi
  done
  [[ ${#SKIPPED[@]} -eq 0 ]] || echo "注意：管理账号未启用这些区域，跳过: ${SKIPPED[*]}"
  REGIONS=("${BOTH[@]}")
fi
[[ " ${REGIONS[*]} " == *" $HOME_REGION "* ]] || die "汇总区域 $HOME_REGION 不在已启用区域里"

RULE=$PREFIX-findings
TOPIC_NAME=$PREFIX-findings
TOPIC_ARN="arn:aws:sns:$HOME_REGION:$TARGET_ID:$TOPIC_NAME"
ROLE_NAME=$PREFIX-forward
ROLE_ARN="arn:aws:iam::$TARGET_ID:role/$ROLE_NAME"
HOME_BUS="arn:aws:events:$HOME_REGION:$TARGET_ID:event-bus/default"
HOME_RULE_ARN="arn:aws:events:$HOME_REGION:$TARGET_ID:rule/$RULE"
PATTERN="{\"source\":[\"aws.guardduty\"],\"detail-type\":[\"GuardDuty Finding\"],\"detail\":{\"severity\":[{\"numeric\":[\">=\",$MIN_SEV]}]}}"

# ---------- 预检：只读，不改任何东西 ----------
echo "模式: $MODE   目标账号: $TARGET_ID${MGMT_ID:+   管理账号: $MGMT_ID}"
echo "区域(${#REGIONS[@]}): ${REGIONS[*]}"
CONFLICT=(); PREFAIL=()
for R in "${REGIONS[@]}"; do
  if [[ $MODE == org ]]; then
    if ! CUR=$(aws_m guardduty list-organization-admin-accounts --region "$R" \
                 --query 'AdminAccounts[0].AdminAccountId' --output text); then
      PREFAIL+=("$R"); continue
    fi
    [[ $CUR == None || $CUR == "$TARGET_ID" ]] || CONFLICT+=("$R:$CUR")
  fi
  if DET=$(aws_t guardduty list-detectors --region "$R" --query 'DetectorIds[0]' --output text) \
     && [[ $DET != None ]]; then
    S3=$(aws_t guardduty get-detector --region "$R" --detector-id "$DET" \
         --query "Features[?Name=='S3_DATA_EVENTS'].Status|[0]" --output text 2>/dev/null || echo ?)
    echo "  $R: 已有 detector，S3 Protection=${S3}（将被关闭）"
  fi
done
[[ ${#CONFLICT[@]} -eq 0 ]] || die "以下区域已有别的委派管理员，请先确认再处理: ${CONFLICT[*]}"
[[ ${#PREFAIL[@]} -eq 0 ]] || echo "注意：这些区域预检失败（权限/SCP？），将会跳过并报告: ${PREFAIL[*]}"
if [[ $DRY == 0 && $YES == 0 ]]; then
  read -rp "将在以上区域开通 GuardDuty、关闭 S3 等付费保护、配置告警。继续? [y/N] " a
  [[ $a == y || $a == Y ]] || exit 1
fi

# ---------- 1. 汇总区域：SNS 主题 + 转发角色 ----------
run aws_t sns create-topic --region "$HOME_REGION" --name "$TOPIC_NAME" >/dev/null || die "创建 SNS 主题失败"
TOPIC_POLICY=$(cat <<EOF
{"Version":"2012-10-17","Statement":[
 {"Sid":"Owner","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::$TARGET_ID:root"},
  "Action":["sns:Publish","sns:Subscribe","sns:GetTopicAttributes","sns:SetTopicAttributes","sns:ListSubscriptionsByTopic"],
  "Resource":"$TOPIC_ARN"},
 {"Sid":"EventBridge","Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},
  "Action":"sns:Publish","Resource":"$TOPIC_ARN",
  "Condition":{"StringEquals":{"aws:SourceAccount":"$TARGET_ID"},"ArnEquals":{"aws:SourceArn":"$HOME_RULE_ARN"}}}]}
EOF
)
run aws_t sns set-topic-attributes --region "$HOME_REGION" --topic-arn "$TOPIC_ARN" \
  --attribute-name Policy --attribute-value "$TOPIC_POLICY" || die "设置 SNS 主题策略失败"
if [[ -n $EMAIL ]]; then
  SUBS=$(aws_t sns list-subscriptions-by-topic --region "$HOME_REGION" --topic-arn "$TOPIC_ARN" \
         --query 'Subscriptions[].Endpoint' --output text 2>/dev/null | tr '\t' '\n' || true)
  if ! grep -Fxq -- "$EMAIL" <<<"$SUBS"; then
    run aws_t sns subscribe --region "$HOME_REGION" --topic-arn "$TOPIC_ARN" \
      --protocol email --notification-endpoint "$EMAIL" >/dev/null || die "订阅邮箱失败"
    [[ $DRY == 1 ]] || echo "  → 请到 $EMAIL 点确认订阅，否则收不到告警"
  fi
fi

NEW_ROLE=0
if ! aws_t iam get-role --role-name "$ROLE_NAME" >/dev/null 2>&1; then
  run aws_t iam create-role --role-name "$ROLE_NAME" --assume-role-policy-document "$(cat <<EOF
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"events.amazonaws.com"},
 "Action":"sts:AssumeRole","Condition":{"StringEquals":{"aws:SourceAccount":"$TARGET_ID"},
 "ArnLike":{"aws:SourceArn":"arn:aws:events:*:$TARGET_ID:rule/$RULE"}}}]}
EOF
)" >/dev/null || die "创建转发角色失败"
  NEW_ROLE=1
fi
run aws_t iam put-role-policy --role-name "$ROLE_NAME" --policy-name forward --policy-document \
  "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"events:PutEvents\",\"Resource\":\"$HOME_BUS\"}]}" \
  || die "设置转发角色权限失败"
[[ $DRY == 1 || $NEW_ROLE == 0 ]] || sleep 15   # 等新角色在 IAM 里生效

# ---------- 2. 逐区域（单个区域失败不影响其他区域） ----------
WARN=()
warn() { WARN+=("$R: $*"); echo "  ! $*" >&2; }
ERRF=$(mktemp); trap 'rm -f "$ERRF"' EXIT
lasterr() { tail -n1 "$ERRF" 2>/dev/null; }   # 最近一次失败的 AWS 报错原文

disable_features_on_detector() {   # $1=aws_t|aws_m  $2=detector
  local f
  for f in "${FEATURES[@]}"; do
    run "$1" guardduty update-detector --region "$R" --detector-id "$2" \
      --features "Name=$f,Status=DISABLED" >/dev/null 2>"$ERRF" || warn "关闭 $f 失败: $(lasterr)"
  done
}

wait_detector() {   # 委派后 detector 是异步建的，最多等 60 秒
  local i d
  for i in $(seq 1 12); do
    d=$(aws_t guardduty list-detectors --region "$R" --query 'DetectorIds[0]' --output text) || return 1
    [[ $d != None ]] && { echo "$d"; return 0; }
    sleep 5
  done
  echo None
}

do_region() {
  local DET st members ids i f n un just=0
  echo "== $R"

  if [[ $MODE == org ]]; then
    # 2a. 管理账号：在该区域设委派管理员（委派按区域）
    if [[ $(aws_m guardduty list-organization-admin-accounts --region "$R" \
            --query 'AdminAccounts[0].AdminAccountId' --output text) != "$TARGET_ID" ]]; then
      run aws_m guardduty enable-organization-admin-account --region "$R" \
        --admin-account-id "$TARGET_ID" || return 1
      if [[ $DRY == 0 ]]; then
        for i in $(seq 1 12); do
          st=$(aws_m guardduty list-organization-admin-accounts --region "$R" \
               --query "AdminAccounts[?AdminAccountId=='$TARGET_ID'].AdminStatus|[0]" --output text)
          [[ $st == ENABLED ]] && break; sleep 5
        done
        [[ $st == ENABLED ]] || { warn "委派管理员 60 秒内未生效"; return 1; }
        just=1
      fi
    fi
  fi

  # 2b. 目标账号：确保有 detector
  if [[ $DRY == 1 ]]; then
    DET=$(aws_t guardduty list-detectors --region "$R" --query 'DetectorIds[0]' --output text) || return 1
    [[ $DET != None ]] || { echo "+ create-detector（新建）" >&2; DET=DRY-RUN-DETECTOR; }
  else
    if [[ $just == 1 ]]; then DET=$(wait_detector) || return 1   # 刚委派：detector 异步出现
    else DET=$(aws_t guardduty list-detectors --region "$R" --query 'DetectorIds[0]' --output text) || return 1; fi
    if [[ $DET == None ]]; then
      echo "+ create-detector" >&2
      DET=$(aws_t guardduty create-detector --region "$R" --enable \
            --finding-publishing-frequency FIFTEEN_MINUTES --query DetectorId --output text) || return 1
    fi
    [[ $DET =~ ^[0-9a-f]{32}$ ]] || { warn "detector ID 异常: $DET"; return 1; }
  fi
  # 单账号模式下，如果这个账号已经是别人的 GuardDuty 成员，设置由对方管理员控制，这里不改
  local admin=None rel=
  if [[ $MODE == single && $DRY == 0 ]]; then
    read -r admin rel <<<"$(aws_t guardduty get-administrator-account --region "$R" --detector-id "$DET" \
            --query 'Administrator.[AccountId,RelationshipStatus]' --output text 2>/dev/null)" || true
    [[ ${rel:-} == Enabled ]] || admin=None   # 只有关系已生效才算被别人管理
  fi
  if [[ $admin != None && -n $admin ]]; then
    warn "该账号是 $admin 的 GuardDuty 成员，付费保护需在 $admin 关闭；这里只配告警"
  else
    run aws_t guardduty update-detector --region "$R" --detector-id "$DET" --enable \
      --finding-publishing-frequency FIFTEEN_MINUTES || return 1
    disable_features_on_detector aws_t "$DET"
  fi

  # 2c. 组织模式：自动启用所有成员，新成员不开付费保护；已有成员逐个关闭
  if [[ $MODE == org ]]; then
    # 一次调用同时打开 ALL 和关闭付费保护，避免中间有成员按默认值开了付费功能
    local fa=(); for f in "${FEATURES[@]}"; do
      [[ $f == EKS_RUNTIME_MONITORING ]] || fa+=("Name=$f,AutoEnable=NONE")   # 不能和 RUNTIME_MONITORING 同一次调用
    done
    if ! run aws_t guardduty update-organization-configuration --region "$R" --detector-id "$DET" \
         --auto-enable-organization-members ALL --features "${fa[@]}" 2>"$ERRF"; then
      # 多半是该区域不支持其中某项功能：逐项关能关的（不动 ALL 设置），再确保 ALL
      for f in "${FEATURES[@]}"; do
        run aws_t guardduty update-organization-configuration --region "$R" --detector-id "$DET" \
          --features "Name=$f,AutoEnable=NONE" 2>"$ERRF" \
          || warn "组织级关闭 $f 失败: $(lasterr)"
      done
      run aws_t guardduty update-organization-configuration --region "$R" --detector-id "$DET" \
        --auto-enable-organization-members ALL || return 1
    fi
    if [[ $DRY == 0 ]]; then
      members=$(aws_t guardduty list-members --region "$R" --detector-id "$DET" \
                --query 'Members[].AccountId' --output text) || return 1
      # 管理账号不会被 ALL 自动纳入：先在管理账号开 GuardDuty（并关付费保护），再加为成员
      if ! grep -qw -- "$MGMT_ID" <<<"$members"; then
        local mdet
        mdet=$(aws_m guardduty list-detectors --region "$R" --query 'DetectorIds[0]' --output text) || return 1
        if [[ $mdet == None ]]; then
          echo "+ 管理账号 create-detector" >&2
          mdet=$(aws_m guardduty create-detector --region "$R" --enable \
                 --finding-publishing-frequency FIFTEEN_MINUTES --query DetectorId --output text) || return 1
        fi
        disable_features_on_detector aws_m "$mdet"
        if run aws_t guardduty create-members --region "$R" --detector-id "$DET" \
             --account-details "AccountId=$MGMT_ID" >/dev/null 2>"$ERRF"; then
          members="$members $MGMT_ID"
        else
          warn "把管理账号加为成员失败: $(lasterr)"
        fi
      fi
      read -ra ids <<<"$members"
      n=${#ids[@]}
      for ((i=0; i<n; i+=50)); do          # 每次最多 50 个账号
        for f in "${FEATURES[@]}"; do
          if ! un=$(run aws_t guardduty update-member-detectors --region "$R" --detector-id "$DET" \
                      --account-ids "${ids[@]:i:50}" --features "Name=$f,Status=DISABLED" \
                      --query 'UnprocessedAccounts[].AccountId' --output text 2>"$ERRF"); then
            warn "成员关闭 $f 失败: $(lasterr)"
          elif [[ -n $un && $un != None ]]; then
            warn "这些成员关闭 $f 未完成（可能还在加入中，稍后重跑）: $un"
          fi
        done
      done
      if [[ $n -lt $((ORG_N - 1)) ]]; then
        warn "成员账号 $n/$((ORG_N - 1)) 已加入（自动启用最多需要 24 小时），请稍后重跑以关闭其余成员的付费保护"
      fi
    else
      echo "+ 逐个关闭已有成员账号的付费保护；必要时把管理账号 $MGMT_ID 加为成员" >&2
    fi
  fi

  # 2d. 告警：汇总区域直接发 SNS；其他区域转发到汇总区域的 default 总线
  #     （EventBridge 的 SNS 目标必须同区域；转发过去的事件由汇总区域的同名规则发出，不会循环）
  run aws_t events put-rule --region "$R" --name "$RULE" --event-pattern "$PATTERN" \
    --description "GuardDuty findings severity>=$MIN_SEV" >/dev/null || return 1
  local target="Id=sns,Arn=$TOPIC_ARN"
  [[ $R == "$HOME_REGION" ]] || target="Id=home,Arn=$HOME_BUS,RoleArn=$ROLE_ARN"
  for i in 1 2 3; do
    n=$(run aws_t events put-targets --region "$R" --rule "$RULE" --targets "$target" \
        --query FailedEntryCount --output text) || return 1
    [[ $DRY == 1 || $n == 0 ]] && return 0
    sleep 10   # 多半是新角色还没生效
  done
  warn "告警转发目标添加失败"; return 1
}

FAILED=()
for R in "${REGIONS[@]}"; do
  [[ " ${PREFAIL[*]-} " == *" $R "* ]] && { FAILED+=("$R(预检失败)"); continue; }
  do_region || FAILED+=("$R")
done

echo
[[ ${#WARN[@]} -eq 0 ]] || { echo "警告:"; printf '  %s\n' "${WARN[@]}"; }
if [[ ${#FAILED[@]} -gt 0 ]]; then
  echo "失败区域（修好原因后重跑即可）: ${FAILED[*]}"; exit 1
fi
echo "全部完成。验证："
echo "  aws --profile $TARGET guardduty create-sample-findings --region <非 $HOME_REGION 的区域> \\"
echo "    --detector-id <该区域 detector> --finding-types Backdoor:EC2/C\&CActivity.B!DNS"
echo "  （样例告警严重度需 >= $MIN_SEV 才会发邮件）"
