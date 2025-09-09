#!/bin/sh
# 此脚本用于防火墙规则的管理，通过设置必要的规则来屏蔽不良IP。规则会持续生效，直到系统重启或手动重置防火墙。
# 设置脚本执行权限：chmod 755 /usr/bin/flytrap.sh
# 清理黑名单所有规则和IP集合：/usr/bin/flytrap.sh clean
# 列出黑名单和白名单中的IP：/usr/bin/flytrap.sh list 4（IPv4或IPv6）
# 将一个IP添加到黑名单：/usr/bin/flytrap.sh add 112.17.165.25
# 从黑名单中删除一个IP：/usr/bin/flytrap.sh del 107.148.94.42
# 如需记录屏蔽IP，在定时任务执行：/usr/bin/flytrap.sh log_blocked_ips
# 添加白名单IP：/usr/bin/flytrap.sh add_whitelist 192.168.1.100
# 删除白名单IP：/usr/bin/flytrap.sh del_whitelist 192.168.1.100

# 可自定义的选项区域

wan_name="ppp0"  # 监控的网络接口名称
trap_ports="20,21,22,23,3389"  # 需要监控的端口，多个端口用逗号分隔
trap6="no"  # 是否启用IPv6支持，"yes"启用，"no"禁用
unlock="16888"  # 黑名单IP的超时时间，0表示永久，单位：秒
log_file="/tmp/IPblacklist-log.txt"  # 日志文件路径
sh_file="/usr/bin"  # 脚本安装路径
max_log_size=$((3*1024*1024))  # 最大日志文件大小，默认3MB
# 白名单的IP地址，可以通过脚本参数动态添加和删除
whitelist_ips="107.149.214.25,107.148.94.42"  # 示例白名单IP，多个IP用逗号分隔

# 可自定义的选项结束

# 设置PATH，确保脚本可以找到所需命令
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/bin:/opt/sbin:$PATH"

# 定义匹配IPv4和IPv6地址的正则表达式
IPREX4='([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[1-2][0-9]|3[0-2]))?'
IPREX6='([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}(([0-9]{1,3}\.){3}[0-9]{1,3})|([0-9a-fA-F]{1,4}:){1,4}:(([0-9]{1,3}\.){3}[0-9]{1,3})'

# 性能优化：批量获取所有命令路径
init_command_paths() {
    # 一次性查找所有需要的命令
    local cmd_list="ipset iptables ip6tables grep awk sed date ps rm touch sleep kill stat"
    local cmd
    
    for cmd in $cmd_list; do
        local path=$(which $cmd 2>/dev/null)
        case $cmd in
            ipset) IPSET_PATH="$path" ;;
            iptables) IPTABLES_PATH="$path" ;;
            ip6tables) IP6TABLES_PATH="$path" ;;
            grep) GREP="$path" ;;
            awk) AWK="$path" ;;
            sed) SED="$path" ;;
            date) DATE="$path" ;;
            ps) PS="$path" ;;
            rm) RM="$path" ;;
            touch) TOUCH="$path" ;;
            sleep) SLEEP="$path" ;;
            kill) KILL="$path" ;;
            stat) STAT="$path" ;;
        esac
    done
}

# 初始化命令路径
init_command_paths

# 检查必需命令是否存在
check_required_commands() {
    local missing_commands=0
    
    if [ -z "$IPSET_PATH" ]; then
        echo "错误: 未找到 ipset 命令" | tee -a "$log_file"
        missing_commands=1
    fi
    
    if [ -z "$IPTABLES_PATH" ]; then
        echo "错误: 未找到 iptables 命令" | tee -a "$log_file"
        missing_commands=1
    fi
    
    if [ -z "$GREP" ] || [ -z "$AWK" ] || [ -z "$SED" ]; then
        echo "错误: 基本文本处理命令 (grep/awk/sed) 缺失" | tee -a "$log_file"
        missing_commands=1
    fi
    
    if [ "$trap6" = "yes" ] && [ -z "$IP6TABLES_PATH" ]; then
        echo "错误: IPv6 已启用但未找到 ip6tables 命令" | tee -a "$log_file"
        missing_commands=1
    fi
    
    if [ $missing_commands -eq 1 ]; then
        exit 1
    fi
}

# 检查规则是否存在的辅助函数
check_rule_exists() {
    local ipt_cmd=$1
    local rule=$2
    $ipt_cmd -C $rule >/dev/null 2>&1
    return $?
}

# 性能优化：批量检查规则是否存在
check_rules_batch() {
    local ipt_cmd=$1
    shift
    local rules_output=$($ipt_cmd -S 2>/dev/null)
    local all_exist=1
    
    for rule in "$@"; do
        # 转换规则格式：从 -C 格式到 -S 输出格式
        local rule_pattern=$(echo "$rule" | sed 's/^/-A /')
        if ! echo "$rules_output" | $GREP -qF "$rule_pattern"; then
            all_exist=0
            break
        fi
    done
    
    return $all_exist
}

# 环境检查函数，检测是否安装了iptables和ip6tables
check_environment() {
    if [ "$trap6" = "yes" ] && [ -z "$IP6TABLES_PATH" ]; then
        echo "trap6设置为yes，但未找到ip6tables命令，IPv6支持将被禁用。" | tee -a "$log_file"
        trap6="no"
    fi

    if [ -z "$IPTABLES_PATH" ] || [ ! -x "$IPTABLES_PATH" ]; then
        echo "未找到iptables命令，请手动安装iptables。" | tee -a "$log_file"
        exit 1
    fi
}

# 检查 IPSET_PATH 是否有效，如果无效则安装 ipset
check_ipset() {
    if [ -z "$IPSET_PATH" ] || [ ! -x "$IPSET_PATH" ]; then
        echo "未找到 ipset 命令，正在尝试安装..."
        install_ipset
        IPSET_PATH=$(which ipset)
        if [ -z "$IPSET_PATH" ] || [ ! -x "$IPSET_PATH" ]; then
            echo "安装 ipset 失败，请手动安装。" | tee -a "$log_file"
            exit 1
        fi
    fi
}

# 检查并清理已运行的进程
check_and_clean_process() {
    local script_name=$(basename "$0")  # 获取当前脚本名称
    local current_pid=$$  # 获取当前脚本的进程ID

    # 查找当前脚本的运行实例
    local running_pids=$($PS w | $GREP "$script_name" | $GREP -v grep | $GREP -v "$current_pid" | $AWK '{print $1}')

    if [ ! -z "$running_pids" ]; then
        echo "发现正在运行的同脚本实例，正在清理..."
        for pid in $running_pids; do
            if $KILL -0 "$pid" 2>/dev/null; then
                echo "终止进程: $pid"
                $KILL "$pid" 2>/dev/null
                $SLEEP 1
            fi
        done
        echo "同脚本进程清理完成"
    else
        echo "没有发现其他运行的脚本实例。"
    fi
}

# 日志管理函数，检查日志文件大小，如果超过限制则删除旧日志并创建新日志
manage_log() {
    if [ -f "$log_file" ]; then
        log_size=$($STAT -c%s "$log_file" 2>/dev/null)
        if [ "$log_size" -ge "$max_log_size" ] 2>/dev/null; then
            echo "日志文件大小超过限制，删除旧日志文件并创建新日志文件。"
            $RM -f "$log_file"
            $TOUCH "$log_file"
        fi
    fi
}

# 创建IP集合（黑名单和白名单）
create_ipset() {
    # 性能优化：一次性获取所有ipset列表
    local ipset_names=$($IPSET_PATH list -n 2>/dev/null)
    
    if ! echo "$ipset_names" | $GREP -q "flytrap_blacklist"; then
        echo "正在创建flytrap ipset ipv4..." | tee -a "$log_file"
        if [ "$unlock" -gt 0 ]; then
            if ! $IPSET_PATH create flytrap_blacklist hash:net timeout $unlock 2>&1 | tee -a "$log_file"; then
                echo "错误：创建flytrap_blacklist失败。" | tee -a "$log_file"
                exit 1
            fi
        else
            if ! $IPSET_PATH create flytrap_blacklist hash:net 2>&1 | tee -a "$log_file"; then
                echo "错误：创建flytrap_blacklist失败。" | tee -a "$log_file"
                exit 1
            fi
        fi
        echo "成功创建flytrap_blacklist。" | tee -a "$log_file"
    else
        echo "flytrap ipset ipv4已经存在。" | tee -a "$log_file"
    fi

    if [ "$trap6" = "yes" ] && ! echo "$ipset_names" | $GREP -q flytrap6_blacklist; then
        echo "正在创建flytrap ipset ipv6..." | tee -a "$log_file"
        if [ "$unlock" -gt 0 ]; then
            if ! $IPSET_PATH create flytrap6_blacklist hash:net family inet6 timeout $unlock 2>&1 | tee -a "$log_file"; then
                echo "错误：创建flytrap6_blacklist失败，禁用IPv6支持。" | tee -a "$log_file"
                trap6="no"
            else
                echo "成功创建flytrap6_blacklist。" | tee -a "$log_file"
            fi
        else
            if ! $IPSET_PATH create flytrap6_blacklist hash:net family inet6 2>&1 | tee -a "$log_file"; then
                echo "错误：创建flytrap6_blacklist失败，禁用IPv6支持。" | tee -a "$log_file"
                trap6="no"
            else
                echo "成功创建flytrap6_blacklist。" | tee -a "$log_file"
            fi
        fi
    elif [ "$trap6" = "yes" ]; then
        echo "flytrap ipset ipv6已经存在。" | tee -a "$log_file"
    fi

    # 创建白名单
    if ! echo "$ipset_names" | $GREP -q "flytrap_whitelist"; then
        echo "正在创建flytrap ipset白名单..." | tee -a "$log_file"
        if ! $IPSET_PATH create flytrap_whitelist hash:net 2>&1 | tee -a "$log_file"; then
            echo "错误：创建flytrap_whitelist失败。" | tee -a "$log_file"
            exit 1
        fi
        echo "成功创建flytrap_whitelist。" | tee -a "$log_file"
    else
        echo "flytrap ipset白名单已经存在。" | tee -a "$log_file"
    fi
}

# 添加常见内网段到白名单（使用预设值，不依赖动态检测）
add_common_internal_networks() {
    echo "添加常见内网段到白名单..." | tee -a "$log_file"
    
    # 常见的内网段
    common_internal_networks="192.168.0.0/16 10.0.0.0/8 172.16.0.0/12 127.0.0.0/8"
    
    for network in $common_internal_networks; do
        if ! $IPSET_PATH test flytrap_whitelist $network 2>/dev/null; then
            if $IPSET_PATH add flytrap_whitelist $network 2>/dev/null; then
                echo "添加内网段到白名单: $network" | tee -a "$log_file"
            else
                echo "警告：添加内网段失败: $network" | tee -a "$log_file"
            fi
        else
            echo "内网段已在白名单中: $network" | tee -a "$log_file"
        fi
    done
    
    echo "常见内网段添加完成。" | tee -a "$log_file"
}

# 清理iptables规则
clean_ipt() {
    rule_exp=$1
    rule_comment=$2
    rule_type=$3
    ipt_cmd=$IPTABLES_PATH
    [ "$rule_type" = "6" ] && ipt_cmd=$IP6TABLES_PATH
    
    # 检查命令是否存在
    if [ -z "$ipt_cmd" ] || [ ! -x "$ipt_cmd" ]; then
        echo "警告：$rule_comment 清理跳过，命令不存在。" | tee -a "$log_file"
        return
    fi
    
    ipt_test=$($ipt_cmd -S 2>/dev/null | $GREP -E "$rule_exp" | head -1)
    while echo "$ipt_test" | $GREP -q "\-A"; do
        echo "清理规则：$rule_comment ..." | tee -a "$log_file"
        if $ipt_cmd $(echo "$ipt_test" | $SED "s/-A/-D/") 2>&1 | tee -a "$log_file"; then
            echo "成功清理规则：$rule_comment" | tee -a "$log_file"
        else
            echo "警告：清理规则失败：$rule_comment" | tee -a "$log_file"
            break
        fi
        ipt_test=$($ipt_cmd -S 2>/dev/null | $GREP -E "$rule_exp" | head -1)
    done
}

# 清理IP集合和相关规则
clean_trap() {
    echo "开始清理防火墙规则和IP集合..." | tee -a "$log_file"
    
    clean_ipt "INPUT.+$wan_name.+multiport.+flytrap_blacklist" "INPUT->flytrap_blacklist(ipset) IPv4" "4"
    clean_ipt "FORWARD.+$wan_name.+multiport.+flytrap_blacklist" "FORWARD->flytrap_blacklist(ipset) IPv4" "4"
    clean_ipt "INPUT.+match-set.+flytrap_blacklist.+DROP" "flytrap_blacklist->INPUT(DROP) IPv4" "4"
    clean_ipt "FORWARD.+match-set.+flytrap_blacklist.+DROP" "flytrap_blacklist->FORWARD(DROP) IPv4" "4"
    clean_ipt "OUTPUT.+match-set.+flytrap_blacklist.+DROP" "flytrap_blacklist->OUTPUT(DROP) IPv4" "4"
    clean_ipt "INPUT.+match-set.+flytrap_whitelist.+ACCEPT" "flytrap_whitelist->INPUT(ACCEPT) IPv4" "4"
    clean_ipt "INPUT.+match-set.+flytrap_whitelist.+RETURN" "flytrap_whitelist->INPUT(RETURN) IPv4" "4"
    
    # 性能优化：批量获取ipset列表
    local ipset_names=$($IPSET_PATH list -n 2>/dev/null)
    
    if echo "$ipset_names" | $GREP -q "flytrap_blacklist"; then
        if $IPSET_PATH destroy flytrap_blacklist 2>&1 | tee -a "$log_file"; then
            echo "成功销毁flytrap_blacklist" | tee -a "$log_file"
        else
            echo "警告：销毁flytrap_blacklist失败" | tee -a "$log_file"
        fi
    fi
    
    if echo "$ipset_names" | $GREP -q "flytrap_whitelist"; then
        if $IPSET_PATH destroy flytrap_whitelist 2>&1 | tee -a "$log_file"; then
            echo "成功销毁flytrap_whitelist" | tee -a "$log_file"
        else
            echo "警告：销毁flytrap_whitelist失败" | tee -a "$log_file"
        fi
    fi
    
    if [ "$trap6" = "yes" ]; then
        clean_ipt "INPUT.+$wan_name.+multiport.+flytrap6_blacklist" "INPUT->flytrap6_blacklist(ipset) IPv6" "6"
        clean_ipt "FORWARD.+$wan_name.+multiport.+flytrap6_blacklist" "FORWARD->flytrap6_blacklist(ipset) IPv6" "6"
        clean_ipt "INPUT.+match-set.+flytrap6_blacklist.+DROP" "flytrap6_blacklist->INPUT(DROP) IPv6" "6"
        clean_ipt "FORWARD.+match-set.+flytrap6_blacklist.+DROP" "flytrap6_blacklist->FORWARD(DROP) IPv6" "6"
        clean_ipt "OUTPUT.+match-set.+flytrap6_blacklist.+DROP" "flytrap6_blacklist->OUTPUT(DROP) IPv6" "6"
        
        if echo "$ipset_names" | $GREP -q flytrap6_blacklist; then
            if $IPSET_PATH destroy flytrap6_blacklist 2>&1 | tee -a "$log_file"; then
                echo "成功销毁flytrap6_blacklist" | tee -a "$log_file"
            else
                echo "警告：销毁flytrap6_blacklist失败" | tee -a "$log_file"
            fi
        fi
    fi
    
    echo "清理完成。" | tee -a "$log_file"
}

# 检查防火墙规则，并记录被加入黑名单的IP
add_trap() {
    local rule_added=0
    
    # 添加白名单规则，确保插入到INPUT链的第一个位置
    if ! $IPTABLES_PATH -C INPUT -m set --match-set flytrap_whitelist src -j ACCEPT >/dev/null 2>&1; then
        echo "添加flytrap_whitelist白名单规则..." | tee -a "$log_file"
        if $IPTABLES_PATH -I INPUT 1 -m set --match-set flytrap_whitelist src -j ACCEPT 2>&1 | tee -a "$log_file"; then
            echo "成功添加白名单ACCEPT规则。" | tee -a "$log_file"
            rule_added=1
        else
            echo "错误：无法添加白名单规则。" | tee -a "$log_file"
            return 1
        fi
        
        # 添加RETURN规则，确保白名单IP直接跳过后续规则
        if $IPTABLES_PATH -I INPUT 2 -m set --match-set flytrap_whitelist src -j RETURN 2>&1 | tee -a "$log_file"; then
            echo "成功添加白名单RETURN规则。" | tee -a "$log_file"
        else
            echo "警告：无法添加白名单跳过规则。" | tee -a "$log_file"
        fi
    else
        echo "flytrap_whitelist白名单规则已存在。" | tee -a "$log_file"
    fi

    # 添加黑名单规则
    if ! $IPTABLES_PATH -C INPUT -m set --match-set flytrap_blacklist src -j DROP >/dev/null 2>&1; then
        echo "添加flytrap_blacklist规则..." | tee -a "$log_file"
        
        # 添加日志规则
        if $IPTABLES_PATH -I INPUT -m set --match-set flytrap_blacklist src -j LOG --log-prefix "IP Blocked: " --log-level 4 2>&1 | tee -a "$log_file"; then
            echo "成功添加日志规则。" | tee -a "$log_file"
        else
            echo "警告：无法添加日志规则。" | tee -a "$log_file"
        fi
        
        # 添加DROP规则
        if $IPTABLES_PATH -I INPUT -m set --match-set flytrap_blacklist src -j DROP 2>&1 | tee -a "$log_file"; then
            echo "成功添加INPUT DROP规则。" | tee -a "$log_file"
            rule_added=1
        else
            echo "错误：无法添加DROP规则。" | tee -a "$log_file"
            return 1
        fi
        
        if $IPTABLES_PATH -I FORWARD -m set --match-set flytrap_blacklist src -j DROP 2>&1 | tee -a "$log_file"; then
            echo "成功添加FORWARD DROP规则。" | tee -a "$log_file"
        else
            echo "警告：无法添加FORWARD规则。" | tee -a "$log_file"
        fi
        
        if $IPTABLES_PATH -I OUTPUT -m set --match-set flytrap_blacklist src -j DROP 2>&1 | tee -a "$log_file"; then
            echo "成功添加OUTPUT DROP规则。" | tee -a "$log_file"
        else
            echo "警告：无法添加OUTPUT规则。" | tee -a "$log_file"
        fi
    else
        echo "flytrap_blacklist规则已存在。" | tee -a "$log_file"
    fi

    # 添加蜜罐规则
    if ! $IPTABLES_PATH -C INPUT -i "$wan_name" -p tcp -m multiport --dports "$trap_ports" -m set ! --match-set flytrap_whitelist src -j SET --add-set flytrap_blacklist src >/dev/null 2>&1; then
        echo "添加蜜罐规则..." | tee -a "$log_file"
        if $IPTABLES_PATH -I INPUT -i "$wan_name" -p tcp -m multiport --dports "$trap_ports" -m set ! --match-set flytrap_whitelist src -j SET --add-set flytrap_blacklist src 2>&1 | tee -a "$log_file"; then
            echo "成功添加INPUT蜜罐规则。" | tee -a "$log_file"
            rule_added=1
        else
            echo "错误：无法添加蜜罐规则。" | tee -a "$log_file"
            return 1
        fi
        
        if $IPTABLES_PATH -I FORWARD -i "$wan_name" -p tcp -m multiport --dports "$trap_ports" -m set ! --match-set flytrap_whitelist src -j SET --add-set flytrap_blacklist src 2>&1 | tee -a "$log_file"; then
            echo "成功添加FORWARD蜜罐规则。" | tee -a "$log_file"
        else
            echo "警告：无法添加FORWARD蜜罐规则。" | tee -a "$log_file"
        fi
    else
        echo "蜜罐规则已存在。" | tee -a "$log_file"
    fi

    # IPv6 规则部分
    if [ "$trap6" = "yes" ]; then
        if ! $IP6TABLES_PATH -C INPUT -m set --match-set flytrap6_blacklist src -j DROP >/dev/null 2>&1; then
            echo "添加flytrap6_blacklist规则..." | tee -a "$log_file"
            
            if $IP6TABLES_PATH -I INPUT -m set --match-set flytrap6_blacklist src -j LOG --log-prefix "IP6 Blocked: " --log-level 4 2>&1 | tee -a "$log_file"; then
                echo "成功添加IPv6日志规则。" | tee -a "$log_file"
            else
                echo "警告：无法添加IPv6日志规则。" | tee -a "$log_file"
            fi
            
            if $IP6TABLES_PATH -I INPUT -m set --match-set flytrap6_blacklist src -j DROP 2>&1 | tee -a "$log_file"; then
                echo "成功添加IPv6 INPUT DROP规则。" | tee -a "$log_file"
                rule_added=1
            else
                echo "错误：无法添加IPv6 DROP规则。" | tee -a "$log_file"
            fi
            
            if $IP6TABLES_PATH -I FORWARD -m set --match-set flytrap6_blacklist src -j DROP 2>&1 | tee -a "$log_file"; then
                echo "成功添加IPv6 FORWARD DROP规则。" | tee -a "$log_file"
            else
                echo "警告：无法添加IPv6 FORWARD规则。" | tee -a "$log_file"
            fi
            
            if $IP6TABLES_PATH -I OUTPUT -m set --match-set flytrap6_blacklist src -j DROP 2>&1 | tee -a "$log_file"; then
                echo "成功添加IPv6 OUTPUT DROP规则。" | tee -a "$log_file"
            else
                echo "警告：无法添加IPv6 OUTPUT规则。" | tee -a "$log_file"
            fi
        else
            echo "flytrap6_blacklist规则已存在。" | tee -a "$log_file"
        fi

        if ! $IP6TABLES_PATH -C INPUT -i "$wan_name" -p tcp -m multiport --dports "$trap_ports" -j SET --add-set flytrap6_blacklist src >/dev/null 2>&1; then
            echo "添加IPv6蜜罐规则..." | tee -a "$log_file"
            if $IP6TABLES_PATH -I INPUT -i "$wan_name" -p tcp -m multiport --dports "$trap_ports" -j SET --add-set flytrap6_blacklist src 2>&1 | tee -a "$log_file"; then
                echo "成功添加IPv6 INPUT蜜罐规则。" | tee -a "$log_file"
                rule_added=1
            else
                echo "错误：无法添加IPv6蜜罐规则。" | tee -a "$log_file"
            fi
            
            if $IP6TABLES_PATH -I FORWARD -i "$wan_name" -p tcp -m multiport --dports "$trap_ports" -j SET --add-set flytrap6_blacklist src 2>&1 | tee -a "$log_file"; then
                echo "成功添加IPv6 FORWARD蜜罐规则。" | tee -a "$log_file"
            else
                echo "警告：无法添加IPv6 FORWARD蜜罐规则。" | tee -a "$log_file"
            fi
        else
            echo "IPv6蜜罐规则已存在。" | tee -a "$log_file"
        fi
    fi
    
    return 0
}

# 添加IP到白名单
add_whitelist() {
    local ip=$1
    if [ -z "$ip" ]; then
        echo "错误：未提供IP地址。" | tee -a "$log_file"
        return 1
    fi
    
    # 先检查IP是否已在白名单中
    if $IPSET_PATH test flytrap_whitelist "$ip" 2>/dev/null; then
        echo "IP $ip 已经在白名单中。" | tee -a "$log_file"
        return 0
    fi
    
    # 添加IP到白名单
    if $IPSET_PATH add flytrap_whitelist "$ip" 2>&1 | tee -a "$log_file"; then
        echo "成功添加IP $ip 到白名单。" | tee -a "$log_file"
        return 0
    else
        echo "错误：添加IP $ip 到白名单失败。" | tee -a "$log_file"
        return 1
    fi
}

# 从白名单中删除IP
del_whitelist() {
    local ip=$1
    if [ -z "$ip" ]; then
        echo "错误：未提供IP地址。" | tee -a "$log_file"
        return 1
    fi
    
    # 先检查IP是否在白名单中
    if ! $IPSET_PATH test flytrap_whitelist "$ip" 2>/dev/null; then
        echo "错误：IP $ip 不在白名单中。" | tee -a "$log_file"
        return 1
    fi
    
    # 从白名单中删除IP
    if $IPSET_PATH del flytrap_whitelist "$ip" 2>&1 | tee -a "$log_file"; then
        echo "成功从白名单中删除IP $ip。" | tee -a "$log_file"
        return 0
    else
        echo "错误：从白名单中删除IP $ip 失败。" | tee -a "$log_file"
        return 1
    fi
}

# 日志记录脚本 - 最终修复版本
log_blocked_ips() {
    manage_log  # 检查日志文件大小

    # 检查所有必要的规则是否存在
    local rules_missing=0
    
    # 检查 ipset 规则集
    local ipset_names=$($IPSET_PATH list -n 2>/dev/null)
    if ! echo "$ipset_names" | $GREP -q "flytrap_blacklist" || \
       ! echo "$ipset_names" | $GREP -q "flytrap_whitelist"; then
        rules_missing=1
    fi

    # 使用 iptables -C 直接检查规则是否存在
    # 检查 IPv4 规则
    $IPTABLES_PATH -C INPUT -m set --match-set flytrap_blacklist src -j DROP >/dev/null 2>&1 || rules_missing=1
    $IPTABLES_PATH -C FORWARD -m set --match-set flytrap_blacklist src -j DROP >/dev/null 2>&1 || rules_missing=1
    $IPTABLES_PATH -C OUTPUT -m set --match-set flytrap_blacklist src -j DROP >/dev/null 2>&1 || rules_missing=1
    $IPTABLES_PATH -C INPUT -m set --match-set flytrap_whitelist src -j ACCEPT >/dev/null 2>&1 || rules_missing=1
    $IPTABLES_PATH -C INPUT -i "$wan_name" -p tcp -m multiport --dports "$trap_ports" -m set ! --match-set flytrap_whitelist src -j SET --add-set flytrap_blacklist src >/dev/null 2>&1 || rules_missing=1

    # 检查防护规则（参数需与setup_firewall_rules中的一致）
    $IPTABLES_PATH -C INPUT -p tcp --syn -m connlimit --connlimit-above 50 --connlimit-mask 32 -j DROP >/dev/null 2>&1 || rules_missing=1
    $IPTABLES_PATH -C INPUT -p tcp ! --syn -m state --state NEW -j DROP >/dev/null 2>&1 || rules_missing=1
    $IPTABLES_PATH -C INPUT -m state --state INVALID -j DROP >/dev/null 2>&1 || rules_missing=1

    # 如果启用了 IPv6，检查 IPv6 规则
    if [ "$trap6" = "yes" ]; then
        if ! echo "$ipset_names" | $GREP -q "flytrap6_blacklist"; then
            rules_missing=1
        else
            $IP6TABLES_PATH -C INPUT -m set --match-set flytrap6_blacklist src -j DROP >/dev/null 2>&1 || rules_missing=1
            $IP6TABLES_PATH -C FORWARD -m set --match-set flytrap6_blacklist src -j DROP >/dev/null 2>&1 || rules_missing=1
            $IP6TABLES_PATH -C OUTPUT -m set --match-set flytrap6_blacklist src -j DROP >/dev/null 2>&1 || rules_missing=1
            $IP6TABLES_PATH -C INPUT -i "$wan_name" -p tcp -m multiport --dports "$trap_ports" -j SET --add-set flytrap6_blacklist src >/dev/null 2>&1 || rules_missing=1
        fi
    fi

    # 如果发现规则缺失，重新运行完整脚本
    if [ $rules_missing -eq 1 ]; then
        echo "检测到防火墙规则不完整，重新运行脚本添加防火墙规则..." | tee -a "$log_file"
        $sh_file/flytrap.sh &
    else
        # 记录当前黑名单
        current_time=$($DATE '+%Y-%m-%d %H:%M:%S')
        echo "$current_time IPv4 黑名单：" >> "$log_file"
        $IPSET_PATH list flytrap_blacklist | $AWK '/^[0-9]/ {print $1}' >> "$log_file"

        if [ "$trap6" = "yes" ]; then
            echo "$current_time IPv6 黑名单：" >> "$log_file"
            $IPSET_PATH list flytrap6_blacklist | $AWK '/^[0-9]/ {print $1}' >> "$log_file"
        fi

        echo "***************************************" >> "$log_file"
    fi
}

# 将白名单组中的IP添加到flytrap_whitelist
add_ips_to_whitelist() {
    oldIFS="$IFS"
    IFS=','
    local added_count=0
    local skipped_count=0
    local failed_count=0
    
    for ip in $whitelist_ips; do
        if [ -n "$ip" ]; then
            # 检查IP是否已在白名单中
            if ! $IPSET_PATH test flytrap_whitelist "$ip" 2>/dev/null; then
                if $IPSET_PATH add flytrap_whitelist "$ip" 2>/dev/null; then
                    echo "添加 $ip 到白名单成功" | tee -a "$log_file"
                    added_count=$((added_count + 1))
                else
                    echo "添加 $ip 到白名单失败" | tee -a "$log_file"
                    failed_count=$((failed_count + 1))
                fi
            else
                echo "IP $ip 已经在白名单中，跳过添加" | tee -a "$log_file"
                skipped_count=$((skipped_count + 1))
            fi
        fi
    done
    IFS="$oldIFS"
    
    echo "白名单添加完成：成功 $added_count，跳过 $skipped_count，失败 $failed_count" | tee -a "$log_file"
}

# 列出IP集合中的IP地址
list_ips() {
    list_type=$1
    # 性能优化：一次性获取ipset列表
    local ipset_names=$($IPSET_PATH list -n 2>/dev/null)
    
    if [ "$list_type" = "4" ]; then
        if echo "$ipset_names" | $GREP -q flytrap_blacklist; then
            echo "IPv4 黑名单中的IP:"
            $IPSET_PATH list flytrap_blacklist || echo "错误：无法列出IPv4黑名单"
        else
            echo "没有找到IPv4黑名单flytrap_blacklist。"
        fi
    elif [ "$list_type" = "6" ]; then
        if echo "$ipset_names" | $GREP -q flytrap6_blacklist; then
            echo "IPv6 黑名单中的IP:"
            $IPSET_PATH list flytrap6_blacklist || echo "错误：无法列出IPv6黑名单"
        else
            echo "没有找到IPv6黑名单flytrap6_blacklist。"
        fi
    else
        echo "未知的IP类型：$list_type"
    fi
    echo "..........................."
    if echo "$ipset_names" | $GREP -q flytrap_whitelist; then
        echo "白名单中的IP:"
        $IPSET_PATH list flytrap_whitelist || echo "错误：无法列出白名单"
    else
        echo "没有找到白名单flytrap_whitelist。"
    fi
}

# 配置防火墙的防护规则
setup_firewall_rules() {
    echo "设置防火墙规则..." | tee -a "$log_file"
    local rules_added=0
    local rules_failed=0

    # 防止重复创建链
    if ! $IPTABLES_PATH -L syn-flood >/dev/null 2>&1; then
        if $IPTABLES_PATH -N syn-flood 2>&1 | tee -a "$log_file"; then
            $IPTABLES_PATH -A INPUT -p tcp --syn -m limit --limit 10/s --limit-burst 20 -j RETURN
            $IPTABLES_PATH -A INPUT -p tcp --syn -j DROP
            echo "成功创建Syn-Flood防护规则。" | tee -a "$log_file"
            rules_added=$((rules_added + 1))
        else
            echo "错误：创建Syn-Flood规则失败。" | tee -a "$log_file"
            rules_failed=$((rules_failed + 1))
        fi
    else
        echo "Syn-Flood规则已存在。" | tee -a "$log_file"
    fi

    # 防止碎片攻击
    if ! $IPTABLES_PATH -C INPUT -f -m limit --limit 500/s --limit-burst 500 -j ACCEPT >/dev/null 2>&1; then
        if $IPTABLES_PATH -A INPUT -f -m limit --limit 500/s --limit-burst 500 -j ACCEPT 2>&1 && \
           $IPTABLES_PATH -A INPUT -f -j DROP 2>&1; then
            echo "成功添加碎片攻击防护规则。" | tee -a "$log_file"
            rules_added=$((rules_added + 1))
        else
            echo "错误：添加碎片攻击规则失败。" | tee -a "$log_file"
            rules_failed=$((rules_failed + 1))
        fi
    else
        echo "碎片攻击规则已存在。" | tee -a "$log_file"
    fi

    # 防止ICMP（Ping）攻击
    if ! $IPTABLES_PATH -C INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 10 -j ACCEPT >/dev/null 2>&1; then
        if $IPTABLES_PATH -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 10 -j ACCEPT 2>&1 && \
           $IPTABLES_PATH -A INPUT -p icmp --icmp-type echo-request -j DROP 2>&1; then
            echo "成功添加ICMP攻击防护规则。" | tee -a "$log_file"
            rules_added=$((rules_added + 1))
        else
            echo "错误：添加ICMP攻击规则失败。" | tee -a "$log_file"
            rules_failed=$((rules_failed + 1))
        fi
    else
        echo "ICMP攻击规则已存在。" | tee -a "$log_file"
    fi
    
    # 防止DOS攻击
    if ! $IPTABLES_PATH -C INPUT -p tcp ! --syn -m state --state NEW -j DROP >/dev/null 2>&1; then
        local dos_rules_ok=1
        $IPTABLES_PATH -A INPUT -p tcp ! --syn -m state --state NEW -j DROP 2>&1 || dos_rules_ok=0
        $IPTABLES_PATH -A INPUT -p tcp --tcp-flags ALL NONE -j DROP 2>&1 || dos_rules_ok=0
        $IPTABLES_PATH -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP 2>&1 || dos_rules_ok=0
        $IPTABLES_PATH -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP 2>&1 || dos_rules_ok=0
        $IPTABLES_PATH -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -j DROP 2>&1 || dos_rules_ok=0
        $IPTABLES_PATH -A INPUT -p tcp --tcp-flags ACK,FIN FIN -j DROP 2>&1 || dos_rules_ok=0
        $IPTABLES_PATH -A INPUT -p tcp --tcp-flags ACK,PSH PSH -j DROP 2>&1 || dos_rules_ok=0
        $IPTABLES_PATH -A INPUT -p tcp --tcp-flags ACK,URG URG -j DROP 2>&1 || dos_rules_ok=0
        $IPTABLES_PATH -A INPUT -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP 2>&1 || dos_rules_ok=0
        
        if [ $dos_rules_ok -eq 1 ]; then
            echo "成功添加DOS攻击防护规则。" | tee -a "$log_file"
            rules_added=$((rules_added + 1))
        else
            echo "警告：部分DOS攻击规则添加失败。" | tee -a "$log_file"
            rules_failed=$((rules_failed + 1))
        fi
    else
        echo "DOS攻击规则已存在。" | tee -a "$log_file"
    fi

    # 防止SYN-Flood攻击的规则（调整连接限制从20改为50）
    if ! $IPTABLES_PATH -C INPUT -p tcp --syn -m connlimit --connlimit-above 50 --connlimit-mask 32 -j DROP >/dev/null 2>&1; then
        if $IPTABLES_PATH -A INPUT -p tcp --syn -m connlimit --connlimit-above 50 --connlimit-mask 32 -j DROP 2>&1; then
            echo "成功添加SYN-Flood攻击防护规则。" | tee -a "$log_file"
            rules_added=$((rules_added + 1))
        else
            echo "错误：添加SYN-Flood攻击规则失败。" | tee -a "$log_file"
            rules_failed=$((rules_failed + 1))
        fi
    else
        echo "SYN-Flood攻击的规则已存在。" | tee -a "$log_file"
    fi

    # 防止伪装攻击（关键修改：移除内网段阻止，只阻止真正的恶意IP段）
    if ! $IPTABLES_PATH -C INPUT -s 224.0.0.0/3 -j DROP >/dev/null 2>&1; then
        local spoof_rules_ok=1
        # 只阻止明显的恶意IP段，不阻止内网段
        $IPTABLES_PATH -A INPUT -s 224.0.0.0/3 -j DROP 2>&1 || spoof_rules_ok=0
        $IPTABLES_PATH -A INPUT -s 169.254.0.0/16 -j DROP 2>&1 || spoof_rules_ok=0
        $IPTABLES_PATH -A INPUT -s 192.0.2.0/24 -j DROP 2>&1 || spoof_rules_ok=0
        $IPTABLES_PATH -A INPUT -s 0.0.0.0/8 -j DROP 2>&1 || spoof_rules_ok=0
        $IPTABLES_PATH -A INPUT -s 240.0.0.0/5 -j DROP 2>&1 || spoof_rules_ok=0
        $IPTABLES_PATH -A INPUT -s 127.0.0.0/8 ! -i lo -j DROP 2>&1 || spoof_rules_ok=0
        # 已移除对内网段的阻止：10.0.0.0/8, 172.16.0.0/12
        # 注意：192.168.0.0/16 在原脚本中本来就没有被阻止
        
        if [ $spoof_rules_ok -eq 1 ]; then
            echo "成功添加伪装攻击防护规则（已排除内网段）。" | tee -a "$log_file"
            rules_added=$((rules_added + 1))
        else
            echo "警告：部分伪装攻击规则添加失败。" | tee -a "$log_file"
            rules_failed=$((rules_failed + 1))
        fi
    else
        echo "伪装攻击规则已存在。" | tee -a "$log_file"
    fi

    # 日志记录和丢弃非法数据包
    if ! $IPTABLES_PATH -C INPUT -m state --state INVALID -j LOG --log-prefix "INVALID DROP: " >/dev/null 2>&1; then
        if $IPTABLES_PATH -A INPUT -m state --state INVALID -j LOG --log-prefix "INVALID DROP: " 2>&1 && \
           $IPTABLES_PATH -A INPUT -m state --state INVALID -j DROP 2>&1; then
            echo "成功添加非法数据包处理规则。" | tee -a "$log_file"
            rules_added=$((rules_added + 1))
        else
            echo "错误：添加非法数据包处理规则失败。" | tee -a "$log_file"
            rules_failed=$((rules_failed + 1))
        fi
    else
        echo "非法数据包处理规则已存在。" | tee -a "$log_file"
    fi

    echo "防火墙规则设置完成！新增规则：$rules_added，失败：$rules_failed" | tee -a "$log_file"
}

# 根据传入的参数执行相应的操作
case "$1" in
    clean)
        clean_trap
        echo "清空所有规则和IP集合完成。" | tee -a "$log_file"
        exit 0
        ;;
    list)
        list_type=$2
        [ -z "$list_type" ] && list_type="4"
        list_ips "$list_type"
        exit 0
        ;;
    add)
        if [ -z "$2" ]; then
            echo "错误：未提供IP地址。用法：$0 add <IP地址>" | tee -a "$log_file"
            exit 1
        fi
        
        # 验证IP格式
        if ! echo "$2" | $GREP -qE "^${IPREX4}$" && ! echo "$2" | $GREP -qE "^${IPREX6}$"; then
            echo "错误：无效的IP地址格式：$2" | tee -a "$log_file"
            exit 1
        fi
        
        # 检查IP是否已在黑名单中
        if $IPSET_PATH test flytrap_blacklist "$2" 2>/dev/null; then
            echo "IP $2 已经在黑名单中。" | tee -a "$log_file"
            exit 0
        fi
        
        # 添加IP到黑名单
        if $IPSET_PATH add flytrap_blacklist "$2" 2>&1 | tee -a "$log_file"; then
            echo "成功添加IP $2 到黑名单。" | tee -a "$log_file"
            exit 0
        else
            echo "错误：添加IP $2 到黑名单失败。" | tee -a "$log_file"
            exit 1
        fi
        ;;
    del)
        if [ -z "$2" ]; then
            echo "错误：未提供IP地址。用法：$0 del <IP地址>" | tee -a "$log_file"
            exit 1
        fi
        
        # 先检查IP是否在黑名单中
        if ! $IPSET_PATH test flytrap_blacklist "$2" 2>/dev/null; then
            echo "错误：IP $2 不在黑名单中，无需删除。" | tee -a "$log_file"
            exit 1
        fi
        
        # 从黑名单中删除IP
        if $IPSET_PATH del flytrap_blacklist "$2" 2>&1 | tee -a "$log_file"; then
            echo "成功从黑名单中删除IP $2。" | tee -a "$log_file"
            exit 0
        else
            echo "错误：从黑名单中删除IP $2 失败。" | tee -a "$log_file"
            exit 1
        fi
        ;;
    add_whitelist)
        if [ -z "$2" ]; then
            echo "错误：未提供IP地址。用法：$0 add_whitelist <IP地址>" | tee -a "$log_file"
            exit 1
        fi
        
        # 验证IP格式
        if ! echo "$2" | $GREP -qE "^${IPREX4}$" && ! echo "$2" | $GREP -qE "^${IPREX6}$"; then
            echo "错误：无效的IP地址格式：$2" | tee -a "$log_file"
            exit 1
        fi
        
        add_whitelist "$2"
        exit $?
        ;;
    del_whitelist)
        if [ -z "$2" ]; then
            echo "错误：未提供IP地址。用法：$0 del_whitelist <IP地址>" | tee -a "$log_file"
            exit 1
        fi
        
        del_whitelist "$2"
        exit $?
        ;;
    log_blocked_ips)
        log_blocked_ips
        echo "检查黑名单日志完成。" | tee -a "$log_file"
        exit 0
        ;;
    *)
        # 显示用法提示
        if [ -n "$1" ]; then
            echo "错误：未知命令：$1" | tee -a "$log_file"
            echo ""
        fi
        echo "用法：$0 [命令] [参数]" | tee -a "$log_file"
        echo "命令：" | tee -a "$log_file"
        echo "  clean            - 清理所有规则和IP集合" | tee -a "$log_file"
        echo "  list [4|6]       - 列出黑名单和白名单中的IP（默认IPv4）" | tee -a "$log_file"
        echo "  add <IP>         - 将IP添加到黑名单" | tee -a "$log_file"
        echo "  del <IP>         - 从黑名单中删除IP" | tee -a "$log_file"
        echo "  add_whitelist <IP> - 将IP添加到白名单" | tee -a "$log_file"
        echo "  del_whitelist <IP> - 从白名单中删除IP" | tee -a "$log_file"
        echo "  log_blocked_ips  - 记录屏蔽的IP到日志" | tee -a "$log_file"
        echo "  无参数           - 初始化并设置防火墙规则" | tee -a "$log_file"
        
        if [ -n "$1" ]; then
            exit 1
        fi
        ;;
esac

# 默认执行清理旧规则、创建新规则并部署防火墙策略
echo "========================================" | tee -a "$log_file"
$DATE +"%Y-%m-%d %H:%M:%S %Z" | tee -a "$log_file"
echo "开始执行防火墙规则部署..." | tee -a "$log_file"
echo "网络接口名称：$wan_name" | tee -a "$log_file"
echo "监控端口：$trap_ports" | tee -a "$log_file"
echo "IPv6支持：$trap6" | tee -a "$log_file"
echo "IP超时设置：$unlock 秒" | tee -a "$log_file"
echo "========================================" | tee -a "$log_file"

# 检查必需命令
check_required_commands
check_and_clean_process
check_environment
check_ipset

# 创建IP集合
if ! create_ipset; then
    echo "错误：创建IP集合失败，脚本终止。" | tee -a "$log_file"
    exit 1
fi

# 添加常见内网段到白名单（使用预设值，保证兼容性）
add_common_internal_networks

# 添加防火墙规则
if ! add_trap; then
    echo "错误：添加防火墙规则失败，脚本终止。" | tee -a "$log_file"
    exit 1
fi

# 添加白名单IP
add_ips_to_whitelist

# 设置额外的防护规则
setup_firewall_rules

echo "========================================" | tee -a "$log_file"
echo "脚本执行完成。" | tee -a "$log_file"
echo "========================================" | tee -a "$log_file"

exit 0
