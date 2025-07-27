#!/bin/sh
set -e -o pipefail

# 添加调试开关
DEBUG=0  # 设置为1启用调试输出,0则禁用

debug() {
    if [ $DEBUG -eq 1 ]; then
        echo "[DEBUG] $(date "+%Y-%m-%d %H:%M:%S") $@"
    fi
}

# 定义备选URL列表
BACKUP_URLS="https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/gfw.txt
https://github.moeyy.xyz/https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt
https://gh-proxy.com/https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt
https://ghproxy.net/https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt
https://ghproxy.cc/https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt
https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt
https://gitlab.com/gfwlist/gfwlist/raw/master/gfwlist.txt"

# 测试URL可访问性并下载文件的函数
try_download_url() {
    local url="$1"
    local processed_url="$url"
    
    # 智能处理不同的代理服务
    if echo "$url" | grep -q "ghproxy.net"; then
        # ghproxy.net 支持 http，只替换协议部分
        processed_url=$(echo $url | sed 's|^https://|http://|')
    elif echo "$url" | grep -q "gh-proxy.com"; then
        # gh-proxy.com 某些版本可能需要特殊处理
        processed_url=$(echo $url | sed 's|^https://|http://|')
    elif echo "$url" | grep -q "github.moeyy.xyz"; then
        # github.moeyy.xyz 保持原样或使用http
        processed_url=$(echo $url | sed 's|^https://|http://|')
    elif echo "$url" | grep -q "ghproxy.cc"; then
        # ghproxy.cc 保持原样或使用http
        processed_url=$(echo $url | sed 's|^https://|http://|')
    elif echo "$url" | grep -q "raw.githubusercontent.com"; then
        # 直接访问GitHub，不使用代理，尝试使用http
        processed_url=$(echo $url | sed 's|^https://|http://|')
    fi
    
    debug "原始URL: $url"
    debug "处理后URL: $processed_url"
    
    # 尝试下载，增加超时时间和重试次数
    if ! curl -4 -s -L -o /tmp/gfwlist_list_origin.conf --connect-timeout 15 --retry 3 --retry-delay 2 "$processed_url"; then
        debug "curl 命令执行失败"
        # 使用更详细的curl命令重试一次以获取错误信息
        debug "详细错误信息："
        curl -4 -v -L -o /tmp/gfwlist_list_origin.conf --connect-timeout 5 --max-time 10 "$processed_url" 2>&1 | tail -20 | while read line; do debug "$line"; done
        return 1
    fi
    
    if [ -f /tmp/gfwlist_list_origin.conf ]; then
        local filesize=$(ls -l /tmp/gfwlist_list_origin.conf | awk '{print $5}')
        debug "下载完成，文件大小: $filesize bytes"
        
        # 检查是否是有效的gfwlist文件（通常是base64编码）
        # 检查文件大小和内容
        if [ $filesize -gt 5000 ]; then
            # 检查是否是有效的gfwlist文件（通常是base64编码）
            # 尝试base64解码测试
            if base64 -d /tmp/gfwlist_list_origin.conf >/dev/null 2>&1; then
                debug "文件看起来是有效的base64编码"
                return 0
            elif grep -q "^[a-zA-Z0-9.-]*\.[a-zA-Z]*$" /tmp/gfwlist_list_origin.conf; then
                debug "文件看起来是纯文本域名列表"
                return 0
            else
                debug "文件格式未知，继续尝试处理"
                return 0
            fi
        else
            debug "文件大小不足5KB（当前: ${filesize} bytes），可能不是完整的gfwlist文件"
            # 显示文件内容帮助诊断
            debug "文件内容预览："
            debug "$(cat /tmp/gfwlist_list_origin.conf | head -c 500)"
        fi
    fi
    
    return 1
}

# 新增：完整的下载和验证函数
try_download_and_process() {
    local url="$1"
    
    # 步骤1：尝试下载
    if ! try_download_url "$url"; then
        debug "URL下载失败: $url"
        # 诊断失败原因
        if [ -f /tmp/gfwlist_list_origin.conf ]; then
            debug "文件存在但不符合要求，查看内容："
            debug "$(head -c 200 /tmp/gfwlist_list_origin.conf)"
            rm -f /tmp/gfwlist_list_origin.conf
        fi
        return 1
    fi
    
    # 步骤2：执行lua处理
    debug "执行 lua 脚本处理"
    lua /etc_ro/ss/gfwupdate.lua
    local lua_status=$?
    debug "lua 脚本执行完成,退出状态: $lua_status"
    
    # 步骤3：验证处理结果
    if [ -f /tmp/gfwlist_list.conf ]; then
        local count=`awk '{print NR}' /tmp/gfwlist_list.conf|tail -n1`
        debug "统计的行数: $count"
        if [ $count -gt 1000 ]; then
            return 0  # 完全成功
        else
            debug "处理后行数不足1000: $count"
            debug "查看处理后文件的前10行："
            debug "$(head -n 10 /tmp/gfwlist_list.conf)"
        fi
    else
        debug "lua处理后文件不存在"
    fi
    
    # 清理失败的临时文件
    rm -f /tmp/gfwlist_list.conf
    return 1
}

NAME=shadowsocksr
GFWLIST_URL="$(nvram get ss_gfwlist_url)"
debug "获取到的 GFWLIST_URL: $GFWLIST_URL"

# 标记是否为首次日志写入
LOG_INITIALIZED=0

log() {
    logger -t "$NAME" "$@"
    # 修改：首次写入使用 >，后续使用 >>
    if [ $LOG_INITIALIZED -eq 0 ]; then
        echo "$(date "+%Y-%m-%d %H:%M:%S") $@" > "/tmp/ssrplus.log"
        LOG_INITIALIZED=1
    else
        echo "$(date "+%Y-%m-%d %H:%M:%S") $@" >> "/tmp/ssrplus.log"
    fi
    debug "$@"  # 同时输出到调试
}

# 移除了更新条件检查，现在脚本会直接执行更新
debug "=============== 开始更新流程 ==============="
debug "脚本参数: $@"

log "GFWList 开始更新..."

# 检查并创建目录
debug "=============== 文件系统检查 ==============="
debug "检查目录 /etc/storage/gfwlist/"
debug "目录权限: $(ls -ld /etc/storage/gfwlist/ 2>/dev/null || echo '目录不存在')"
[ ! -d /etc/storage/gfwlist/ ] && {
    debug "创建目录 /etc/storage/gfwlist/"
    mkdir -p /etc/storage/gfwlist/
    debug "创建结果: $?"
}

# 备份旧文件
[ -f /tmp/gfwlist_list_origin.conf ] && {
    debug "备份已存在的文件"
    cp -f /tmp/gfwlist_list_origin.conf /tmp/gfwlist_list_origin.conf.bak
}

# 尝试下载文件
debug "=============== 文件下载和处理 ==============="
download_success=0

# 首先尝试主URL
if [ -n "$GFWLIST_URL" ]; then
    debug "尝试主URL: $GFWLIST_URL"
    debug "DNS 解析测试: $(nslookup $(echo $GFWLIST_URL | awk -F/ '{print $3}') 2>&1)"
    debug "网络连接测试: ping -c 1 $(echo $GFWLIST_URL | awk -F/ '{print $3}') 2>&1"
    
    if try_download_and_process "$GFWLIST_URL"; then
        download_success=1
        log "使用主URL更新成功"
    else
        log "主URL更新失败，尝试备用地址"
    fi
fi

# 如果主URL失败，尝试备用URL
if [ $download_success -eq 0 ]; then
    debug "开始尝试备用URL列表"
    for url in $BACKUP_URLS; do
        if [ -n "$url" ]; then
            if try_download_and_process "$url"; then
                download_success=1
                log "使用备用URL更新成功: $url"
                break
            else
                log "备用URL处理失败，继续尝试下一个: $url"
            fi
        fi
    done
fi

# 如果所有URL都失败，恢复备份
if [ $download_success -eq 0 ]; then
    log "所有URL尝试失败"
    if [ -f /tmp/gfwlist_list_origin.conf.bak ]; then
        debug "恢复备份文件"
        cp -f /tmp/gfwlist_list_origin.conf.bak /tmp/gfwlist_list_origin.conf
    else
        debug "无备份文件可恢复，退出脚本"
        exit 1
    fi
fi

# 成功处理后的文件操作
debug "=============== 文件更新 ==============="
if [ $download_success -eq 1 ] && [ -f /tmp/gfwlist_list.conf ]; then
    debug "开始更新文件"
    rm -f /etc/storage/gfwlist/gfwlist_list.conf
    mv -f /tmp/gfwlist_list.conf /etc/storage/gfwlist/gfwlist_list.conf
    debug "执行存储保存"
    mtd_storage.sh save >/dev/null 2>&1
    debug "存储保存完成"
    log "GFWList 更新完成！"
    echo 3 > /proc/sys/vm/drop_caches
    debug "清理系统缓存完成"
    if [ $(nvram get ss_enable) = 1 ]; then
        debug "=============== 服务重启 ==============="
        lua /etc_ro/ss/gfwcreate.lua
        log "正在重启 ShadowSocksR Plus..."
        /usr/bin/shadowsocks.sh stop
        /usr/bin/shadowsocks.sh start
    else
        debug "SS 未启用,跳过重启"
    fi
else
    log "GFWList 更新失败！"
fi

# 清理临时文件
debug "=============== 清理工作 ==============="
rm -f /tmp/gfwlist_list_origin.conf
rm -f /tmp/gfwlist_list.conf
[ -f /tmp/gfwlist_list_origin.conf.bak ] && rm -f /tmp/gfwlist_list_origin.conf.bak
debug "临时文件清理完成"
debug "脚本执行完成"
