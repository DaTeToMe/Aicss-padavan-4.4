#!/bin/sh

NAME=shadowsocksr

# 优化：批量缓存常用nvram变量，避免重复系统调用
cache_nvram_vars() {
    pppoemwan=$(nvram get pppoemwan_enable)
    http_username=$(nvram get http_username)
    run_mode=$(nvram get ss_run_mode)
    lan_con=$(nvram get lan_con)
    ss_cgroups=$(nvram get ss_cgroups)
    ss_threads=$(nvram get ss_threads)
    tunnel_forward=$(nvram get tunnel_forward)
    s_dports=$(nvram get s_dports)
    socks5_port=$(nvram get socks5_port)
    socks5_enable=$(nvram get socks5_enable)
    ss_watchcat=$(nvram get ss_watchcat)
    ss_update_chnroute=$(nvram get ss_update_chnroute)
    ss_update_gfwlist=$(nvram get ss_update_gfwlist)
    ss_enable=$(nvram get ss_enable)
    ss_adblock=$(nvram get ss_adblock)
    ss_adblock_url=$(nvram get ss_adblock_url)
    udp_relay_server=$(nvram get udp_relay_server)
    backup_server=$(nvram get backup_server)
}

# 实时获取可能变化的关键变量
get_dynamic_vars() {
    GLOBAL_SERVER=$(nvram get global_server)
}

# 初始化缓存变量
cache_nvram_vars
get_dynamic_vars

CONFIG_FILE=/tmp/${NAME}.json
CONFIG_UDP_FILE=/tmp/${NAME}_u.json
CONFIG_SOCK5_FILE=/tmp/${NAME}_s.json
v2_json_file="/tmp/v2-redir.json"
trojan_json_file="/tmp/tj-redir.json"
server_count=0
redir_tcp=0
v2ray_enable=0
redir_udp=0
tunnel_enable=0
local_enable=0
pdnsd_enable_flag=0
wan_bp_ips="/tmp/whiteip.txt"
wan_fw_ips="/tmp/blackip.txt"
lan_fp_ips="/tmp/lan_ip.txt"
lan_gm_ips="/tmp/lan_gmip.txt"
socks=""
args=${args:-""}
SS_RULES=/usr/bin/ss-rules
[ -x /etc/storage/ss-rules ] && SS_RULES=/etc/storage/ss-rules

log() {
	logger -t "$NAME" "$@"
	echo "$(date "+%Y-%m-%d %H:%M:%S") $@" >> "/tmp/ssrplus.log"
}

find_bin() {
	case "$1" in
	ss) ret="/usr/bin/ss-redir" ;;
	ss-local) ret="/usr/bin/ss-local" ;;
	ssr) ret="/usr/bin/ssr-redir" ;;
	ssr-local) ret="/usr/bin/ssr-local" ;;
	ssr-server) ret="/usr/bin/ssr-server" ;;
	v2ray|xray)
		if [ -f "/usr/bin/$1" ]; then
			ret="/usr/bin/$1"
		else
			bin=$(echo -e "v2ray\nxray" | grep -v $1)
			ret="/usr/bin/$bin"
		fi
		;;
	trojan) ret="/usr/bin/trojan" ;;
	socks5) ret="/usr/bin/ipt2socks" ;;
	esac
	echo $ret
}

run_bin() {
	(
		if [ "$ss_cgroups" = "1" ]; then
			echo $$ > /sys/fs/cgroup/cpu/$NAME/tasks
			echo $$ > /sys/fs/cgroup/memory/$NAME/tasks
		fi
		exec "$@" > /dev/null 2>&1
	) &
}

cgroups_init() {
	if [ "$ss_cgroups" = "1" ]; then
		cpu_limit=$(nvram get ss_cgoups_cpu_s)
		mem_limit=$(nvram get ss_cgoups_mem_s)
		log "启用进程资源限制, CPU: $cpu_limit, 内存: $mem_limit"
		mkdir -p /sys/fs/cgroup/cpu/$NAME
		mkdir -p /sys/fs/cgroup/memory/$NAME
		echo $cpu_limit > /sys/fs/cgroup/cpu/$NAME/cpu.shares
		echo $mem_limit > /sys/fs/cgroup/memory/$NAME/memory.limit_in_bytes
		limit_bytes="$(cat /sys/fs/cgroup/memory/$NAME/memory.limit_in_bytes)"
		[ -n "$limit_bytes" ] && export GOMEMLIMIT="$limit_bytes"
	fi
}

cgroups_cleanup() {
	cat /sys/fs/cgroup/cpu/$NAME/tasks > /sys/fs/cgroup/cpu/tasks
	cat /sys/fs/cgroup/memory/$NAME/tasks > /sys/fs/cgroup/memory/tasks
	rmdir /sys/fs/cgroup/cpu/$NAME
	rmdir /sys/fs/cgroup/memory/$NAME
}

gen_config_file() {
	case "$2" in
	0) config_file=$CONFIG_FILE && local stype=$(nvram get d_type) ;;
	1) config_file=$CONFIG_UDP_FILE && local stype=$(nvram get ud_type) ;;
	*) config_file=$CONFIG_SOCK5_FILE && local stype=$(nvram get s5_type) ;;
	esac
	local type=$stype
	case "$type" in
	ss)
		lua /etc_ro/ss/genssconfig.lua $1 $3 >$config_file
		sed -i 's/\\//g' $config_file
		;;
	ssr)
		lua /etc_ro/ss/genssrconfig.lua $1 $3 >$config_file
		sed -i 's/\\//g' $config_file
		;;
	trojan)
		v2ray_enable=1
		if [ "$2" = "0" ]; then
			lua /etc_ro/ss/gentrojanconfig.lua $1 nat 1080 >$trojan_json_file
			sed -i 's/\\//g' $trojan_json_file
		else
			lua /etc_ro/ss/gentrojanconfig.lua $1 client 10801 >/tmp/trojan-ssr-reudp.json
			sed -i 's/\\//g' /tmp/trojan-ssr-reudp.json
		fi
		;;
	v2ray)
		v2ray_enable=1
		if [ "$2" = "1" ]; then
			lua /etc_ro/ss/genv2config.lua $1 udp 1080 >/tmp/v2-ssr-reudp.json
			sed -i 's/\\//g' /tmp/v2-ssr-reudp.json
		else
			lua /etc_ro/ss/genv2config.lua $1 tcp 1080 >$v2_json_file
			sed -i 's/\\//g' $v2_json_file
		fi
		;;
	xray)
		v2ray_enable=1
		if [ "$2" = "1" ]; then
			lua /etc_ro/ss/genxrayconfig.lua $1 udp 1080 >/tmp/v2-ssr-reudp.json
			sed -i 's/\\//g' /tmp/v2-ssr-reudp.json
		else
			lua /etc_ro/ss/genxrayconfig.lua $1 tcp 1080 >$v2_json_file
			sed -i 's/\\//g' $v2_json_file
		fi
		;;	
	esac
}

get_arg_out() {
	router_proxy="1"
	case "$router_proxy" in
	1) echo "-o" ;;
	2) echo "-O" ;;
	esac
}

# 优化：提取服务器地址解析逻辑，减少重复代码
resolve_server_address() {
    local server="$1"
    local temp_file="$2"
    
    if echo "$server" | grep -E "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$" >/dev/null; then
        echo "$server"
    elif echo "$server" | grep -E "^([a-fA-F0-9:]+)$" >/dev/null; then
        echo "$server"  # IPv6 地址
    else
        resolved=$(resolveip -4 -t 3 "$server" | awk 'NR==1{print}')
        if echo "$resolved" | grep -E "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$" >/dev/null; then
            echo "$resolved"
        else
            log "服务器地址解析失败，使用本地缓存或默认地址 8.8.8.8"
            cat /etc/storage/ssr_ip 2>/dev/null || echo "8.8.8.8"
        fi
    fi
}

start_rules() {
    log "正在添加防火墙规则..."

    # 获取全局服务器地址
    lua /etc_ro/ss/getconfig.lua $GLOBAL_SERVER > /tmp/server.txt
    server=$(cat /tmp/server.txt)
    rm -f /tmp/server.txt

    # 优化：合并IP列表文件操作
    {
        cat /etc/storage/ss_ip.sh | grep -v '^!' | grep -v "^$" >$wan_fw_ips
        cat /etc/storage/ss_wan_ip.sh | grep -v '^!' | grep -v "^$" >$wan_bp_ips
    } &

    # 解析服务器地址
    server=$(resolve_server_address "$server")

    # 等待IP列表文件操作完成
    wait

    # 设置默认本地端口
    local_port="1080"
    udp_local_port="1080"
    ac_ips=""
    udp_server=""

    # 判断 UDP 中继服务器是否启用
    if [ "$udp_relay_server" != "nil" ]; then
        ARG_UDP="-U"
        lua /etc_ro/ss/getconfig.lua $udp_relay_server > /tmp/userver.txt
        udp_server=$(cat /tmp/userver.txt)
        rm -f /tmp/userver.txt
    fi

    # 设置内网控制规则
    if [ -n "$lan_ac_ips" ]; then
        case "$lan_ac_mode" in
        w | W | b | B) ac_ips="$lan_ac_mode$lan_ac_ips" ;;
        esac
    fi

    # 设置运行模式
    gfwmode=""
    case "$run_mode" in
    gfw) gfwmode="-g" ;;
    router) gfwmode="-r" ;;
    oversea) gfwmode="-c" ;;
    all) gfwmode="-z" ;;
    esac

    # 设置 LAN IP 策略
    if [ "$lan_con" = "0" ]; then
        rm -f $lan_fp_ips
        lancon="all"
        lancons="全部IP走代理..."
        cat /etc/storage/ss_lan_ip.sh | grep -v '^!' | grep -v "^$" >$lan_fp_ips
    elif [ "$lan_con" = "1" ]; then
        rm -f $lan_fp_ips
        lancon="bip"
        lancons="指定 IP 走代理: 请到规则管理页面添加需要走代理的 IP..."
        cat /etc/storage/ss_lan_bip.sh | grep -v '^!' | grep -v "^$" >$lan_fp_ips
    fi

    # 获取 LAN 游戏模式 IP 列表
    rm -f $lan_gm_ips
    cat /etc/storage/ss_lan_gmip.sh | grep -v '^!' | grep -v "^$" >$lan_gm_ips

    # 设置代理端口
    if [ "$s_dports" = "0" ]; then
        proxyport="--syn"
    else
        proxyport="-m multiport --dports 22,53,587,465,995,993,143,80,443,3389 --syn"
    fi

    # 调用 SS_RULES 添加规则
    $SS_RULES \
        -s "$server" \
        -l "$local_port" \
        -S "$udp_server" \
        -L "$udp_local_port" \
        -a "$ac_ips" \
        -i "" \
        -b "$wan_bp_ips" \
        -w "$wan_fw_ips" \
        -p "$lan_fp_ips" \
        -G "$lan_gm_ips" \
        -D "$proxyport" \
        -k "$lancon" \
        $(get_arg_out) $gfwmode $ARG_UDP

    return $?
}

start_redir_tcp() {
	ARG_OTA=""
	gen_config_file $GLOBAL_SERVER 0 1080
	stype=$(nvram get d_type)
	local bin=$(find_bin $stype)
	[ ! -f "$bin" ] && log "Main node:Can't find $bin program, can't start!" && return 1
	
	# 优化：使用缓存的线程数设置
	if [ "$ss_threads" = "0" ]; then
		threads=$(cat /proc/cpuinfo | grep 'processor' | wc -l)
	else
		threads=$ss_threads
	fi
	
	log "正在启动 $stype 服务器..."
	case "$stype" in
	ss | ssr)
		last_config_file=$CONFIG_FILE
		pid_file="/tmp/ssr-retcp.pid"
		for i in $(seq 1 $threads); do
			run_bin $bin -c $CONFIG_FILE $ARG_OTA -f /tmp/ssr-retcp_$i.pid
			usleep 500000
		done
		redir_tcp=1
		log "Shadowsocks/ShadowsocksR $threads 线程启动成功..."
		;;
	trojan)
		for i in $(seq 1 $threads); do
			run_bin $bin --config $trojan_json_file
			usleep 500000
		done
		log "已运行 $($bin --version 2>&1 | head -1)"
		;;
	v2ray)
		run_bin $bin -config $v2_json_file
		log "已运行 $($bin -version | head -1)"
		;;
	xray)
		run_bin $bin -config $v2_json_file
		log "已运行 $($bin -version | head -1)"
		;;	
	socks5)
		for i in $(seq 1 $threads); do
			run_bin lua /etc_ro/ss/gensocks.lua $GLOBAL_SERVER 1080
			usleep 500000
		done
		;;
	esac
	return 0
}

start_redir_udp() {
	if [ "$udp_relay_server" != "nil" ]; then
		redir_udp=1
		utype=$(nvram get ud_type)
		log "正在启动 $utype 游戏 UDP 中继服务器..."
		local bin=$(find_bin $utype)
		[ ! -f "$bin" ] && log "UDP TPROXY Relay:Can't find $bin program, can't start!" && return 1
		case "$utype" in
		ss | ssr)
			ARG_OTA=""
			gen_config_file $udp_relay_server 1 1080
			last_config_file=$CONFIG_UDP_FILE
			pid_file="/var/run/ssr-reudp.pid"
			run_bin $bin -c $last_config_file $ARG_OTA -U -f /var/run/ssr-reudp.pid
			;;
		v2ray)
			gen_config_file $udp_relay_server 1
			run_bin $bin -config /tmp/v2-ssr-reudp.json
			;;
		xray)
			gen_config_file $udp_relay_server 1
			run_bin $bin -config /tmp/v2-ssr-reudp.json
			;;	
		trojan)
			gen_config_file $udp_relay_server 1
			$bin --config /tmp/trojan-ssr-reudp.json >/dev/null 2>&1 &
			run_bin ipt2socks -U -b 0.0.0.0 -4 -s 127.0.0.1 -p 10801 -l 1080
			;;
		socks5)
			echo "1"
			;;
		esac
	fi
	return 0
}

stop_dns_proxy() {
	pgrep dns2tcp | args kill
	pgrep dnsproxy | args kill	
}

start_dns_proxy() {
	pdnsd_enable=$(nvram get pdnsd_enable)
	pdnsd_enable_flag=$pdnsd_enable
	dnsserver=$(echo "$tunnel_forward" | awk -F '#' '{print $1}')
	if [ $pdnsd_enable = 1 ]; then
	    log "启动 dns2tcp：5353 端口..."
		ipset add gfwlist $dnsserver 2>/dev/null
		dns2tcp -L"127.0.0.1#5353" -R"$dnsserver" >/dev/null 2>&1 &
	elif [ $pdnsd_enable = 0 ]; then
		log "启动 dnsproxy：5353 端口..."
		ipset add gfwlist $dnsserver 2>/dev/null
		dnsproxy -d -p 5353 -R $dnsserver >/dev/null 2>&1 &
	else
		log "DNS解析方式不支持该选项: $pdnsd_enable , 建议选择dnsproxy"
	fi
}

start_dns() {
	echo "create china hash:net family inet hashsize 1024 maxelem 65536" >/tmp/china.ipset
	awk '!/^$/&&!/^#/{printf("add china %s'" "'\n",$0)}' /etc/storage/chinadns/chnroute.txt >>/tmp/china.ipset
	ipset -! flush china
	ipset -! restore </tmp/china.ipset 2>/dev/null
	rm -f /tmp/china.ipset
	
	case "$run_mode" in
	router)
		ipset add gfwlist $dnsserver 2>/dev/null
		stop_dns_proxy
		start_dns_proxy
		killall dnsmasq
		/user/sbin/dnsmasq >/dev/null 2>&1 &
	;;
	gfw)
		dnsserver=$(echo "$tunnel_forward" | awk -F '#' '{print $1}')
		ipset add gfwlist $dnsserver 2>/dev/null
		stop_dns_proxy
		start_dns_proxy
		log "开始处理 GFWList..."
		;;
	oversea)
		ipset add gfwlist $dnsserver 2>/dev/null
		mkdir -p /etc/storage/dnsmasq.oversea
		sed -i '/dnsmasq-ss/d' /etc/storage/dnsmasq/dnsmasq.conf
		sed -i '/dnsmasq.oversea/d' /etc/storage/dnsmasq/dnsmasq.conf
		cat >>/etc/storage/dnsmasq/dnsmasq.conf <<EOF
conf-dir=/etc/storage/dnsmasq.oversea
EOF
    ;;
	*)
		ipset -N ss_spec_wan_ac hash:net 2>/dev/null
		ipset add ss_spec_wan_ac $dnsserver 2>/dev/null
	;;
	esac
	/sbin/restart_dhcpd
}

start_AD() {
	mkdir -p /tmp/dnsmasq.dom
	curl -s -o /tmp/adnew.conf --connect-timeout 10 --retry 3 $ss_adblock_url
	if [ ! -f "/tmp/adnew.conf" ]; then
		log "广告过滤功能未开启或者过滤地址失效，网络异常等 ！！！"
	else
		log "去广告文件下载成功广告过滤功能已启用..."
		if [ -f "/tmp/adnew.conf" ]; then
			check=$(grep -wq "address=" /tmp/adnew.conf)
	  		if [ ! -n "$check" ] ; then
				cp /tmp/adnew.conf /tmp/dnsmasq.dom/anti-ad-for-dnsmasq.conf
	  		else
			    cat /tmp/adnew.conf | grep ^\|\|[^\*]*\^$ | sed -e 's:||:address\=\/:' -e 's:\^:/0\.0\.0\.0:' > /tmp/dnsmasq.dom/anti-ad-for-dnsmasq.conf
			fi
		fi
	fi
	rm -f /tmp/adnew.conf
}

start_local() {
	local local_server="$socks5_enable"
	[ "$local_server" == "nil" ] && return 1
	[ "$local_server" == "same" ] && local_server=$GLOBAL_SERVER
	local type=$(nvram get s5_type)
	local bin=$(find_bin $type)
	[ ! -f "$bin" ] && log "Global_Socks5:Can't find $bin program, can't start!" && return 1
	case "$type" in
	ss | ssr)
		local name="Shadowsocks"
		local bin=$(find_bin ss-local)
		[ ! -f "$bin" ] && log "Global_Socks5:Can't find $bin program, can't start!" && return 1
		[ "$type" == "ssr" ] && name="ShadowsocksR"
		gen_config_file $local_server 3 $socks5_port
		run_bin $bin -c $CONFIG_SOCK5_FILE -u -f /var/run/ssr-local.pid
		log "Global_Socks5:$name Started!"
		;;
	v2ray)
		lua /etc_ro/ss/genv2config.lua $local_server tcp 0 $socks5_port >/tmp/v2-ssr-local.json
		sed -i 's/\\//g' /tmp/v2-ssr-local.json
		run_bin $bin -config /tmp/v2-ssr-local.json
		log "Global_Socks5:$($bin -version | head -1) Started!"
		;;
	xray)
		lua /etc_ro/ss/genxrayconfig.lua $local_server tcp 0 $socks5_port >/tmp/v2-ssr-local.json
		sed -i 's/\\//g' /tmp/v2-ssr-local.json
		run_bin $bin -config /tmp/v2-ssr-local.json
		log "Global_Socks5:$($bin -version | head -1) Started!"
		;;
	trojan)
		lua /etc_ro/ss/gentrojanconfig.lua $local_server client $socks5_port >/tmp/trojan-ssr-local.json
		sed -i 's/\\//g' /tmp/trojan-ssr-local.json
		run_bin $bin --config /tmp/trojan-ssr-local.json
		log "Global_Socks5:$($bin --version 2>&1 | head -1) Started!"
		;;
	*)
		[ -e /proc/sys/net/ipv6 ] && local listenip='-i ::'
		run_bin microsocks $listenip -p $socks5_port ssr-local
		log "Global_Socks5:$type Started!"
		;;
	esac
	local_enable=1
	return 0
}

rules() {
	[ "$GLOBAL_SERVER" = "nil" ] && return 1
	if [ "$udp_relay_server" = "same" ]; then
		udp_relay_server=$GLOBAL_SERVER
	fi
	if start_rules; then
		return 0
	else
		return 1
	fi
}

start_watchcat() {
	if [ "$ss_watchcat" = "1" ]; then
		let total_count=server_count+redir_tcp+redir_udp+tunnel_enable+v2ray_enable+local_enable+pdnsd_enable_flag
		if [ $total_count -gt 0 ]; then
			/usr/bin/ss-monitor $server_count $redir_tcp $redir_udp $tunnel_enable $v2ray_enable $local_enable $pdnsd_enable_flag 0 >/dev/null 2>&1 &
		fi
	fi
}

auto_update() {
	sed -i '/update_chnroute/d' /etc/storage/cron/crontabs/$http_username
	sed -i '/update_gfwlist/d' /etc/storage/cron/crontabs/$http_username
	sed -i '/ss-watchcat/d' /etc/storage/cron/crontabs/$http_username
	if [ "$ss_update_chnroute" = "1" ]; then
		cat >>/etc/storage/cron/crontabs/$http_username <<EOF
0 7 * * * /usr/bin/update_chnroute.sh > /dev/null 2>&1
EOF
	fi
	if [ "$ss_update_gfwlist" = "1" ]; then
		cat >>/etc/storage/cron/crontabs/$http_username <<EOF
0 8 * * * /usr/bin/update_gfwlist.sh > /dev/null 2>&1
EOF
	fi
}

ssp_start() { 
	if rules; then
		cgroups_init
		if start_redir_tcp; then
			start_redir_udp
			start_dns
		fi
	fi
	start_local
	start_watchcat
	auto_update
	ENABLE_SERVER=$(nvram get global_server)
	[ "$ENABLE_SERVER" = "nil" ] && return 1
	log "已启动科学上网..."
	log "内网IP控制为: $lancons"
	nvram set check_mode=0
	if [ "$pppoemwan" = "0" ]; then
		/usr/bin/detect.sh
	fi
}

ssp_close() {
	rm -rf /tmp/cdn
	$SS_RULES -f
	kill -9 $(ps | grep ss-monitor | grep -v grep | awk '{print $1}') >/dev/null 2>&1
	kill_process
	cgroups_cleanup
	sed -i '/no-resolv/d' /etc/storage/dnsmasq/dnsmasq.conf
	sed -i '/server=127.0.0.1/d' /etc/storage/dnsmasq/dnsmasq.conf
	sed -i '/cdn/d' /etc/storage/dnsmasq/dnsmasq.conf
	sed -i '/gfwlist/d' /etc/storage/dnsmasq/dnsmasq.conf
	sed -i '/dnsmasq.oversea/d' /etc/storage/dnsmasq/dnsmasq.conf
	if [ -f "/etc/storage/dnsmasq-ss.d" ]; then
		rm -f /etc/storage/dnsmasq-ss.d
	fi
	clear_iptable
	/sbin/restart_dhcpd
	if [ "$pppoemwan" = "0" ]; then
		/usr/bin/detect.sh
	fi
}

clear_iptable() {
	iptables -t filter -D INPUT -p tcp --dport $socks5_port -j ACCEPT 2>/dev/null
	iptables -t filter -D INPUT -p tcp --dport $socks5_port -j ACCEPT 2>/dev/null
	ip6tables -t filter -D INPUT -p tcp --dport $socks5_port -j ACCEPT 2>/dev/null
	ip6tables -t filter -D INPUT -p tcp --dport $socks5_port -j ACCEPT 2>/dev/null
}

# 优化：统一进程终止函数，消除重复代码
kill_single_process() {
    local process_name="$1"
    local display_name="$2"
    local process_pid
    
    process_pid=$(pidof "$process_name")
    if [ -n "$process_pid" ]; then
        log "关闭 $display_name 进程..."
        killall "$process_name" >/dev/null 2>&1
        kill -9 "$process_pid" >/dev/null 2>&1
    fi
}

kill_process() {
    # 优化：使用统一函数处理所有进程终止逻辑
    kill_single_process "v2ray" "V2Ray"
    kill_single_process "xray" "XRay"
    kill_single_process "ss-redir" "ss-redir"
    kill_single_process "ssr-redir" "ssr-redir"
    kill_single_process "ss-local" "ss-local"
    kill_single_process "trojan" "trojan"
    kill_single_process "ipt2socks" "ipt2socks"
    kill_single_process "srelay" "socks5"
    kill_single_process "ssr-server" "ssr-server"
    kill_single_process "dns2tcp" "dns2tcp"
    kill_single_process "dnsproxy" "dnsproxy"
    kill_single_process "microsocks" "socks5 服务端"
}

ressp() {
	if start_rules $backup_server; then
		start_dns
		start_local
		start_watchcat
		auto_update
		ENABLE_SERVER=$(nvram get global_server)
		log "备用服务器启动成功！"
		log "内网IP控制为: $lancons"
	fi
}

case $1 in
start)
	if [ "$ss_adblock" = "1" ]; then
		start_AD
	fi
	ssp_start
	echo 3 > /proc/sys/vm/drop_caches
	;;
stop)
	ssp_close
	echo 3 > /proc/sys/vm/drop_caches
	;;
restart)
	ssp_close
	ssp_start
	echo 3 > /proc/sys/vm/drop_caches
	;;
reserver)
	ssp_close
	ressp
	echo 3 > /proc/sys/vm/drop_caches
	;;
*)
	echo "check"
	;;
esac
