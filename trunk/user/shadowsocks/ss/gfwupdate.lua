------------------------------------------------
-- This file is part of the luci-app-ssr-plus update.lua
-- By Mattraks - Modified for large file support
------------------------------------------------

require 'nixio'
local b64decode = nixio.bin.b64decode

-- 配置参数
local CHUNK_SIZE = 1024 * 32  -- 32KB chunks，更保守的大小
local MAX_MEMORY_READ = 1024 * 10  -- 只读取前10KB用于格式检测

-- 安全的文件读取函数（限制读取大小）
local function safeReadFile(filename, maxsize)
	local f = io.open(filename, "r")
	if not f then return nil end
	
	local content = f:read(maxsize or MAX_MEMORY_READ)
	f:close()
	return content
end

-- 检测是否需要base64解码
local function needsDecode(content)
	if not content or #content < 10 then
		return false
	end
	
	-- 只检查前2000个字符
	local sample = content:sub(1, math.min(2000, #content))
	
	-- 检查GFWList纯文本格式的特征
	if sample:find("^!") or sample:find("\n!") or           -- 注释行
	   sample:find("^||") or sample:find("\n||") or         -- 域名规则
	   sample:find("^@@") or sample:find("\n@@") or         -- 白名单规则
	   sample:find("^/") and sample:find("/$") then         -- 正则规则
		return false
	end
	
	-- 检查是否为纯域名列表格式
	local line_count = 0
	local domain_count = 0
	for line in sample:gmatch("[^\r\n]+") do
		line_count = line_count + 1
		line = line:match("^%s*(.-)%s*$")
		if line and line ~= "" then
			if line:match("^[%w%-%_]+%.[%w%.%-%_]+$") then
				domain_count = domain_count + 1
			end
		end
		if line_count >= 20 then break end
	end
	
	if line_count > 5 and domain_count / line_count > 0.7 then
		return false
	end
	
	return true
end

-- 原始的简单解码函数（用于小文件）
local function simpleBase64Decode(text)
	if not text then return '' end
	text = text:gsub("%z", "")
	text = text:gsub("_", "/")
	text = text:gsub("-", "+")
	local mod4 = #text % 4
	text = text .. string.sub('====', mod4 + 1)
	
	local success, result = pcall(b64decode, text)
	if success and result then
		return result:gsub("%z", "")
	else
		return text  -- 返回原文
	end
end

-- 使用系统命令进行base64解码（最可靠的方法）
local function systemBase64Decode(input_file, output_file)
	-- 先检查是否需要解码
	local sample = safeReadFile(input_file, MAX_MEMORY_READ)
	if not sample then
		return false, "无法读取输入文件"
	end
	
	if not needsDecode(sample) then
		-- 直接复制文件
		local cmd = string.format("cp '%s' '%s'", input_file, output_file)
		local ret = os.execute(cmd)
		return ret == 0, "复制文件" .. (ret == 0 and "成功" or "失败")
	end
	
	-- 使用base64命令解码
	local cmd = string.format("base64 -d '%s' > '%s' 2>/dev/null", input_file, output_file)
	local ret = os.execute(cmd)
	
	if ret ~= 0 then
		-- base64解码失败，可能不是有效的base64，直接复制
		cmd = string.format("cp '%s' '%s'", input_file, output_file)
		ret = os.execute(cmd)
		return ret == 0, "base64解码失败，复制原文件"
	end
	
	return true, "base64解码成功"
end

-- 分块处理大文件（备用方案）
local function chunkedProcess(input_file, output_file)
	local inf = io.open(input_file, "r")
	local outf = io.open(output_file, "w")
	
	if not inf or not outf then
		if inf then inf:close() end
		if outf then outf:close() end
		return false, "无法打开文件"
	end
	
	-- 先检查文件大小
	inf:seek("end")
	local file_size = inf:tell()
	inf:seek("set", 0)
	
	-- 如果文件较小（<100KB），使用简单方法
	if file_size < 1024 * 100 then
		local content = inf:read("*a")
		inf:close()
		
		if needsDecode(content) then
			content = simpleBase64Decode(content)
		end
		
		outf:write(content)
		outf:close()
		return true, "小文件处理成功"
	end
	
	-- 大文件：先读取样本判断格式
	local sample = inf:read(MAX_MEMORY_READ)
	inf:seek("set", 0)
	
	if not needsDecode(sample) then
		-- 纯文本，直接复制
		local chunk
		repeat
			chunk = inf:read(CHUNK_SIZE)
			if chunk then
				outf:write(chunk)
			end
		until not chunk
		
		inf:close()
		outf:close()
		return true, "纯文本复制成功"
	else
		-- 需要base64解码，关闭文件，使用系统命令
		inf:close()
		outf:close()
		os.remove(output_file)  -- 删除空文件
		return systemBase64Decode(input_file, output_file)
	end
end

-- 主更新函数
local function update()
	local input_file = "/tmp/gfwlist_list_origin.conf"
	local output_file = "/tmp/gfwlist_list.conf"
	
	-- 检查输入文件是否存在
	local f = io.open(input_file, "r")
	if not f then
		print("错误：输入文件不存在")
		return false
	end
	f:close()
	
	-- 优先使用系统命令（最可靠）
	local success, msg = systemBase64Decode(input_file, output_file)
	print("系统命令处理：" .. msg)
	
	if not success then
		-- 备用方案：分块处理
		print("尝试备用方案...")
		success, msg = chunkedProcess(input_file, output_file)
		print("分块处理：" .. msg)
	end
	
	-- 验证输出文件
	if success then
		local outf = io.open(output_file, "r")
		if outf then
			outf:seek("end")
			local size = outf:tell()
			outf:close()
			print(string.format("输出文件大小：%d 字节", size))
			
			-- 统计行数
			local line_count = 0
			for line in io.lines(output_file) do
				line_count = line_count + 1
				-- 避免计数过多导致性能问题
				if line_count > 100000 then
					print("行数超过100000")
					break
				end
			end
			if line_count <= 100000 then
				print(string.format("输出文件行数：%d", line_count))
			end
		else
			print("警告：无法验证输出文件")
		end
	end
	
	return success
end

-- 错误处理包装
local function safeUpdate()
	-- 设置安全的执行环境
	local ok, result = pcall(update)
	
	if not ok then
		print("错误：" .. tostring(result))
		-- 确保有输出文件（即使是空的）
		local f = io.open("/tmp/gfwlist_list.conf", "w")
		if f then
			f:close()
		end
		return false
	end
	
	return result
end

-- 执行更新
safeUpdate()
