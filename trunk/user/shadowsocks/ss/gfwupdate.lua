------------------------------------------------
-- This file is part of the luci-app-ssr-plus update.lua
-- By Mattraks
------------------------------------------------
-- base64decoding
require 'nixio'
local b64decode = nixio.bin.b64decode
local function base64Decode(text)
	local raw = text
	if not text then return '' end
	text = text:gsub("%z", "")
	text = text:gsub("_", "/")
	text = text:gsub("-", "+")
	local mod4 = #text % 4
	text = text .. string.sub('====', mod4 + 1)
	local result = b64decode(text)
	
	if result then
		return result:gsub("%z", "")
	else
		return raw
	end
end

-- 新增：改进的格式检测函数
local function needsDecode(content)
	if not content or #content < 10 then
		return false  -- 内容太短，不处理
	end
	
	-- 检查前2000个字符（足够判断格式）
	local sample = content:sub(1, math.min(2000, #content))
	
	-- 检查GFWList纯文本格式的特征
	-- 这些模式在纯文本格式中会直接出现在行首
	if sample:find("^!") or sample:find("\n!") or           -- 注释行
	   sample:find("^||") or sample:find("\n||") or         -- 域名规则
	   sample:find("^@@") or sample:find("\n@@") or         -- 白名单规则
	   sample:find("^/") and sample:find("/$") then         -- 正则规则
		return false  -- 已经是纯文本格式，不需要解码
	end
	
	-- 检查是否为纯域名列表格式（Loyalsoldier的gfw.txt格式）
	local line_count = 0
	local domain_count = 0
	for line in sample:gmatch("[^\r\n]+") do
		line_count = line_count + 1
		-- 移除空白字符后检查
		line = line:match("^%s*(.-)%s*$")
		if line and line ~= "" then
			-- 检查是否符合域名格式
			if line:match("^[%w%-%_]+%.[%w%.%-%_]+$") then
				domain_count = domain_count + 1
			end
		end
		-- 检查前20行足够判断
		if line_count >= 20 then break end
	end
	
	-- 如果超过70%的非空行都是域名格式，则为纯文本域名列表
	if line_count > 5 and domain_count / line_count > 0.7 then
		return false  -- 纯域名列表，不需要解码
	end
	
	-- 默认认为需要解码（可能是base64）
	-- base64Decode函数会安全地处理，失败时返回原文
	return true
end

local function update()
	local gfwlist = io.open("/tmp/gfwlist_list_origin.conf", "r")
	local decode = gfwlist:read("*a")
	-- 修改：使用改进的判断逻辑替代原来的 google 检查
	if needsDecode(decode) then
		decode = base64Decode(decode)
	end
		gfwlist:close()
		gfwlist = io.open("/tmp/gfwlist_list.conf", "w")
		gfwlist:write(decode)
		gfwlist:close()
end
update()
