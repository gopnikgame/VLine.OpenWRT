-- A subscription response is data. Only supported share links can become candidates.
local BODY_LIMIT = 512 * 1024
local URL_LIMIT = 8192
local SERVER_LIMIT = 256
local NAME_LIMIT = 160
local UUID_PATTERN = "^%x%x%x%x%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x$"
local URI_CHARS = "^[A-Za-z0-9%-._~:/?%[%]@!$&'()*+,;=%%]*$"
local function uri_bytes(value)
    return value:match(URI_CHARS) and not value:gsub("%%%x%x", ""):find("%", 1, true)
end

local function percent_decode(value)
    return (value:gsub("%%(%x%x)", function(byte)
        return string.char(tonumber(byte, 16))
    end))
end

local function dns_name(host, core)
    -- A public DNS suffix excludes libcurl's alternative spellings of IPv4 literals.
    return core.valid_domain(host) and host:match("%.[A-Za-z][A-Za-z0-9%-]*$")
end

local function subscription_url(url, core)
    if type(url) ~= "string" or #url > URL_LIMIT or not uri_bytes(url) then return nil end
    local authority, suffix = url:match("^[Hh][Tt][Tt][Pp][Ss]://([^/?]+)(.*)$")
    if not authority then return nil end
    local host, port = authority:match("^([A-Za-z0-9.%-]+):?(%d*)$")
    if not host or not dns_name(host, core) or (port ~= "" and port ~= "443") then return nil end
    host = host:lower()
    if authority:lower() ~= host and authority:lower() ~= host .. ":443" then return nil end
    return host, "https://" .. host .. suffix
end

local function ascii_space(byte)
    return byte == 32 or (byte >= 9 and byte <= 13)
end

local function trim(value)
    local first, last = 1, #value
    while first <= last and ascii_space(value:byte(first)) do first = first + 1 end
    while last >= first and ascii_space(value:byte(last)) do last = last - 1 end
    return value:sub(first, last)
end

local function safe_utf8(value)
    local pos = 1
    while pos <= #value do
        local first = value:byte(pos)
        local width, code, minimum
        if first < 0x80 then
            width, code, minimum = 1, first, 0
        elseif first >= 0xc2 and first <= 0xdf then
            width, code, minimum = 2, first - 0xc0, 0x80
        elseif first >= 0xe0 and first <= 0xef then
            width, code, minimum = 3, first - 0xe0, 0x800
        elseif first >= 0xf0 and first <= 0xf4 then
            width, code, minimum = 4, first - 0xf0, 0x10000
        else
            return false
        end
        for offset = 1, width - 1 do
            local next_byte = value:byte(pos + offset)
            if not next_byte or next_byte < 0x80 or next_byte > 0xbf then return false end
            code = code * 64 + next_byte - 0x80
        end
        if code < minimum or code > 0x10ffff or (code >= 0xd800 and code <= 0xdfff)
            or code < 0x20 or (code >= 0x7f and code <= 0x9f) or code == 0x61c
            or code == 0x200e or code == 0x200f or code == 0x2028 or code == 0x2029
            or (code >= 0x202a and code <= 0x202e) or (code >= 0x2066 and code <= 0x2069) then
            return false
        end
        pos = pos + width
    end
    return true
end

local function display_name(fragment, credential, position, hysteria)
    if #fragment <= NAME_LIMIT * 3 and not fragment:gsub("%%%x%x", ""):find("%", 1, true) then
        local name = trim(percent_decode(fragment))
        local lower = name:lower()
        local password = hysteria and credential:match("^[^:]+:(.+)$")
        if name ~= "" and #name <= NAME_LIMIT and safe_utf8(name)
            and not name:find("://", 1, true) and not name:find("[<>]")
            and not lower:find(credential:lower(), 1, true)
            and (not hysteria or not name:find("%%%x%x"))
            and (not password or not lower:find(password:lower(), 1, true)) then
            return name
        end
    end
    return "Сервер " .. position
end

local function public_node(host, port, core)
    return #port <= 5 and tonumber(port) <= 65535
        and (core.public_ipv4(host) or dns_name(host, core))
end

local function hysteria_auth(link, core)
    if not uri_bytes(link) then return nil end
    local scheme, userinfo, hostport, suffix = link:match("^([a-z0-9]+)://([^@/?]+)@([^/?]+)(.*)$")
    if scheme ~= "hysteria2" and scheme ~= "hy2" then return nil end
    local host, port = hostport:match("^([A-Za-z0-9.%-]+):([1-9]%d*)$")
    if not host then host, port = hostport:match("^([A-Za-z0-9.%-]+)$"), "443" end
    if not host or not public_node(host, port, core) then return nil end
    local query = suffix:match("^/?%?(.*)$")
    if not query and suffix ~= "" and suffix ~= "/" then return nil end
    local params = {}
    if query and query ~= "" then
        for pair in (query .. "&"):gmatch("([^&]*)&") do
            local key, value = pair:match("^([^=]+)=(.*)$")
            if not key then return nil end
            key, value = percent_decode(key), percent_decode(value)
            if params[key] ~= nil or (key ~= "sni" and key ~= "alpn" and key ~= "insecure") then return nil end
            params[key] = value
        end
    end
    if (params.sni and not core.valid_domain(params.sni))
        or (params.alpn and params.alpn ~= "h3")
        or (params.insecure and params.insecure ~= "0" and params.insecure ~= "false") then return nil end
    local auth = percent_decode(userinfo)
    if #auth > 512 or not safe_utf8(auth) then return nil end
    return auth
end

local function parse_link(line, core)
    if #line > URL_LIMIT then return nil end
    local link, fragment = line:match("^([^#]*)#?(.*)$")
    if not link or not uri_bytes(link) then return nil end
    local uuid, host, port, tail = link:match("^vless://([%x%-]+)@([A-Za-z0-9.%-]+):([1-9]%d*)(.*)$")
    if uuid and uuid:match(UUID_PATTERN) and public_node(host, port, core)
        and (tail == "" or tail:sub(1, 1) == "?") then
        return link, fragment, uuid
    end
    local auth = hysteria_auth(link, core)
    if auth then return link, fragment, auth, true end
end

local function parse_reserve(name, line, core)
    if type(line) ~= "string" or #line > URL_LIMIT or line:find("[%c]") then return nil, "invalid_server" end
    local link, fragment, uuid, hysteria = parse_link(trim(line), core)
    if not link or hysteria or fragment:find("://", 1, true) then return nil, "invalid_server" end
    if type(name) ~= "string" or #name > NAME_LIMIT or not safe_utf8(name) then return nil, "invalid_reserve_name" end
    name = trim(name)
    local decoded = percent_decode(name):lower()
    if name == "" or name:find("[<>]") or decoded:find("://", 1, true)
        or decoded:find(uuid:lower(), 1, true) then return nil, "invalid_reserve_name" end
    return { name = name, link = link }
end

local function parse_subscription(body, core)
    body = trim((body:gsub("^\239\187\191", "")))
    if not body:find("://", 1, true) then
        local encoded = body:gsub("[ \t\r\n]", ""):gsub("%-", "+"):gsub("_", "/")
        if not encoded:find("=", 1, true) then
            encoded = encoded .. string.rep("=", (4 - #encoded % 4) % 4)
        end
        local ok, decoded = pcall(core.decode_base64, encoded, BODY_LIMIT)
        if not ok then return nil end
        body = trim((decoded:gsub("^\239\187\191", "")))
    end
    -- JSON and HTML remain unsupported even if their text contains a share URI.
    if body:match("^[<%[{]") then return nil end
    local servers, seen = {}, {}
    for raw_line in body:gmatch("[^\r\n]+") do
        local link, fragment, credential, hysteria = parse_link(trim(raw_line), core)
        if link and not seen[link] then
            seen[link] = true
            servers[#servers + 1] = { name = display_name(fragment, credential, #servers + 1, hysteria), link = link }
            if #servers == SERVER_LIMIT then break end
        end
    end
    if #servers > 0 then return servers end
end

local function pin_addresses(platform, core, host)
    local answers = platform.resolve4(host)
    if type(answers) ~= "table" or #answers == 0 or #answers > 16 then return nil end
    for _, address in ipairs(answers) do
        if type(address) ~= "string" or not core.public_ipv4(address) then return nil end
    end
    return host .. ":443:" .. table.concat(answers, ",")
end

return function(json, platform, core, device)
    local function permitted(url, allowed_hosts, approved_host)
        local host, normalized = subscription_url(url, core)
        if not host then return nil, "invalid_url" end
        if approved_host ~= nil then
            if type(approved_host) ~= "string" or approved_host:lower() ~= host then
                return nil, "source_not_allowed"
            end
        elseif type(allowed_hosts) ~= "table" or rawget(allowed_hosts, host) ~= true then
            return nil, "source_not_allowed"
        end
        return host, normalized
    end

    local function fetch(url, allowed_hosts, approved_host)
        local host, normalized = permitted(url, allowed_hosts, approved_host)
        if not host then return nil, normalized end
        local pins = pin_addresses(platform, core, host)
        if not pins then return nil, "subscription_unavailable" end
        local hwid = device.get()
        if not hwid then return nil, "hwid_unavailable" end

        local servers, outcome = platform.with_workspace(function(dir)
            local config = dir .. "/curl.conf"
            local body_file, status_file = dir .. "/body", dir .. "/status"
            -- URI_CHARS excludes config quote escapes and all line separators.
            local request = 'url = "' .. normalized .. '"\n'
                .. 'header = "x-hwid: ' .. hwid .. '"\nheader = "x-device-os: OpenWrt"\n'
            if not platform.write(config, request) then return nil end
            local argv = {
                "/usr/bin/curl", "-q", "--silent", "--globoff", "--path-as-is", "--ipv4", "--request", "GET",
                "--proto", "=https", "--noproxy", "*", "--proxy", "", "--max-redirs", "0",
                "--resolve", pins, "--connect-timeout", "4", "--max-time", "10",
                "--max-filesize", tostring(BODY_LIMIT), "--header", "Accept: text/plain",
                "--user-agent", "VPN-Routing-OpenWrt/1.0",
                "--output", body_file, "--write-out", "%{http_code}\t%header{x-hwid-max-devices-reached}"
                    .. "\t%header{x-hwid-limit}\t%header{x-hwid-not-supported}", "--config", config,
            }
            local exit_code = platform.run(argv, { timeout = 11, stdout = status_file })
            if exit_code ~= 0 then return nil end
            local response = platform.read(status_file, 256) or ""
            local status, max_devices, limit, rejected = response:match("^(%d%d%d)\t([^\t\r\n]*)\t([^\t\r\n]*)\t([^\t\r\n]*)$")
            if status == "200" or (status and status:sub(1, 1) == "4") then
                if max_devices:lower() == "true" or limit:lower() == "true" then return nil, "hwid_limit_reached" end
                if rejected:lower() == "true" then return nil, "hwid_rejected" end
            end
            if status ~= "200" then return nil end
            local body = platform.read(body_file, BODY_LIMIT)
            if not body then return nil end
            local parsed = parse_subscription(body, core)
            if not parsed then return nil, "unsupported_subscription" end
            return parsed
        end)
        if servers then return servers end
        if outcome == "unsupported_subscription" or outcome == "hwid_limit_reached" or outcome == "hwid_rejected" then
            return nil, outcome
        end
        return nil, "subscription_unavailable"
    end

    return {
        fetch = fetch, permitted = permitted,
        parse_reserve = function(name, line) return parse_reserve(name, line, core) end,
        hysteria_auth = function(link) return hysteria_auth(link, core) end,
    }
end
