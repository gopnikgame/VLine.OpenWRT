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

local function routing_offer(line, core)
    local payload = line:match("^happ://routing/onadd/(.+)$") or line:match("^happ://routing/add/(.+)$")
    if payload then
        if #payload > 4 * math.ceil(core.profile_limit / 3) then return nil end
        local ok = pcall(core.decode_base64, payload, core.profile_limit)
        if ok then return "happ", "happ://routing/onadd/" .. payload end
        return nil
    end
    local url = line:match("^incy://autorouting/onadd/(.+)$") or line:match("^incy://autorouting/add/(.+)$")
        or line:match("^://autorouting/onadd/(.+)$") or line:match("^://autorouting/add/(.+)$")
    if url and #url <= 512 then
        -- Match the compiler's exact-URL policy, including its plain-path restriction.
        local host, path = url:match("^https://([a-z0-9.%-]+)(/[A-Za-z0-9._~/%-]+)$")
        if not host or not dns_name(host, core) then return nil end
        for segment in path:gmatch("[^/]+") do
            if segment == "." or segment == ".." then return nil end
        end
        return "incy", "incy://autorouting/onadd/" .. url
    end
end

local function add_offer(offers, line, core)
    local source, value = routing_offer(line, core)
    if not source then return nil, "routing_invalid" end
    if offers[source] and offers[source] ~= value then return nil, "routing_ambiguous" end
    offers[source] = value
    return true
end

local function routing_headers(input, core)
    if type(input) ~= "string" or #input > core.headers_limit then return nil, "routing_invalid" end
    input = input:gsub("\r\n", "\n")
    if input:find("[%z\1-\8\11-\31\127]") then return nil, "routing_invalid" end
    local offers, status, final, closed = {}, nil, false, true
    for line in input:gmatch("([^\n]*)\n") do
        if closed then
            local version, code, reason = line:match("^HTTP/([0-9.]+) (%d%d%d)(.*)$")
            if final or not ({ ["1.0"] = true, ["1.1"] = true, ["2"] = true, ["3"] = true })[version]
                or (code ~= "200" and code:sub(1, 1) ~= "1")
                or (reason ~= "" and reason:sub(1, 1) ~= " ") then return nil, "routing_invalid" end
            status, closed, offers = code, false, {}
        elseif line == "" then
            closed, final = true, status == "200"
        else
            local name, value = line:match("^([!#$%%&'*+.^_\96|~0-9A-Za-z%-]+):[ \t]*(.-)[ \t]*$")
            if not name then return nil, "routing_invalid" end
            if status == "200" and (name:lower() == "routing" or name:lower() == "autorouting") then
                local expected = name:lower() == "routing" and "happ" or "incy"
                local source = routing_offer(value, core)
                if source ~= expected then return nil, "routing_invalid" end
                local ok, err = add_offer(offers, value, core)
                if not ok then return nil, err end
            end
        end
    end
    if not final or not closed or input:sub(-2) ~= "\n\n" then return nil, "routing_invalid" end
    return offers
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
    local servers, seen, offers = {}, {}, {}
    for raw_line in body:gmatch("[^\r\n]+") do
        local line = trim(raw_line)
        local link, fragment, credential, hysteria = parse_link(line, core)
        if line:match("^happ://routing/") or line:match("^incy://autorouting/") or line:match("^://autorouting/") then
            local ok, err = add_offer(offers, line, core)
            if not ok then return nil, err end
        elseif link and not seen[link] and #servers < SERVER_LIMIT then
            seen[link] = true
            servers[#servers + 1] = { name = display_name(fragment, credential, #servers + 1, hysteria), link = link }
        end
    end
    if #servers > 0 then return servers, nil, offers end
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

        local response_data, outcome = platform.with_workspace(function(dir)
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
            local headers_file = dir .. "/headers"
            argv[#argv + 1], argv[#argv + 2] = "--dump-header", headers_file
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
            local parsed, parse_error, offers = parse_subscription(body, core)
            if not parsed then return nil, parse_error or "unsupported_subscription" end
            local from_headers, header_error = routing_headers(platform.read(headers_file, core.headers_limit), core)
            if not from_headers then return nil, header_error end
            for _, offer in pairs(from_headers) do
                local ok, err = add_offer(offers, offer, core)
                if not ok then return nil, err end
            end
            return { servers = parsed, offers = json.object(offers) }
        end)
        if response_data then return response_data.servers, nil, response_data.offers end
        if outcome == "unsupported_subscription" or outcome == "hwid_limit_reached" or outcome == "hwid_rejected"
            or outcome == "routing_invalid" or outcome == "routing_ambiguous" then
            return nil, outcome
        end
        return nil, "subscription_unavailable"
    end

    local function valid_offers(offers)
        if offers == nil then return true end
        if not json.is_object(offers) then return false end
        for source, offer in pairs(offers) do
            if type(offer) ~= "string" then return false end
            local format, normalized = routing_offer(offer, core)
            if format ~= source or normalized ~= offer then return false end
        end
        return true
    end

    local function routing_params(offers, source, dir)
        if not valid_offers(offers) or not offers or not offers[source] then return nil, "routing_missing" end
        local policy = json.object({ inboundTag = "vpn-routing-tproxy", routeOrder = "block-proxy-direct" })
        local params = { source = source, policy = "", profile = "" }
        if source == "happ" then
            params.headers = "routing: " .. offers.happ
        elseif source == "incy" then
            local url = offers.incy:match("^incy://autorouting/onadd/(.+)$")
            local host = subscription_url(url, core)
            local pins = host and pin_addresses(platform, core, host)
            if not pins then return nil, "routing_download" end
            local config, body, status = dir .. "/routing-curl.conf", dir .. "/routing-profile", dir .. "/routing-status"
            if not platform.write(config, 'url = "' .. url .. '"\n') then return nil, "storage_error" end
            -- Routing sources receive no subscription credentials or device identifiers.
            local code = platform.run({ "/usr/bin/curl", "-q", "--silent", "--globoff", "--path-as-is", "--ipv4",
                "--proto", "=https", "--noproxy", "*", "--proxy", "", "--max-redirs", "0",
                "--resolve", pins, "--connect-timeout", "4", "--max-time", "10",
                "--max-filesize", tostring(core.profile_limit), "--output", body,
                "--write-out", "%{http_code}", "--config", config,
            }, { timeout = 11, stdout = status })
            if code ~= 0 or platform.read(status, 3) ~= "200" then return nil, "routing_download" end
            params.profile = platform.read(body, core.profile_limit)
            if not params.profile or params.profile == "" then return nil, "routing_download" end
            params.headers = "autorouting: " .. offers.incy
            policy.incySource = json.object({ url = url })
        else
            return nil, "routing_invalid"
        end
        params.policy = json.encode(policy)
        return params
    end

    return {
        fetch = fetch, permitted = permitted,
        valid_offers = valid_offers, routing_params = routing_params,
        valid_url = function(url) return subscription_url(url, core) ~= nil end,
        parse_reserve = function(name, line) return parse_reserve(name, line, core) end,
        hysteria_auth = function(link) return hysteria_auth(link, core) end,
    }
end
