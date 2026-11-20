-- Shared routing compiler. Reads supplied strings and performs no file or network I/O.
local json = ...

local ORDER = "block-proxy-direct"
local PROFILE_LIMIT = 64 * 1024
local HEADERS_LIMIT = 96 * 1024
local DAT_KINDS = { "geoip", "geosite" }
local GROUPS = {
    { name = "Block", tag = "block" },
    { name = "Proxy", tag = "proxy" },
    { name = "Direct", tag = "direct" },
}
local MATCHES = { { field = "Sites", key = "domain" }, { field = "Ip", key = "ip" } }

local function fail(message)
    error({ message = message }, 0)
end

local function decode_object(input, label)
    local ok, value = pcall(json.decode, input)
    if not ok or not json.is_object(value) then fail("invalid JSON object: " .. label) end
    return value
end

local function only_keys(value, allowed, label)
    if not json.is_object(value) then fail(label .. " must be an object") end
    for key in pairs(value) do
        if not allowed[key] then fail(label .. " contains an unsupported field") end
    end
end

local function string_list(value, label)
    if value == nil then return json.array() end
    if not json.is_array(value) or #value > 512 then
        fail(label .. " must be an array of up to 512 strings")
    end
    for i, item in ipairs(value) do
        if type(item) ~= "string" or #item > 512 or not item:match("^[!-~]+$") then
            fail(label .. " contains an invalid string at index " .. i)
        end
    end
    return value
end

local function valid_domain(name)
    if #name > 253 or name:sub(1, 1) == "." or name:sub(-1) == "."
        or name:find("..", 1, true) or not name:match("^[A-Za-z0-9.%-]+$") then
        return false
    end
    for label in name:gmatch("[^.]+") do
        if #label > 63 or label:sub(1, 1) == "-" or label:sub(-1) == "-" then return false end
    end
    return true
end

local function ipv4_octets(address)
    local a, b, c, d = address:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return nil end
    local parts = { a, b, c, d }
    for i, part in ipairs(parts) do
        if #part > 3 or (#part > 1 and part:sub(1, 1) == "0") or tonumber(part) > 255 then
            return nil
        end
        parts[i] = tonumber(part)
    end
    return parts
end

local function public_ipv4(address)
    local octets = ipv4_octets(address)
    if not octets then return false end
    local a, b, c = octets[1], octets[2], octets[3]
    return not (a == 0 or a == 10 or a == 127 or a >= 224
        or (a == 100 and b >= 64 and b <= 127)
        or (a == 169 and b == 254)
        or (a == 172 and b >= 16 and b <= 31)
        or (a == 192 and (b == 168 or (b == 0 and (c == 0 or c == 2)) or (b == 88 and c == 99)))
        or (a == 198 and (b == 18 or b == 19 or (b == 51 and c == 100)))
        or (a == 203 and b == 0 and c == 113))
end

local function ipv6_group_count(side)
    if side == "" then return 0 end
    if side:sub(1, 1) == ":" or side:sub(-1) == ":" then return nil end
    local count = 0
    for group in side:gmatch("[^:]+") do
        if #group > 4 then return nil end
        count = count + 1
    end
    return count
end

local function valid_ipv6(address)
    if not address:match("^[0-9A-Fa-f:]+$") or not address:find(":", 1, true) then return false end
    local split = address:find("::", 1, true)
    if not split then return ipv6_group_count(address) == 8 end
    local right = address:sub(split + 2)
    if right:find("::", 1, true) then return false end
    local left_count = ipv6_group_count(address:sub(1, split - 1))
    local right_count = ipv6_group_count(right)
    return left_count and right_count and left_count + right_count < 8
end

local function valid_ip_rule(rule)
    local address, prefix = rule:match("^([^/]+)/(%d+)$")
    address = address or rule
    local width = 128
    if ipv4_octets(address) then
        width = 32
    elseif not valid_ipv6(address) then
        return false
    end
    if not prefix then return true end
    return #prefix <= 3 and prefix:sub(1, 1) ~= "0" and tonumber(prefix) <= width
end

local function sha256(value)
    return type(value) == "string" and #value == 64 and value:match("^[0-9a-f]+$")
end

local function valid_category(value)
    return #value <= 64 and value:match("^[a-z0-9][a-z0-9_-]*$")
end

local function valid_regex(value)
    return #value > 7 and value:sub(1, 7) == "regexp:" and not value:find("://", 1, true)
end

local function parse_policy(input)
    local policy = decode_object(input, "local policy")
    only_keys(policy, {
        inboundTag = true, routeOrder = true, allowedRegex = true, geo = true, incySource = true,
    }, "local policy")
    if type(policy.inboundTag) ~= "string" or #policy.inboundTag > 64
        or not policy.inboundTag:match("^[A-Za-z0-9_.%-]+$") then
        fail("local policy requires a valid inboundTag")
    end
    if policy.routeOrder ~= ORDER then fail("local policy must explicitly select " .. ORDER) end

    local regexes = {}
    for _, expression in ipairs(string_list(policy.allowedRegex, "allowedRegex")) do
        if not valid_regex(expression) or regexes[expression] then fail("invalid allowedRegex") end
        regexes[expression] = true
    end

    local categories = {}
    if policy.geo ~= nil then
        only_keys(policy.geo, { geoip = true, geosite = true }, "geo policy")
        for _, kind in ipairs(DAT_KINDS) do
            local entry = policy.geo[kind]
            only_keys(entry, { sha256 = true, categories = true }, kind .. " policy")
            if not sha256(entry.sha256) or entry.categories == nil then
                fail(kind .. " requires a SHA-256 and a category array")
            end
            categories[kind] = {}
            for _, category in ipairs(string_list(entry.categories, kind .. " categories")) do
                if not valid_category(category) or categories[kind][category] then
                    fail("invalid or duplicate " .. kind .. " category in local policy")
                end
                categories[kind][category] = true
            end
        end
    end
    return policy, regexes, categories
end

local function parse_header(input, selected)
    local value, closed, line_no = nil, false, 0
    for raw in (input .. "\n"):gmatch("([^\n]*)\n") do
        line_no = line_no + 1
        local line = raw:gsub("\r$", "")
        if line:find("[%z\1-\8\10-\31\127]") then fail("invalid control character in headers") end
        if line == "" then
            closed = true
        elseif closed then
            fail("provide one HTTP header block without a body")
        elseif line_no == 1 and line:sub(1, 5) == "HTTP/" then
            local version, status, reason = line:match("^HTTP/([0-9.]+) (%d%d%d)(.*)$")
            local versions = { ["1.0"] = true, ["1.1"] = true, ["2"] = true, ["3"] = true }
            if not versions[version] or status ~= "200" or (reason ~= "" and reason:sub(1, 1) ~= " ") then
                fail("expected HTTP 200 header block")
            end
        else
            local name, field = line:match("^([!#$%%&'*+.^_\96|~0-9A-Za-z%-]+):[ \t]*(.-)[ \t]*$")
            if not name then fail("invalid HTTP header line") end
            if name:lower() == selected then
                if value ~= nil then fail("duplicate " .. selected .. " header") end
                value = field
            end
        end
    end
    if not value or value == "" then fail("missing " .. selected .. " header") end
    return value
end

local base64 = {}
local alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
for i = 1, #alphabet do base64[alphabet:sub(i, i)] = i - 1 end

local function decode_base64(value, limit)
    limit = limit or PROFILE_LIMIT
    if #value == 0 or #value % 4 ~= 0 or #value > 4 * math.ceil(limit / 3) then
        fail("invalid Happ Base64 payload length")
    end
    local output = {}
    for pos = 1, #value, 4 do
        local a, b, c, d = value:sub(pos, pos + 3):match("^(.)(.)(.)(.)$")
        a, b = base64[a], base64[b]
        local third, fourth = base64[c], base64[d]
        if not a or not b then fail("invalid Happ Base64 payload") end
        local first = a * 4 + math.floor(b / 16)
        if third and fourth then
            output[#output + 1] = string.char(first, (b % 16) * 16 + math.floor(third / 4),
                (third % 4) * 64 + fourth)
        elseif pos + 3 ~= #value or d ~= "=" then
            fail("invalid Happ Base64 padding")
        elseif third and third % 4 == 0 then
            output[#output + 1] = string.char(first, (b % 16) * 16 + math.floor(third / 4))
        elseif c == "=" and b % 16 == 0 then
            output[#output + 1] = string.char(first)
        else
            fail("invalid Happ Base64 padding")
        end
    end
    local decoded = table.concat(output)
    if #decoded > limit then fail("Happ profile is too large") end
    return decoded
end

local function trusted_incy_host(url, source, fetch)
    only_keys(source, { url = true, ipv4 = true }, "local INCY source")
    if type(source.url) ~= "string" or source.url ~= url or #url > 512 then
        fail("INCY header does not match the approved HTTPS URL")
    end
    local host, path = url:match("^https://([a-z0-9.%-]+)(/[A-Za-z0-9._~/%-]+)$")
    if not host or not valid_domain(host) or not host:match("%.[a-z][a-z0-9%-]*$") then
        fail("local INCY source requires a plain HTTPS URL")
    end
    if (fetch or source.ipv4 ~= nil) and (type(source.ipv4) ~= "string" or not public_ipv4(source.ipv4)) then
        fail("INCY fetch requires a pinned public IPv4")
    end
    for segment in path:gmatch("[^/]+") do
        if segment == "." or segment == ".." then fail("INCY URL contains a dot segment") end
    end
    return host
end

local function parse_profile(source, headers, policy, read_incy, fetch)
    local input
    if source == "happ" then
        local header = parse_header(headers, "routing")
        local payload = header:match("^happ://routing/onadd/(.+)$") or header:match("^happ://routing/add/(.+)$")
        if not payload then fail("expected a Happ routing add or onadd link") end
        input = decode_base64(payload)
    else
        local header = parse_header(headers, "autorouting")
        local url = header:match("^incy://autorouting/onadd/(.+)$")
            or header:match("^incy://autorouting/add/(.+)$")
            or header:match("^://autorouting/onadd/(.+)$")
            or header:match("^://autorouting/add/(.+)$")
        if not url then fail("expected an INCY autorouting add or onadd link") end
        local host = trusted_incy_host(url, policy.incySource, fetch)
        input = read_incy(url, host, policy.incySource.ipv4)
        if type(input) ~= "string" or #input == 0 or #input > PROFILE_LIMIT then
            fail("local INCY profile is empty, unreadable or too large")
        end
    end
    return decode_object(input, "routing profile")
end

local PROFILE_KEYS = {
    GlobalProxy = true, DomainStrategy = true, RouteOrder = true, FakeDNS = true,
    Name = true, LastUpdated = true, useChunkFiles = true,
    Geoipurl = true, Geositeurl = true, DnsHosts = true,
    RemoteDNSType = true, RemoteDNSDomain = true, RemoteDNSIP = true, RemoteDns = true,
    DomesticDNSType = true, DomesticDNSDomain = true, DomesticDNSIP = true, DomesticDns = true,
    DirectSites = true, DirectIp = true, ProxySites = true, ProxyIp = true, BlockSites = true, BlockIp = true,
}

local function valid_rule(value, is_domain, regexes, categories)
    local prefix, body = value:match("^([a-z]+):(.+)$")
    local dat = is_domain and "geosite" or "geoip"
    if prefix == dat then
        if valid_category(body) and (not categories or (categories[dat] and categories[dat][body])) then
            return true, true
        end
        return false
    end
    if not is_domain then return valid_ip_rule(value) end
    if prefix == "regexp" then return valid_regex(value) and (not regexes or regexes[value]) end
    return (prefix == "full" or prefix == "domain") and valid_domain(body)
end

local function compile(profile, policy, regexes, categories)
    only_keys(profile, PROFILE_KEYS, "routing profile")
    if profile.GlobalProxy ~= "true" then fail('GlobalProxy must be the string "true"') end
    if profile.RouteOrder ~= nil and profile.RouteOrder ~= ORDER then fail("unsupported RouteOrder") end
    if profile.FakeDNS ~= nil and profile.FakeDNS ~= "false" and profile.FakeDNS ~= false then
        fail("FakeDNS must be disabled for this adapter")
    end
    local strategy = profile.DomainStrategy
    if strategy ~= "IPIfNonMatch" and strategy ~= "AsIs" then fail("unsupported DomainStrategy") end

    local rules, counts, dat_refs = json.array(), {}, 0
    for _, group in ipairs(GROUPS) do
        for _, match in ipairs(MATCHES) do
            local field = group.name .. match.field
            local values = string_list(profile[field], field)
            counts[#counts + 1] = field .. "=" .. #values
            for i, value in ipairs(values) do
                local valid, uses_dat = valid_rule(value, match.key == "domain", regexes, categories)
                if not valid then fail("unsupported or unapproved rule in " .. field .. " at index " .. i) end
                if uses_dat then dat_refs = dat_refs + 1 end
            end
            if #values > 0 then
                rules[#rules + 1] = json.object({
                    type = "field", inboundTag = json.array({ policy.inboundTag }),
                    ruleTag = "vpn-routing-" .. group.tag .. "-" .. match.key, outboundTag = group.tag,
                    [match.key] = values,
                })
            end
        end
    end
    if #rules == 0 then fail("profile has no supported routing rules") end
    if strategy == "AsIs" then
        rules[#rules + 1] = json.object({
            type = "field", inboundTag = json.array({ policy.inboundTag }),
            ruleTag = "vpn-routing-fallback", outboundTag = "proxy",
        })
    end
    return json.object({ routing = json.object({ domainStrategy = strategy, rules = rules }) }), counts, dat_refs
end

local function preview(source, headers, policy_input, read_incy, fetch, authorize_geo)
    if source ~= "happ" and source ~= "incy" then fail("select Happ or INCY") end
    if type(policy_input) ~= "string" or #policy_input == 0 or #policy_input > PROFILE_LIMIT then
        fail("local policy is empty, unreadable or too large")
    end
    if type(headers) ~= "string" or #headers == 0 or #headers > HEADERS_LIMIT then
        fail("HTTP headers are empty, unreadable or too large")
    end
    if source == "incy" and type(read_incy) ~= "function" then fail("INCY profile is required") end

    local policy, regexes, categories = parse_policy(policy_input)
    local profile = parse_profile(source, headers, policy, read_incy, fetch)
    local managed = not policy.geo and authorize_geo and authorize_geo(profile)
    if managed then
        categories = managed.categories
        for expression in pairs(managed.regexes) do regexes[expression] = true end
    end
    local candidate, counts, dat_refs = compile(profile, policy, regexes, categories)
    return candidate, counts, dat_refs, policy, dat_refs > 0 and managed and managed.urls or nil
end

return {
    valid_domain = valid_domain,
    public_ipv4 = public_ipv4,
    ipv4_octets = ipv4_octets,
    decode_base64 = decode_base64,
    preview = preview,
    fail = fail,
    decode_object = decode_object,
    only_keys = only_keys,
    string_list = string_list,
    -- Persisted compiled rules have already passed the import allowlists.
    valid_compiled_rule = function(value, is_domain) return valid_rule(value, is_domain) end,
    order = ORDER,
    profile_limit = PROFILE_LIMIT,
    headers_limit = HEADERS_LIMIT,
    groups = GROUPS,
    matches = MATCHES,
}
