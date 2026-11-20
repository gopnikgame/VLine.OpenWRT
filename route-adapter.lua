local directory = arg[0]:match("^(.*[/\\])") or "./"
local json = dofile(directory .. "route_json.lua")

local BRAND = "VPN Routing Adapter"
local core = assert(loadfile(directory .. "route_core.lua"))(json)
local ORDER, PROFILE_LIMIT, HEADERS_LIMIT = core.order, core.profile_limit, core.headers_limit
local GROUPS, MATCHES = core.groups, core.matches
local fail, decode_object, only_keys, string_list = core.fail, core.decode_object, core.only_keys, core.string_list
local DUMP_LIMIT = 4 * 1024 * 1024

local function read_bounded(path, limit, label)
    local file = io.open(path, "rb")
    if not file then fail("cannot open " .. label) end
    local input = file:read(limit + 1)
    file:close()
    if not input or #input == 0 or #input > limit then
        fail(label .. " is empty, unreadable or too large")
    end
    return input
end

local function fetch_incy(url, host, address)
    if package.config:sub(1, 1) ~= "/" then fail("INCY --fetch requires a POSIX shell") end
    -- URL, host and address use a restricted alphabet checked before reaching the shell.
    -- Report curl's exit explicitly because Lua 5.1 popen close can hide it.
    local command = "curl -q --silent --fail --globoff --noproxy '*' --proto '=https'"
        .. " --max-redirs 0 --connect-timeout 5 --max-time 15 --max-filesize " .. PROFILE_LIMIT
        .. " --resolve '" .. host .. ":443:" .. address .. "' --url '" .. url
        .. "' --write-out '\\n%{http_code}' 2>/dev/null; rc=$?; printf '\\nVPN_ROUTING_CURL_EXIT=%s\\n' \"$rc\""
    local pipe = io.popen(command, "r")
    if not pipe then fail("INCY HTTPS fetch could not start") end
    local marker = "\n200\nVPN_ROUTING_CURL_EXIT=0\n"
    local output = pipe:read(PROFILE_LIMIT + #marker + 1)
    pipe:close()
    if not output or #output <= #marker or #output > PROFILE_LIMIT + #marker
        or output:sub(-#marker) ~= marker then
        fail("INCY HTTPS fetch failed, exceeded the limit or returned non-200")
    end
    return output:sub(1, -#marker - 1)
end

local function verify_dat(path, geo)
    if not path then fail("verify requires --dat-sha256 when the candidate uses DAT") end
    local input = read_bounded(path, 1024, "DAT SHA-256 list")
    local seen = {}
    for line in input:gmatch("[^\r\n]+") do
        local hash, name = line:match("^([0-9a-f]+)[ \t]+%*?(%w+)%.dat$")
        if not name or not geo[name] or seen[name] or hash ~= geo[name].sha256 then
            fail("DAT SHA-256 mismatch or invalid digest list")
        end
        seen[name] = true
    end
    if not seen.geoip or not seen.geosite then fail("DAT SHA-256 list must cover both files") end
end

local function require_tags(config, policy, strategy)
    if not json.is_array(config.inbounds) or not json.is_array(config.outbounds) then
        fail("merged Xray config requires inbound and outbound arrays")
    end
    local inbound_tags = {}
    for _, inbound in ipairs(config.inbounds) do
        if not json.is_object(inbound) or type(inbound.tag) ~= "string"
            or inbound.tag == "" or inbound_tags[inbound.tag] then
            fail("merged Xray inbounds must have unique nonempty tags")
        end
        inbound_tags[inbound.tag] = true
    end
    if not inbound_tags[policy.inboundTag] then fail("approved inboundTag is missing in the merged config") end

    local outbounds = {}
    for _, outbound in ipairs(config.outbounds) do
        if not json.is_object(outbound) or type(outbound.tag) ~= "string"
            or outbound.tag == "" or outbounds[outbound.tag] then
            fail("merged Xray outbounds must have unique nonempty tags")
        end
        outbounds[outbound.tag] = outbound.protocol
        if type(outbound.protocol) ~= "string" then fail("merged Xray outbound has no protocol") end
    end
    if outbounds.proxy ~= "vless" or outbounds.direct ~= "freedom" or outbounds.block ~= "blackhole" then
        fail("expected merged outbound tags proxy/vless, direct/freedom and block/blackhole")
    end
    if strategy == "IPIfNonMatch" and config.outbounds[1].tag ~= "proxy" then
        fail("IPIfNonMatch requires proxy to be the first merged outbound")
    end
end

local function verify_previous(routing, inbound_tag)
    only_keys(routing, { domainStrategy = true, rules = true }, "previous routing")
    local strategy = routing.domainStrategy
    if (strategy ~= "IPIfNonMatch" and strategy ~= "AsIs")
        or not json.is_array(routing.rules) or #routing.rules == 0 then
        fail("previous routing is not an adapter fragment")
    end
    local expected, position = {}, 0
    for _, group in ipairs(GROUPS) do
        for _, match in ipairs(MATCHES) do
            position = position + 1
            expected["vpn-routing-" .. group.tag .. "-" .. match.key] = {
                key = match.key, tag = group.tag, position = position,
            }
        end
    end
    if strategy == "AsIs" then
        expected["vpn-routing-fallback"] = { tag = "proxy", position = position + 1 }
        local fallback = routing.rules[#routing.rules]
        if #routing.rules < 2 or not json.is_object(fallback) or fallback.ruleTag ~= "vpn-routing-fallback" then
            fail("previous AsIs routing is missing adapter rules or fallback")
        end
    end
    local last = 0
    for _, rule in ipairs(routing.rules) do
        local definition = json.is_object(rule) and expected[rule.ruleTag]
        if not definition or definition.position <= last or rule.type ~= "field"
            or rule.outboundTag ~= definition.tag
            or not json.equal(rule.inboundTag, json.array({ inbound_tag })) then
            fail("previous routing is not scoped to the approved adapter inbound")
        end
        local keys = { type = true, ruleTag = true, inboundTag = true, outboundTag = true }
        if definition.key then
            keys[definition.key] = true
            if #string_list(rule[definition.key], "previous rule") == 0 then
                fail("previous routing contains an empty match")
            end
        end
        only_keys(rule, keys, "previous rule")
        last = definition.position
    end
end

local function require_pinned_dat_config(config)
    if config.geodata ~= nil then fail("DAT verification requires locally fixed assets without a geodata updater") end
    if config.env ~= nil then
        if not json.is_object(config.env) then fail("invalid merged Xray env") end
        for key in pairs(config.env) do
            if key:lower():gsub("%.", "_") == "xray_location_asset" then
                fail("merged Xray config overrides the DAT directory")
            end
        end
    end
end

local function verify(options, policy, candidate, dat_refs)
    local baseline = decode_object(read_bounded(options.baseline, DUMP_LIMIT, "baseline dump"), "baseline dump")
    local merged = decode_object(read_bounded(options.merged, DUMP_LIMIT, "candidate dump"), "candidate dump")
    if options.previous then
        local previous = decode_object(read_bounded(options.previous, PROFILE_LIMIT * 2, "previous fragment"),
            "previous fragment")
        only_keys(previous, { routing = true }, "previous fragment")
        if not json.is_object(previous.routing) or not json.equal(previous.routing, baseline.routing) then
            fail("baseline routing does not match the explicitly approved previous fragment")
        end
        verify_previous(previous.routing, policy.inboundTag)
    elseif baseline.routing ~= nil then
        fail("baseline already owns routing; provide the explicitly approved previous fragment")
    end
    if not json.equal(merged.routing, candidate.routing) then
        fail("effective Xray routing differs from the generated candidate")
    end
    require_tags(merged, policy, candidate.routing.domainStrategy)
    baseline.routing, merged.routing = nil, nil
    if not json.equal(baseline, merged) then fail("Xray config changed outside routing") end
    if dat_refs > 0 or options["dat-sha256"] then
        if not policy.geo then fail("DAT digests supplied without a local geo policy") end
        require_pinned_dat_config(merged)
        verify_dat(options["dat-sha256"], policy.geo)
    end
end

local USAGE = [[VPN Routing Adapter
  lua route-adapter.lua preview --source happ --headers FILE --policy FILE
  lua route-adapter.lua preview --source incy --headers FILE --policy FILE (--profile FILE | --fetch)
  lua route-adapter.lua verify <offline source options> --baseline DUMP --merged DUMP
      [--previous FILE] [--dat-sha256 FILE]

preview emits a routing candidate to stdout. verify checks a full Xray merge.
]]

local OPTION_KEYS = {
    source = true, headers = true, policy = true, profile = true, fetch = true,
    baseline = true, merged = true, previous = true, ["dat-sha256"] = true,
}

local function read_options(command)
    if command ~= "preview" and command ~= "verify" then fail("expected preview or verify; see --help") end
    local options, i = {}, 2
    while i <= #arg do
        local key = arg[i]:match("^%-%-([a-z0-9%-]+)$")
        if not key or not OPTION_KEYS[key] or options[key] ~= nil then
            fail("invalid or duplicate command option; see --help")
        end
        if key == "fetch" then
            options.fetch = true
            i = i + 1
        else
            local value = arg[i + 1]
            if not value or value == "" or value:sub(1, 2) == "--" then fail("missing value for --" .. key) end
            options[key] = value
            i = i + 2
        end
    end
    if not options.headers or not options.policy or (options.source ~= "happ" and options.source ~= "incy") then
        fail("select --source happ or incy and provide --headers and --policy")
    end
    if options.source == "happ" and (options.profile or options.fetch) then
        fail("Happ reads only the local routing header")
    end
    if options.source == "incy" and (options.profile ~= nil) == (options.fetch == true) then
        fail("INCY requires exactly one of --profile and --fetch")
    end
    if command == "verify" then
        if not options.baseline or not options.merged or options.fetch then
            fail("verify requires two Xray dumps and an offline profile")
        end
    elseif options.baseline or options.merged or options.previous or options["dat-sha256"] then
        fail("merge verification options require verify")
    end
    return options
end

local function main()
    if #arg == 1 and arg[1] == "--help" then io.write(USAGE); return end
    local command = arg[1]
    local options = read_options(command)
    local policy_input = read_bounded(options.policy, PROFILE_LIMIT, "local policy")
    local headers = read_bounded(options.headers, HEADERS_LIMIT, "HTTP headers")
    local read_incy = options.fetch and fetch_incy or nil
    if options.profile then
        read_incy = function()
            return read_bounded(options.profile, PROFILE_LIMIT, "local INCY profile")
        end
    end
    local candidate, counts, dat_refs, policy = core.preview(
        options.source, headers, policy_input, read_incy, options.fetch)
    local strategy = candidate.routing.domainStrategy
    if command == "verify" then
        verify(options, policy, candidate, dat_refs)
    else
        local ok = io.write(json.encode(candidate), "\n")
        if not ok or not io.flush() then fail("could not write preview output") end
    end
    local fallback = strategy == "IPIfNonMatch" and "first-outbound:proxy" or "scoped-rule:proxy"
    local result = command == "verify" and "merge verified" or "candidate only"
    io.stderr:write(BRAND .. " | " .. result .. " | " .. options.source .. " | " .. strategy
        .. " | inbound=" .. policy.inboundTag .. " | " .. ORDER .. " | fallback=" .. fallback
        .. " | DAT references=" .. dat_refs .. "\n" .. table.concat(counts, " ") .. "\n")
end

local ok, err = pcall(main)
if not ok then
    local message = type(err) == "table" and err.message or "internal adapter error"
    io.stderr:write(BRAND .. " | " .. message .. "\n")
    os.exit(1)
end
