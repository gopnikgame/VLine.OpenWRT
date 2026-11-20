-- Real response parsing, routing compilation and connection lifecycle with synthetic I/O only.
local json = dofile("route_json.lua")
local core = assert(loadfile("route_core.lua"))(json)
local SUB_HOST, OTHER_HOST = "sub.example.test", "other.example.test"
local SUB, OTHER = "https://" .. SUB_HOST .. "/fixture", "https://" .. OTHER_HOST .. "/fixture"
local PROFILE = "https://profiles.example.test/routing.json"
local LINK = "vless://00000000-0000-4000-8000-000000000001@node.example.test:443?security=tls&type=tcp"
local RUNTIME, CONFIG = "/run/vpn-routing", "/etc/vpn-routing"
local POLICY, SETTINGS, JOURNAL = CONFIG .. "/policy.json", CONFIG .. "/connection.json", RUNTIME .. "/operation.json"
local CACHE, REFRESH = RUNTIME .. "/subscription.json", RUNTIME .. "/subscription-refresh.json"
local TRANSACTION = CONFIG .. "/routing-update.json"

local function base64(bytes)
    local alphabet, output = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", {}
    local function char(value) return alphabet:sub(value + 1, value + 1) end
    for pos = 1, #bytes, 3 do
        local a, b, c = bytes:byte(pos, pos + 2)
        output[#output + 1] = char(math.floor(a / 4))
        output[#output + 1] = char((a % 4) * 16 + math.floor((b or 0) / 16))
        output[#output + 1] = b and char((b % 16) * 4 + math.floor((c or 0) / 64)) or "="
        output[#output + 1] = c and char(c % 64) or "="
    end
    return table.concat(output)
end

local function profile(name, dat)
    local value = json.object({ GlobalProxy = "true", DomainStrategy = "AsIs",
        BlockSites = json.array({ "domain:ads.example.test" }),
        ProxySites = json.array({ "domain:foreign.example.test" }),
        DirectSites = json.array({ "domain:" .. name .. ".example.test" }),
    })
    if dat then
        value.DirectIp, value.DirectSites = json.array({ "geoip:allowed" }), json.array({ "geosite:allowed" })
        value.Geoipurl, value.Geositeurl = "https://geo.example.test/geoip.dat", "https://geo.example.test/geosite.dat"
    end
    return json.encode(value)
end

local function option(argv, flag)
    for index, value in ipairs(argv) do if value == flag then return argv[index + 1] end end
end

local function direct_name(routes)
    for _, rule in ipairs(routes and routes.rules or {}) do
        if rule.outboundTag == "direct" and rule.domain then return rule.domain[1] end
    end
end

local function fixture()
    local e = { files = {}, responses = {}, sequence = 0, clock = 100,
        subscription_fetches = 0, profile_fetches = 0, starts = 0, dat_fetches = 0,
        running = false, captured = false, guarded = false,
    }
    local platform = { runtime_dir = RUNTIME, config_dir = CONFIG }
    local function capture_cut(operation, path)
        local trigger = e.cut_trigger
        if not trigger or e.cut_state or trigger.operation ~= operation or trigger.path ~= path then return end
        local files = {}
        for name, bytes in pairs(e.files) do files[name] = bytes end
        e.cut_state = { files = files, running = e.running, captured = e.captured, guarded = e.guarded,
            active_routes = e.active_routes and json.decode(json.encode(e.active_routes)), active_link = e.active_link,
            starts = e.starts, sequence = e.sequence, subscription_fetches = e.subscription_fetches, profile_fetches = e.profile_fetches }
    end
    function platform.lstat(path)
        if e.files[path] then return { type = "reg", uid = 0, modestr = "rw-------" } end
    end
    function platform.read(path, limit)
        local value = e.files[path]
        if value and (not limit or #value <= limit) then return value end
    end
    function platform.write(path, bytes, durable)
        if path == POLICY or path == SETTINGS or path == TRANSACTION then assert(durable) end
        if path == POLICY and e.fail_policy_once then e.fail_policy_once = false; return nil end
        if path == SETTINGS and e.fail_settings_once then e.fail_settings_once = false; return nil end
        e.files[path] = bytes
        capture_cut("written", path)
        if path == SETTINGS and e.fail_settings_sync_once then
            e.fail_settings_sync_once = false
            return nil, "not_synced"
        end
        return true
    end
    function platform.remove(path, durable)
        if path == TRANSACTION then assert(durable) end
        if not e.files[path] then return nil end -- production unlink reports ENOENT, not idempotent success
        capture_cut("removing", path)
        e.files[path] = nil
        return true
    end
    function platform.private_dir() return true end
    function platform.uptime() return e.clock end
    function platform.random_hex() e.sequence = e.sequence + 1; return string.format("%032x", e.sequence) end
    function platform.resolve4(host)
        assert(host == SUB_HOST or host == OTHER_HOST or host == "profiles.example.test")
        return { "1.1.1.1" }
    end
    function platform.with_lock(callback)
        assert(not e.locked)
        e.locked = true
        local result, err = callback()
        e.locked = false
        return result, err
    end
    function platform.with_workspace(callback)
        local dir = RUNTIME .. "/work-" .. platform.random_hex()
        local result, err = callback(dir)
        for path in pairs(e.files) do if path:sub(1, #dir + 1) == dir .. "/" then e.files[path] = nil end end
        return result, err
    end
    function platform.run(argv, options)
        assert(argv[1] == "/usr/bin/curl", "synthetic fixture must never execute a command")
        assert(option(argv, "--max-redirs") == "0" and option(argv, "--proxy") == "")
        local config = assert(e.files[option(argv, "--config")])
        local url = assert(config:match('^url = "([^"]+)"\n'))
        local response = assert(e.responses[url], "unexpected synthetic URL")
        if url == SUB or url == OTHER then
            e.subscription_fetches = e.subscription_fetches + 1
            assert(config:find("x-hwid: ", 1, true))
        else
            e.profile_fetches = e.profile_fetches + 1
            assert(url == PROFILE and not config:find("x-hwid", 1, true))
        end
        assert(option(argv, "--resolve") == url:match("^https://([^/]+)") .. ":443:1.1.1.1")
        e.files[option(argv, "--output")] = response.body
        local status = response.status or "200"
        local dump = option(argv, "--dump-header")
        if dump then e.files[dump] = "HTTP/2 " .. status .. "\r\n" .. (response.headers or "") .. "\r\n" end
        e.files[options.stdout] = option(argv, "--write-out") == "%{http_code}" and status or status .. "\t\t\t"
        return response.exit or 0
    end
    local subscription = dofile("luci/runtime/subscription.lua")(json, platform, core, {
        get = function() assert(e.locked); return string.rep("ab", 16) end,
    })
    local capture_real = dofile("luci/runtime/capture.lua")(json, {
        runtime_dir = RUNTIME, dependency = function(name) return "/usr/bin/" .. name end,
    }, core)
    local capture = {
        validate = capture_real.validate,
        networks = function()
            return json.array({ json.object({ device = "br-lan", label = "lan", clients = json.array() }) }), {}
        end,
        inspect = function() return e.captured and "active" or "absent" end,
        start = function(scope, _, arm)
            assert(scope.interface == "br-lan" and e.running and e.guarded and arm())
            e.captured = true
            if e.fail_capture_for and direct_name(e.active_routes) == e.fail_capture_for then return nil, "capture_failed" end
            return true
        end,
        stop = function() e.captured = false; return true end,
    }
    local guard = {
        inspect = function(scope) return e.guarded and (scope and "active" or "conflict") or "absent" end,
        start = function(scope) assert(scope.interface == "br-lan"); e.guarded = true; return true end,
        stop = function() assert(not e.captured and not e.running); e.guarded = false; return true end,
    }
    local service = {
        control_user = "vpn-routing", available = function() return true end,
        inspect = function() return e.running and "ready" or "absent" end,
        can_start = function() return not e.running end,
        routing_matches = function(routes) return json.equal(e.active_routes, routes) end,
        validate_routing = function(_, routes)
            assert(routes.rules[1].outboundTag == "block" and routes.rules[2].outboundTag == "proxy")
            if e.fail_routing_check then return nil, "routing_check_failed" end
            return true
        end,
        stage = function(_, outbound, routes, assets)
            return { bytes = "{}", health_port = 30000, password = "synthetic", routes = routes, asset_dir = assets, link = outbound.link }
        end,
        start = function(_, candidate, arm)
            assert(not e.running and not e.captured and arm())
            e.running, e.active_routes, e.active_link = true, candidate.routes, candidate.link
            e.starts = e.starts + 1
            return true
        end,
        stop = function() assert(not e.captured); e.running, e.active_routes = false, nil; return true end,
    }
    local probe = {
        outbound = function(_, link) return { tag = "proxy", link = link } end,
        check = function() return { result = "response", httpCode = 204, elapsedMs = 1 } end,
        head = function()
            assert(e.running and not e.captured)
            return { result = "response", httpCode = e.fail_head_for and direct_name(e.active_routes) == e.fail_head_for and 503 or 204, elapsedMs = 1 }
        end,
    }
    local geodata = {
        authorize = function(value)
            if value.Geoipurl and value.Geositeurl then
                return { urls = { geoip = value.Geoipurl, geosite = value.Geositeurl },
                    categories = { geoip = { allowed = true }, geosite = { allowed = true } }, regexes = {} }
            end
        end,
        fetch_pair = function()
            e.dat_fetches = e.dat_fetches + 1
            if e.fail_dat then return nil, e.fail_dat end
            return json.object({ managed = true, geoip = string.rep("a", 64), geosite = string.rep("b", 64) })
        end,
        store = function() return true end,
        verify = function() return "/synthetic-assets" end,
        asset_path = function() return "/synthetic-assets" end,
    }
    local routing = dofile("luci/runtime/routing.lua")(json, platform, core, geodata)
    local create_connection = dofile("luci/runtime/connection.lua")
    function e:reload_backend()
        e.handle = create_connection(json, platform, core, subscription, probe, capture, service,
            routing, guard, { get = function() return string.rep("ab", 16) end }).handle
    end
    e:reload_backend()
    function e:get(path) return e.files[path] and json.decode(e.files[path]) end
    function e:response(formats, bytes, in_body)
        local headers, body = {}, { LINK .. "#Synthetic" }
        for _, source in ipairs(formats) do
            local link = source == "happ" and "happ://routing/onadd/" .. base64(bytes or profile("first"))
                or "incy://autorouting/onadd/" .. PROFILE
            if in_body then body[#body + 1] = link
            else headers[#headers + 1] = (source == "happ" and "routing: " or "autorouting: ") .. link .. "\r\n" end
        end
        e.responses[SUB] = { body = table.concat(body, "\n"), headers = table.concat(headers) }
        e.responses[PROFILE] = { body = bytes or profile("first") }
    end
    function e:load(url, host)
        local list = assert(e.handle("subscription", { url = url or SUB, confirmHost = host or SUB_HOST }))
        e.selected = { snapshot = list.snapshot, server = list.servers[1].id }
        return list
    end
    function e:connect(source)
        local params = { snapshot = e.selected.snapshot, server = e.selected.server, routingSource = source }
        return e.handle("connect", params)
    end
    function e:reject(action, params, expected)
        local result, err = e.handle(action, params or {})
        assert(not result and err == expected, "expected " .. expected .. ", received " .. tostring(err))
    end
    function e:snapshot()
        return { policy = e.files[POLICY], settings = e.files[SETTINGS], cache = e.files[CACHE],
            refresh = e.files[REFRESH], routes = e.active_routes and json.encode(e.active_routes), starts = e.starts }
    end
    function e:retained(before, allow_restart)
        assert(e.files[POLICY] == before.policy and e.files[SETTINGS] == before.settings, "persistent intent changed after rejection")
        assert(e.files[CACHE] == before.cache and e.files[REFRESH] == before.refresh, "accepted server snapshot changed after rejection")
        assert(json.encode(e.active_routes) == before.routes, "previous active routing was not restored")
        assert(e.running and e.captured and e.guarded and e.handle("status", {}).state == "connected")
        if not allow_restart then assert(e.starts == before.starts, "rejected input restarted the tunnel") end
    end
    function e:reboot()
        for path in pairs(e.files) do if path:sub(1, #RUNTIME + 1) == RUNTIME .. "/" then e.files[path] = nil end end
        e.running, e.captured, e.guarded, e.active_routes = false, false, false, nil
        e.locked = false
        e:reload_backend()
    end
    function e:restore_cut(reboot)
        assert(e.cut_state, "the requested power-cut point was not reached")
        local cut = e.cut_state
        e.files, e.running, e.captured, e.guarded = cut.files, cut.running, cut.captured, cut.guarded
        e.active_routes, e.active_link = cut.active_routes, cut.active_link
        e.starts, e.sequence = cut.starts, cut.sequence
        e.subscription_fetches, e.profile_fetches = cut.subscription_fetches, cut.profile_fetches
        e.cut_trigger, e.cut_state, e.locked = nil, nil, false
        if reboot then e:reboot() else e:reload_backend() end
    end
    return e
end

-- Single-format import obtains rules without pasting a profile or a vendor-specific URL.
do
    local e = fixture()
    e:response({ "happ" }, profile("first"), true)
    local list = e:load()
    assert(#list.routingSources == 1 and list.routingSources[1] == "happ" and not list.hasManualRouting)
    assert(not e.files[POLICY] and e.profile_fetches == 0, "getting servers must not silently activate unvalidated rules")
    assert(e:connect().state == "connected")
    local saved = e:get(POLICY)
    assert(saved.routing.source == "happ" and saved.routingSubscription.source == "happ" and saved.routingSubscription.url == SUB)
    assert(direct_name(e.active_routes) == "domain:first.example.test")
    local rules = e.active_routes.rules
    assert(#rules == 4 and rules[1].outboundTag == "block" and rules[2].outboundTag == "proxy"
        and rules[3].outboundTag == "direct" and rules[4].outboundTag == "proxy")
    local settings = assert(e.handle("settings", {}))
    assert(settings.routing.fromSubscription and settings.routingStatus.state == "applied")
    assert(not json.encode(json.object(settings)):find(SUB, 1, true), "settings leaked the subscription URL")

    -- A routing-only change must reconnect even while the selected server URI is identical.
    local starts = e.starts
    e:response({ "happ" }, profile("second"))
    assert(e.handle("refresh_subscription", {}).state == "reconnected")
    assert(e.starts == starts + 1 and e:get(SETTINGS).link == LINK and direct_name(e.active_routes) == "domain:second.example.test")
    local snapshot = e:get(REFRESH).snapshot
    starts = e.starts
    assert(e.handle("refresh_subscription", {}).state == "unchanged")
    assert(e.starts == starts and e:get(REFRESH).snapshot == snapshot)

    -- Reboot restore uses only the last validated local profile and stored server.
    local fetches = e.subscription_fetches + e.profile_fetches
    local policy = e.files[POLICY]
    e:reboot()
    e.responses = {}
    assert(e.handle("restore", {}).state == "connected")
    assert(e.subscription_fetches + e.profile_fetches == fetches and e.files[POLICY] == policy)
    assert(direct_name(e.active_routes) == "domain:second.example.test")
    assert(e.handle("disconnect", {}).state == "disconnected")
    assert(not e.handle("remove_subscription", {}).hasSubscription)
    assert(not e:get(POLICY).routingSubscription and not e:get(POLICY).routing and not e.files[SETTINGS])
end

-- Competing formats require an explicit choice, which survives every refresh.
do
    local e = fixture()
    e:response({ "happ", "incy" }, profile("first"))
    local list = e:load()
    assert(#list.routingSources == 2 and list.routingSources[1] == "happ" and list.routingSources[2] == "incy")
    e:reject("connect", e.selected, "routing_choice_required")
    assert(not e.files[POLICY] and not e.files[SETTINGS] and e.profile_fetches == 0)
    assert(e:connect("incy").state == "connected")
    assert(e:get(POLICY).routingSubscription.source == "incy" and e.profile_fetches == 1)
    e:response({ "happ", "incy" }, profile("second"))
    assert(e.handle("refresh_subscription", {}).state == "reconnected")
    assert(e:get(POLICY).routing.source == "incy" and direct_name(e.active_routes) == "domain:second.example.test")
    local before = e:snapshot()
    e:response({ "happ" }, profile("third"))
    e:reject("refresh_subscription", {}, "routing_missing")
    e:retained(before)
end

-- Manual routing remains an override until the user explicitly chooses subscription routing.
do
    local e = fixture()
    local params = { source = "happ", headers = "routing: happ://routing/onadd/" .. base64(profile("manual")),
        profile = "", policy = '{"inboundTag":"vpn-routing-tproxy","routeOrder":"block-proxy-direct"}' }
    assert(e.handle("save_routing", params).routing.source == "happ")
    local policy = e.files[POLICY]
    e:response({ "happ", "incy" }, profile("first"))
    assert(e:load().hasManualRouting)
    assert(e:connect().state == "connected")
    assert(e.files[POLICY] == policy and not e:get(POLICY).routingSubscription and direct_name(e.active_routes) == "domain:manual.example.test")
    e:response({ "incy" }, profile("second"))
    assert(e.handle("refresh_subscription", {}))
    assert(e.files[POLICY] == policy and e.profile_fetches == 0 and direct_name(e.active_routes) == "domain:manual.example.test")
end

-- Validation and download failures retain the accepted profile, runtime and server snapshot.
for _, failure in ipairs({ "invalid_profile", "http", "timeout", "subscription_http", "subscription_offer", "xray", "dat_download", "dat_hash", "policy_write", "apply_head", "apply_capture", "settings_write" }) do
    local e = fixture()
    e:response({ "incy" }, profile("first"))
    e:load()
    assert(e:connect().state == "connected")
    assert(e.handle("refresh_subscription", {})) -- establish a refresh snapshot before the rejection
    local before = e:snapshot()
    e:response({ "incy" }, profile("second"))
    local expected, restart = nil, false
    if failure == "invalid_profile" then
        e.responses[PROFILE].body, expected = '{"GlobalProxy":"false","DomainStrategy":"AsIs"}', "routing_invalid"
    elseif failure == "http" then e.responses[PROFILE].status, expected = "503", "routing_download"
    elseif failure == "timeout" then e.responses[PROFILE].exit, expected = 28, "routing_download"
    elseif failure == "subscription_http" then e.responses[SUB].status, expected = "503", "subscription_unavailable"
    elseif failure == "subscription_offer" then
        e.responses[SUB].headers, expected = "autorouting: incy://autorouting/onadd/https://127.0.0.1/profile.json\r\n", "routing_invalid"
    elseif failure == "xray" then e.fail_routing_check, expected = true, "routing_check_failed"
    elseif failure == "dat_download" or failure == "dat_hash" then
        e.responses[PROFILE].body = profile("second", true)
        expected = failure == "dat_hash" and "routing_assets_invalid" or "routing_assets_download"
        e.fail_dat = expected
    elseif failure == "policy_write" then e.fail_policy_once, expected = true, "storage_error"
    elseif failure == "apply_head" then e.fail_head_for, expected, restart = "domain:second.example.test", "check_failed", true
    elseif failure == "apply_capture" then e.fail_capture_for, expected, restart = "domain:second.example.test", "capture_failed", true
    elseif failure == "settings_write" then e.fail_settings_once, expected, restart = true, "storage_error", true end
    e:reject("refresh_subscription", {}, expected)
    e:retained(before, restart)
    if failure == "dat_download" or failure == "dat_hash" then assert(e.dat_fetches == 1) end
end

-- A visible successful intent whose sync fails must keep runtime and policy consistent.
do
    local e = fixture()
    e:response({ "happ" }, profile("first"))
    e:load()
    assert(e:connect().state == "connected")
    e:response({ "happ" }, profile("second"))
    e.fail_settings_sync_once = true
    e:reject("refresh_subscription", {}, "storage_error")
    assert(e.running and e.captured and e.guarded and direct_name(e.active_routes) == "domain:second.example.test")
    assert(direct_name(e:get(POLICY).routing.rules) == "domain:second.example.test")
    assert(e.handle("settings", {}).routingStatus.state == "applied")
end

-- Subscription bindings do not follow an unrelated replacement provider, and opt-out persists.
do
    local e = fixture()
    e:response({ "happ" }, profile("first"))
    e:load()
    assert(e:connect().state == "connected")
    assert(e.handle("disconnect", {}).state == "disconnected")
    e.responses[OTHER] = { body = LINK .. "#Other" }
    e:load(OTHER, OTHER_HOST)
    assert(assert(e:connect()).state == "connected")
    assert(not e:get(POLICY).routing and not e:get(POLICY).routingSubscription and not e.active_routes)
    assert(e.handle("disconnect", {}).state == "disconnected")
    assert(not e.handle("remove_subscription", {}).hasSubscription)
    e:response({ "happ", "incy" }, profile("first"))
    e:load()
    assert(e:connect("none").state == "connected")
    assert(not e:get(POLICY).routing and e:get(POLICY).routingSubscription.source == "none")
    assert(e.handle("refresh_subscription", {}))
    assert(e.profile_fetches == 0 and not e.active_routes and e:get(POLICY).routingSubscription.source == "none")
end

-- Freeze virtual disk/runtime at durable-write boundaries, discarding ordinary callback rollback.
-- Lua 5.1 cannot yield across pcall; restoring these snapshots models an abrupt process/power loss.
for _, point in ipairs({
    { operation = "written", path = TRANSACTION, reboot = true },
    { operation = "written", path = POLICY, reboot = true },
    { operation = "written", path = SETTINGS, reboot = true },
    { operation = "removing", path = TRANSACTION, reboot = true },
    { operation = "removing", path = TRANSACTION, reboot = false },
}) do
    local e = fixture()
    e:response({ "incy" }, profile("first"))
    e:load()
    assert(e:connect().state == "connected")
    local before = e:snapshot()
    e:response({ "incy" }, profile("second"))
    e.cut_trigger = point
    assert(e.handle("refresh_subscription", {}).state == "reconnected")
    e:restore_cut(point.reboot)
    assert(e.files[TRANSACTION], "power loss discarded the durable rollback record")
    local rollback = e:get(TRANSACTION)
    assert(json.equal(rollback.policy, json.decode(before.policy)) and json.equal(rollback.settings, json.decode(before.settings)))
    if point.operation == "removing" and not point.reboot then
        assert(e.running and e.captured and e.guarded and direct_name(e.active_routes) == "domain:second.example.test")
    end
    local fetches = e.subscription_fetches + e.profile_fetches
    e.responses = {} -- recovery must rely exclusively on the complete previous local configuration
    local result = assert(e.handle(point.reboot and "restore" or "status", {}))
    assert(result.state == "connected" and result.serverId == e.selected.server)
    assert(e.files[POLICY] == before.policy and e.files[SETTINGS] == before.settings)
    assert(direct_name(e.active_routes) == "domain:first.example.test" and e.running and e.captured and e.guarded)
    assert(not e.files[TRANSACTION] and e.subscription_fetches + e.profile_fetches == fetches)
    local starts = e.starts
    assert(e.handle("status", {}).state == "connected" and e.starts == starts, "completed recovery restarted again")
end

-- Failed recovery retains the rollback record and fail-closed guard for a later retry.
do
    local e = fixture()
    e:response({ "happ" }, profile("first"))
    e:load()
    assert(e:connect().state == "connected")
    local before = e:snapshot()
    e:response({ "happ" }, profile("second"))
    e.cut_trigger = { operation = "written", path = POLICY }
    assert(e.handle("refresh_subscription", {}).state == "reconnected")
    e:restore_cut(true)
    local fetches = e.subscription_fetches + e.profile_fetches
    e.responses, e.fail_head_for = {}, "domain:first.example.test"
    e:reject("restore", {}, "rollback_failed")
    assert(e.files[TRANSACTION] and e.guarded and not e.running and not e.captured)
    assert(e.files[POLICY] == before.policy and e.files[SETTINGS] == before.settings)
    assert(e.subscription_fetches + e.profile_fetches == fetches)
    e.fail_head_for = nil
    assert(e.handle("status", {}).state == "connected")
    assert(not e.files[TRANSACTION] and e.guarded and e.running and e.captured)
    assert(direct_name(e.active_routes) == "domain:first.example.test" and e.subscription_fetches + e.profile_fetches == fetches)
end

-- An interrupted first connection has no previous active intent to resurrect.
do
    local e = fixture()
    e:response({ "happ" }, profile("first"))
    e:load()
    e.cut_trigger = { operation = "removing", path = TRANSACTION }
    assert(e:connect().state == "connected")
    e:restore_cut(true)
    assert(e:get(TRANSACTION).settings == false)
    local fetches = e.subscription_fetches + e.profile_fetches
    e.responses = {}
    assert(e.handle("status", {}).state == "disconnected")
    assert(not e.files[SETTINGS] and not e:get(POLICY).routing and not e.files[TRANSACTION])
    assert(not e.running and not e.captured and not e.guarded and e.subscription_fetches + e.profile_fetches == fetches)
end

-- An ordinary failed first connection has no SETTINGS file for rollback to unlink.
do
    local e = fixture()
    e:response({ "happ" }, profile("first"))
    e:load()
    e.fail_head_for = "domain:first.example.test"
    e:reject("connect", e.selected, "check_failed")
    assert(not e.files[SETTINGS] and not e.files[TRANSACTION])
    assert(not e:get(POLICY).routing and not e.running and not e.captured and not e.guarded)
    local fetches = e.subscription_fetches + e.profile_fetches
    e.responses = {}
    assert(e.handle("status", {}).state == "disconnected")
    assert(not e.files[TRANSACTION] and e.subscription_fetches + e.profile_fetches == fetches)
end

-- Explicit Disconnect cancels a pending recovery even when its previous server remains unavailable.
for _, interruption in ipairs({ "none", "reboot", "process" }) do
    local e = fixture()
    e:response({ "happ" }, profile("first"))
    e:load()
    assert(e:connect().state == "connected")
    local before = e:snapshot()
    e:response({ "happ" }, profile("second"))
    e.cut_trigger = { operation = "written", path = POLICY }
    assert(e.handle("refresh_subscription", {}).state == "reconnected")
    e:restore_cut(true)
    e.responses, e.fail_head_for = {}, "domain:first.example.test"
    e:reject("status", {}, "rollback_failed")
    assert(e.files[TRANSACTION] and e.guarded and not e.running and not e.captured)
    local fetches, starts = e.subscription_fetches + e.profile_fetches, e.starts
    if interruption ~= "none" then e.cut_trigger = { operation = "written", path = TRANSACTION } end
    assert(e.handle("disconnect", {}).state == "disconnected")
    if interruption ~= "none" then
        e:restore_cut(interruption == "reboot")
        assert(e.files[TRANSACTION] and e:get(TRANSACTION).settings.resume == false,
            "Disconnect cancellation did not survive its durable transaction write")
        assert(e.handle("status", {}).state == "disconnected")
    end
    local expected = json.decode(before.settings)
    expected.resume = false
    assert(json.equal(e:get(SETTINGS), expected) and e.files[POLICY] == before.policy)
    assert(not e.files[TRANSACTION] and not e.running and not e.captured and not e.guarded)
    assert(e.subscription_fetches + e.profile_fetches == fetches and e.starts == starts,
        "Disconnect tried to reconnect the unreachable rollback server")
    e:reboot()
    assert(e.handle("restore", {}).state == "disconnected" and e.handle("status", {}).state == "disconnected")
    assert(e:get(SETTINGS).resume == false and not e.files[TRANSACTION] and e.starts == starts)
    assert(not e.running and not e.captured and not e.guarded and e.subscription_fetches + e.profile_fetches == fetches)
end

print("subscription routing lifecycle tests passed")
