local json = dofile("route_json.lua")
local core = assert(loadfile("route_core.lua"))(json)
local files, clock, sequence = {}, 100, 0
local runtime, config = "/run/vpn-routing", "/etc/vpn-routing"
local settings, policy, marker = config .. "/connection.json", config .. "/policy.json", runtime .. "/operation.json"
local cache = runtime .. "/subscription.json"
local refresh_cache = runtime .. "/subscription-refresh.json"
local device_path = "/etc/vpn-routing-hwid"
local locked, fail_settings_write, fail_settings_sync = false, false, false
local function put(path, value)
    files[path] = json.encode(json.object(value))
end
local function get(path)
    return files[path] and json.decode(files[path])
end
local platform = {
    runtime_dir = runtime, config_dir = config,
    lstat = function(path)
        if path == device_path then assert(locked, "device identity accessed outside backend lock") end
        if files[path] then return { type = "reg", uid = 0, modestr = "rw-------" } end
        return nil, 2
    end,
    read = function(path) return files[path] end,
    write = function(path, value, durable)
        if path == device_path then assert(durable and not files[path]) end
        if path == settings then assert(durable and #value <= 32 * 1024) end
        if path == settings and fail_settings_write then
            assert(durable)
            return nil
        end
        files[path] = value
        if path == settings and fail_settings_sync then
            assert(durable)
            return nil, "not_synced"
        end
        return true
    end,
    remove = function(path, durable)
        if path == settings then assert(durable) end
        files[path] = nil
        return true
    end,
    private_dir = function() return true end,
    sync_persistent = function(path) return path == device_path and files[path] ~= nil end,
    with_lock = function(callback)
        assert(not locked)
        locked = true
        local result, reason = callback()
        locked = false
        return result, reason
    end,
    with_workspace = function(callback) return callback(runtime .. "/job") end,
    uptime = function() return clock end,
    random_hex = function() sequence = sequence + 1; return string.format("%032x", sequence) end,
}
local fixture_host = "sub.example.invalid"
local fixture_url = "https://" .. fixture_host .. "/demo"
local fixture_link = "vless://synthetic"
local second_link = "vless://another"
local other_host = "another.example.invalid"
local other_url = "https://" .. other_host .. "/replacement"
local device = dofile("luci/runtime/device.lua")(platform)
local subscription_fetches = 0
local refresh_fixture, fetch_failure
local function permitted(url, hosts, approved)
    local host = url:match("^https://([^/]+)/")
    if (approved and approved ~= host) or not (hosts[host] or host == approved) then
        return nil, "source_not_allowed"
    end
    return host, url
end
local subscription = {
    permitted = permitted,
    parse_reserve = dofile("luci/runtime/subscription.lua")(json, platform, core, device).parse_reserve,
    fetch = function(url, hosts, approved)
        local host, err = permitted(url, hosts, approved)
        if not host then return nil, err end
        if not device.get() then return nil, "hwid_unavailable" end
        subscription_fetches = subscription_fetches + 1
        if fetch_failure then return nil, "subscription_unavailable" end
        if host == other_host then return { { name = "Другой сервис", link = "vless://replacement" } } end
        if refresh_fixture then
            local entries = {}
            for i, entry in ipairs(refresh_fixture) do entries[i] = { name = entry.name, link = entry.link } end
            return entries
        end
        return { { name = "Тестовый узел", link = fixture_link }, { name = "Тестовый узел 2", link = second_link } }
    end,
}
local captured, running, captured_scope = false, false, nil
local guarded, fail_guard_stop = false, false
local probe_code, fail_capture, fail_cleanup = 204, false, false
local fail_routing_check, staged_routes, applied_routes = false, nil, nil
local staged_link, reject_staged_link
local preprobe_code = 204
local route_config = json.object({ domainStrategy = "IPIfNonMatch", rules = json.array({
    json.object({ outboundTag = "direct", domain = json.array({ "full:local.test" }) }),
}) })
local order = {}
local function step(value) order[#order + 1] = value end
local guard = {
    inspect = function(scope)
        if not guarded then return "absent" end
        return scope and "active" or "conflict"
    end,
    start = function(scope)
        assert(scope.interface == "br-lan")
        if not guarded then step("guard_start") end
        guarded = true
        return true
    end,
    stop = function(scope)
        if not guarded then return true end
        assert(scope.interface == "br-lan" and not captured and not running)
        if fail_guard_stop then return nil, "guard_failed" end
        step("guard_stop")
        guarded = false
        return true
    end,
}
local probe = {
    outbound = function(_, link) return json.object({ tag = "proxy", link = link }) end,
    head = function()
        assert(running and not captured, "health check must precede capture")
        step("head")
        return { result = "response", httpCode = staged_link == reject_staged_link and 503 or probe_code, elapsedMs = 27 }
    end,
    check = function() return { result = "response", httpCode = preprobe_code, elapsedMs = 27 } end,
}
local capture_runtime = dofile("luci/runtime/capture.lua")(json, {
    runtime_dir = runtime, dependency = function(name) return "/usr/bin/" .. name end,
}, core)
local capture = {
    validate = capture_runtime.validate,
    networks = function()
        return json.array({ json.object({ device = "br-lan", label = "lan", clients = json.array() }) }), { lan = true }
    end,
    scope_on_network = function(scope, inventory)
        return inventory.lan and scope.interface == "br-lan"
            and (scope.mode == "all" or (#scope.sources == 1 and scope.sources[1] == "192.168.1.50"))
    end,
    inspect = function() return captured and "active" or "absent" end,
    start = function(scope, _, arm)
        assert(arm())
        captured_scope = scope
        assert(guarded and running and get(marker).captureArmed, "capture requires the guard, owned proxy and journal")
        step("capture_start")
        captured = true
        if fail_capture then return nil, "capture_failed" end
        return true
    end,
    stop = function()
        step("capture_stop")
        if fail_cleanup then return nil, "capture_failed" end
        captured = false
        return true
    end,
}
local service = {
    control_user = "vpn-routing",
    available = function() return true end,
    inspect = function() return running and "ready" or "absent" end,
    routing_matches = function(routes, health_port)
        assert(running and captured and guarded and health_port == 30000)
        return json.equal(applied_routes, routes)
    end,
    can_start = function() return not running end,
    stage = function(_, outbound, routes)
        staged_link, staged_routes = outbound.link, routes
        return { bytes = "{}", health_port = 30000, password = "synthetic" }
    end,
    validate_routing = function(_, routes)
        assert(routes == route_config)
        if fail_routing_check then return nil, "routing_check_failed" end
        return true
    end,
    start = function(_, _, arm)
        assert(arm())
        assert(get(marker).serviceArmed and not captured)
        step("xray_start")
        running = true
        applied_routes = staged_routes
        return true
    end,
    stop = function()
        assert(not captured, "Xray stopped before removing capture")
        step("xray_stop")
        running = false
        applied_routes = nil
        return true
    end,
}
local routing = {
    import = function(params, dir, validate_routing)
        assert(params.source == "happ" or params.source == "incy")
        local checked, err = validate_routing(dir, route_config)
        if not checked then return nil, err end
        return json.object({ source = params.source, rules = route_config })
    end,
    validate = function(value) return (value.source == "happ" or value.source == "incy") and value or nil end,
    configure = function() return route_config end,
    asset_path = function() return nil end,
    summary = dofile("luci/runtime/routing.lua")(json, platform, core).summary,
}
local handle = dofile("luci/runtime/connection.lua")(json, platform, core, subscription, probe, capture, service, routing, guard, device).handle
local function rejected(action, params, reason)
    local result, actual = handle(action, params)
    assert(result == nil and actual == reason, tostring(actual))
end
local profile = json.object({ interface = "br-lan", sources = json.array({ "192.168.1.50" }) })
assert(handle("status", {}).canConnect and not files[device_path])
-- Fresh installs require an explicit source confirmation before any request.
rejected("subscription", { url = fixture_url }, "source_not_allowed")
assert(subscription_fetches == 0)
assert(handle("subscription", { url = fixture_url, confirmHost = fixture_host }))
assert(subscription_fetches == 1 and handle("settings", {}).routing == nil)
assert(handle("remove_subscription", {}).hasSubscription == false)
subscription_fetches = 0
put(policy, { subscriptionHosts = json.array({ fixture_host }) })

local list = assert(handle("subscription", { url = fixture_url }))
assert(#list.servers == 2 and not list.servers[1].link and not list.url)
local selected = { snapshot = list.snapshot, server = list.servers[1].id }
local checked = assert(handle("probe", selected))
assert(checked.method == "HEAD" and checked.serverId == selected.server and checked.httpCode == 204)

local initial_policy = files[policy]
assert(handle("connect", selected).state == "connected")
assert(captured_scope.mode == "all" and captured_scope.interface == "br-lan" and not captured_scope.sources)
assert(get(settings).scope.mode == "all" and files[policy] == initial_policy)
local default_routing = assert(handle("settings", {})).routingStatus
assert(default_routing.state == "default" and not default_routing.counts and not default_routing.rules)
assert(handle("disconnect", {}).state == "disconnected")
files[settings], order = nil, {}

local settings_before = assert(handle("settings", {}))
local original_hwid = assert(settings_before.hwid)
assert(settings_before.editable and settings_before.capture.mode == "all"
    and settings_before.capture.interface == "br-lan" and not settings_before.capture.sources)
assert(settings_before.routingStatus.state == "inactive" and not settings_before.routingStatus.counts)
assert(files[device_path] == original_hwid .. "\n")
rejected("save_capture", { interface = "wan", sources = "192.168.1.50" }, "capture_policy")
rejected("save_capture", { mode = "all", interface = "br-lan", sources = "192.168.1.50" }, "capture_policy")
rejected("save_capture", { mode = "selected", interface = "br-lan" }, "capture_policy")
assert(files[policy] == initial_policy)
local all = assert(handle("save_capture", { mode = "all", interface = "br-lan" }))
assert(all.capture.mode == "all" and not get(policy).capture.sources)
local stored = assert(handle("save_capture", { interface = "br-lan", sources = " 192.168.1.50\n" }))
assert(stored.capture.mode == "selected" and stored.capture.sources[1] == "192.168.1.50"
    and get(policy).subscriptionHosts[1] == fixture_host)
local prior_scope = files[policy]
fail_routing_check = true
rejected("save_routing", { source = "happ" }, "routing_check_failed")
assert(files[policy] == prior_scope and not running and not captured)
fail_routing_check = false
local saved_profile = assert(handle("save_routing", { source = "happ" }))
assert(saved_profile.routing.source == "happ" and saved_profile.routingStatus.state == "inactive")
assert(json.equal(saved_profile.routingStatus.counts, json.object({ direct = 1, proxy = 0, block = 0 })))
assert(get(policy).capture.interface == "br-lan" and get(policy).subscriptionHosts[1] == fixture_host)
assert(handle("status", {}).canConnect)
probe_code = 503
rejected("connect", selected, "check_failed")
assert(not running and not captured and not get(settings) and not get(marker))
assert(table.concat(order, ",") == "xray_start,head,xray_stop")

probe_code, order = 204, {}
local connected = assert(handle("connect", selected))
assert(connected.state == "connected" and connected.serverId == selected.server)
assert(staged_routes == route_config)
assert(handle("status", {}).state == "connected")
local live_profile = assert(handle("settings", {}))
assert(not live_profile.editable and live_profile.routingStatus.state == "applied")
assert(json.equal(live_profile.routingStatus.counts, saved_profile.routingStatus.counts))
assert(json.equal(live_profile.routingStatus.rules, saved_profile.routingStatus.rules))
assert(json.equal(live_profile.routingStatus.rules, json.array({
    json.object({ tag = "direct", kind = "domain", values = json.array({ "full:local.test" }) }),
})))
local public_settings = json.encode(json.object(live_profile))
assert(not public_settings:find(fixture_url, 1, true) and not public_settings:find(fixture_link, 1, true))
applied_routes = nil
assert(handle("settings", {}).routingStatus.state == "unverified")
applied_routes = route_config
captured = false
assert(handle("settings", {}).routingStatus.state == "unverified")
captured = true
rejected("save_routing", { source = "none" }, "settings_busy")
assert(get(settings).url == fixture_url and get(settings).link == fixture_link)
assert(get(settings).resume == true and get(settings).scope.interface == "br-lan")
assert(table.concat(order, ",") == "xray_start,head,guard_start,capture_start")
rejected("connect", selected, "operation_pending")
rejected("remove_subscription", {}, "subscription_busy")
assert(handle("disconnect", {}).state == "disconnected")
assert(not running and not captured and not guarded and not get(marker))
assert(get(settings).resume == false)
assert(handle("status", {}).subscription.url == fixture_url)
assert(handle("settings", {}).routingStatus.state == "inactive")
assert(handle("save_routing", { source = "none" }).routing == nil)
assert(get(policy).capture.interface == "br-lan" and not get(policy).routing)
local previous = files[settings]

fail_capture, fail_cleanup = true, true
rejected("connect", selected, "rollback_failed")
assert(files[settings] == previous and running and captured)
assert(handle("status", {}).state == "degraded")
assert(handle("settings", {}).routingStatus.state == "unverified")
local interrupted = get(marker)
interrupted.startedAt = clock
put(marker, interrupted)
rejected("status", {}, "operation_pending")
rejected("disconnect", {}, "operation_pending")
clock, fail_cleanup = clock + 46, false
assert(handle("disconnect", {}).state == "disconnected")
assert(files[settings] == previous and not running and not captured)

clock = clock + 1800
rejected("probe", selected, "stale_snapshot")
local updated = assert(handle("subscription", { url = fixture_url }))
assert(updated.preferredServerId == selected.server and updated.snapshot ~= list.snapshot)
rejected("probe", selected, "stale_snapshot")
put(policy, { capture = profile, subscriptionHosts = json.array({ "other.example.invalid" }) })
rejected("probe", { snapshot = updated.snapshot, server = selected.server }, "source_not_allowed")

local function reboot()
    for path in pairs(files) do
        if path:sub(1, #runtime + 1) == runtime .. "/" then files[path] = nil end
    end
    running, captured, guarded, order, clock = false, false, false, {}, 1
end

put(policy, { capture = profile, subscriptionHosts = json.array({ fixture_host }) })
assert(handle("settings", {}).capture.mode == "selected" and not get(policy).capture.mode)
reboot()
local disconnected = files[settings]
files[settings] = nil
assert(handle("restore", {}).state == "disconnected" and #order == 0)
assert(handle("arm_guard", {}).state == "disconnected" and not guarded)
files[settings] = disconnected
assert(handle("restore", {}).state == "disconnected" and #order == 0)
local legacy = get(settings)
legacy.resume = nil
put(settings, legacy)
local legacy_bytes = files[settings]
assert(handle("restore", {}).state == "disconnected" and #order == 0)
assert(files[settings] == legacy_bytes)

local fresh = assert(handle("subscription", { url = fixture_url }))
local second = fresh.servers[2]
local choice = { snapshot = fresh.snapshot, server = second.id }
fail_capture = false
assert(handle("connect", choice).serverId == second.id)
assert(get(settings).resume == true and get(settings).link == second_link)
local persisted, fetches_before_boot, selected_policy = files[settings], subscription_fetches, files[policy]
put(policy, { subscriptionHosts = json.array({ fixture_host }) })
reboot()
local missing_scope = get(settings)
missing_scope.scope = nil
put(settings, missing_scope)
rejected("arm_guard", {}, "capture_not_configured")
assert(not guarded)
files[settings] = persisted
assert(handle("arm_guard", {}).state == "restoring" and guarded and not running and not captured)
local restoring = assert(handle("status", {}))
assert(restoring.state == "restoring" and restoring.serverId == second.id)
assert(restoring.subscription.url == fixture_url and restoring.subscription.savedOnly
    and restoring.subscription.servers[1].id == second.id)
local restoring_settings = assert(handle("settings", {}))
assert(not restoring_settings.editable and restoring_settings.routingStatus.state == "unverified")
rejected("save_capture", { interface = "br-lan", sources = "192.168.1.50" }, "settings_busy")
rejected("save_routing", { source = "none" }, "settings_busy")
rejected("remove_subscription", {}, "subscription_busy")

probe_code = 503
rejected("restore", {}, "check_failed")
assert(files[settings] == persisted and not running and not captured and guarded and not get(marker))
assert(handle("status", {}).state == "restoring")
probe_code, order = 204, {}
local restored = assert(handle("restore", {}))
assert(restored.state == "connected" and restored.serverId == second.id and restored.serverName == second.name)
assert(staged_link == second_link and subscription_fetches == fetches_before_boot)
assert(get(settings).resume == true and handle("status", {}).state == "connected")
assert(table.concat(order, ",") == "xray_start,head,capture_start")
assert(captured_scope.mode == "selected" and captured_scope.sources[1] == "192.168.1.50")
files[policy] = selected_policy

reboot()
fail_capture, fail_cleanup = true, true
rejected("restore", {}, "rollback_failed")
assert(get(marker).stopping and get(settings).resume and captured and running)
fail_capture, fail_cleanup = false, false
assert(handle("restore", {}).serverId == second.id)
assert(handle("status", {}).state == "connected")

fail_cleanup = true
rejected("disconnect", {}, "disconnect_failed")
assert(get(settings).resume == false and captured and running)
fail_cleanup = false
reboot()
assert(handle("restore", {}).state == "disconnected" and #order == 0)

fresh = assert(handle("subscription", { url = fixture_url }))
assert(handle("connect", { snapshot = fresh.snapshot, server = fresh.servers[1].id }).state == "connected")
reboot()
assert(handle("arm_guard", {}).state == "restoring" and guarded)
assert(handle("status", {}).state == "restoring")
assert(handle("disconnect", {}).state == "disconnected")
assert(get(settings).resume == false and handle("restore", {}).state == "disconnected" and not guarded)

fresh = assert(handle("subscription", { url = fixture_url }))
fail_settings_sync = true
rejected("connect", { snapshot = fresh.snapshot, server = fresh.servers[1].id }, "storage_error")
assert(get(settings).resume and handle("status", {}).state == "connected")
rejected("disconnect", {}, "storage_error")
assert(not get(settings).resume and handle("status", {}).state == "disconnected" and not running and not captured)
fail_settings_sync = false

assert(handle("connect", { snapshot = fresh.snapshot, server = fresh.servers[1].id }).state == "connected")
fail_guard_stop = true
rejected("disconnect", {}, "disconnect_failed")
assert(guarded and not running and not captured and get(marker).stopping)
rejected("remove_subscription", {}, "subscription_busy")
fail_guard_stop = false
assert(handle("disconnect", {}).state == "disconnected" and not guarded)

local original_policy = files[policy]
local removed = assert(handle("remove_subscription", {}))
assert(removed.state == "disconnected" and removed.hasSubscription == false and not removed.subscription)
assert(not files[settings] and not files[cache] and files[policy] == original_policy)
rejected("probe", { snapshot = fresh.snapshot, server = fresh.servers[1].id }, "stale_snapshot")
rejected("subscription", { url = other_url }, "source_not_allowed")
rejected("subscription", { url = other_url, confirmHost = fixture_host }, "source_not_allowed")
local replacement = assert(handle("subscription", { url = other_url, confirmHost = other_host }))
assert(handle("status", {}).subscription.url == other_url)
replacement = assert(handle("subscription", { url = other_url }))
assert(handle("connect", { snapshot = replacement.snapshot, server = replacement.servers[1].id }).state == "connected")
assert(get(settings).sourceHost == other_host and get(settings).url == other_url)
local replacement_fetches = subscription_fetches
reboot()
assert(handle("restore", {}).serverId == replacement.servers[1].id)
assert(subscription_fetches == replacement_fetches and guarded)
assert(handle("settings", {}).hwid == original_hwid)
assert(handle("disconnect", {}).state == "disconnected")
assert(handle("remove_subscription", {}).hasSubscription == false)
assert(handle("remove_subscription", {}).hasSubscription == false)
assert(handle("settings", {}).hwid == original_hwid)

put(policy, { capture = profile, subscriptionHosts = json.array({ fixture_host }) })
local before_idle = subscription_fetches
assert(handle("refresh_subscription", {}).state == "idle" and subscription_fetches == before_idle)
local first_uri = "vless://11111111-1111-4111-8111-111111111111@router.example.invalid:443?security=reality"
local changed_uri = "vless://22222222-2222-4222-8222-222222222222@router.example.invalid:443?security=reality"
local next_uri = "vless://33333333-3333-4333-8333-333333333333@router.example.invalid:443?security=reality"
local moved_uri = changed_uri:gsub("router.example", "different.example")
local first_entry = { name = "Узел 1", link = first_uri }
local second_entry = { name = "Узел 2", link = second_link }
local function refresh_result(state)
    local result, err = handle("refresh_subscription", {})
    assert(result and result.state == state, tostring(err or result and result.state))
    return get(refresh_cache)
end
refresh_fixture = { first_entry, second_entry }
fresh = assert(handle("subscription", { url = fixture_url }))
local active_id = fresh.servers[1].id
assert(handle("connect", { snapshot = fresh.snapshot, server = active_id }).state == "connected")
local scheduled = refresh_result("updated")
assert(handle("status", {}).subscription.snapshot == scheduled.snapshot)
rejected("probe", { snapshot = fresh.snapshot, server = active_id }, "stale_snapshot")
local recent = assert(handle("subscription", { url = fixture_url }))
assert(handle("status", {}).subscription.snapshot == recent.snapshot)
rejected("probe", { snapshot = scheduled.snapshot, server = active_id }, "stale_snapshot")
assert(handle("probe", { snapshot = recent.snapshot, server = active_id }).httpCode == 204)
clock = clock + 1800
assert(handle("status", {}).subscription.snapshot == recent.snapshot)
local draft = assert(handle("subscription", { url = other_url, confirmHost = other_host }))
local draft_bytes = files[cache]
order = {}
local automatic = refresh_result("unchanged")
assert(automatic.servers[1].id == active_id and #order == 0 and files[cache] == draft_bytes)
assert(handle("probe", { snapshot = draft.snapshot, server = draft.servers[1].id }).httpCode == 204)
clock = clock + 1800
assert(handle("status", {}).subscription.snapshot == automatic.snapshot)
assert(refresh_result("unchanged").snapshot == automatic.snapshot and #order == 0)

local saved_bytes, auto_bytes = files[settings], files[refresh_cache]
fetch_failure = true
rejected("refresh_subscription", {}, "subscription_unavailable")
assert(files[settings] == saved_bytes and files[refresh_cache] == auto_bytes and #order == 0)
fetch_failure = false

refresh_fixture = { second_entry, { name = first_entry.name, link = moved_uri } }
assert(#refresh_result("retained").servers == 2 and files[settings] == saved_bytes and #order == 0)
refresh_fixture = { { name = first_entry.name, link = changed_uri }, { name = first_entry.name, link = next_uri } }
refresh_result("retained")
assert(files[settings] == saved_bytes and #order == 0)
refresh_fixture = { second_entry, { name = "Переименован", link = first_uri } }
local renamed = refresh_result("updated")
assert(renamed.servers[2].id == active_id and handle("status", {}).serverName == "Переименован" and #order == 0)

refresh_fixture = { second_entry, { name = "Переименован", link = changed_uri } }
saved_bytes = files[settings]
preprobe_code = 503
rejected("refresh_subscription", {}, "check_failed")
assert(files[settings] == saved_bytes and #order == 0 and running and captured and guarded)
preprobe_code, reject_staged_link = 204, changed_uri
rejected("refresh_subscription", {}, "check_failed")
assert(files[settings] == saved_bytes and handle("status", {}).state == "connected" and staged_link == first_uri)
assert(table.concat(order, ",") == "capture_stop,xray_stop,xray_start,head,xray_stop,xray_start,head,capture_start")

order, reject_staged_link = {}, nil
local generation_before = get(settings).generation
local rotated = refresh_result("reconnected")
assert(rotated.servers[2].id == active_id and get(settings).link == changed_uri)
assert(get(settings).generation == generation_before and not get(marker).stopping and guarded)
assert(captured_scope.mode == "selected" and captured_scope.sources[1] == "192.168.1.50")
assert(table.concat(order, ",") == "capture_stop,xray_stop,xray_start,head,capture_start")
local stopped = get(marker)
stopped.stopping, stopped.startedAt = true, clock
put(marker, stopped)
rejected("refresh_subscription", {}, "operation_pending")
clock = clock + 46
order = {}
refresh_result("unchanged")
assert(handle("status", {}).state == "connected" and get(settings).link == changed_uri and guarded)
assert(table.concat(order, ",") == "capture_stop,xray_stop,xray_start,head,capture_start")

stopped = get(marker)
stopped.stopping, stopped.serviceArmed, stopped.captureArmed = true, false, false
put(marker, stopped)
running, captured, order = false, false, {}
clock = clock + 46
refresh_result("unchanged")
assert(handle("status", {}).state == "connected" and guarded)
assert(table.concat(order, ",") == "xray_start,head,capture_start")

refresh_fixture = { { name = "Переименован", link = next_uri } }
fail_settings_sync = true
rejected("refresh_subscription", {}, "storage_error")
fail_settings_sync = false
assert(get(settings).link == next_uri and handle("status", {}).state == "connected" and guarded)
assert(handle("disconnect", {}).state == "disconnected")
refresh_fixture = { { name = "Переименован", link = changed_uri }, second_entry }
order = {}
local disconnected_list = refresh_result("updated")
assert(not running and not captured and not guarded and #order == 0 and get(settings).resume == false)
assert(disconnected_list.servers[1].id == active_id)
assert(handle("probe", { snapshot = disconnected_list.snapshot, server = active_id }).httpCode == 204)
refresh_fixture = { second_entry }
local manually_removed = assert(handle("subscription", { url = fixture_url }))
assert(#manually_removed.servers == 1 and manually_removed.servers[1].id ~= active_id)
assert(handle("subscription", { url = other_url, confirmHost = other_host }))
assert(handle("status", {}).subscription.snapshot == manually_removed.snapshot)
rejected("connect", { snapshot = disconnected_list.snapshot, server = active_id }, "stale_snapshot")
assert(handle("remove_subscription", {}).hasSubscription == false and not files[refresh_cache])
refresh_fixture = nil

-- Manual selection is a compare-and-switch against the last confirmed active server.
fresh = assert(handle("subscription", { url = fixture_url }))
local original_id = fresh.servers[1].id
local handoff = { snapshot = fresh.snapshot, server = fresh.servers[2].id, activeServer = original_id }
rejected("connect", handoff, "connection_changed")
assert(handle("connect", { snapshot = fresh.snapshot, server = original_id }).state == "connected")
local active_snapshot = refresh_result("updated")
local target = active_snapshot.servers[2]
handoff.snapshot, handoff.server = active_snapshot.snapshot, target.id
local previous_bytes = files[settings]
local foreign = assert(handle("subscription", { url = other_url, confirmHost = other_host }))
order = {}
rejected("connect", { snapshot = foreign.snapshot, server = foreign.servers[1].id, activeServer = original_id },
    "connection_changed")
rejected("connect", { snapshot = handoff.snapshot, server = handoff.server, activeServer = "stale-active" },
    "connection_changed")
rejected("connect", { snapshot = handoff.snapshot, server = original_id, activeServer = original_id },
    "connection_changed")
rejected("connect", { snapshot = fresh.snapshot, server = fresh.servers[2].id, activeServer = original_id },
    "stale_snapshot")
local old_operation = get(marker)
old_operation.stopping = true
put(marker, old_operation)
rejected("connect", handoff, "connection_changed")
old_operation.stopping = false
put(marker, old_operation)
assert(#order == 0 and files[settings] == previous_bytes and guarded and running and captured)

preprobe_code = 503
rejected("connect", handoff, "check_failed")
assert(#order == 0 and files[settings] == previous_bytes and guarded and running and captured)
preprobe_code, reject_staged_link = 204, second_link
rejected("connect", handoff, "check_failed")
assert(files[settings] == previous_bytes and get(marker).serverId == original_id and guarded)
assert(handle("status", {}).state == "connected" and staged_link == fixture_link)
assert(table.concat(order, ",") == "capture_stop,xray_stop,xray_start,head,xray_stop,xray_start,head,capture_start")

reject_staged_link, fail_settings_write = nil, true
rejected("connect", handoff, "storage_error")
assert(files[settings] == previous_bytes and handle("status", {}).serverId == original_id and guarded)
fail_settings_write, order = false, {}
local switched = assert(handle("connect", handoff))
assert(switched.state == "connected" and switched.serverId == target.id and switched.serverName == target.name)
local chosen = get(settings)
assert(chosen.resume and chosen.serverId == target.id and chosen.link == second_link and chosen.url == fixture_url)
assert(get(marker).serverId == target.id and guarded and not get(marker).stopping)
assert(captured_scope.mode == "selected" and captured_scope.sources[1] == "192.168.1.50")
assert(table.concat(order, ",") == "capture_stop,xray_stop,xray_start,head,capture_start")
rejected("connect", handoff, "connection_changed")
assert(refresh_result("unchanged").servers[2].id == target.id)

reboot()
assert(handle("arm_guard", {}).state == "restoring" and guarded and not running and not captured)
assert(handle("restore", {}).serverId == target.id and staged_link == second_link and guarded and captured)
local after_boot = assert(handle("subscription", { url = fixture_url }))
fail_settings_sync = true
rejected("connect", { snapshot = after_boot.snapshot, server = after_boot.servers[1].id, activeServer = target.id },
    "storage_error")
fail_settings_sync = false
assert(get(settings).serverId == after_boot.servers[1].id and get(settings).link == fixture_link)
assert(handle("status", {}).state == "connected" and guarded and captured)
assert(handle("disconnect", {}).state == "disconnected")
assert(handle("remove_subscription", {}).hasSubscription == false)

-- The reserve and last good MYSUB survive independent writes and a cold boot.
do
    local backup_link = "vless://12345678-1234-4234-8234-1234567890ab@backup.example.invalid:443"
        .. "?type=tcp&security=reality&flow=xtls-rprx-vision&sni=front.example.invalid"
        .. "&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=01234567"
    local legacy_id = "legacy-server"
    put(settings, { generation = "legacy-generation", url = fixture_url, sourceHost = fixture_host,
        link = first_uri, serverId = legacy_id, serverName = first_entry.name, scope = profile, resume = true })
    reboot()
    assert(handle("restore", {}).serverId == legacy_id and staged_link == first_uri and guarded and captured)
    rejected("save_reserve", { name = "Резерв", link = backup_link .. "\n" .. backup_link }, "invalid_server")
    rejected("save_reserve", { name = "12345678-1234-4234-8234-1234567890ab", link = backup_link }, "invalid_reserve_name")
    local result = assert(handle("save_reserve", { name = "Резерв", link = backup_link .. "#ignored" }))
    local older = result.reserve
    assert(result.activeSource == "subscription" and result.serverId == legacy_id and result.state == "connected")
    assert(older.name == "Резерв" and not older.link and get(settings).reserve.link == backup_link)
    assert(get(settings).url == fixture_url and get(settings).link == first_uri and get(settings).resume)
    rejected("save_reserve", { name = "Запас", link = backup_link }, "stale_snapshot")
    fail_settings_write = true
    rejected("save_reserve", { name = "Запас", link = backup_link, snapshot = older.snapshot }, "storage_error")
    fail_settings_write = false
    assert(get(settings).reserve.id == older.id)
    result = assert(handle("save_reserve", { name = "Запас", link = backup_link, snapshot = older.snapshot }))
    local reserve = result.reserve
    assert(reserve.id ~= older.id and reserve.snapshot ~= older.snapshot)
    rejected("probe", { snapshot = older.snapshot, server = older.id }, "stale_snapshot")
    rejected("remove_reserve", { snapshot = older.snapshot }, "stale_snapshot")
    rejected("save_reserve", { name = "Резерв", link = backup_link, snapshot = older.snapshot }, "stale_snapshot")
    local checked_backup = assert(handle("probe", { snapshot = reserve.snapshot, server = reserve.id }))
    assert(checked_backup.method == "HEAD" and checked_backup.httpCode == 204 and not checked_backup.link)

    local to_reserve = { snapshot = reserve.snapshot, server = reserve.id, activeServer = legacy_id }
    local before = files[settings]
    reject_staged_link = backup_link
    rejected("connect", to_reserve, "check_failed")
    assert(files[settings] == before and staged_link == first_uri and guarded and captured)
    reject_staged_link = nil
    result = assert(handle("connect", to_reserve))
    assert(result.activeSource == "reserve" and result.serverId == reserve.id and result.hasSavedSubscription)
    assert(get(settings).url == fixture_url and get(settings).link == first_uri and get(settings).resume)
    rejected("remove_reserve", { snapshot = reserve.snapshot }, "reserve_busy")
    rejected("save_reserve", { name = "Резерв", link = backup_link, snapshot = reserve.snapshot }, "reserve_busy")

    refresh_fixture, order = { { name = first_entry.name, link = changed_uri } }, {}
    assert(handle("refresh_subscription", {}).state == "updated")
    assert(#order == 0 and staged_link == backup_link and get(settings).link == first_uri)
    local stopping = get(marker)
    stopping.stopping = true
    put(marker, stopping)
    local before_recovery_fetches = subscription_fetches
    rejected("refresh_subscription", {}, "operation_pending")
    assert(subscription_fetches == before_recovery_fetches and #order == 0)
    clock = clock + 45
    assert(handle("refresh_subscription", {}).state == "unchanged")
    assert(staged_link == backup_link and guarded and running and captured and not get(marker).stopping)
    local fetches = subscription_fetches
    reboot()
    fetch_failure = true
    assert(handle("arm_guard", {}).state == "restoring" and guarded)
    rejected("remove_reserve", { snapshot = reserve.snapshot }, "reserve_busy")
    reject_staged_link = backup_link
    rejected("restore", {}, "check_failed")
    assert(guarded and not running and not captured and get(settings).activeSource == "reserve")
    assert(subscription_fetches == fetches)
    reject_staged_link = nil
    assert(handle("restore", {}).activeSource == "reserve" and staged_link == backup_link)
    assert(subscription_fetches == fetches)
    rejected("refresh_subscription", {}, "subscription_unavailable")
    result = assert(handle("status", {}))
    local cached_primary = result.subscription
    assert(result.serverId == reserve.id and cached_primary.savedOnly and cached_primary.servers[1].id == legacy_id)
    assert(not json.encode(json.object(result)):find("12345678-1234-4234-8234-1234567890ab", 1, true))
    local to_primary = { snapshot = cached_primary.snapshot, server = legacy_id, activeServer = reserve.id }
    reject_staged_link = first_uri
    rejected("connect", to_primary, "check_failed")
    assert(handle("status", {}).serverId == reserve.id and staged_link == backup_link and guarded and captured)
    reject_staged_link = nil
    assert(handle("connect", to_primary).activeSource == "subscription" and staged_link == first_uri)
    assert(handle("status", {}).reserve.id == reserve.id and get(settings).reserve.link == backup_link)
    reboot()
    reject_staged_link = first_uri
    rejected("restore", {}, "check_failed")
    assert(guarded and not running and not captured and get(settings).activeSource == nil)
    reject_staged_link = nil
    assert(handle("restore", {}).serverId == legacy_id and staged_link == first_uri)
    assert(handle("connect", to_reserve).activeSource == "reserve")
    assert(handle("status", {}).subscription.snapshot == cached_primary.snapshot)
    assert(handle("connect", to_primary).activeSource == "subscription")
    assert(handle("connect", to_reserve).activeSource == "reserve")
    result = assert(handle("remove_subscription", {}))
    assert(result.state == "connected" and not result.hasSubscription and result.reserve.id == reserve.id)
    assert(get(settings).url == nil and get(settings).resume and get(settings).reserve.link == backup_link)
    rejected("probe", { snapshot = cached_primary.snapshot, server = legacy_id }, "stale_snapshot")
    fetches = subscription_fetches
    assert(handle("refresh_subscription", {}).state == "idle" and subscription_fetches == fetches)
    reboot()
    reject_staged_link = backup_link
    rejected("refresh_subscription", {}, "check_failed")
    assert(guarded and not running and not captured and subscription_fetches == fetches)
    reject_staged_link = nil
    assert(handle("refresh_subscription", {}).state == "idle" and subscription_fetches == fetches)
    assert(handle("status", {}).serverId == reserve.id and staged_link == backup_link and running and captured)
    assert(handle("disconnect", {}).reserve.id == reserve.id)
    assert(not handle("remove_reserve", { snapshot = reserve.snapshot }).reserve and not files[settings])
    local standalone = assert(handle("save_reserve", { name = "Резерв без подписки", link = backup_link })).reserve
    assert(handle("connect", { snapshot = standalone.snapshot, server = standalone.id }).activeSource == "reserve")
    fetch_failure, refresh_fixture = false, nil
    local new_primary = assert(handle("subscription", { url = fixture_url }))
    assert(handle("connect", { snapshot = new_primary.snapshot, server = new_primary.servers[1].id,
        activeServer = standalone.id }).activeSource == "subscription")
    result = assert(handle("remove_reserve", { snapshot = standalone.snapshot }))
    assert(not result.reserve and result.state == "connected" and result.hasSavedSubscription)
    assert(handle("disconnect", {}).hasSavedSubscription)
    assert(not handle("remove_subscription", {}).hasSubscription and not files[settings])
end

files[device_path] = "invalid\n"
local current_settings = assert(handle("settings", {}))
assert(not current_settings.hwid and current_settings.editable)
rejected("subscription", { url = other_url }, "source_not_allowed")
rejected("subscription", { url = other_url, confirmHost = other_host }, "hwid_unavailable")
assert(files[device_path] == "invalid\n")
print("connection tests passed")
