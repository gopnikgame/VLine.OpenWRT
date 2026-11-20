local json = dofile("route_json.lua")
local core = assert(loadfile("route_core.lua"))(json)
local assets = "/usr/share/vpn-routing/xray"
local xray = "/usr/libexec/vpn-routing/deps/xray"
local active_config = "/run/vpn-routing/xray.json"
local dir = "/fixture"
local ip_hash, site_hash = string.rep("a", 64), string.rep("b", 64)
local files = {}
local xray_code, xray_present, writes_allowed = 0, true, true
local asset_mode, digest_ok, calls = "rw-r--r--", true, 0
local active_mode = "rw-------"

local platform = {
    runtime_dir = "/run/vpn-routing",
    dependency = function(name) assert(name == "xray"); return xray end,
    xray_assets = function() return assets end,
    executable = function(path) return path ~= xray or xray_present end,
    tcp_port = function() return 32109 end,
    random_hex = function() return string.rep("1", 32) end,
    lstat = function(path)
        if path == active_config and files[path] then return { uid = 0, type = "reg", modestr = active_mode } end
        if path == assets .. "/geoip.dat" or path == assets .. "/geosite.dat" then
            return { uid = 0, type = "reg", modestr = asset_mode }
        end
        if assets:sub(1, #path) == path then return { uid = 0, type = "dir", modestr = "rwxr-xr-x" } end
    end,
    read = function(path) return files[path] end,
    write = function(path, bytes)
        assert(path == dir .. "/candidate.json")
        if not writes_allowed then return nil end
        files[path] = bytes
        return true
    end,
    run = function(argv, options)
        calls = calls + 1
        if argv[1] == "/bin/busybox" then
            assert(#argv == 4 and argv[2] == "sha256sum")
            assert(argv[3] == assets .. "/geoip.dat" and argv[4] == assets .. "/geosite.dat")
            files[options.stdout] = (digest_ok and ip_hash or site_hash) .. "  " .. argv[3] .. "\n"
                .. site_hash .. "  " .. argv[4] .. "\n"
            return 0
        end
        assert(#argv == 5 and argv[1] == xray and argv[2] == "run" and argv[3] == "-test"
            and argv[4] == "-config" and argv[5] == dir .. "/candidate.json")
        assert(options.env.XRAY_LOCATION_ASSET == assets)
        return xray_code
    end,
}

local function read(path)
    local input = assert(io.open(path, "rb"))
    local value = input:read("*a")
    input:close()
    return value
end
local function rejected(code, result, reason)
    assert(result == nil and reason == code, "expected " .. code .. ", got " .. tostring(reason))
end

local headers, policy = read("examples/headers.txt"), read("examples/policy.json")
local routing = dofile("luci/runtime/routing.lua")(json, platform, core)
local happ = assert(routing.compile({ source = "happ", headers = headers, policy = policy, profile = "" }))
assert(happ.source == "happ" and not happ.geo and #happ.rules.rules == 4)
assert(not json.encode(happ):find("://", 1, true))
for _, rule in ipairs(happ.rules.rules) do
    assert(#rule.inboundTag == 1 and rule.inboundTag[1] == "vpn-routing-tproxy")
end
local routes = assert(routing.configure(assert(routing.validate(json.decode(json.encode(happ)))), dir))
assert(calls == 0 and json.equal(routes, happ.rules))

local bad = json.decode(json.encode(happ))
bad.rules.rules[1].inboundTag[1] = "vpn-routing-health"
assert(not routing.validate(bad))
bad.rules.rules[1].inboundTag[1] = "vpn-routing-tproxy"
bad.rules.rules[1].network = "udp"
assert(not routing.validate(bad))
bad.rules.rules[1].network = nil
bad.rules.rules[1].domain[1] = "ext:injected.dat:category"
assert(not routing.validate(bad))
rejected("routing_invalid", routing.compile({ source = "happ", headers = "secret", policy = policy }))

local incy_profile = json.decode(read("examples/profile.json"))
incy_profile.DomainStrategy = "AsIs"
incy_profile.ProxySites[2] = "geosite:allowed"
incy_profile.DirectIp[3] = "geoip:allowed"
local incy_policy = json.decode(policy)
incy_policy.geo = json.object({
    geoip = json.object({ sha256 = ip_hash, categories = json.array({ "allowed" }) }),
    geosite = json.object({ sha256 = site_hash, categories = json.array({ "allowed" }) }),
})
local params = { source = "incy", headers = headers, profile = json.encode(incy_profile), policy = json.encode(incy_policy) }
local incy = assert(routing.compile(params))
assert(incy.source == "incy" and incy.geo.geoip == ip_hash and incy.geo.geosite == site_hash)
local fallback = incy.rules.rules[#incy.rules.rules]
assert(fallback.ruleTag == "vpn-routing-fallback" and fallback.outboundTag == "proxy")
assert(json.equal(routing.summary(happ), json.object({ proxy = 1, direct = 3, block = 1 })))
local counts, listed = routing.summary(incy)
assert(json.equal(counts, json.object({ proxy = 2, direct = 4, block = 1 })))
assert(#listed == #incy.rules.rules - 1 and listed[1].tag == "block" and listed[1].kind == "domain")
assert(listed[#listed].tag == "direct" and listed[#listed].kind == "ip")
assert(json.equal(listed[#listed].values, incy.rules.rules[#listed].ip))
assert(routing.configure(assert(routing.validate(incy)), dir))
digest_ok = false
rejected("routing_assets", routing.configure(incy, dir))
digest_ok, asset_mode = true, "rw-rw-r--"
local before = calls
rejected("routing_assets", routing.configure(incy, dir))
assert(calls == before, "writable DAT was read")
local tampered = json.decode(json.encode(incy))
tampered.rules.rules[#tampered.rules.rules] = nil
assert(not routing.validate(tampered), "AsIs lost its fallback")
tampered = json.decode(json.encode(incy))
tampered.geo = nil
assert(not routing.validate(tampered), "DAT hash requirement was lost")

local service = dofile("luci/runtime/service.lua")(json, platform, 61229)
assert(service.validate_routing(dir, routes))
local test_cfg = json.decode(files[dir .. "/candidate.json"])
assert(test_cfg.outbounds[1].tag == "proxy" and test_cfg.outbounds[1].protocol == "blackhole")
local outbound = json.object({ tag = "proxy", protocol = "vless" })
local candidate = assert(service.stage(dir, outbound, routes))
assert(candidate.health_port == 32109)
local cfg = json.decode(candidate.bytes)
assert(not cfg.dns and #cfg.outbounds == 3 and json.equal(cfg.outbounds[1], outbound))
assert(cfg.outbounds[2].tag == "direct" and cfg.outbounds[2].protocol == "freedom")
assert(cfg.outbounds[3].tag == "block" and cfg.outbounds[3].protocol == "blackhole")
assert(cfg.inbounds[1].sniffing.enabled and cfg.inbounds[1].sniffing.routeOnly and not cfg.inbounds[2].sniffing)
assert(cfg.routing.rules[1].outboundTag == "proxy" and cfg.routing.rules[1].inboundTag[1] == "vpn-routing-health")
for i, rule in ipairs(routes.rules) do assert(json.equal(cfg.routing.rules[i + 1], rule)) end
local ip_rules = json.object({ domainStrategy = "IPIfNonMatch", rules = json.array({ routes.rules[#routes.rules] }) })
local ip_cfg = json.decode(assert(service.stage(dir, outbound, ip_rules)).bytes)
assert(ip_cfg.routing and not ip_cfg.inbounds[1].sniffing)
local baseline = json.decode(assert(service.stage(dir, outbound)).bytes)
assert(#baseline.outbounds == 1 and not baseline.routing and not baseline.inbounds[1].sniffing)

assert(not service.routing_matches(routes, candidate.health_port))
files[active_config] = candidate.bytes
assert(service.routing_matches(routes, candidate.health_port))
assert(not service.routing_matches(routes, candidate.health_port + 1))
assert(not service.routing_matches(nil, candidate.health_port))
active_mode = "rw-r--r--"
assert(not service.routing_matches(routes, candidate.health_port))
active_mode = "rw-------"
cfg.routing.rules[2], cfg.routing.rules[3] = cfg.routing.rules[3], cfg.routing.rules[2]
files[active_config] = json.encode(cfg)
assert(not service.routing_matches(routes, candidate.health_port))
files[active_config] = json.encode(baseline)
assert(service.routing_matches(nil, candidate.health_port))
assert(not service.routing_matches(routes, candidate.health_port))
files[active_config] = "{"
assert(not service.routing_matches(nil, candidate.health_port))

xray_code = 23
rejected("routing_check_failed", service.validate_routing(dir, routes))
rejected("routing_check_failed", service.stage(dir, outbound, routes))
rejected("invalid_server", service.stage(dir, outbound))
writes_allowed = false
rejected("storage_error", service.validate_routing(dir, routes))
xray_present = false
rejected("dependency_missing", service.validate_routing(dir, routes))
print("routing runtime tests passed")
