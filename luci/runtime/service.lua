return function(json, platform, port)
    local xray = platform.dependency("xray")
    local assets = platform.xray_assets()
    local init = "/etc/init.d/vpn-routing-xray"
    local name = "vpn-routing-xray"
    local config = platform.runtime_dir .. "/xray.json"
    local command = { xray, "run", "-config", config }
    local M = { control_user = "vpn-routing" }

    function M.available()
        return platform.executable(init) and platform.executable(xray)
    end

    local function instance(dir)
        local output = dir .. "/service"
        if platform.run({ "/bin/ubus", "call", "service", "list", '{"name":"vpn-routing-xray"}' },
            { timeout = 1.5, stdout = output }) ~= 0 then return nil end
        local raw = platform.read(output, 65536)
        local ok, list = pcall(json.decode, raw or "")
        if not ok or not json.is_object(list) then return nil end
        if not list[name] then return false end
        local service = list[name]
        local instances = json.is_object(service) and service.instances
        local main = json.is_object(instances) and instances.main
        if not json.is_object(main) or not json.is_array(main.command) or #main.command ~= #command then return nil end
        for index, arg in ipairs(command) do
            if main.command[index] ~= arg then return nil end
        end
        for key in pairs(instances) do
            if key ~= "main" then return nil end
        end
        return main
    end

    local function uses_assets(pid, asset_dir)
        local environment = platform.read("/proc/" .. pid .. "/environ", 65536)
        return environment and ("\0" .. environment):find("\0XRAY_LOCATION_ASSET=" .. asset_dir .. "\0", 1, true)
    end

    function M.inspect(dir, health_port, asset_dir)
        local state = instance(dir)
        if state == nil then return nil end
        if state == false then return "absent" end
        local pid = json.integer(state.pid)
        if state.running == true and pid and pid > 1 and health_port
            and platform.transparent_ready(pid, port, health_port)
            and (not asset_dir or uses_assets(pid, asset_dir)) then
            return "ready"
        end
        return "partial"
    end

    function M.can_start(dir)
        return not platform.lstat(config) and M.inspect(dir) == "absent"
    end

    local obj, array = json.object, json.array

    local function render(outbound, routes, health_port, password)
        local candidate = obj({
            log = obj({ access = "none", error = "none", loglevel = "none" }),
            inbounds = array({
                obj({ tag = "vpn-routing-tproxy", listen = "127.0.0.1", port = port, protocol = "dokodemo-door",
                    settings = obj({ network = "tcp,udp", followRedirect = true }),
                    streamSettings = obj({ sockopt = obj({ tproxy = "tproxy" }) }) }),
                obj({ tag = "vpn-routing-health", listen = "127.0.0.1", port = health_port, protocol = "socks",
                    settings = obj({ auth = "password", udp = false,
                        accounts = array({ obj({ user = M.control_user, pass = password }) }) }) }),
            }),
            outbounds = array({ outbound }),
        })
        if routes then
            candidate.outbounds[2] = obj({ tag = "direct", protocol = "freedom" })
            candidate.outbounds[3] = obj({ tag = "block", protocol = "blackhole" })
            local rules = array({
                obj({ type = "field", inboundTag = array({ "vpn-routing-health" }), outboundTag = "proxy" }),
            })
            local sniff_domains = false
            for _, rule in ipairs(routes.rules) do
                rules[#rules + 1] = rule
                sniff_domains = sniff_domains or rule.domain ~= nil
            end
            if sniff_domains then
                candidate.inbounds[1].sniffing = obj({
                    enabled = true, routeOnly = true, destOverride = array({ "http", "tls", "quic" }),
                })
            end
            candidate.routing = obj({ domainStrategy = routes.domainStrategy, rules = rules })
        end
        return json.encode(candidate)
    end

    -- Called after inspect() confirms the owned process and its health listener.
    -- VPN Routing writes this private config before starting Xray, and removes it on stop.
    function M.routing_matches(routes, health_port)
        local file = platform.lstat(config)
        if not file or file.type ~= "reg" or file.uid ~= 0 or file.modestr ~= "rw-------" then return false end
        local bytes = platform.read(config, 256 * 1024)
        local ok, active = pcall(json.decode, bytes or "")
        if not ok or not json.is_object(active) then return false end
        local outbound = json.is_array(active.outbounds) and active.outbounds[1]
        local health = json.is_array(active.inbounds) and active.inbounds[2]
        local settings = json.is_object(health) and health.settings
        local account = json.is_object(settings) and json.is_array(settings.accounts) and settings.accounts[1]
        if not json.is_object(outbound) or outbound.tag ~= "proxy"
            or not json.is_object(account) or type(account.pass) ~= "string" then return false end
        return bytes == render(outbound, routes, health_port, account.pass)
    end

    local function test_config(dir, bytes, rejection, asset_dir)
        local path = dir .. "/candidate.json"
        if not platform.write(path, bytes) then return nil, "storage_error" end
        local code, err = platform.run({ xray, "run", "-test", "-config", path }, {
            timeout = 4, env = { XRAY_LOCATION_ASSET = asset_dir or assets },
        })
        if code == 0 then return true end
        return nil, err == "dependency_missing" and err or rejection
    end

    function M.validate_routing(dir, routes, asset_dir)
        if not routes then return nil, "routing_invalid" end
        if not M.available() then return nil, "dependency_missing" end
        -- Xray -test builds the configuration without starting its listeners.
        local dummy = obj({ tag = "proxy", protocol = "blackhole" })
        local test_port = port == 65535 and 65534 or 65535
        return test_config(dir, render(dummy, routes, test_port, "validation"), "routing_check_failed", asset_dir)
    end

    function M.stage(dir, outbound, routes, asset_dir)
        if not M.available() then return nil, "dependency_missing" end
        local health_port, password = platform.tcp_port(), platform.random_hex(16)
        if not health_port or health_port == port or not password then return nil, "apply_failed" end
        local bytes = render(outbound, routes, health_port, password)
        local ok, err = test_config(dir, bytes, routes and "routing_check_failed" or "invalid_server", asset_dir)
        if not ok then return nil, err end
        return { bytes = bytes, health_port = health_port, password = password, asset_dir = asset_dir }
    end

    function M.start(dir, candidate, arm)
        if not M.can_start(dir) then return nil, "capture_conflict" end
        if not arm() then return nil, "storage_error" end
        if not platform.write(config, candidate.bytes) then return nil, "storage_error" end
        if platform.run({ init, "start", candidate.asset_dir }, { timeout = 3 }) ~= 0 then return nil, "apply_failed" end
        for _ = 1, 12 do
            local state = M.inspect(dir, candidate.health_port, candidate.asset_dir)
            if state == "ready" then return true end
            if not state then break end
            platform.sleep(0.1)
        end
        return nil, "apply_failed"
    end

    function M.stop(dir)
        local state = M.inspect(dir)
        if not state then return nil, "disconnect_failed" end
        if state ~= "absent" then
            if platform.run({ init, "stop" }, { timeout = 5 }) ~= 0 then return nil, "disconnect_failed" end
            for _ = 1, 10 do
                state = M.inspect(dir)
                if state == "absent" then break end
                platform.sleep(0.1)
            end
            if state ~= "absent" then return nil, "disconnect_failed" end
        end
        if platform.lstat(config) and not platform.remove(config) then return nil, "storage_error" end
        return true
    end

    return M
end
