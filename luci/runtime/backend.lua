return function(directory, json, core)
    local platform = dofile(directory .. "platform.lua")
    local device = dofile(directory .. "device.lua")(platform)
    local subscription = dofile(directory .. "subscription.lua")(json, platform, core, device)
    local probe = dofile(directory .. "probe.lua")(json, platform, core, subscription.hysteria_auth)
    local capture = dofile(directory .. "capture.lua")(json, platform, core)
    local service = dofile(directory .. "service.lua")(json, platform, capture.port)
    local geodata = dofile(directory .. "geodata.lua")(json, platform, core)
    local routing = dofile(directory .. "routing.lua")(json, platform, core, geodata)
    local guard = dofile(directory .. "guard.lua")(json, platform, capture.validate)
    local connection = dofile(directory .. "connection.lua")(json, platform, core, subscription, probe, capture,
        service, routing, guard, device)
    return {
        handle = function(action, params)
            if action == "dns_settings" or action == "check_dns" or action == "apply_dns" then
                local dns = dofile(directory .. "dns.lua")(json, platform, core)
                return platform.with_lock(function()
                    return platform.with_workspace(function(dir) return dns.handle(dir, action, params) end)
                end)
            end
            return connection.handle(action, params)
        end,
    }, platform
end
