local directory = "/usr/lib/vpn-routing/"
local json = dofile(directory .. "route_json.lua")
local core = assert(loadfile(directory .. "route_core.lua"))(json)
local backend, platform = dofile(directory .. "backend.lua")(directory, json, core)

local interval, idle_interval, retry_interval = 6 * 60 * 60, 60, 10 * 60
local delays = {
    idle = idle_interval,
    updated = interval,
    reconnected = interval,
    retained = interval,
    unchanged = interval,
}

local once = arg and arg[1] == "once"
if not once then platform.sleep(30) end

while true do
    local started = platform.uptime()
    local result, err = backend.handle("refresh_subscription", {})
    local state = result and result.state
    local delay = delays[state]
    if delay then
        if once or state ~= "idle" then
            print("VPN Routing subscription refresh (" .. state .. ").")
            io.stdout:flush()
        end
        if once then os.exit(0) end
    else
        local busy = err == "operation_pending"
        local recovery = err == "rollback_failed"
        delay = (busy or recovery) and idle_interval or retry_interval
        if once or not busy then
            local status = busy and "busy" or (recovery and "recovery pending" or "failed")
            io.stderr:write("VPN Routing subscription refresh (" .. status .. ").\n")
        end
        if once then os.exit(1) end
    end
    platform.sleep(math.max(1, delay - (platform.uptime() - started)))
end
