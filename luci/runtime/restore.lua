local directory = "/usr/lib/vpn-routing/"
local json = dofile(directory .. "route_json.lua")
local core = assert(loadfile(directory .. "route_core.lua"))(json)
local backend, platform = dofile(directory .. "backend.lua")(directory, json, core)

if arg and arg[1] == "guard" then
    local result, err = backend.handle("arm_guard", {})
    if not result then
        io.stderr:write("VPN Routing boot guard failed (", err or "internal_error", ")\n")
        os.exit(1)
    end
    return
end

local delay, last_error = 2, nil

while true do
    local status, err = backend.handle("restore", {})
    if status then
        if status.state == "connected" then print("VPN Routing connection restored.") end
        break
    end
    if err ~= "operation_pending" and err ~= last_error then
        io.stderr:write("VPN Routing restore will retry (", err or "internal_error", ")\n")
        last_error = err
    end
    platform.sleep(delay)
    delay = math.min(delay * 2, 30)
end
