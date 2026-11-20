local nixio = require("nixio")
local fs = require("nixio.fs")

local M = {
    runtime_dir = "/var/run/vpn-routing",
    config_dir = "/etc/vpn-routing",
    lstat = fs.lstat,
    list = fs.dir,
}

function M.private_dir(path)
    if not fs.lstat(path) then fs.mkdir(path, 700) end
    local info = fs.lstat(path)
    return info and info.type == "dir" and info.uid == 0 and info.modestr == "rwx------"
end

function M.read(path, limit)
    local file = io.open(path, "rb")
    if not file then return nil end
    local data = file:read(limit + 1) or ""
    file:close()
    if #data <= limit then return data end
end

local function sync_directory(path)
    local dir = nixio.open(path, "r")
    if not dir then return nil end
    local synced = dir:sync()
    dir:close()
    return synced
end

function M.sync_persistent(path)
    local parent = path:match("^(.+)/[^/]+$")
    if not parent or not sync_directory(parent) then return nil end
    return parent == "/etc" or sync_directory("/etc")
end

function M.remove(path, durable)
    if not fs.unlink(path) then return nil end
    if not durable then return true end
    return sync_directory(M.config_dir)
end

function M.write(path, data, durable)
    local suffix = M.random_hex(12)
    if not suffix then return nil end
    local tmp = path .. "." .. suffix
    local file = nixio.open(tmp, nixio.open_flags("wronly", "creat", "excl"), 600)
    if not file then return nil end
    local written = 0
    while written < #data do
        local count = file:write(data, written)
        if not count or count == 0 then break end
        written = written + count
    end
    local synced = written == #data and file:sync()
    local closed = file:close()
    if synced and closed and fs.rename(tmp, path) then
        if not durable then return true end
        -- Persist both the renamed file entry and the potentially new configuration directory.
        if M.sync_persistent(path) then return true end
        return nil, "not_synced"
    end
    fs.unlink(tmp)
end

function M.random_hex(bytes)
    local file = io.open("/dev/urandom", "rb")
    if not file then return nil end
    local data = file:read(bytes)
    file:close()
    if not data or #data ~= bytes then return nil end
    return (data:gsub(".", function(char) return string.format("%02x", char:byte()) end))
end

local function clean_workspace(dir)
    local entries = fs.dir(dir)
    if entries then
        for name in entries do
            if name ~= "." and name ~= ".." then fs.unlink(dir .. "/" .. name) end
        end
    end
    fs.rmdir(dir)
end

function M.with_workspace(fn)
    local nonce = M.random_hex(12)
    if not nonce or not M.private_dir(M.runtime_dir) then return nil, "storage_error" end
    local dir = M.runtime_dir .. "/work-" .. M.uptime() .. "-" .. nonce
    if not fs.mkdir(dir, 700) then return nil, "storage_error" end
    local ok, first, second = pcall(fn, dir)
    clean_workspace(dir)
    if not ok then return nil, "internal_error" end
    return first, second
end

local function sweep_workspaces()
    local now = M.uptime()
    local entries = fs.dir(M.runtime_dir)
    if not entries then return end
    for name in entries do
        local started, nonce = name:match("^work%-(%d+)%-(%x+)$")
        if started and #nonce == 24 and now - tonumber(started) > 120 then
            local dir = M.runtime_dir .. "/" .. name
            local info = fs.lstat(dir)
            if info and info.type == "dir" and info.uid == 0 and info.modestr == "rwx------" then
                clean_workspace(dir)
            end
        end
    end
end

function M.with_lock(fn)
    if nixio.getuid() ~= 0 or not M.private_dir(M.runtime_dir) then return nil, "storage_error" end
    local path = M.runtime_dir .. "/lock"
    local current = fs.lstat(path)
    if current and (current.type ~= "reg" or current.uid ~= 0 or current.modestr ~= "rw-------") then
        return nil, "storage_error"
    end
    local file = nixio.open(path, "a+", 600)
    if not file then return nil, "storage_error" end
    if not file:lock("tlock") then
        file:close()
        return nil, "operation_pending"
    end
    local ok, first, second = pcall(function()
        sweep_workspaces()
        return fn()
    end)
    file:close()
    if not ok then return nil, "internal_error" end
    return first, second
end

function M.executable(path)
    return fs.access(path, "x") and true or false
end

local deps_dir = "/usr/libexec/vpn-routing/deps/"

function M.dependency(name)
    local path = deps_dir .. name
    return M.executable(path) and path or "/usr/bin/" .. name
end

function M.xray_assets()
    return M.dependency("xray") == deps_dir .. "xray" and "/usr/share/vpn-routing/xray" or "/usr/share/xray"
end

function M.sleep(seconds)
    local whole = math.floor(seconds)
    nixio.nanosleep(whole, math.floor((seconds - whole) * 1e9))
end

function M.uptime()
    return nixio.sysinfo().uptime
end

function M.band(a, b)
    return nixio.bit.band(a, b) % 4294967296
end

-- Run known binaries without passing credentials on the command line or
-- inheriting proxy settings, the CGI's streams or the caller's environment.
function M.spawn(argv, options)
    options = options or {}
    local args = { "env", "-i" }
    local env = { PATH = "/usr/sbin:/usr/bin:/sbin:/bin", LC_ALL = "C", HOME = "/" }
    for key, value in pairs(options.env or {}) do env[key] = value end
    for key, value in pairs(env) do args[#args + 1] = key .. "=" .. value end
    if options.lifetime then
        if not M.executable("/usr/bin/timeout") then return nil end
        for _, arg in ipairs({ "/usr/bin/timeout", "-k", "1", tostring(options.lifetime) }) do
            args[#args + 1] = arg
        end
    end
    for _, arg in ipairs(argv) do args[#args + 1] = arg end

    local input = nixio.open(options.stdin or "/dev/null", "r")
    local output = nixio.open(options.stdout or "/dev/null", "w", 600)
    local errors = nixio.open("/dev/null", "w")
    local pid
    if input and output and errors then
        pid = nixio.fork()
        if pid == 0 then
            pcall(function()
                if not nixio.setsid() or not nixio.dup(input, nixio.stdin)
                    or not nixio.dup(output, nixio.stdout) or not nixio.dup(errors, nixio.stderr) then
                    return
                end
                input:close()
                output:close()
                errors:close()
                nixio.umask(77)
                nixio.exec("/bin/busybox", unpack(args))
            end)
            os.exit(126)
        end
    end
    if input then input:close() end
    if output then output:close() end
    if errors then errors:close() end
    if pid then return { pid = pid } end
end

local function reap(process)
    local pid, state, code = nixio.waitpid(process.pid, "nohang")
    if pid ~= false then
        process.done = true
        return state == "exited" and code or 125
    end
end

function M.stop(process)
    if process.done or reap(process) then return true end
    -- Before setsid the negative PID has no process group yet.
    nixio.kill(-process.pid, 15)
    nixio.kill(process.pid, 15)
    for _ = 1, 10 do
        if reap(process) then return true end
        M.sleep(0.05)
    end
    nixio.kill(-process.pid, 9)
    nixio.kill(process.pid, 9)
    for _ = 1, 20 do
        if reap(process) then return true end
        M.sleep(0.05)
    end
    return false
end

function M.run(argv, options)
    options = options or {}
    local limit = options.timeout or 4
    local process = M.spawn(argv, {
        lifetime = limit, stdin = options.stdin, stdout = options.stdout, env = options.env,
    })
    if not process then return nil, "dependency_missing" end
    for _ = 1, math.ceil((limit + 1.5) * 20) do
        local code = reap(process)
        if code == 124 then return nil, "timeout" end
        if code then return code end
        M.sleep(0.05)
    end
    M.stop(process)
    return nil, "timeout"
end

local function sockets(pid)
    local descriptors = "/proc/" .. pid .. "/fd"
    local list = fs.dir(descriptors)
    if not list then return {} end
    local owned = {}
    for name in list do
        local link = fs.readlink(descriptors .. "/" .. name)
        local inode = link and link:match("^socket:%[(%d+)%]$")
        if inode then owned[inode] = true end
    end
    return owned
end

local function owns_listener(owned, port, protocol, state)
    local address = string.format("0100007F:%04X", port)
    local data = M.read("/proc/net/" .. protocol, 1024 * 1024)
    local count = 0
    for line in (data or ""):gmatch("[^\n]+") do
        local fields = {}
        for field in line:gmatch("%S+") do fields[#fields + 1] = field end
        if fields[2] == address and fields[4] == state then
            if not owned[fields[10]] then return false end
            count = count + 1
        end
    end
    return count == 1
end

function M.tcp_port()
    local sock = nixio.socket("inet", "stream")
    if not sock then return nil end
    local port
    if sock:bind("127.0.0.1", 0) then
        local _, selected = sock:getsockname()
        port = selected
    end
    sock:close()
    return port
end

local function only_child(parent)
    local processes = fs.dir("/proc")
    if not processes then return nil end
    local child
    for name in processes do
        if name:match("^%d+$") then
            local stat = M.read("/proc/" .. name .. "/stat", 4096)
            -- comm is parenthesized and can itself contain parentheses.
            if stat and stat:match("^%d+ %(.*%) %S (%d+) ") == parent then
                if child then return nil end
                child = name
            end
        end
    end
    return child
end

function M.child_listener(process, port)
    if process.done or reap(process) then return false end
    -- GNU timeout has one child. OpenWrt can omit /proc/PID/task/TID/children.
    local child = only_child(tostring(process.pid))
    return child ~= nil and owns_listener(sockets(child), port, "tcp", "0A")
end

function M.transparent_ready(pid, port, health_port)
    local owned = sockets(pid)
    return owns_listener(owned, port, "tcp", "0A") and owns_listener(owned, port, "udp", "07")
        and owns_listener(owned, health_port, "tcp", "0A")
end

function M.resolve4(host)
    -- getaddrinfo() is blocking, so bound it in a separate process.
    local lookup = [[
local nixio = require("nixio")
local result = nixio.getaddrinfo(os.getenv("VPN_ROUTING_HOST"), "inet")
for _, row in ipairs(result or {}) do io.write(row.address, "\n") end
]]
    return M.with_workspace(function(dir)
        local output = dir .. "/addresses"
        if M.run({ "/usr/bin/lua", "-e", lookup }, {
            timeout = 4, stdout = output, env = { VPN_ROUTING_HOST = host },
        }) ~= 0 then return nil end
        local data = M.read(output, 4096)
        if not data then return nil end
        local addresses, seen = {}, {}
        for address in data:gmatch("[^\r\n]+") do
            if not seen[address] then
                addresses[#addresses + 1] = address
                seen[address] = true
            end
        end
        if #addresses > 0 and #addresses <= 32 then return addresses end
    end)
end

return M
