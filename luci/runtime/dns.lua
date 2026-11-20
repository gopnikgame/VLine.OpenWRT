-- The LAN DNS setting changes dnsmasq's default upstreams only.
local UCI = "/sbin/uci"
local BUSYBOX = "/bin/busybox"
local DNSMASQ = "/etc/init.d/dnsmasq"
local PROXY = "/usr/bin/dnsproxy"
local PROXY_INIT = "/etc/init.d/dnsproxy"
local DHCP_FILE = "/etc/config/dhcp"
local PROXY_FILE = "/etc/config/dnsproxy"
local DNSMASQ_SECTION = "dhcp.@dnsmasq[0]"
local PROXY_PORT = 61230
local PROXY_TARGET = "127.0.0.1#" .. PROXY_PORT
local DNSCRYPT = "127.0.0.10"
local PROBE_NAME = "example.net"
local FILE_LIMIT = 128 * 1024
local PRESETS = {
    dnscrypt = { servers = { DNSCRYPT } },
    yandex = { servers = { "77.88.8.8", "77.88.8.1" } },
    adguard_doh = { address = "https://dns.adguard-dns.com/dns-query", bootstrap = "94.140.14.14" },
    adguard_dot = { address = "tls://dns.adguard-dns.com", bootstrap = "94.140.14.14" },
    adguard_doq = { address = "quic://dns.adguard-dns.com", bootstrap = "94.140.14.14" },
    cloudflare_doh = { address = "https://cloudflare-dns.com/dns-query", bootstrap = "1.1.1.1" },
    cloudflare_dot = { address = "tls://one.one.one.one", bootstrap = "1.1.1.1" },
}

local function trim(value)
    return value and value:match("^%s*(.-)%s*$")
end

local function same_list(left, right)
    if #left ~= #right then return false end
    for index, value in ipairs(left) do
        if right[index] ~= value then return false end
    end
    return true
end

local function port_number(value)
    if not value or not value:match("^[1-9]%d*$") or #value > 5 then return nil end
    local port = tonumber(value)
    if port <= 65535 then return port end
end

return function(json, platform, core)
    local function unicast(value)
        local octets = core.ipv4_octets(value)
        if octets and octets[1] > 0 and octets[1] < 224
            and not (octets[1] == 169 and octets[2] == 254) then
            return octets
        end
    end

    local function plain_target(value)
        local host, raw_port = value:match("^([%d.]+)#(%d+)$")
        host = host or value
        local port = raw_port and port_number(raw_port) or not raw_port and 53
        if port and unicast(host) then
            return port == 53 and host or host .. "#" .. port, host, port
        end
    end

    local function encrypted_target(value)
        local scheme, authority, path = value:match("^(%a+)://([^/]+)(.*)$")
        if scheme ~= "https" and scheme ~= "tls" and scheme ~= "quic" then return nil end
        local host, raw_port = authority:match("^([%w%.%-]+):(%d+)$")
        host = host or authority
        local numeric = unicast(host)
        if not numeric and (not core.valid_domain(host) or not host:match("%.[%a][%w%-]*$")) then
            return nil
        end
        if (raw_port and not port_number(raw_port)) or (scheme == "https" and not path:match("^/[%w/_%.~%-]+$"))
            or (scheme ~= "https" and path ~= "") then
            return nil
        end
        return host, numeric ~= nil
    end

    local function requested(params)
        local id = params.profile
        if PRESETS[id] then
            if params.address ~= nil or params.bootstrap ~= nil then return nil end
            local preset = PRESETS[id]
            return { profile = id, servers = preset.servers or { PROXY_TARGET },
                address = preset.address, bootstrap = preset.bootstrap, encrypted = preset.address ~= nil }
        end
        if id ~= "custom" or type(params.address) ~= "string" or #params.address > 384 then return nil end
        local address, bootstrap = params.address, params.bootstrap
        local plain = plain_target(address)
        if plain then
            if bootstrap ~= nil or plain == PROXY_TARGET or plain == "127.0.0.1" then return nil end
            return { profile = id, servers = { plain }, address = plain }
        end
        local host, numeric = encrypted_target(address)
        if not host then return nil end
        if bootstrap ~= nil then
            if type(bootstrap) ~= "string" or not unicast(bootstrap) or bootstrap == "127.0.0.1" then return nil end
        elseif not numeric then
            bootstrap = "1.1.1.1"
        end
        return { profile = id, servers = { PROXY_TARGET }, encrypted = true,
            address = address, bootstrap = bootstrap }
    end

    local function command(dir, argv, timeout)
        local output = dir .. "/dns-command"
        local code = platform.run(argv, { timeout = timeout or 2, stdout = output })
        if code ~= 0 then return nil, code end
        return platform.read(output, FILE_LIMIT)
    end

    local function clean_uci(dir, package)
        return trim(command(dir, { UCI, "-q", "changes", package })) == ""
    end

    local function uci_args(dir, shadow)
        if shadow then return { UCI, "-q", "-c", shadow, "-t", dir } end
        return { UCI, "-q" }
    end

    local function uci_get(dir, path, shadow)
        local argv = uci_args(dir, shadow)
        argv[#argv + 1], argv[#argv + 2] = "get", path
        local output, code = command(dir, argv)
        return trim(output), code
    end

    local function instances(dir, name)
        local output = command(dir, { "/bin/ubus", "call", "service", "list", '{"name":"' .. name .. '"}' })
        local ok, result = pcall(json.decode, output or "")
        if not ok or not json.is_object(result) then return nil end
        if result[name] == nil then return {} end
        if not json.is_object(result[name]) then return nil end
        local entries = result[name].instances
        if entries == nil or (json.is_array(entries) and #entries == 0) then return {} end
        if json.is_object(entries) then return entries end
    end

    local function running(entry)
        local pid = json.is_object(entry) and json.integer(entry.pid)
        return pid and pid > 1 and entry.running == true and json.is_array(entry.command)
    end

    local function safe_mode(path, kind)
        local info = platform.lstat(path)
        local mode = info and info.modestr
        if info and info.type == kind and info.uid == 0 and type(mode) == "string" and #mode == 9
            and mode:sub(5, 5) ~= "w" and mode:sub(8, 8) ~= "w" then
            return mode
        end
    end

    local function safe_read(path, limit)
        local mode = safe_mode(path, "reg")
        if mode then return platform.read(path, limit or FILE_LIMIT), mode end
    end

    local function parse_server(value)
        if value:match("^/[%w._*%-%/:#%[%]@]+$") and not value:find("/#/", 1, true)
            and not value:find("/*/", 1, true) and not value:find("/./", 1, true) then
            return "conditional", value
        end
        local address = plain_target(value)
        if address then return "default", address end
        -- A running dnsmasq already validated IPv6. Keep its active addresses readable.
        if value:match("^[%x:]+#?%d*$") and value:find(":", 1, true) then return "default", value end
    end

    local function configured_servers(value)
        local defaults, conditional = {}, {}
        for server in (value or ""):gmatch("%S+") do
            local kind, address = parse_server(server)
            if not kind or #defaults + #conditional >= 32 then return nil end
            local list = kind == "default" and defaults or conditional
            list[#list + 1] = address
        end
        return defaults, conditional
    end

    local function read_dnsmasq(dir)
        local list = instances(dir, "dnsmasq")
        if not list then return nil end
        local name, entry = next(list)
        if not name or not running(entry) then return nil end
        if next(list, name) or not name:match("^[%w_%-]+$") then return nil, "dns_conflict" end
        local path = entry.command[3]
        if not (path == "/var/etc/dnsmasq.conf." .. name or path == "/tmp/etc/dnsmasq.conf." .. name)
            or not same_list(entry.command, { "/usr/sbin/dnsmasq", "-C", path, "-k", "-x",
                "/var/run/dnsmasq/dnsmasq." .. name .. ".pid" }) then
            return nil
        end

        local state = { servers = {}, addresses = {}, noresolv = false, port = 53, pid = json.integer(entry.pid) }
        local visited, files = {}, 0
        local function inspect(file, generated)
            if visited[file] or files >= 24 then return false end
            visited[file], files = true, files + 1
            local content = safe_read(file)
            if not content then return false end
            for line in content:gmatch("[^\r\n]+") do
                line = trim(line)
                if line == "no-resolv" then
                    state.noresolv = true
                    if not generated then return false end
                else
                    local key, value = line:match("^([%w%-]+)%s*=%s*(.+)$")
                    if key == "server" or key == "local" then
                        local kind, address = parse_server(value)
                        if not kind then return false end
                        if kind == "default" then
                            if not generated or #state.servers >= 16 then return false end
                            state.servers[#state.servers + 1] = address
                        end
                    elseif key == "conf-file" then
                        if not (value == "/etc/dnsmasq.conf" or value == "/etc/dnsmasq." .. name .. ".conf"
                            or value:match("^/usr/share/dnsmasq/[%w_%.%-]+%.conf$")) or not inspect(value, false) then
                            return false
                        end
                    elseif key == "conf-dir" then
                        if value ~= "/tmp/dnsmasq." .. name .. ".d" and value ~= "/tmp/dnsmasq.d" then return false end
                        local entries = safe_mode(value, "dir") and platform.list(value)
                        if not entries then return false end
                        for item in entries do
                            if item:sub(1, 1) ~= "." and item:sub(-1) ~= "~" then
                                if not item:match("^[%w_%.%-]+$") or not inspect(value .. "/" .. item, false) then
                                    return false
                                end
                            end
                        end
                    elseif key == "resolv-file" then
                        if not generated or state.resolv or value ~= "/tmp/resolv.conf.d/resolv.conf.auto" then return false end
                        state.resolv = value
                    elseif (key == "address" or key == "local")
                        and (value:find("/#/", 1, true) or value:find("/*/", 1, true)) then
                        return false
                    elseif key == "servers-file" or key == "conf-script" then
                        return false
                    elseif key == "port" then
                        state.port = port_number(value)
                        if not state.port then return false end
                    end
                end
            end
            return true
        end

        if not inspect(path, true) then return nil, "dns_conflict" end
        local seen = {}
        local function add(address)
            if not seen[address] and #state.addresses < 16 then
                state.addresses[#state.addresses + 1] = address
                seen[address] = true
            end
        end
        for _, address in ipairs(state.servers) do add(address) end
        if not state.noresolv and state.resolv then
            for line in (safe_read(state.resolv, 8192) or ""):gmatch("[^\r\n]+") do
                local value = line:match("^%s*nameserver%s+(%S+)%s*$")
                local kind, address
                if value then kind, address = parse_server(value) end
                if kind == "default" then add(address) end
            end
        end
        return state
    end

    local function editable(dir, state)
        if not clean_uci(dir, "dhcp") or uci_get(dir, DNSMASQ_SECTION) ~= "dnsmasq" then return nil end
        local second, second_error = uci_get(dir, "dhcp.@dnsmasq[1]")
        if second ~= nil or second_error ~= 1 then return nil end
        local current, current_error = uci_get(dir, DNSMASQ_SECTION .. ".server")
        if current == nil and current_error ~= 1 then return nil end
        local defaults, conditional = configured_servers(current)
        if not defaults or not same_list(defaults, state.servers) then return nil end
        local noresolv, noresolv_error = uci_get(dir, DNSMASQ_SECTION .. ".noresolv")
        if noresolv == nil and noresolv_error ~= 1 then return nil end
        if (noresolv == "1") ~= state.noresolv or (noresolv and noresolv ~= "1" and noresolv ~= "0") then return nil end
        return { conditional = conditional, has_server = current ~= nil }
    end

    local function query(dir, address, port, timeout)
        timeout = timeout or 4
        local server = port == 53 and address or address .. ":" .. port
        local output = command(dir, { BUSYBOX, "nslookup", "-type=A", "-retry=1",
            "-timeout=" .. timeout, PROBE_NAME, server }, timeout + 1)
        local matching = false
        for line in (output or ""):gmatch("[^\r\n]+") do
            local name = line:match("^Name:%s+(%S+)")
            if name then matching = name == PROBE_NAME or name == PROBE_NAME .. "." end
            local ip = matching and line:match("^Address[%s%d]*:%s+([%d.]+)%s*$")
            if ip and unicast(ip) then return true end
        end
        return false
    end

    local function query_reloaded(dir, port)
        -- procd reports a new running PID before the daemon has bound its listener.
        if query(dir, "127.0.0.1", port, 2) then return true end
        platform.sleep(0.15)
        return query(dir, "127.0.0.1", port)
    end

    local function proxy_command(config, port)
        local args = { PROXY, "--listen", "127.0.0.1", "--port", tostring(port) }
        if config.bootstrap then
            args[#args + 1], args[#args + 2] = "--bootstrap", config.bootstrap
        end
        for _, value in ipairs({ "--upstream", config.address, "--timeout", "3s", "--hosts-file-enabled=false" }) do
            args[#args + 1] = value
        end
        return args
    end

    local function proxy_config(config, enabled)
        local lines = {
            "config dnsproxy 'global'",
            "\toption vpn_profile '" .. config.profile .. "'",
            "\toption enabled '" .. (enabled and "1" or "0") .. "'",
            "\tlist listen_addr '127.0.0.1'",
            "\tlist listen_port '" .. PROXY_PORT .. "'",
            "\toption timeout '3s'",
            "",
            "config dnsproxy 'servers'",
            "\tlist upstream '" .. config.address .. "'",
        }
        if config.bootstrap then lines[#lines + 1] = "\tlist bootstrap '" .. config.bootstrap .. "'" end
        return table.concat(lines, "\n") .. "\n"
    end

    local function owned_proxy(bytes)
        local id = bytes and bytes:match("\n\toption vpn_profile '([%w_]+)'\n")
        if not id then return nil end
        local params = { profile = id }
        if id == "custom" then
            params.address = bytes:match("\n\tlist upstream '([^'\n]+)'\n")
            params.bootstrap = bytes:match("\n\tlist bootstrap '([^'\n]+)'\n")
        end
        local config = requested(params)
        if not config or not config.encrypted then return nil end
        if bytes == proxy_config(config, true) then return config, true end
        if bytes == proxy_config(config, false) then return config, false end
    end

    local function installed_proxy()
        return platform.executable(PROXY) and platform.executable(PROXY_INIT)
    end

    local function proxy_matches(list, config)
        local entry = list and list.dnsproxy
        return running(entry) and next(list) == "dnsproxy" and not next(list, "dnsproxy")
            and same_list(entry.command, proxy_command(config, PROXY_PORT))
    end

    local function factory_proxy(dir)
        -- opkg records the installed factory conffile digest. An edited or
        -- unrelated service may not be taken over, even if currently stopped.
        local status = command(dir, { "/bin/opkg", "status", "dnsproxy" })
        local hash = status and status:match("\n /etc/config/dnsproxy ([0-9a-f]+)\n")
        local algorithm = hash and ({ [32] = "md5sum", [64] = "sha256sum" })[#hash]
        if not algorithm then return false end
        local digest = command(dir, { BUSYBOX, algorithm, PROXY_FILE })
        return digest and digest:match("^[0-9a-f]+") == hash
    end

    local function settings(dir, state, error_code)
        local result = { profile = "system", addresses = json.array(), encryptedAvailable = installed_proxy() and true or false,
            configurable = false }
        if not state then
            result.reason = error_code or "dns_unavailable"
            return result
        end
        result.addresses = json.array(state.addresses)
        result.configurable = editable(dir, state) ~= nil
        if not result.configurable then result.reason = "dns_conflict" end
        if not state.noresolv then return result end
        for id, preset in pairs(PRESETS) do
            if preset.servers and same_list(state.servers, preset.servers) then
                result.profile = id
                return result
            end
        end
        if same_list(state.servers, { PROXY_TARGET }) then
            local config, enabled = owned_proxy(safe_read(PROXY_FILE))
            if enabled and proxy_matches(instances(dir, "dnsproxy"), config) then
                result.profile = config.profile
                result.addresses = json.array({ config.address })
                if config.profile == "custom" then
                    result.address, result.bootstrap = config.address, config.bootstrap
                end
            end
        elseif #state.servers == 1 and plain_target(state.servers[1]) then
            result.profile, result.address = "custom", state.servers[1]
        end
        return result
    end

    local function off_router(dir, address)
        local route = command(dir, { "/sbin/ip", "-4", "route", "get", address })
        return route and not route:match("^local%s")
    end

    local function dnscrypt_listener()
        local udp = platform.read("/proc/net/udp", 1024 * 1024) or ""
        return udp:match("\n%s*%d+:%s+0A00007F:0035%s+%S+%s+07%s") ~= nil
    end

    local function precheck(dir, config, local_port)
        if config.encrypted then
            if config.bootstrap == DNSCRYPT and not dnscrypt_listener() then return false end
            if config.bootstrap and local_port == 53 and config.bootstrap ~= DNSCRYPT
                and not off_router(dir, config.bootstrap) then return false end
            local port = platform.tcp_port()
            if not port then return false end
            local process = platform.spawn(proxy_command(config, port), { lifetime = 9 })
            if not process then return false end
            local success = false
            for _ = 1, 15 do
                if platform.child_listener(process, port) then
                    success = query(dir, "127.0.0.1", port)
                    break
                end
                platform.sleep(0.08)
            end
            return platform.stop(process) and success
        end
        for _, server in ipairs(config.servers) do
            local _, address, port = plain_target(server)
            if address == DNSCRYPT and port == 53 then
                if not dnscrypt_listener() then return false end
            elseif port == local_port and not off_router(dir, address) then
                return false
            end
            if not query(dir, address, port) then return false end
        end
        return true
    end

    local function replace_config(path, data, mode)
        if not platform.write(path, data, true) then return false end
        return mode == "rw-------" or (mode == "rw-r--r--" and platform.run({ BUSYBOX, "chmod", "0644", path }, { timeout = 2 }) == 0)
    end

    local function poll_dnsmasq(dir, servers, noresolv, old_pid)
        for _ = 1, 10 do
            local state = read_dnsmasq(dir)
            if state and state.noresolv == noresolv and same_list(state.servers, servers)
                and (not old_pid or state.pid ~= old_pid) then return state end
            platform.sleep(0.1)
        end
    end

    local function poll_proxy(dir, config)
        for _ = 1, 10 do
            local list = instances(dir, "dnsproxy")
            if config and proxy_matches(list, config) or not config and list and not next(list) then
                return true
            end
            platform.sleep(0.1)
        end
        return false
    end

    local function stage_dhcp(dir, change, servers, before)
        local lines = { "set " .. DNSMASQ_SECTION .. ".noresolv=1" }
        local option = DNSMASQ_SECTION .. ".server"
        if change.has_server then lines[#lines + 1] = "delete " .. option end
        for _, server in ipairs(change.conditional) do
            lines[#lines + 1] = "add_list " .. option .. "='" .. server .. "'"
        end
        for _, server in ipairs(servers) do
            lines[#lines + 1] = "add_list " .. option .. "='" .. server .. "'"
        end
        local shadow = dir .. "/dns-uci-config"
        if platform.run({ BUSYBOX, "mkdir", "-m", "0700", shadow }, { timeout = 2 }) ~= 0 then return nil end
        local function prepare()
            local batch, path = dir .. "/dns-uci", shadow .. "/dhcp"
            if not platform.write(path, before) or not platform.write(batch, table.concat(lines, "\n") .. "\n") then
                return nil
            end
            local args = uci_args(dir, shadow)
            args[#args + 1] = "batch"
            if platform.run(args, { timeout = 3, stdin = batch }) ~= 0 then return nil end
            local defaults, conditional = configured_servers(uci_get(dir, option, shadow))
            if not defaults or not same_list(defaults, servers) or not same_list(conditional, change.conditional)
                or uci_get(dir, DNSMASQ_SECTION .. ".noresolv", shadow) ~= "1" then return nil end
            args[#args], args[#args + 1] = "commit", "dhcp"
            if platform.run(args, { timeout = 3 }) ~= 0 then return nil end
            return safe_read(path)
        end
        local bytes = prepare()
        local entries = platform.list(shadow)
        if entries then
            for name in entries do
                if name ~= "." and name ~= ".." then platform.remove(shadow .. "/" .. name) end
            end
        end
        if platform.run({ BUSYBOX, "rmdir", shadow }, { timeout = 2 }) == 0 then return bytes end
    end

    local function apply(dir, params, state, reason)
        local config = requested(params)
        if not config then return nil, "dns_invalid" end
        if not state then return nil, reason or "dns_unavailable" end
        local change = editable(dir, state)
        if not change then return nil, "dns_conflict" end
        local dhcp_before, dhcp_mode = safe_read(DHCP_FILE)
        if not dhcp_before or (dhcp_mode ~= "rw-------" and dhcp_mode ~= "rw-r--r--") then return nil, "storage_error" end

        local proxy_before, proxy_mode = safe_read(PROXY_FILE)
        local old_proxy, was_enabled = owned_proxy(proxy_before)
        local proxy_after, old_boot
        if config.encrypted or old_proxy and was_enabled then
            if not installed_proxy() then return nil, "dns_dependency" end
            local list = instances(dir, "dnsproxy")
            if not list or not clean_uci(dir, "dnsproxy") or not proxy_before
                or (proxy_mode ~= "rw-------" and proxy_mode ~= "rw-r--r--") then return nil, "dns_conflict" end
            if next(list) and (not was_enabled or not proxy_matches(list, old_proxy)) then return nil, "dns_conflict" end
            if not old_proxy and (uci_get(dir, "dnsproxy.global.enabled") ~= "0" or not factory_proxy(dir)) then
                return nil, "dns_conflict"
            end
            local boot = platform.run({ PROXY_INIT, "enabled" }, { timeout = 2 })
            if boot ~= 0 and boot ~= 1 then return nil, "dns_conflict" end
            old_boot = boot == 0
            proxy_after = config.encrypted and proxy_config(config, true) or proxy_config(old_proxy, false)
        end

        local dhcp_needed = not state.noresolv or not same_list(state.servers, config.servers)
        if not precheck(dir, config, state.port) then return nil, "dns_check_failed" end
        if safe_read(DHCP_FILE) ~= dhcp_before or not clean_uci(dir, "dhcp")
            or (proxy_after and (safe_read(PROXY_FILE) ~= proxy_before or not clean_uci(dir, "dnsproxy"))) then
            return nil, "dns_conflict"
        end
        local dhcp_after
        if dhcp_needed then
            dhcp_after = stage_dhcp(dir, change, config.servers, dhcp_before)
            if not dhcp_after or dhcp_after == dhcp_before then return nil, "storage_error" end
        end

        local dhcp_touched, proxy_touched, boot_touched
        local function failed(error_code)
            local recovered = true
            if proxy_touched then
                local current = safe_read(PROXY_FILE)
                if (current ~= proxy_after and current ~= proxy_before) or not clean_uci(dir, "dnsproxy") then
                    recovered = false
                else
                    local service_action = was_enabled and "restart" or "stop"
                    recovered = replace_config(PROXY_FILE, proxy_before, proxy_mode)
                        and platform.run({ PROXY_INIT, service_action }, { timeout = 4 }) == 0
                        and poll_proxy(dir, was_enabled and old_proxy or nil)
                        and (not was_enabled or query_reloaded(dir, PROXY_PORT))
                    if boot_touched then
                        recovered = (platform.run({ PROXY_INIT, "disable" }, { timeout = 2 }) == 0) and recovered
                    end
                end
            end
            if dhcp_touched then
                local current = safe_read(DHCP_FILE)
                local active = read_dnsmasq(dir)
                local changed_pid = active and active.pid ~= state.pid and active.pid or nil
                if current ~= dhcp_before then
                    local restored = current == dhcp_after and clean_uci(dir, "dhcp")
                        and replace_config(DHCP_FILE, dhcp_before, dhcp_mode)
                        and platform.run({ DNSMASQ, "reload" }, { timeout = 4 }) == 0
                        and poll_dnsmasq(dir, state.servers, state.noresolv, changed_pid)
                    restored = restored and query_reloaded(dir, restored.port)
                    recovered = restored and recovered
                end
            end
            return nil, recovered and error_code or "dns_rollback_failed"
        end

        local function change_proxy(enabled)
            if safe_read(PROXY_FILE) ~= proxy_before or not clean_uci(dir, "dnsproxy") then
                return nil, "dns_conflict"
            end
            proxy_touched = true
            local action = enabled and "restart" or "stop"
            if not replace_config(PROXY_FILE, proxy_after, proxy_mode)
                or platform.run({ PROXY_INIT, action }, { timeout = 4 }) ~= 0
                or not poll_proxy(dir, enabled and config or nil) then return nil, "dns_apply_failed" end
            if enabled and not old_boot then
                boot_touched = true
                if platform.run({ PROXY_INIT, "enable" }, { timeout = 2 }) ~= 0 then return nil, "dns_apply_failed" end
            end
            return true
        end

        if config.encrypted and (proxy_after ~= proxy_before or not was_enabled or not old_boot
            or not proxy_matches(instances(dir, "dnsproxy"), config)) then
            local changed, error_code = change_proxy(true)
            if not changed then return failed(error_code) end
        end
        if config.encrypted and not query_reloaded(dir, PROXY_PORT) then return failed("dns_apply_failed") end
        if dhcp_needed then
            if not clean_uci(dir, "dhcp") or safe_read(DHCP_FILE) ~= dhcp_before then return failed("dns_conflict") end
            dhcp_touched = true
            if not replace_config(DHCP_FILE, dhcp_after, dhcp_mode)
                or platform.run({ DNSMASQ, "reload" }, { timeout = 4 }) ~= 0 then
                return failed("dns_apply_failed")
            end
        end

        local current = poll_dnsmasq(dir, config.servers, true, dhcp_needed and state.pid or nil)
        if not current or not query_reloaded(dir, current.port) then return failed("dns_apply_failed") end
        if not config.encrypted and proxy_after then
            local changed, error_code = change_proxy(false)
            if not changed then return failed(error_code) end
        end
        local result = settings(dir, current)
        if result.profile ~= config.profile and not (config.profile == "custom" and not config.encrypted
            and same_list(result.addresses, config.servers)) then return failed("dns_apply_failed") end
        result.checked = true
        return result
    end

    return {
        handle = function(dir, action, params)
            local state, reason = read_dnsmasq(dir)
            if action == "apply_dns" then return apply(dir, params, state, reason) end
            if action == "dns_settings" then return settings(dir, state, reason) end
            if action ~= "check_dns" then return nil, "dns_invalid" end
            if not state then return nil, reason or "dns_unavailable" end
            if not query(dir, "127.0.0.1", state.port) then return nil, "dns_check_failed" end
            local result = settings(dir, state)
            if same_list(state.servers, { PROXY_TARGET }) then
                if result.profile == "system" or not query(dir, "127.0.0.1", PROXY_PORT) then
                    return nil, "dns_check_failed"
                end
            elseif result.profile == "dnscrypt" or result.profile == "yandex" or result.profile == "custom" then
                local available = false
                for _, server in ipairs(state.servers) do
                    local _, address, port = plain_target(server)
                    if (address ~= DNSCRYPT or port ~= 53 or dnscrypt_listener()) and query(dir, address, port) then
                        available = true
                        break
                    end
                end
                if not available then return nil, "dns_check_failed" end
            end
            result.checked = true
            return result
        end,
    }
end
