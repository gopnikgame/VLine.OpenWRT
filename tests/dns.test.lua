local json = dofile("route_json.lua")
local core = assert(loadfile("route_core.lua"))(json)
local dns = dofile("luci/runtime/dns.lua")

local work = "/work"
local dhcp_path = "/etc/config/dhcp"
local proxy_path = "/etc/config/dnsproxy"
local generated = "/var/etc/dnsmasq.conf.cfg01411c"
local shadow = work .. "/dns-uci-config"
local shadow_path = shadow .. "/dhcp"
local conditional = "/printer.lan/192.168.1.2"
local dnscrypt = "127.0.0.10"
local proxy_target = "127.0.0.1#61230"
local original = "original UCI config with LAN options, DHCP and local address record"
local factory = "packaged, disabled configuration"
local sections = "dhcp.@dnsmasq[0]"
local loopback = "127.0.0.1"
local answer = "Server:\t127.0.0.1\nAddress:\t127.0.0.1:53\n\nName:\texample.net\nAddress: 23.215.0.135\n"

local function fixture()
    local f = {
        files = {
            [dhcp_path] = original, [proxy_path] = factory,
            ["/etc/dnsmasq.conf"] = "# stock\n",
            ["/usr/share/dnsmasq/rfc6761.conf"] = "local=/test/\n",
            ["/tmp/resolv.conf.d/resolv.conf.auto"] = "nameserver 192.168.0.1\nnameserver 2001:db8::53\n",
            ["/proc/net/udp"] = "  sl  local_address rem_address st\n  2: 0A00007F:0035 00000000:0000 07\n",
        },
        pid = 1540, server = dnscrypt .. " " .. conditional, noresolv = "1",
        dependency = true, log = {}, modes = { [proxy_path] = "rw-r--r--" },
    }
    local platform = {}
    f.module = dns(json, platform, core)
    local proxy_command = function(address, bootstrap, port)
        local args = { "/usr/bin/dnsproxy", "--listen", loopback, "--port", port or "61230" }
        if bootstrap then
            args[#args + 1], args[#args + 2] = "--bootstrap", bootstrap
        end
        for _, arg in ipairs({ "--upstream", address, "--timeout", "3s", "--hosts-file-enabled=false" }) do
            args[#args + 1] = arg
        end
        return json.array(args)
    end

    function f.refresh_dnsmasq()
        local lines = {
            "# auto-generated config file from /etc/config/dhcp",
            "conf-file=/etc/dnsmasq.conf",
            "conf-dir=/tmp/dnsmasq.cfg01411c.d",
            "conf-file=/usr/share/dnsmasq/rfc6761.conf",
            "address=/router.example/192.168.1.1",
        }
        if f.noresolv == "1" then
            lines[#lines + 1] = "no-resolv"
        else
            lines[#lines + 1] = "resolv-file=/tmp/resolv.conf.d/resolv.conf.auto"
        end
        for item in (f.server or ""):gmatch("%S+") do lines[#lines + 1] = "server=" .. item end
        f.files[generated] = table.concat(lines, "\n")
    end

    function platform.read(path, limit)
        local data = f.files[path]
        if data and #data <= limit then return data end
    end

    function platform.lstat(path)
        if path == "/tmp/dnsmasq.cfg01411c.d" then return { type = "dir", uid = 0, modestr = "rwxr-xr-x" } end
        if f.files[path] then return { type = "reg", uid = 0, modestr = f.modes[path] or "rw-------" } end
    end

    function platform.write(path, value, durable)
        f.files[path], f.modes[path] = value, "rw-------"
        if durable then
            f.log[#f.log + 1] = "write " .. path
            if path == dhcp_path then
                f.server, f.noresolv = value:match("server=(.+)$") or dnscrypt .. " " .. conditional, "1"
            end
        end
        return true
    end

    function platform.list(path)
        if path == shadow and f.files[shadow_path] then
            return coroutine.wrap(function() coroutine.yield("dhcp") end)
        end
        assert(path == "/tmp/dnsmasq.cfg01411c.d" or path == shadow)
        return function() end
    end

    function platform.remove(path)
        assert(path == shadow_path)
        f.files[path] = nil
        return true
    end

    function platform.executable(path)
        return f.dependency and (path == "/usr/bin/dnsproxy" or path == "/etc/init.d/dnsproxy")
    end

    function platform.tcp_port() return 50000 end
    function platform.sleep() end
    function platform.spawn(argv)
        local port = "50000"
        local address, bootstrap
        for i, arg in ipairs(argv) do
            if arg == "--upstream" then address = argv[i + 1] end
            if arg == "--bootstrap" then bootstrap = argv[i + 1] end
        end
        assert(address and json.equal(proxy_command(address, bootstrap, port), json.array(argv)))
        f.log[#f.log + 1] = "spawn"
        return {}
    end
    function platform.child_listener() return true end
    function platform.stop() return true end

    local function procd(list_name)
        local service
        if list_name == "dnsmasq" and not f.no_dnsmasq then
            local entries = json.object({
                cfg01411c = json.object({ running = true, pid = f.pid, command = json.array({
                    "/usr/sbin/dnsmasq", "-C", generated, "-k", "-x", "/var/run/dnsmasq/dnsmasq.cfg01411c.pid",
                }) }),
            })
            if f.extra_instance then entries.other = entries.cfg01411c end
            service = json.object({ instances = entries })
        elseif list_name == "dnsproxy" then
            if f.proxy_active then
                service = json.object({ instances = json.object({
                    dnsproxy = json.object({ running = true, pid = 1883, command = f.proxy_active }),
                }) })
            else
                service = json.object({ triggers = json.array() })
            end
        end
        return json.encode(json.object({ [list_name] = service }))
    end

    function platform.run(argv, options)
        local out
        if argv[1] == "/bin/ubus" then
            out = procd(json.decode(argv[5]).name)
        elseif argv[1] == "/sbin/uci" then
            local offset = argv[3] == "-c" and 7 or 3
            if offset == 7 then assert(argv[4] == shadow and argv[5] == "-t" and argv[6] == work) end
            local action, key = argv[offset], argv[offset + 1]
            if action == "changes" then
                out = f.pending == key and "somebody else's UCI draft\n" or ""
            elseif action == "get" then
                if key == sections then out = "dnsmasq"
                elseif key == "dnsproxy.global.enabled" and f.files[proxy_path] == factory then out = "0"
                elseif key == sections .. ".server" then out = offset == 7 and f.staged_servers or f.server
                elseif key == sections .. ".noresolv" then out = offset == 7 and "1" or f.noresolv
                end
                if not out then return 1 end
                out = out .. "\n"
            elseif action == "batch" then
                assert(offset == 7 and f.files[shadow_path] == f.files[dhcp_path])
                local batch = f.files[options.stdin]
                assert(batch:find(sections .. ".noresolv=1", 1, true))
                local servers = {}
                for server in batch:gmatch("add_list [^=]+='([^']+)'") do servers[#servers + 1] = server end
                f.staged_servers = table.concat(servers, " ")
            elseif action == "commit" then
                assert(key == "dhcp" and offset == 7)
                if f.commit_error then return 1 end
                f.files[shadow_path] = original .. "\nnoresolv=1; server=" .. f.staged_servers
                if f.concurrent_proxy then f.files[proxy_path] = "unknown concurrent DNS proxy edit" end
                f.log[#f.log + 1] = "stage dhcp"
            else error("unexpected UCI action") end
        elseif argv[1] == "/bin/busybox" then
            if argv[2] == "sha256sum" or argv[2] == "md5sum" then
                assert(argv[3] == proxy_path)
                local length = argv[2] == "sha256sum" and 64 or 32
                out = string.rep(f.files[proxy_path] == factory and "a" or "b", length) .. " " .. proxy_path .. "\n"
            elseif argv[2] == "mkdir" then
                assert(argv[3] == "-m" and argv[4] == "0700" and argv[5] == shadow)
            elseif argv[2] == "rmdir" then
                assert(argv[3] == shadow and not f.files[shadow_path])
            elseif argv[2] == "nslookup" then
                local server = argv[7]
                assert(argv[6] == "example.net" and server)
                f.log[#f.log + 1] = "query " .. server
                if f.listener_starting and server == loopback and f.files[dhcp_path] ~= original then
                    f.listener_starting = false
                    return 1
                end
                if f.fail_query == server or (f.fail_after_commit and f.files[dhcp_path] ~= original and server == loopback)
                    or (f.fail_native_proxy and server == loopback .. ":61230") then return 1 end
                out = f.bad_answer and "Server:\t127.0.0.1\nAddress:\t127.0.0.1\n" or answer
            elseif argv[2] == "chmod" then
                assert(argv[3] == "0644")
                f.modes[argv[4]] = "rw-r--r--"
            else error("unexpected BusyBox action") end
        elseif argv[1] == "/sbin/ip" then
            assert(argv[2] == "-4" and argv[3] == "route" and argv[4] == "get")
            local address = argv[5]
            out = (address == "192.168.1.1" and "local " or "") .. address .. " dev wan"
        elseif argv[1] == "/bin/opkg" then
            assert(argv[2] == "status" and argv[3] == "dnsproxy")
            out = "Package: dnsproxy\nConffiles:\n /etc/config/dnsproxy " .. string.rep("a", f.legacy_md5 and 32 or 64) .. "\n"
        elseif argv[1] == "/etc/init.d/dnsmasq" then
            assert(argv[2] == "reload")
            f.log[#f.log + 1] = "reload dnsmasq"
            if f.concurrent_edit then f.files[dhcp_path] = "unknown concurrent edit" end
            if not f.stale and not (f.stale_rollback and f.files[dhcp_path] == original) then f.pid = f.pid + 1 end
            f.refresh_dnsmasq()
        elseif argv[1] == "/etc/init.d/dnsproxy" then
            local action = argv[2]
            if action == "enabled" then return f.proxy_boot and 0 or 1 end
            f.log[#f.log + 1] = action .. " dnsproxy"
            if action == "restart" then
                local raw = f.files[proxy_path]
                assert(raw:find("option enabled '1'", 1, true))
                local addr = raw:match("list upstream '([^']+)'")
                local bootstrap = raw:match("list bootstrap '([^']+)'")
                f.proxy_active = proxy_command(addr, bootstrap)
            elseif action == "stop" then f.proxy_active = nil
            elseif action == "enable" then f.proxy_boot = true
            elseif action == "disable" then f.proxy_boot = false
            else error("unexpected dnsproxy action") end
        else error("unexpected command " .. argv[1]) end
        if options.stdout then f.files[options.stdout] = out or "" end
        return 0
    end

    f.refresh_dnsmasq()
    return f
end

local function handle(f, action, params)
    return f.module.handle(work, action, params or {})
end
local function expect(f, action, params, expected)
    local value, err = handle(f, action, params)
    assert(value == nil and err == expected, "expected " .. expected .. ", got " .. tostring(err))
end
local function has(f, action)
    for _, entry in ipairs(f.log) do
        if entry == action then return true end
    end
end

local current = fixture()
local shown = assert(handle(current, "dns_settings"))
assert(shown.profile == "dnscrypt" and shown.addresses[1] == dnscrypt and shown.configurable)
assert(#current.log == 0 and assert(handle(current, "check_dns")).checked)
current.fail_query = dnscrypt
expect(current, "check_dns", {}, "dns_check_failed")

local stock = fixture()
stock.server, stock.noresolv = nil, nil
stock.refresh_dnsmasq()
local system = assert(handle(stock, "dns_settings"))
assert(system.profile == "system" and system.configurable)
assert(json.equal(system.addresses, json.array({ "192.168.0.1", "2001:db8::53" })))

local plain = fixture()
local yandex = assert(handle(plain, "apply_dns", { profile = "yandex" }))
assert(yandex.profile == "yandex" and yandex.checked)
assert(plain.server == conditional .. " 77.88.8.8 77.88.8.1")
assert(has(plain, "query 77.88.8.8") and has(plain, "query 77.88.8.1") and has(plain, "reload dnsmasq"))
assert(plain.files[proxy_path] == factory and not has(plain, "restart dnsproxy"))
plain.log = {}
assert(handle(plain, "apply_dns", { profile = "yandex" }))
assert(not has(plain, "write " .. dhcp_path) and not has(plain, "reload dnsmasq"))
local custom = assert(handle(plain, "apply_dns", { profile = "custom", address = "192.168.1.2#5353" }))
assert(custom.profile == "custom" and custom.address == "192.168.1.2#5353")
assert(plain.server == conditional .. " 192.168.1.2#5353")
local local_loop = { profile = "custom", address = "192.168.1.1" }
expect(plain, "apply_dns", local_loop, "dns_check_failed")
assert(plain.server == conditional .. " 192.168.1.2#5353")

local reject = fixture()
for _, input in ipairs({ "dns.google", "127.0.0.1#53", proxy_target, "http://dns.google/dns-query",
    "https://user:secret@dns.google/dns-query", "https://dns.google/dns-query?token=secret",
    "https://dns.google/dns-query#fragment", "tls://dns.google:65536", "quic://dns.google/path",
    "https://dns.google/$(uname)", "1.1.1.1;reboot", "169.254.169.254", "239.0.0.1" }) do
    expect(reject, "apply_dns", { profile = "custom", address = input }, "dns_invalid")
end
assert(#reject.log == 0)
reject.fail_query = "77.88.8.1"
expect(reject, "apply_dns", { profile = "yandex" }, "dns_check_failed")
assert(reject.files[dhcp_path] == original and not has(reject, "write " .. dhcp_path))
reject.bad_answer = true
expect(reject, "check_dns", {}, "dns_check_failed")
reject.files["/proc/net/udp"] = "  sl  local_address rem_address st\n  2: 00000000:0035 00000000:0000 07\n"
expect(reject, "apply_dns", { profile = "dnscrypt" }, "dns_check_failed")

for _, option in ipairs({ "fail_after_commit", "stale" }) do
    local rollback = fixture()
    rollback[option] = true
    expect(rollback, "apply_dns", { profile = "yandex" }, "dns_apply_failed")
    assert(rollback.files[dhcp_path] == original and assert(handle(rollback, "dns_settings")).profile == "dnscrypt")
end

local staging_error = fixture()
staging_error.commit_error = true
expect(staging_error, "apply_dns", { profile = "yandex" }, "storage_error")
assert(staging_error.files[dhcp_path] == original and not has(staging_error, "write " .. dhcp_path))

local startup = fixture()
startup.listener_starting = true
assert(assert(handle(startup, "apply_dns", { profile = "yandex" })).checked)
assert(not startup.listener_starting and startup.server == conditional .. " 77.88.8.8 77.88.8.1")

local concurrent = fixture()
concurrent.concurrent_edit, concurrent.fail_after_commit = true, true
expect(concurrent, "apply_dns", { profile = "yandex" }, "dns_rollback_failed")
assert(concurrent.files[dhcp_path] == "unknown concurrent edit")

local concurrent_proxy = fixture()
concurrent_proxy.concurrent_proxy = true
expect(concurrent_proxy, "apply_dns", { profile = "cloudflare_doh" }, "dns_conflict")
assert(concurrent_proxy.files[proxy_path] == "unknown concurrent DNS proxy edit")
assert(concurrent_proxy.files[dhcp_path] == original and not concurrent_proxy.proxy_active)

local stale_rollback = fixture()
stale_rollback.stale_rollback, stale_rollback.fail_after_commit = true, true
expect(stale_rollback, "apply_dns", { profile = "yandex" }, "dns_rollback_failed")

local encrypt = fixture()
encrypt.dependency = false
expect(encrypt, "apply_dns", { profile = "adguard_dot" }, "dns_dependency")
assert(#encrypt.log == 0)
encrypt.dependency = true
local doh = assert(handle(encrypt, "apply_dns", { profile = "adguard_doh" }))
assert(doh.profile == "adguard_doh" and doh.addresses[1] == "https://dns.adguard-dns.com/dns-query")
assert(encrypt.server == conditional .. " " .. proxy_target and encrypt.proxy_boot and encrypt.proxy_active)
assert(not encrypt.files[proxy_path]:find("fallback", 1, true) and not encrypt.files[proxy_path]:find("insecure", 1, true))
assert(has(encrypt, "query 127.0.0.1:61230"))
encrypt.log = {}
local doq = assert(handle(encrypt, "apply_dns", { profile = "adguard_doq" }))
assert(doq.profile == "adguard_doq" and doq.addresses[1] == "quic://dns.adguard-dns.com")
assert(not has(encrypt, "reload dnsmasq") and has(encrypt, "restart dnsproxy") and has(encrypt, "query 127.0.0.1:61230"))
local secure_custom = assert(handle(encrypt, "apply_dns", { profile = "custom", address = "tls://198.51.100.2:8853" }))
assert(secure_custom.profile == "custom" and secure_custom.address == "tls://198.51.100.2:8853")
assert(not secure_custom.bootstrap and not encrypt.files[proxy_path]:find("bootstrap", 1, true))
local bootstrap = { profile = "custom", address = "tls://resolver.example:8853", bootstrap = "192.168.1.1" }
expect(encrypt, "apply_dns", bootstrap, "dns_check_failed")
assert(handle(encrypt, "apply_dns", { profile = "dnscrypt" }))
assert(not encrypt.proxy_active and encrypt.server == conditional .. " " .. dnscrypt)

local broken = fixture()
broken.legacy_md5 = true
broken.fail_native_proxy = true
expect(broken, "apply_dns", { profile = "cloudflare_dot" }, "dns_apply_failed")
assert(not broken.proxy_boot and not broken.proxy_active)
assert(broken.files[proxy_path] == factory and broken.files[dhcp_path] == original)

local conflict = fixture()
conflict.files[proxy_path] = "externally configured"
expect(conflict, "apply_dns", { profile = "cloudflare_doh" }, "dns_conflict")
assert(#conflict.log == 0)
conflict.pending = "dhcp"
assert(not assert(handle(conflict, "dns_settings")).configurable)
expect(conflict, "apply_dns", { profile = "yandex" }, "dns_conflict")
conflict.pending, conflict.extra_instance = nil, true
local unavailable = assert(handle(conflict, "dns_settings"))
assert(not unavailable.configurable and #unavailable.addresses == 0)
conflict.extra_instance = false
conflict.files["/etc/dnsmasq.conf"] = "server=/#/192.168.1.200\n"
assert(not assert(handle(conflict, "dns_settings")).configurable)
expect(conflict, "apply_dns", { profile = "yandex" }, "dns_conflict")
conflict.files["/etc/dnsmasq.conf"] = "address=/#/192.168.1.200\n"
assert(not assert(handle(conflict, "dns_settings")).configurable)
expect(conflict, "check_dns", {}, "dns_conflict")

print("DNS settings tests passed")
