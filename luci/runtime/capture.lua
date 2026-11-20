-- Dedicated IPv4 capture using the pinned TPROXY Manager. Its own default
-- UCI profile, kernel objects and runtime state are outside this adapter.
return function(json, platform, core)
    local manager = platform.dependency("tproxy-manager.sh")
    local digest = "344d8369125aead4db3c579673dfbcedb4947f5850f492ed3d05810f9f2f27e8"
    local shim_dir = "/usr/libexec/vpn-routing/shim"
    local lock_dir = "/var/lock/tproxy-manager"
    local state_dir = platform.runtime_dir .. "/capture"
    local state_file = state_dir .. "/manager.state"
    local source_file = state_dir .. "/sources4"
    local unused_list = state_dir .. "/unused"
    local nft = "/usr/sbin/nft"
    local ip = "/sbin/ip"
    local ubus = "/bin/ubus"
    local table_name = "vpn_capture"
    local port = 61229
    local tcp_table, udp_table = 21219, 21220
    local tcp_mark, udp_mark = 0x10000000, 0x20000000
    local marks = { [tcp_table] = tcp_mark, [udp_table] = udp_mark }
    local state_values = {
        NFT_TABLE = table_name, IPV6_ENABLED = "0",
        FWMARK_TCP = "0x10000000", FWMARK_UDP = "0x20000000",
        RTTAB_TCP = tostring(tcp_table), RTTAB_UDP = tostring(udp_table),
        RULE_PRIO_TCP = tostring(tcp_table), RULE_PRIO_UDP = tostring(udp_table),
    }

    local function valid_fields(value, allowed)
        if not json.is_object(value) then return false end
        for key in pairs(value) do
            if not allowed[key] then return false end
        end
        return true
    end

    local function private_ipv4(octets)
        local a, b = octets[1], octets[2]
        return a == 10 or (a == 172 and b >= 16 and b <= 31) or (a == 192 and b == 168)
    end

    local function ipv4_number(addr)
        local octets = type(addr) == "string" and core.ipv4_octets(addr)
        if octets then return ((octets[1] * 256 + octets[2]) * 256 + octets[3]) * 256 + octets[4] end
    end

    local function interface_name(value)
        return type(value) == "string" and #value <= 15 and value ~= "lo" and value:match("^[%a][%w_.%-]*$")
    end

    local function validate(capture)
        if not valid_fields(capture, { interface = true, mode = true, sources = true })
            or not interface_name(capture.interface) then return nil end
        if capture.mode == "all" then
            if capture.sources ~= nil then return nil end
            return json.object({ interface = capture.interface, mode = "all" })
        end
        if (capture.mode ~= nil and capture.mode ~= "selected") or not json.is_array(capture.sources)
            or #capture.sources < 1 or #capture.sources > 32 then return nil end
        local sources, seen = {}, {}
        for _, source in ipairs(capture.sources) do
            local octets = type(source) == "string" and core.ipv4_octets(source)
            if not octets or not private_ipv4(octets) or seen[source] then return nil end
            seen[source] = true
            sources[#sources + 1] = source
        end
        table.sort(sources)
        return json.object({ interface = capture.interface, mode = "selected", sources = json.array(sources) })
    end

    local function output(argv, dir, limit)
        local path = dir .. "/capture-output"
        if platform.run(argv, { timeout = 3, stdout = path }) ~= 0 then return nil end
        return platform.read(path, limit)
    end

    local function read_json(argv, dir)
        local data = output(argv, dir, 512 * 1024)
        if not data then return nil end
        local ok, value = pcall(json.decode, data)
        if ok then return value end
    end

    local function uint(value)
        local n = json.integer(value)
        if type(value) == "string" then
            if value:match("^%d+$") then n = tonumber(value)
            elseif value:match("^0[xX][%da-fA-F]+$") then n = tonumber(value:sub(3), 16) end
        end
        if n and n >= 0 and n <= 4294967295 then return n end
    end

    local function subnet(address, prefix)
        local addr, bits = ipv4_number(address), uint(prefix)
        if not addr or not bits or bits < 8 or bits > 31 then return nil end
        local size = 2 ^ (32 - bits)
        local first = addr - addr % size
        return { addr = addr, first = first, last = first + size - 1, bits = bits }
    end

    local function client_on_subnet(address, subnets)
        local addr, found = ipv4_number(address), false
        if not addr then return false end
        for _, net in ipairs(subnets) do
            if addr == net.addr then return false end
            if (addr > net.first and addr < net.last)
                or (net.bits == 31 and addr >= net.first and addr <= net.last) then
                found = true
            end
        end
        return found
    end

    local function clients_fit(profile, subnets)
        for _, source in ipairs(profile.sources) do
            if not client_on_subnet(source, subnets) then return false end
        end
        return true
    end

    local function uplink_devices(dir)
        local routes = read_json({ ip, "-j", "-4", "route", "show", "table", "all" }, dir)
        if not json.is_array(routes) then return nil end
        local uplinks = {}
        for _, route in ipairs(routes) do
            if json.is_object(route) and (route.dst == "default" or route.dst == "0.0.0.0/0") then
                if route.dev then uplinks[route.dev] = true end
                for _, next_hop in ipairs(json.is_array(route.nexthops) and route.nexthops or {}) do
                    if json.is_object(next_hop) and next_hop.dev then uplinks[next_hop.dev] = true end
                end
            end
        end
        return uplinks
    end

    local function local_networks(dir)
        local state = read_json({ ubus, "call", "network.interface", "dump" }, dir)
        local uplinks = uplink_devices(dir)
        if not json.is_object(state) or not json.is_array(state.interface) or not uplinks then return nil end
        local by_device = {}
        for _, row in ipairs(state.interface) do
            if json.is_object(row) and row.up == true and interface_name(row.l3_device)
                and type(row.interface) == "string" and #row.interface <= 32
                and row.interface:match("^[A-Za-z0-9_.%-]+$") and not row.interface:lower():match("^wan")
                and not uplinks[row.l3_device] and json.is_array(row["ipv4-address"]) then
                local net = by_device[row.l3_device] or { label = row.interface, subnets = {} }
                for _, entry in ipairs(row["ipv4-address"]) do
                    local octets = json.is_object(entry) and type(entry.address) == "string" and core.ipv4_octets(entry.address)
                    local candidate = octets and private_ipv4(octets) and subnet(entry.address, entry.mask)
                    if candidate then net.subnets[#net.subnets + 1] = candidate end
                end
                if #net.subnets > 0 then by_device[row.l3_device] = net end
            end
        end
        return by_device
    end

    local function networks(dir)
        local by_device = local_networks(dir)
        if not by_device then return nil end
        local devices = {}
        for device in pairs(by_device) do devices[#devices + 1] = device end
        table.sort(devices)
        local leases = read_json({ ubus, "call", "luci-rpc", "getDHCPLeases", '{"family":4}' }, dir)
        leases = json.is_object(leases) and json.is_array(leases.dhcp_leases) and leases.dhcp_leases or {}
        local result = json.array()
        for index = 1, math.min(#devices, 32) do
            local device, net = devices[index], by_device[devices[index]]
            local clients, seen = json.array(), {}
            for _, lease in ipairs(leases) do
                local address = json.is_object(lease) and lease.ipaddr
                if address and not seen[address] and client_on_subnet(address, net.subnets) then
                    local name = lease.hostname
                    if type(name) ~= "string" or #name > 80 or not name:match("^[A-Za-z0-9_.%-]+$") then name = nil end
                    clients[#clients + 1] = json.object({ address = address, name = name })
                    seen[address] = true
                    if #clients >= 64 then break end
                end
            end
            table.sort(clients, function(a, b) return ipv4_number(a.address) < ipv4_number(b.address) end)
            result[#result + 1] = json.object({ device = device, label = net.label, clients = clients })
        end
        return result, by_device
    end

    local function scope_on_network(profile, inventory)
        local net = inventory[profile.interface]
        return net ~= nil and (profile.mode == "all" or clients_fit(profile, net.subnets))
    end

    local function ip_state(family, dir)
        local rules = read_json({ ip, "-j", "-N", family, "rule", "show" }, dir)
        local routes = read_json({ ip, "-j", "-N", family, "route", "show", "table", "all" }, dir)
        if not json.is_array(rules) or not json.is_array(routes) then return nil end

        local state = { rules = {}, routes = {} }
        local fields = { priority = true, src = true, fwmark = true, fwmask = true, table = true,
            protocol = true, flags = true }
        for _, rule in ipairs(rules) do
            if not json.is_object(rule) then return nil end
            local priority, target, mark = uint(rule.priority), uint(rule.table), uint(rule.fwmark)
            local mask = rule.fwmask == nil and 4294967295 or uint(rule.fwmask)
            if not priority or (rule.fwmark ~= nil and not mark) or not mask then return nil end
            local reserved = marks[priority] or marks[target]
            if reserved then
                if family ~= "-4" or priority ~= target or mark ~= reserved or mask ~= reserved
                    or rule.src ~= "all" or state.rules[target] or not valid_fields(rule, fields)
                    or (rule.flags and (not json.is_array(rule.flags) or #rule.flags ~= 0)) then
                    state.conflict = true
                else
                    state.rules[target] = true
                end
            elseif mark and (platform.band(tcp_mark, mask) == mark or platform.band(udp_mark, mask) == mark) then
                state.policy = true
            elseif family == "-4" and priority < tcp_table
                and not (priority == 0 and (target == 255 or rule.table == "local") and rule.src == "all") then
                -- A higher priority custom rule can consume a marked packet first.
                state.policy = true
            end
        end
        local route_fields = { type = true, dst = true, dev = true, table = true, scope = true,
            protocol = true, flags = true }
        for _, route in ipairs(routes) do
            if not json.is_object(route) then return nil end
            local target = uint(route.table)
            local default = route.dst == "default" or route.dst == "0.0.0.0/0" or route.dst == "::/0"
            if marks[target] then
                if family ~= "-4" or not default or route.dev ~= "lo"
                    or (route.type ~= "local" and uint(route.type) ~= 2)
                    or (route.scope ~= "host" and uint(route.scope) ~= 254)
                    or state.routes[target] or not valid_fields(route, route_fields)
                    or (route.flags and (not json.is_array(route.flags) or #route.flags ~= 0)) then
                    state.conflict = true
                else
                    state.routes[target] = true
                end
            elseif family == "-6" and default and
                (not route.type or route.type == "unicast" or uint(route.type) == 1) then
                state.policy = true
            end
        end
        return state
    end

    local function meta(expr, key)
        return type(expr) == "table" and type(expr.meta) == "table" and expr.meta.key == key
    end

    local function payload(expr, field)
        return type(expr) == "table" and type(expr.payload) == "table"
            and expr.payload.protocol == "ip" and expr.payload.field == field
    end

    local function transport(value)
        local number = uint(value)
        if value == "tcp" or number == 6 then return "tcp" end
        if value == "udp" or number == 17 then return "udp" end
    end

    local function exact_set(right, convert, expected)
        if type(right) ~= "table" or not json.is_array(right.set) then return false end
        local seen = {}
        for _, value in ipairs(right.set) do
            local key = convert(value)
            if not key or not expected[key] or seen[key] then return false end
            seen[key] = true
        end
        for key in pairs(expected) do if not seen[key] then return false end end
        return true
    end

    local function fib_type(value)
        local number = uint(value)
        if value == "local" or number == 2 then return "local" end
        if value == "broadcast" or number == 3 then return "broadcast" end
        if value == "multicast" or number == 5 then return "multicast" end
    end

    local function standard_return(match)
        local left, right = match.left, match.right
        if match.op == "!=" then
            return (meta(left, "l4proto") and exact_set(right, transport, { tcp = true, udp = true }))
                or (payload(left, "saddr") and right == "@lan_saddr4")
        end
        if match.op ~= "==" then return false end
        local fib = type(left) == "table" and left.fib
        if type(fib) == "table" and fib.result == "type" and (fib.flags == "daddr"
            or (json.is_array(fib.flags) and #fib.flags == 1 and fib.flags[1] == "daddr")) then
            return exact_set(right, fib_type, { ["local"] = true, broadcast = true, multicast = true })
        end
        return payload(left, "daddr") and (right == "@direct_cidrs" or right == "@bypass_cidrs" or right == "@bypass_hosts")
    end

    local function marked_return(first, second)
        if first.op ~= "==" or not meta(first.left, "l4proto") or not json.is_object(second) or second.op ~= "==" then
            return false
        end
        local proto = transport(first.right)
        local mark = proto == "tcp" and tcp_mark or proto == "udp" and udp_mark
        local mask = type(second.left) == "table" and second.left["&"]
        return mark and uint(second.right) == mark and json.is_array(mask) and #mask == 2
            and meta(mask[1], "mark") and uint(mask[2]) == mark
    end

    local function empty_elements(elements)
        return elements == nil or (json.is_array(elements) and #elements == 0)
    end

    local function source_matches(set, profile)
        if set.type ~= "ipv4_addr" then return false end
        -- Manager emits the set even when SRC_MODE=off and its input file is absent.
        if profile.mode == "all" then return empty_elements(set.elem) end
        if not json.is_array(set.elem) or #set.elem > #profile.sources then return false end
        local expected = {}
        for _, source in ipairs(profile.sources) do expected[ipv4_number(source)] = true end
        for _, element in ipairs(set.elem) do
            local first, last
            if type(element) == "table" and type(element.prefix) == "table" then
                local bits = uint(element.prefix.len)
                first = ipv4_number(element.prefix.addr)
                if not first or not bits or bits < 27 or bits > 32 then return false end
                local size = 2 ^ (32 - bits)
                if first % size ~= 0 then return false end
                last = first + size - 1
            elseif type(element) == "table" and json.is_array(element.range) and #element.range == 2 then
                first, last = ipv4_number(element.range[1]), ipv4_number(element.range[2])
            else
                first = ipv4_number(element)
                last = first
            end
            if not first or not last or first > last or last - first >= #profile.sources then
                return false
            end
            for addr = first, last do
                if not expected[addr] then return false end
                expected[addr] = nil
            end
        end
        return next(expected) == nil
    end

    local function nft_state(profile, dir)
        local data = read_json({ nft, "-j", "-nn", "list", "ruleset" }, dir)
        if not json.is_object(data) or not json.is_array(data.nftables) then return nil end
        local state = {}
        local own_tables, own_chains, scope_sets = 0, 0, 0
        local interface_gate, source_gate, protocols = false, false, {}
        local selected = profile.mode == "selected"
        local allowed_sets = { src_only4 = true, lan_saddr4 = true, direct_cidrs = true,
            bypass_cidrs = true, bypass_hosts = true }
        local empty_sets = { ports_tcp = "inet_service", ports_udp = "inet_service", src_bypass4 = "ipv4_addr" }

        for _, item in ipairs(data.nftables) do
            if not json.is_object(item) then return nil end
            for kind, object in pairs(item) do
                if not json.is_object(object) then return nil end
                local own = (kind == "table" and object.name == table_name) or object.table == table_name
                if own then
                    state.present = true
                    if object.family ~= "inet" then return { conflict = true } end
                    if kind == "table" then
                        own_tables = own_tables + 1
                    elseif kind == "chain" and object.name == "prerouting" and object.type == "filter"
                        and object.hook == "prerouting" and object.policy == "accept"
                        and uint(object.prio) == 0 and not object.dev then
                        own_chains = own_chains + 1
                    elseif kind == "set" and allowed_sets[object.name] then
                        if object.name == "src_only4" then
                            if not source_matches(object, profile) then return { conflict = true } end
                            scope_sets = scope_sets + 1
                        end
                    elseif kind == "set" and empty_sets[object.name] and empty_sets[object.name] == object.type then
                        if not empty_elements(object.elem) then return { conflict = true } end
                    elseif kind == "rule" and object.chain == "prerouting" and json.is_array(object.expr) then
                        local expr = object.expr
                        local first, second = expr[1], expr[2]
                        if not json.is_object(first) or not json.is_object(second)
                            or not json.is_object(first.match) then
                            return { conflict = true }
                        end
                        local match = first.match
                        if #expr == 2 and second["return"] ~= nil then
                            if match.op == "!=" and meta(match.left, "iifname") then
                                local right = match.right
                                if type(right) == "table" and json.is_array(right.set) and #right.set == 1 then
                                    right = right.set[1]
                                end
                                if interface_gate or right ~= profile.interface then return { conflict = true } end
                                interface_gate = true
                            elseif match.op == "!=" and match.right == "@src_only4" and payload(match.left, "saddr") then
                                if not selected or source_gate then return { conflict = true } end
                                source_gate = true
                            elseif not standard_return(match) then
                                return { conflict = true }
                            end
                        elseif #expr == 4 and interface_gate and (not selected or source_gate) and match.op == "=="
                            and meta(match.left, "l4proto") then
                            local proto = transport(match.right)
                            local mark = proto == "tcp" and tcp_mark or proto == "udp" and udp_mark
                            local mangle = second.mangle
                            local target = type(expr[3]) == "table" and expr[3].tproxy
                            if not mark or protocols[proto] or type(mangle) ~= "table"
                                or not meta(mangle.key, "mark") or uint(mangle.value) ~= mark
                                or type(target) ~= "table" or target.family ~= "ip"
                                or target.addr ~= "127.0.0.1" or uint(target.port) ~= port
                                or not json.is_object(expr[4]) or expr[4].accept == nil then
                                return { conflict = true }
                            end
                            protocols[proto] = true
                        elseif #expr ~= 3 or not marked_return(match, second.match) or not json.is_object(expr[3])
                            or expr[3]["return"] == nil then
                            return { conflict = true }
                        end
                    else
                        return { conflict = true }
                    end
                elseif kind == "flowtable" then
                    state.policy = true
                elseif kind == "rule" and json.is_array(object.expr) then
                    for _, stmt in ipairs(object.expr) do
                        if type(stmt) == "table" then
                            local target = type(stmt.xt) == "table" and stmt.xt.name
                            if stmt.tproxy ~= nil or target == "TPROXY" or target == "MARK" or target == "CONNMARK"
                                or (type(stmt.mangle) == "table" and meta(stmt.mangle.key, "mark")) then
                                state.policy = true
                            end
                        end
                    end
                end
            end
        end

        if state.present then
            if own_tables ~= 1 or own_chains ~= 1 or scope_sets ~= 1 or not protocols.tcp or not protocols.udp then
                -- A manager nft batch is atomic. An incomplete or modified
                -- tree under the reserved name is not proven ours to remove.
                return { conflict = true }
            end
            state.active = true
        end
        return state
    end

    local function state_file_ok(path)
        local info = platform.lstat(path)
        if not info then return true, false end
        if info.type ~= "reg" or info.uid ~= 0 or info.modestr ~= "rw-------" then return false end
        local data = platform.read(path, 4096)
        if not data then return false end
        local seen = {}
        for line in data:gmatch("[^\n]+") do
            local key, value = line:match("^([A-Z_0-9]+)=(.*)$")
            if state_values[key] then
                if seen[key] or (value ~= state_values[key] and value ~= "") then return false end
                seen[key] = true
            elseif key == "STALE_NFT" then
                if value ~= table_name then return false end
            elseif key == "STALE_ROUTE" then
                if value ~= "4," .. tcp_table and value ~= "4," .. udp_table then return false end
            elseif key == "STALE_RULE" then
                if value ~= "4,0x10000000," .. tcp_table .. "," .. tcp_table
                    and value ~= "4,0x20000000," .. udp_table .. "," .. udp_table then return false end
            else
                return false
            end
        end
        for key in pairs(state_values) do
            if not seen[key] then return false end
        end
        return true, true
    end

    local function inspect_details(profile, dir)
        local nft_result, v4, v6 = nft_state(profile, dir), ip_state("-4", dir), ip_state("-6", dir)
        if not nft_result or not v4 or not v6 then return nil, "capture_unavailable" end
        local file_ok, state = state_file_ok(state_file)
        local recovery_ok, recovery = state_file_ok(state_file .. ".recovery")
        if not file_ok or not recovery_ok or nft_result.conflict or v4.conflict or v6.conflict then
            return "conflict"
        end
        local policy = nft_result.policy or v4.policy or v6.policy
        if nft_result.active and v4.rules[tcp_table] and v4.rules[udp_table]
            and v4.routes[tcp_table] and v4.routes[udp_table] and (state or recovery) and not policy then
            return "active"
        end
        if nft_result.present or next(v4.rules) or next(v4.routes) or state or recovery then
            return "partial"
        end
        return "absent", policy and "capture_policy" or nil
    end

    local function inspect(profile, dir)
        local checked = validate(profile)
        if not checked then return nil, "capture_policy" end
        return inspect_details(checked, dir)
    end

    local function scope_on_lan(profile, dir)
        if profile.mode == "all" then
            local inventory = local_networks(dir)
            return inventory ~= nil and scope_on_network(profile, inventory)
        end
        local uplinks = uplink_devices(dir)
        if not uplinks or uplinks[profile.interface] then return false end
        local devices = read_json({ ip, "-j", "-4", "addr", "show", "dev", profile.interface }, dir)
        if not json.is_array(devices) or #devices ~= 1 or not json.is_object(devices[1])
            or not json.is_array(devices[1].addr_info) then return false end
        local subnets = {}
        for _, entry in ipairs(devices[1].addr_info) do
            local candidate = json.is_object(entry) and subnet(entry["local"], entry.prefixlen)
            if candidate then subnets[#subnets + 1] = candidate end
        end
        return clients_fit(profile, subnets)
    end

    local function offload_disabled(dir)
        local path = dir .. "/capture-output"
        for _, option in ipairs({ "flow_offloading", "flow_offloading_hw" }) do
            local status = platform.run({ "/sbin/uci", "-q", "get", "firewall.@defaults[0]." .. option },
                { timeout = 3, stdout = path })
            if status == 0 then
                local value = platform.read(path, 32)
                if not value or not ({ ["0"] = true, no = true, off = true, ["false"] = true })[
                    value:gsub("%s", ""):lower()] then return false end
            elseif status ~= 1 then return false end
        end
        return true
    end

    local function safe_table_names()
        local function check(path)
            if not platform.lstat(path) then return true end
            local text = platform.read(path, 65536)
            if not text then return false end
            for line in text:gmatch("[^\r\n]+") do
                local name = line:match("^%s*[^%s#]+%s+([^%s#]+)")
                if name == tostring(tcp_table) or name == tostring(udp_table) then return false end
            end
            return true
        end
        for _, parent in ipairs({ "/etc/iproute2", "/usr/lib/iproute2", "/usr/share/iproute2" }) do
            if not check(parent .. "/rt_tables") then return false end
            local dir = parent .. "/rt_tables.d"
            if platform.lstat(dir) then
                local names = platform.list(dir)
                if not names then return false end
                for name in names do
                    if name:match("%.conf$") and not check(dir .. "/" .. name) then return false end
                end
            end
        end
        return true
    end

    local function runtime_ready(dir)
        local shim = shim_dir .. "/uci"
        local info = platform.lstat(shim)
        if not info or info.type ~= "reg" or info.uid ~= 0 or info.modestr ~= "rwxr-xr-x"
            or not platform.executable(shim) or platform.read(shim, 64) ~= "#!/bin/sh\nexit 1\n"
            or not platform.executable(manager) then return false end
        local hash = output({ "/bin/busybox", "sha256sum", manager }, dir, 256)
        if not hash or hash:match("^(%x+)%s") ~= digest then return false end
        return safe_table_names() and platform.private_dir(platform.runtime_dir) and platform.private_dir(state_dir)
            and platform.private_dir(lock_dir) and not platform.lstat(unused_list)
    end

    local function run_manager(action, profile)
        local selected = profile.mode == "selected"
        local env = {
            PATH = shim_dir .. ":/usr/sbin:/usr/bin:/sbin:/bin",
            LAN_IFACES = profile.interface, SRC_MODE = selected and "only" or "off",
            SRC_ONLY_V4_FILE = selected and source_file or unused_list,
            PORT_MODE_DEFAULT = "bypass", TPORT_TCP = tostring(port), TPORT_UDP = tostring(port),
            STATE_FILE = state_file, TMP_ROOT = state_dir,
            LOCK_ROOT = lock_dir, LOCK_WAIT_SECONDS = "1", LOG_ENABLED = "0",
            BYPASS_V4_FILE = unused_list, BYPASS_V6_FILE = unused_list, BYPASS_PORTS_FILE = unused_list,
            SRC_ONLY_V6_FILE = unused_list, SRC_BYPASS_V4_FILE = unused_list, SRC_BYPASS_V6_FILE = unused_list,
        }
        for key, value in pairs(state_values) do env[key] = value end
        return platform.run({ manager, "-q", action }, { timeout = 8, env = env })
    end

    local function start(profile, dir, arm)
        profile = validate(profile)
        if not profile then return nil, "capture_policy" end
        local before, err = inspect_details(profile, dir)
        if not before or err then return nil, err end
        if before ~= "absent" then return nil, "capture_conflict" end
        if not offload_disabled(dir) or not scope_on_lan(profile, dir) then return nil, "capture_policy" end
        if not runtime_ready(dir) then return nil, "capture_unavailable" end
        if profile.mode == "selected" and not platform.write(source_file, table.concat(profile.sources, "\n") .. "\n") then
            return nil, "capture_failed"
        end
        if not arm() then return nil, "storage_error" end
        local result = run_manager("start", profile)
        local after = inspect_details(profile, dir)
        if result ~= 0 or after ~= "active" then
            return nil, "capture_failed"
        end
        return true
    end

    local function stop(profile, dir)
        profile = validate(profile)
        if not profile then return nil, "capture_policy" end
        local before, err = inspect_details(profile, dir)
        if not before then return nil, err end
        if before == "conflict" then return nil, "capture_conflict" end
        if before == "absent" then return true end
        if not runtime_ready(dir) then return nil, "capture_unavailable" end
        local result = run_manager("stop", profile)
        local after = inspect_details(profile, dir)
        if result ~= 0 or after ~= "absent" then
            return nil, "capture_failed"
        end
        return true
    end

    return {
        validate = validate, inspect = inspect, start = start, stop = stop, port = port,
        networks = networks, scope_on_network = scope_on_network,
    }
end
