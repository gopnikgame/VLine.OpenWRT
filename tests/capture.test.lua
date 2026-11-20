local json = dofile("route_json.lua")
local core = assert(loadfile("route_core.lua"))(json)
local capture_module = dofile("luci/runtime/capture.lua")
local profile = json.decode('{"interface":"br-vpn-routing","sources":["192.168.77.12","192.168.77.7"]}')
local whole_lan = json.decode('{"interface":"br-vpn-routing","mode":"all"}')
local lan_networks = [[{"interface":[
 {"up":true,"interface":"lan","l3_device":"br-vpn-routing","ipv4-address":[{"address":"192.168.77.1","mask":24}]}
]}]]
local runtime = "/var/run/vpn-routing"
local state_path = runtime .. "/capture/manager.state"
local digest = "344d8369125aead4db3c579673dfbcedb4947f5850f492ed3d05810f9f2f27e8"
local state_bytes = [[NFT_TABLE=vpn_capture
FWMARK_TCP=0x10000000
FWMARK_UDP=0x20000000
RTTAB_TCP=21219
RTTAB_UDP=21220
RULE_PRIO_TCP=21219
RULE_PRIO_UDP=21220
IPV6_ENABLED=0
]]
local rules = [[
[{"priority":0,"src":"all","table":"255"},
 {"priority":21219,"src":"all","fwmark":"0x10000000","fwmask":"0x10000000","table":"21219"},
 {"priority":21220,"src":"all","fwmark":"0x20000000","fwmask":"0x20000000","table":"21220"},
 {"priority":32766,"src":"all","table":"254"}]
]]
local routes = [[
[{"type":"local","dst":"default","dev":"lo","table":"21219","scope":"254","flags":[]},
 {"type":"local","dst":"default","dev":"lo","table":"21220","scope":"254","flags":[]}]
]]
local tree = [[
{"nftables":[
 {"metainfo":{"json_schema_version":1}},
 {"table":{"family":"inet","name":"vpn_capture"}},
 {"set":{"family":"inet","table":"vpn_capture","name":"ports_tcp","type":"inet_service","flags":["interval"]}},
 {"set":{"family":"inet","table":"vpn_capture","name":"ports_udp","type":"inet_service","flags":["interval"]}},
 {"set":{"family":"inet","table":"vpn_capture","name":"src_bypass4","type":"ipv4_addr","flags":["interval"]}},
 {"set":{"family":"inet","table":"vpn_capture","name":"src_only4","type":"ipv4_addr",
  "flags":["interval"],"elem":["192.168.77.7",{"prefix":{"addr":"192.168.77.12","len":32}}]}},
 {"chain":{"family":"inet","table":"vpn_capture","name":"prerouting","type":"filter",
  "hook":"prerouting","prio":0,"policy":"accept"}},
 {"rule":{"family":"inet","table":"vpn_capture","chain":"prerouting","expr":[
  {"match":{"op":"!=","left":{"meta":{"key":"iifname"}},"right":{"set":["br-vpn-routing"]}}},{"return":null}]}},
 {"rule":{"family":"inet","table":"vpn_capture","chain":"prerouting","expr":[
  {"match":{"op":"!=","left":{"meta":{"key":"l4proto"}},"right":{"set":[6,17]}}},{"return":null}]}},
 {"rule":{"family":"inet","table":"vpn_capture","chain":"prerouting","expr":[
  {"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":6}},
  {"match":{"op":"==","left":{"&":[{"meta":{"key":"mark"}},268435456]},"right":268435456}},{"return":null}]}},
 {"rule":{"family":"inet","table":"vpn_capture","chain":"prerouting","expr":[
  {"match":{"op":"==","left":{"fib":{"flags":["daddr"],"result":"type"}},"right":{"set":[2,3,5]}}},{"return":null}]}},
 {"rule":{"family":"inet","table":"vpn_capture","chain":"prerouting","expr":[
  {"match":{"op":"!=","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"@src_only4"}},{"return":null}]}},
 {"rule":{"family":"inet","table":"vpn_capture","chain":"prerouting","expr":[
  {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"@bypass_cidrs"}},{"return":null}]}},
 {"rule":{"family":"inet","table":"vpn_capture","chain":"prerouting","expr":[
  {"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":6}},
  {"mangle":{"key":{"meta":{"key":"mark"}},"value":268435456}},
  {"tproxy":{"family":"ip","addr":"127.0.0.1","port":61229}},{"accept":null}]}},
 {"rule":{"family":"inet","table":"vpn_capture","chain":"prerouting","expr":[
  {"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":17}},
  {"mangle":{"key":{"meta":{"key":"mark"}},"value":536870912}},
  {"tproxy":{"family":"ip","addr":"127.0.0.1","port":61229}},{"accept":null}]}}
]}
]]

-- With an absent source file Manager declares an empty src_only4 set and emits no rule for it.
local whole_tree = json.decode(tree)
local source_set, source_rule, source_rule_index
for index, row in ipairs(whole_tree.nftables) do
    if row.set and row.set.name == "src_only4" then source_set = row.set end
    if row.rule and row.rule.expr[1].match.right == "@src_only4" then
        source_rule, source_rule_index = row, index
    end
end
source_set.elem = nil
table.remove(whole_tree.nftables, source_rule_index)
local whole_ruleset = json.encode(whole_tree)

local function fixture(options)
    options = options or {}
    local stage = options.stage or {}
    local files, actions = {}, {}
    local shim = "/usr/libexec/vpn-routing/shim/uci"
    files[shim] = "#!/bin/sh\nexit 1\n"
    files[state_path] = options.state
    local p = { runtime_dir = runtime }
    function p.band(a, b)
        local power, result = 1, 0
        for _ = 1, 32 do
            if a % 2 == 1 and b % 2 == 1 then result = result + power end
            a, b, power = math.floor(a / 2), math.floor(b / 2), power * 2
        end
        return result
    end
    function p.private_dir(path)
        return path ~= "/var/lock/tproxy-manager" or not options.unsafe_lock
    end
    function p.lstat(path)
        if files[path] then
            return { type = "reg", uid = 0, modestr = path == shim and "rwxr-xr-x" or "rw-------" }
        end
    end
    function p.executable()
        return true
    end
    function p.dependency(name)
        return "/usr/bin/" .. name
    end
    function p.read(path, limit)
        local value = files[path]
        if value and #value <= limit then return value end
    end
    function p.write(path, value)
        files[path] = value
        return true
    end
    function p.run(argv, opts)
        local cmd = table.concat(argv, " ")
        local value
        if cmd == "/usr/sbin/nft -j -nn list ruleset" then
            value = stage.nft or '{"nftables":[]}'
        elseif cmd == "/sbin/ip -j -N -4 rule show" then
            value = stage.rules or '[]'
        elseif cmd == "/sbin/ip -j -N -4 route show table all" then
            value = stage.routes or '[]'
        elseif cmd == "/sbin/ip -j -N -6 rule show" then
            value = options.v6_rules or '[]'
        elseif cmd == "/sbin/ip -j -N -6 route show table all" then
            value = options.v6_routes or '[]'
        elseif cmd == "/bin/ubus call network.interface dump" then
            value = options.networks or '{"interface":[]}'
        elseif cmd == "/sbin/ip -j -4 route show table all" then
            value = options.uplinks or '[]'
        elseif cmd == '/bin/ubus call luci-rpc getDHCPLeases {"family":4}' then
            value = options.leases or '{"dhcp_leases":[]}'
        elseif cmd == "/sbin/ip -j -4 addr show dev br-vpn-routing" then
            value = options.iface or '[{"addr_info":[{"local":"192.168.77.1","prefixlen":24}]}]'
        elseif cmd:find("/sbin/uci -q get firewall.", 1, true) == 1 then
            value = options.offload or "0\n"
        elseif cmd == "/bin/busybox sha256sum /usr/bin/tproxy-manager.sh" then
            value = (options.sha or digest) .. "  /usr/bin/tproxy-manager.sh\n"
        elseif cmd == "/usr/bin/tproxy-manager.sh -q start" then
            local env = opts.env
            assert(env.PATH == "/usr/libexec/vpn-routing/shim:/usr/sbin:/usr/bin:/sbin:/bin")
            assert(env.IPV6_ENABLED == "0" and env.LAN_IFACES == "br-vpn-routing")
            if options.mode == "all" then
                assert(env.SRC_MODE == "off" and env.SRC_ONLY_V4_FILE == runtime .. "/capture/unused")
                assert(not files[env.SRC_ONLY_V4_FILE])
            else
                assert(env.SRC_MODE == "only" and files[env.SRC_ONLY_V4_FILE] == "192.168.77.12\n192.168.77.7\n")
            end
            assert(env.FWMARK_TCP == "0x10000000" and env.FWMARK_UDP == "0x20000000")
            assert(env.NFT_TABLE == "vpn_capture" and env.STATE_FILE == state_path)
            assert(env.TMP_ROOT == runtime .. "/capture")
            actions[#actions + 1] = "start"
            if not options.no_apply then
                stage = { nft = options.mode == "all" and whole_ruleset or tree, rules = rules, routes = routes }
                files[state_path] = state_bytes
            end
            return 0
        elseif cmd == "/usr/bin/tproxy-manager.sh -q stop" then
            assert(opts.env.STATE_FILE == state_path)
            actions[#actions + 1] = "stop"
            if not options.no_remove then
                stage = {}
                files[state_path] = nil
            end
            return 0
        else
            error("unexpected mock command: " .. cmd)
        end
        files[opts.stdout] = value
        return 0
    end
    return capture_module(json, p, core), actions
end

local function rejected(options, code, scope)
    local capture, actions = fixture(options)
    local ok, err = capture.start(scope or profile, "/work", function() error("must not arm on preflight failure") end)
    assert(not ok and err == code, tostring(err))
    assert(#actions == 0)
end

do
    local capture, actions = fixture()
    assert(capture.port == 61229)
    local legacy = assert(capture.validate(profile))
    assert(legacy.mode == "selected" and legacy.sources[1] == "192.168.77.12")
    assert(json.equal(capture.validate(whole_lan), whole_lan))
    assert(json.equal(capture.validate(legacy), legacy))
    for _, invalid in ipairs({
        '{"interface":"lo","sources":["192.168.77.7"]}',
        '{"interface":"br-vpn-routing","sources":[]}',
        '{"interface":"br-vpn-routing;id","sources":["192.168.77.7"]}',
        '{"interface":"br-vpn-routing","sources":["192.168.77.7/32"]}',
        '{"interface":"br-vpn-routing","sources":["127.0.0.1"]}',
        '{"interface":"br-vpn-routing","sources":["8.8.8.8"]}',
        '{"interface":"br-vpn-routing","sources":["10.0.0.3","10.0.0.3"]}',
        '{"interface":"br-vpn-routing","sources":["192.168.77.7"],"extra":true}',
        '{"interface":"br-vpn-routing","mode":"all","sources":[]}',
        '{"interface":"br-vpn-routing","mode":"all","sources":null}',
        '{"interface":"br-vpn-routing","mode":"selected"}',
        '{"interface":"br-vpn-routing","mode":false,"sources":["192.168.77.7"]}',
        '{"interface":"br-vpn-routing","mode":"unknown","sources":["192.168.77.7"]}',
    }) do
        assert(not capture.validate(json.decode(invalid)), invalid)
    end
    assert(capture.inspect(profile, "/work") == "absent")
    assert(capture.start(profile, "/work", function() return true end))
    assert(capture.inspect(profile, "/work") == "active")
    assert(not capture.start(profile, "/work", function() error("must not arm twice") end))
    assert(capture.stop(profile, "/work"))
    assert(capture.inspect(profile, "/work") == "absent")
    assert(capture.stop(profile, "/work"))
    assert(table.concat(actions, ",") == "start,stop")
end

do
    local capture = fixture({
        networks = [[{"interface":[
          {"up":true,"interface":"lan","l3_device":"br-vpn-routing","ipv4-address":[{"address":"192.168.77.1","mask":24}]},
          {"up":true,"interface":"upstream","l3_device":"eth1","ipv4-address":[{"address":"192.168.78.2","mask":24}]},
          {"up":false,"interface":"guest","l3_device":"br-guest","ipv4-address":[{"address":"192.168.79.1","mask":24}]}
        ]}]],
        uplinks = '[{"dst":"default","dev":"eth1"}]',
        leases = [[{"dhcp_leases":[
          {"ipaddr":"192.168.77.7","hostname":"test-device","macaddr":"local-only"},
          {"ipaddr":"192.168.77.1","hostname":"router"},
          {"ipaddr":"192.168.78.9","hostname":"uplink"},
          {"ipaddr":"192.168.77.9","hostname":"<script>"}
        ]}]],
    })
    local list, inventory = capture.networks("/work")
    assert(#list == 1 and list[1].device == "br-vpn-routing" and list[1].label == "lan")
    local clients = list[1].clients
    assert(#clients == 2 and clients[1].name == "test-device" and not clients[1].macaddr and not clients[2].name)
    assert(capture.scope_on_network(profile, inventory))
    assert(capture.scope_on_network(whole_lan, inventory))
    assert(not capture.scope_on_network({ interface = "eth1", mode = "all" }, inventory))
    assert(not capture.scope_on_network({ interface = "eth1", sources = { "192.168.78.9" } }, inventory))
    assert(not capture.scope_on_network({ interface = "br-vpn-routing", sources = { "192.168.77.1" } }, inventory))
    assert(not capture.scope_on_network({ interface = "br-vpn-routing", sources = { "192.168.77.255" } }, inventory))
end

do
    local options = { networks = lan_networks }
    local capture, actions = fixture(options)
    assert(capture.start(profile, "/work", function() return true end))
    assert(capture.inspect(whole_lan, "/work") == "conflict")
    assert(capture.stop(profile, "/work"))

    options.mode = "all"
    assert(capture.start(whole_lan, "/work", function() return true end))
    assert(capture.inspect(whole_lan, "/work") == "active")
    assert(capture.inspect(profile, "/work") == "conflict")
    local ok, err = capture.stop(profile, "/work")
    assert(not ok and err == "capture_conflict")
    assert(capture.stop(whole_lan, "/work"))
    assert(capture.inspect(whole_lan, "/work") == "absent")
    assert(table.concat(actions, ",") == "start,stop,start,stop")
end

do
    source_set.elem = json.array()
    local capture = fixture({ stage = { nft = json.encode(whole_tree), rules = rules, routes = routes },
        state = state_bytes })
    assert(capture.inspect(whole_lan, "/work") == "active")

    table.insert(whole_tree.nftables, source_rule_index, source_rule)
    capture = fixture({ stage = { nft = json.encode(whole_tree), rules = rules, routes = routes },
        state = state_bytes })
    assert(capture.inspect(whole_lan, "/work") == "conflict")
    table.remove(whole_tree.nftables, source_rule_index)

    source_set.elem = json.array({ "192.168.77.7", "192.168.77.12" })
    capture = fixture({ stage = { nft = json.encode(whole_tree), rules = rules, routes = routes },
        state = state_bytes })
    assert(capture.inspect(whole_lan, "/work") == "conflict")
    assert(capture.inspect(profile, "/work") == "conflict")
end

rejected({}, "capture_policy", whole_lan)
rejected({ networks = lan_networks, uplinks = '[{"dst":"default","dev":"br-vpn-routing"}]' }, "capture_policy", whole_lan)
rejected({ networks = lan_networks, offload = "1\n" }, "capture_policy", whole_lan)
rejected({ networks = lan_networks, v6_routes = '[{"dst":"default","dev":"wan6"}]' }, "capture_policy", whole_lan)

rejected({ sha = "0000" }, "capture_unavailable")
rejected({ unsafe_lock = true }, "capture_unavailable")
rejected({ offload = "1\n" }, "capture_policy")
rejected({ iface = '[{"addr_info":[{"local":"192.168.78.1","prefixlen":24}]}]' }, "capture_policy")
rejected({ uplinks = '[{"dst":"default","dev":"br-vpn-routing"}]' }, "capture_policy")
rejected({ v6_routes = '[{"dst":"default","dev":"wan6"}]' }, "capture_policy")
rejected({ stage = { nft = '{"nftables":[{"flowtable":{"family":"inet","table":"fw4","name":"ft"}}]}' } },
    "capture_policy")
rejected({ stage = { nft = '{"nftables":[{"rule":{"family":"inet","table":"foreign","expr":[{"tproxy":{}}]}}]}' } },
    "capture_policy")
rejected({ stage = { routes = '[{"dst":"default","dev":"wan","table":"21219"}]' } }, "capture_conflict")
rejected({ v6_rules = '[{"priority":21219,"src":"all","table":"main"}]' }, "capture_conflict")
rejected({ stage = { rules = '[{"priority":1234,"src":"all","table":"1234","fwmark":"0","fwmask":"0xff"}]' } },
    "capture_policy")
rejected({ state = state_bytes .. "STALE_NFT=foreign\n" }, "capture_conflict")

do
    local capture, actions = fixture({ no_apply = true })
    local ok, err = capture.start(profile, "/work", function() return true end)
    assert(not ok and err == "capture_failed")
    assert(table.concat(actions) == "start")
end

do
    local capture, actions = fixture({ stage = { routes = routes }, state = state_bytes })
    assert(capture.inspect(profile, "/work") == "partial")
    assert(capture.stop(profile, "/work"))
    assert(table.concat(actions) == "stop")
end

do
    local capture, actions = fixture({ stage = { nft = tree, rules = rules, routes = routes },
        state = state_bytes, no_remove = true })
    local ok, err = capture.stop(profile, "/work")
    assert(not ok and err == "capture_failed")
    assert(table.concat(actions) == "stop")
end

do
    local modified = tree:gsub("192%.168%.77%.7", "192.168.77.9")
    local capture, actions = fixture({ stage = { nft = modified, routes = routes }, state = state_bytes })
    assert(capture.inspect(profile, "/work") == "conflict")
    local ok, err = capture.stop(profile, "/work")
    assert(not ok and err == "capture_conflict" and #actions == 0)
end

print("capture tests passed")
