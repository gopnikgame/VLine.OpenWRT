local json = dofile("route_json.lua")
local core = assert(loadfile("route_core.lua"))(json)
local capture = dofile("luci/runtime/capture.lua")(json, {
    dependency = function() return "/unused" end,
    runtime_dir = "/var/run/vpn-routing",
}, core)
local module = dofile("luci/runtime/guard.lua")
local dir = "/var/run/vpn-routing/test"
local profile = json.decode('{"interface":"br-vpn-routing","sources":["192.168.77.7","192.168.77.12"]}')
local whole_lan = json.decode('{"interface":"br-vpn-routing","mode":"all"}')
local foreign_profile = json.decode('{"interface":"br-vpn-routing","sources":["192.168.77.7"]}')

local active = [[{"nftables":[
 {"metainfo":{"json_schema_version":1}},
 {"table":{"family":"inet","name":"vpn_guard","handle":78}},
 {"chain":{"family":"inet","table":"vpn_guard","name":"forward","type":"filter","hook":"forward",
  "prio":-10,"policy":"accept","handle":1}},
 {"set":{"family":"inet","table":"vpn_guard","name":"sources4","type":"ipv4_addr","handle":2,
  "elem":["192.168.77.7","192.168.77.12"]}},
 {"set":{"family":"inet","table":"vpn_guard","name":"bypass4","type":"ipv4_addr","handle":3,
  "flags":["interval"],"elem":[{"prefix":{"addr":"10.0.0.0","len":8}},{"prefix":{"addr":"100.64.0.0","len":10}},
  {"prefix":{"addr":"127.0.0.0","len":8}},{"prefix":{"addr":"169.254.0.0","len":16}},
  {"prefix":{"addr":"172.16.0.0","len":12}},{"prefix":{"addr":"192.168.0.0","len":16}},
  {"prefix":{"addr":"224.0.0.0","len":4}},{"prefix":{"addr":"240.0.0.0","len":4}}]}},
 {"rule":{"family":"inet","table":"vpn_guard","chain":"forward","handle":4,"comment":"VPN Routing forward guard v1","expr":[
  {"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"br-vpn-routing"}},
  {"match":{"op":"!=","left":{"meta":{"key":"oifname"}},"right":"br-vpn-routing"}},
  {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"@sources4"}},
  {"match":{"op":"!=","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"@bypass4"}},
  {"counter":{"packets":3,"bytes":18446744073709551615}},{"drop":null}]}}
]}]]

local batch = [[create table inet vpn_guard
add chain inet vpn_guard forward { type filter hook forward priority -10; policy accept; }
add set inet vpn_guard sources4 { type ipv4_addr; elements = { 192.168.77.12, 192.168.77.7 }; }
add set inet vpn_guard bypass4 { type ipv4_addr; flags interval; elements = { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16, 224.0.0.0/4, 240.0.0.0/4, 100.64.0.0/10 }; }
add rule inet vpn_guard forward iifname "br-vpn-routing" oifname != "br-vpn-routing" ip saddr @sources4 ip daddr != @bypass4 counter drop comment "VPN Routing forward guard v1"
]]

local whole_table = json.decode(active)
for index = #whole_table.nftables, 1, -1 do
    local row = whole_table.nftables[index]
    if row.set and row.set.name == "sources4" then table.remove(whole_table.nftables, index) end
    if row.rule then table.remove(row.rule.expr, 3) end
end
local whole_active = json.encode(whole_table)
local whole_batch = batch:gsub('add set inet vpn_guard sources4 [^\n]+\n', ''):gsub('ip saddr @sources4 ', '')

local function environment(all_devices)
    local state = { changes = 0, files = {}, read_fail = false }
    local guard = module(json, {
        run = function(argv, options)
            assert(argv[1] == "/usr/sbin/nft" and options.timeout == 3)
            if argv[2] == "-j" then
                assert(argv[3] == "-a" and argv[4] == "-nn" and argv[5] == "list")
                assert(options.stdout == dir .. "/guard-output")
                if state.read_fail then return 1 end
                if argv[6] == "tables" then
                    local tables = '{"nftables":[{"table":{"family":"inet","name":"fw4","handle":20}}'
                    if state.live then
                        tables = tables .. ',{"table":{"family":"inet","name":"vpn_guard","handle":78}}'
                    end
                    state.files[options.stdout] = state.tables_override or tables .. ']}'
                else
                    assert(argv[6] == "table" and argv[7] == "inet" and argv[8] == "vpn_guard")
                    state.files[options.stdout] = state.live
                end
                return 0
            end
            state.changes = state.changes + 1
            if argv[2] == "-f" then
                local expected = all_devices and whole_batch or batch
                assert(#argv == 3 and argv[3] == dir .. "/guard.nft" and state.files[argv[3]] == expected)
                if state.fail_batch then return 1 end
                if state.replace_before_create then state.live = state.replace_before_create return 1 end
                state.live = state.created_result or (all_devices and whole_active or active)
                return 0
            end
            assert(#argv == 6 and table.concat(argv, " ", 2) == "delete table inet handle 78")
            state.live = nil
            return 0
        end,
        read = function(path, limit)
            assert(path == dir .. "/guard-output" and limit > #active)
            return state.files[path]
        end,
        write = function(path, value)
            assert(path == dir .. "/guard.nft")
            if state.write_fail then return nil end
            state.files[path] = value
            return true
        end,
    }, capture.validate)
    return guard, state
end

local function error_is(expected, result, err)
    assert(result == nil and err == expected, tostring(result) .. " / " .. tostring(err))
end

local guard, state = environment()
assert(guard.inspect(profile, dir) == "absent")
assert(guard.stop(nil, dir))
assert(guard.start(profile, dir))
assert(state.changes == 1 and guard.inspect(profile, dir) == "active")
assert(guard.start(profile, dir) and state.changes == 1)
assert(guard.inspect(foreign_profile, dir) == "conflict")
assert(guard.inspect(whole_lan, dir) == "conflict")
error_is("guard_conflict", guard.stop(foreign_profile, dir))
error_is("guard_conflict", guard.stop(nil, dir))
assert(state.changes == 1)
assert(guard.stop(profile, dir) and state.changes == 2)
assert(guard.stop(profile, dir) and state.changes == 2 and guard.inspect(profile, dir) == "absent")

guard, state = environment(true)
assert(guard.start(whole_lan, dir))
assert(state.changes == 1 and guard.inspect(whole_lan, dir) == "active")
assert(guard.start(whole_lan, dir) and state.changes == 1)
assert(guard.inspect(profile, dir) == "conflict")
error_is("guard_conflict", guard.stop(profile, dir))
assert(state.changes == 1 and guard.stop(whole_lan, dir) and state.changes == 2)
assert(guard.inspect(whole_lan, dir) == "absent")

guard, state = environment(true)
local tampered, count = whole_active:gsub('"field":%s*"daddr"', '"field": "saddr"')
assert(count == 1)
state.live = tampered
assert(guard.inspect(whole_lan, dir) == "conflict")
error_is("guard_conflict", guard.stop(whole_lan, dir))
assert(state.changes == 0)

for _, invalid in ipairs({
    [[{"interface":"br-vpn-routing\"; flush ruleset; #","sources":["192.168.77.7"]}]],
    [[{"interface":"br-vpn-routing","sources":["192.168.77.7 }; flush ruleset"]}]],
    [[{"interface":"br-vpn-routing","sources":["8.8.8.8"]}]],
    [[{"interface":"br-vpn-routing","mode":"all","sources":["192.168.77.7"]}]],
}) do
    guard, state = environment()
    error_is("guard_failed", guard.start(json.decode(invalid), dir))
    assert(state.changes == 0 and next(state.files) == nil)
end

for _, corrupt in ipairs({
    (active:gsub("VPN Routing forward guard v1", "foreign")),
    (active:gsub('"handle":78', '"handle":79')),
    (active:gsub('"prio":%-10', '"prio":1')),
    (active:gsub('"policy":"accept"', '"policy":"drop"')),
    (active:gsub('"192%.168%.77%.12"', '"192.168.77.13"')),
    (active:gsub('"224%.0%.0%.0","len":4', '"0.0.0.0","len":0')),
    (active:gsub('"key":"oifname"', '"key":"iifname"')),
    (active:gsub('"drop":null', '"accept":null')),
    (active:gsub('{"drop":null}', '{"log":{"prefix":"packet"}},{"drop":null}')),
    (active:gsub('"handle":78', '"handle":78,"flags":["dormant"]')),
    (active:gsub('{"chain":', '{"counter":{"family":"inet","table":"vpn_guard","name":"extra"}},{"chain":', 1)),
}) do
    guard, state = environment()
    state.live = corrupt
    assert(guard.inspect(profile, dir) == "conflict")
    error_is("guard_conflict", guard.start(profile, dir))
    error_is("guard_conflict", guard.stop(profile, dir))
    assert(state.changes == 0 and state.live == corrupt)
end

guard, state = environment()
state.live = active:gsub('{"prefix":{"addr":"224%.0%.0%.0","len":4}},{"prefix":{"addr":"240%.0%.0%.0","len":4}}',
    '{"range":["224.0.0.0","255.255.255.255"]}')
assert(guard.inspect(profile, dir) == "active")

guard, state = environment()
state.live = active:gsub('%["192%.168%.77%.7","192%.168%.77%.12"%]', '"192.168.77.7"')
assert(guard.inspect(foreign_profile, dir) == "active")

guard, state = environment()
state.live = "invalid JSON"
error_is("guard_failed", guard.inspect(profile, dir))
error_is("guard_failed", guard.stop(profile, dir))
assert(state.changes == 0 and state.live == "invalid JSON")

guard, state = environment()
state.read_fail = true
error_is("guard_failed", guard.inspect(profile, dir))
error_is("guard_failed", guard.start(profile, dir))
error_is("guard_failed", guard.stop(nil, dir))
assert(state.changes == 0)

guard, state = environment()
state.tables_override = '{"nftables":[{"rule":{}}]}'
error_is("guard_failed", guard.start(profile, dir))
error_is("guard_failed", guard.stop(nil, dir))
assert(state.changes == 0)

guard, state = environment()
state.write_fail = true
error_is("guard_failed", guard.start(profile, dir))
assert(state.changes == 0)
state.write_fail, state.fail_batch = false, true
error_is("guard_failed", guard.start(profile, dir))
assert(state.changes == 1 and guard.inspect(profile, dir) == "absent")
state.fail_batch, state.replace_before_create = false, active:gsub("VPN Routing forward guard v1", "foreign")
error_is("guard_conflict", guard.start(profile, dir))
assert(state.changes == 2 and state.live == state.replace_before_create)

print("guard tests passed")
