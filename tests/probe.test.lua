local json = dofile("route_json.lua")
local core = assert(loadfile("route_core.lua"))(json)
local build = dofile("luci/runtime/probe.lua")
local subscription = dofile("luci/runtime/subscription.lua")(json, nil, core)

local DIR = "/tmp/vpn-routing-test"
local ID = "00000000-0000-4000-8000-000000000001"
local LINK = "vless://" .. ID .. "@node.example.invalid:443?type=xhttp&security=tls&mode=stream-up"
local PROBE_URL = "https://probe.example.invalid/generate_204"
local PORT = 51001
local USER = "vpn-routing"
local PASS = ("ab"):rep(16)

local function argument(command, flag)
    for i, item in ipairs(command) do
        if item == flag then return command[i + 1] end
    end
end

local function fixture()
    local fields = json.decode([[
      {"tag":"proxy","protocol":"vless","settings":{"vnext":[{
        "address":"node.example.invalid","port":443,
        "users":[{"id":"]] .. ID .. [[","flow":"","encryption":"none"}]
      }]},
      "network":"xhttp","security":"tls","headerType":"none","host":"web.example.invalid",
      "path":"/r","mode":"stream-up","authority":"","serviceName":"","serverName":"",
      "fingerprint":"chrome","publicKey":"","shortId":"","spiderX":"/","allowInsecure":false,"alpn":[]}
    ]])
    local mock = {
        files = {}, fields = fields, curl_calls = 0, stops = 0, starts = 0, resolutions = 0,
        exit_code = 0, status_line = "204\t0.011600\t127.0.0.1\t51001\n",
        answers = { "93.184.215.14" },
    }
    local platform = {
        dependency = function(name) return "/usr/bin/" .. name end,
        executable = function(path) return path ~= mock.missing end,
        write = function(path, data)
            mock.files[path] = data
            return true
        end,
        read = function(path, limit)
            local data = mock.files[path]
            return data and #data <= limit and data or nil
        end,
        resolve4 = function(hostname)
            assert(hostname == "node.example.invalid")
            mock.resolutions = mock.resolutions + 1
            return mock.answers
        end,
        with_workspace = function(task)
            local result, reason = task(DIR)
            mock.cleaned = true
            return result, reason
        end,
        tcp_port = function() return PORT end,
        random_hex = function(bytes)
            assert(bytes == 16)
            return PASS
        end,
        sleep = function(seconds) assert(seconds == 0.1 or seconds == 0.15) end,
        spawn = function(command, options)
            mock.starts = mock.starts + 1
            mock.owner_checks, mock.curl_baseline = 0, mock.curl_calls
            assert(command[1] == "/usr/bin/xray" and command[2] == "run")
            assert(options.lifetime == 14)
            assert(not table.concat(command, " "):find(ID, 1, true))
            local config = json.decode(mock.files[argument(command, "-config")])
            local incoming = config.inbounds[1]
            assert(#config.inbounds == 1 and #config.outbounds == 1)
            assert(incoming.listen == "127.0.0.1" and json.integer(incoming.port) == PORT)
            assert(incoming.protocol == "socks" and incoming.settings.auth == "password")
            assert(incoming.settings.udp == false and #incoming.settings.users == 1)
            assert(incoming.settings.users[1].user == USER and incoming.settings.users[1].pass == PASS)
            assert(config.outbounds[1].tag == "proxy")
            assert(config.outbounds[1].protocol == (mock.protocol or "vless"))
            assert(config.log.loglevel == "none" and not config.routing)
            return 501
        end,
        stop = function(process)
            assert(process == 501)
            mock.stops = mock.stops + 1
            return not mock.stop_failed
        end,
        child_listener = function(process, port)
            assert(process == 501 and port == PORT)
            mock.owner_checks = mock.owner_checks + 1
            if mock.foreign_listener or (mock.owner_lost and mock.curl_calls > mock.curl_baseline) then return false end
            return mock.owner_checks >= (mock.ready_after or 1)
        end,
        run = function(command, options)
            if command[1] == "/usr/bin/vless2json.sh" then
                assert(options.timeout == 3)
                assert(argument(command, "--tag") == "proxy" and command[#command] == "--one-outbound")
                local source = mock.files[argument(command, "-r")]
                assert(source:sub(-1) == "\n")
                assert(not table.concat(command, " "):find(ID, 1, true))
                local template = json.decode(mock.files[argument(command, "-t")]).outbounds[1]
                assert(template.protocol == (mock.protocol or "vless"))
                if mock.protocol == "hysteria" then
                    assert(template.auth == "__HY2_AUTH__")
                    assert(not table.concat(command, " "):find("fixture+pass", 1, true))
                    assert(source == mock.source)
                else
                    assert(source:match("^vless://") and template.path == "__PATH__")
                end
                mock.files[options.stdout] = mock.raw_output or json.encode(mock.fields)
                return 0
            end
            assert(command[1] == "/usr/bin/curl" and command[2] == "-q")
            mock.curl_calls = mock.curl_calls + 1
            if mock.curl_throws then error("injected platform exception") end
            local arguments = table.concat(command, " ")
            assert(arguments:find(" --head ", 1, true))
            assert(not arguments:find(" --location ", 1, true) and not arguments:find(" --insecure ", 1, true))
            assert(argument(command, "--proxy") == "socks5h://127.0.0.1:" .. PORT)
            assert(argument(command, "--noproxy") == "" and argument(command, "--proto") == "=https")
            assert(options.timeout == 8 and argument(command, "--max-time") == "7")
            assert(not arguments:find("https://", 1, true) and not arguments:find(PASS, 1, true))
            local config = mock.files[argument(command, "--config")]
            assert(config:find('url = "' .. PROBE_URL .. '"\n', 1, true))
            assert(config:find('proxy-user = "' .. USER .. ":" .. PASS .. '"\n', 1, true))
            if mock.refuse_first and mock.curl_calls == 1 then return 7 end
            mock.files[options.stdout] = mock.status_line
            return mock.exit_code, mock.exit_reason
        end,
    }
    return mock, build(json, platform, core, subscription.hysteria_auth)
end

local mock, probe = fixture()
local selected = assert(probe.outbound(DIR, LINK))
assert(selected.settings.vnext[1].address == "93.184.215.14" and mock.resolutions == 1)
assert(selected.streamSettings.tlsSettings.serverName == "node.example.invalid")
assert(selected.streamSettings.tlsSettings.useSystemCA == true and not selected.streamSettings.tlsSettings.allowInsecure)
assert(selected.streamSettings.xhttpSettings.path == "/r")
assert(selected.streamSettings.xhttpSettings.mode == "stream-up")
assert(selected.streamSettings.xhttpSettings.host == "web.example.invalid")
local result = assert(probe.check(selected, PROBE_URL))
assert(result.result == "response" and result.httpCode == 204 and result.elapsedMs == 12)
assert(mock.starts == 1 and mock.stops == 1 and mock.cleaned and mock.owner_checks == 2)

mock, probe = fixture()
mock.answers = { "93.184.215.14", "192.168.1.1" }
local value, reason = probe.outbound(DIR, LINK)
assert(value == nil and reason == "invalid_server")
mock.fields.settings.vnext[1].address = "127.0.0.1"
value, reason = probe.outbound(DIR, LINK)
assert(value == nil and reason == "invalid_server" and mock.resolutions == 1)

mock, probe = fixture()
mock.fields.allowInsecure = true
value, reason = probe.outbound(DIR, LINK)
assert(value == nil and reason == "invalid_server" and mock.resolutions == 0)
mock.fields.allowInsecure = false
value, reason = probe.outbound(DIR, LINK .. "&%65xtra=%7B%7D")
assert(value == nil and reason == "invalid_server")
value, reason = probe.outbound(DIR, LINK .. "&pcs=test-fixture")
assert(value == nil and reason == "invalid_server" and mock.resolutions == 0)
mock.raw_output = '[]'
value, reason = probe.outbound(DIR, LINK)
assert(value == nil and reason == "invalid_server")
mock.raw_output = nil
mock.fields.protocol = "freedom"
value, reason = probe.outbound(DIR, LINK)
assert(value == nil and reason == "invalid_server")

mock, probe = fixture()
mock.fields.network = "tcp"
mock.fields.security = "reality"
mock.fields.serverName = "tls.example.invalid"
mock.fields.publicKey = ("a"):rep(43)
mock.fields.shortId = "00"
selected = assert(probe.outbound(DIR, LINK))
assert(selected.streamSettings.network == "raw" and not selected.streamSettings.tlsSettings)
assert(selected.streamSettings.realitySettings.serverName == "tls.example.invalid")
mock.fields.spiderX = "/?p=0-999999999"
value, reason = probe.outbound(DIR, LINK)
assert(value == nil and reason == "invalid_server")

mock, probe = fixture()
selected = assert(probe.outbound(DIR, LINK))
mock.refuse_first = true
mock.ready_after = 3
mock.status_line = "302\t0.016000\t127.0.0.1\t51001\n"
result = assert(probe.check(selected, PROBE_URL))
assert(result.result == "response" and result.httpCode == 302 and mock.curl_calls == 2 and mock.owner_checks == 4)
mock.exit_code = 28
assert(assert(probe.check(selected, PROBE_URL)).result == "timeout")
mock.owner_lost = true
value, reason = probe.check(selected, PROBE_URL)
assert(value == nil and reason == "probe_failed" and mock.starts == mock.stops)
mock.owner_lost = false
mock.exit_code, mock.exit_reason = nil, "timeout"
assert(assert(probe.check(selected, PROBE_URL)).result == "timeout")
mock.exit_code, mock.exit_reason = 97, nil
assert(assert(probe.check(selected, PROBE_URL)).result == "unreachable")
mock.exit_code, mock.status_line = 0, "200\t0.016000\t93.184.215.14\t443\n"
value, reason = probe.check(selected, PROBE_URL)
assert(value == nil and reason == "probe_failed")
mock.curl_throws = true
value, reason = probe.check(selected, PROBE_URL)
assert(value == nil and reason == "probe_failed" and mock.starts == mock.stops)
mock.curl_throws, mock.stop_failed = false, true
mock.status_line = "200\t0.016000\t127.0.0.1\t51001\n"
value, reason = probe.check(selected, PROBE_URL)
assert(value == nil and reason == "probe_failed" and mock.starts == mock.stops)

mock, probe = fixture()
mock.missing = "/usr/bin/curl"
value, reason = probe.check(selected, PROBE_URL)
assert(value == nil and reason == "dependency_missing" and mock.starts == 0)
mock.missing = nil
value, reason = probe.check(selected, "https://probe.example.invalid/\"\nurl=http://localhost")
assert(value == nil and reason == "probe_failed" and mock.starts == 0)
value, reason = probe.head(PORT, USER, 'bad"password', PROBE_URL, DIR)
assert(value == nil and reason == "probe_failed" and mock.curl_calls == 0)
value, reason = probe.check(json.object({ protocol = "freedom", tag = "proxy" }), PROBE_URL)
assert(value == nil and reason == "invalid_server" and mock.starts == 0)
mock.foreign_listener = true
value, reason = probe.check(selected, PROBE_URL)
assert(value == nil and reason == "probe_failed" and mock.curl_calls == 0 and mock.starts == mock.stops)
assert(assert(probe.head(PORT, USER, PASS, PROBE_URL, DIR)).httpCode == 204)

mock, probe = fixture()
mock.protocol = "hysteria"
mock.fields = json.object({
    tag = "proxy", protocol = "hysteria", address = "node.example.invalid", port = 443,
    auth = "fixture+pass", serverName = "", allowInsecure = false,
    dialerProxy = "direct",
})
local link = "hy2://fixture+pass@node.example.invalid/"
mock.source = "hy2://fixture%2Bpass@node.example.invalid/\n"
selected = assert(probe.outbound(DIR, link))
assert(selected.protocol == "hysteria" and selected.settings.version == 2)
assert(selected.settings.address == "93.184.215.14" and selected.settings.port == 443)
assert(selected.streamSettings.network == "hysteria" and selected.streamSettings.security == "tls")
assert(selected.streamSettings.hysteriaSettings.auth == "fixture+pass")
assert(selected.streamSettings.tlsSettings.serverName == "node.example.invalid")
assert(selected.streamSettings.tlsSettings.useSystemCA and selected.streamSettings.tlsSettings.alpn[1] == "h3")
assert(not selected.dialerProxy and assert(probe.check(selected, PROBE_URL)).httpCode == 204)
mock.fields.auth = "different"
value, reason = probe.outbound(DIR, link)
assert(value == nil and reason == "invalid_server")
mock.fields.auth = "fixture+pass"
mock.answers = { "93.184.215.14", "192.168.1.1" }
value, reason = probe.outbound(DIR, link)
assert(value == nil and reason == "invalid_server")
value, reason = probe.outbound(DIR, link .. "?insecure=1")
assert(value == nil and reason == "invalid_server")
print("probe tests passed")
