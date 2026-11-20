local json = dofile("route_json.lua")
local core = assert(loadfile("route_core.lua"))(json)
local subscription = dofile("luci/runtime/subscription.lua")

local HOST = "sub.example.test"
local SOURCE = "https://" .. HOST .. "/fixture?key=synthetic-test-value"
local ALLOWED = { [HOST] = true }
local ID = "00000000-0000-4000-8000-000000000001"
local VLESS = "vless://" .. ID .. "@node.example.test:443?type=xhttp&security=reality&path=%2Ffixture"
local BODY_LIMIT = 512 * 1024
local HWID = ("ab"):rep(16)
local WORKSPACE = "/tmp/vpn-routing-fixture"
local function equal(actual, expected, message)
    assert(actual == expected, message or ("expected " .. tostring(expected) .. ", got " .. tostring(actual)))
end

local function option(argv, flag)
    for i, value in ipairs(argv) do
        if value == flag then return argv[i + 1], true end
    end
    return nil, false
end

local function fixture(body, options)
    options = options or {}
    local files = {}
    local calls = { dns = 0, curl = 0, identity = 0, reads = {} }
    local platform = {}
    function platform.resolve4(host)
        equal(host, options.host or HOST)
        calls.dns = calls.dns + 1
        return options.addresses or { "1.1.1.1", "8.8.8.8" }
    end
    function platform.with_workspace(callback)
        local value, err = callback(WORKSPACE)
        files = {}
        return value, err
    end
    function platform.write(path, data)
        if options.write_failed then return false end
        files[path] = data
        return true
    end
    function platform.read(path, limit)
        calls.reads[path] = limit
        local data = files[path]
        if data and #data <= limit then return data end
    end
    function platform.run(argv, run_options)
        calls.curl = calls.curl + 1
        calls.argv = argv
        calls.timeout = run_options.timeout
        calls.private_config = files[option(argv, "--config")]
        files[option(argv, "--output")] = body
        local dump = option(argv, "--dump-header")
        if dump then files[dump] = options.headers end
        local status = options.status or "200"
        if option(argv, "--write-out") == "%{http_code}" then
            files[run_options.stdout] = status
        else
            files[run_options.stdout] = table.concat({ status, options.max_devices or "",
                options.limit or "", options.rejected or "" }, "\t")
        end
        return options.exit_code or 0
    end
    local device = {
        get = function()
            calls.identity = calls.identity + 1
            if not options.identity_failed then return HWID end
        end,
    }
    return subscription(json, platform, core, device), calls
end

local function rejects(source, allowed, reason, options, approved_host)
    local backend, calls = fixture(VLESS, options)
    local result, err = backend.fetch(source, allowed, approved_host)
    equal(result, nil)
    equal(err, reason)
    equal(calls.curl, 0)
    return calls
end

local function base64(value)
    local alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    local out = {}
    local function char(n) return alphabet:sub(n + 1, n + 1) end
    for i = 1, #value, 3 do
        local a, b, c = value:byte(i, i + 2)
        out[#out + 1] = char(math.floor(a / 4))
        out[#out + 1] = char((a % 4) * 16 + math.floor((b or 0) / 16))
        out[#out + 1] = b and char((b % 16) * 4 + math.floor((c or 0) / 64)) or "="
        out[#out + 1] = c and char(c % 64) or "="
    end
    return table.concat(out)
end

-- The input is kept in a private config. TLS and transport options never depend on it.
local backend, calls = fixture("\239\187\191  \r\n# fixture\r\nss://ignored\r\n" .. VLESS .. "#%D0%A3%D0%B7%D0%B5%D0%BB%20A\r\n")
local servers = assert(backend.fetch("HTTPS://SUB.EXAMPLE.TEST:443/fixture?key=synthetic-test-value", ALLOWED))
equal(#servers, 1)
equal(servers[1].name, "Узел A")
equal(servers[1].link, VLESS)
equal(calls.dns, 1)
equal(calls.curl, 1)
equal(calls.identity, 1)
assert(calls.private_config == 'url = "' .. SOURCE .. '"\n'
    .. 'header = "x-hwid: ' .. HWID .. '"\nheader = "x-device-os: OpenWrt"\n', "invalid private curl headers")
equal(calls.argv[1], "/usr/bin/curl")
equal(calls.argv[2], "-q")
equal(option(calls.argv, "--request"), "GET")
equal(option(calls.argv, "--proto"), "=https")
equal(option(calls.argv, "--noproxy"), "*")
equal(option(calls.argv, "--proxy"), "")
equal(option(calls.argv, "--max-redirs"), "0")
equal(option(calls.argv, "--resolve"), HOST .. ":443:1.1.1.1,8.8.8.8")
equal(option(calls.argv, "--max-filesize"), tostring(BODY_LIMIT))
equal(option(calls.argv, "--max-time"), "10")
equal(option(calls.argv, "--user-agent"), "VPN-Routing-OpenWrt/1.0")
equal(calls.timeout, 11)
for _, flag in ipairs({ "--location", "--follow", "--insecure", "--show-error", "--verbose" }) do
    local _, present = option(calls.argv, flag)
    equal(present, false)
end
for _, arg in ipairs(calls.argv) do
    assert(not arg:find("synthetic-test-value", 1, true), "subscription value leaked into curl argv")
    assert(not arg:find(HWID, 1, true), "device identity leaked into curl argv")
end

for _, source in ipairs({
    "http://" .. HOST .. "/fixture",
    "https://user@" .. HOST .. "/fixture",
    "https://" .. HOST .. ":444/fixture",
    "https://" .. HOST .. ":/fixture",
    "https://" .. HOST .. "/fixture#fragment",
    "https://" .. HOST .. "/fixture%2",
    "https://" .. HOST .. '/fixture"\\',
    "https://" .. HOST .. "/fixture\nurl = evil",
    "https://" .. HOST .. "./fixture",
    "https://127.0.0.1/fixture",
    "https://0x7f.0.0.0x1/fixture",
    "https://[::1]/fixture",
    "https://" .. HOST .. "/" .. string.rep("a", 8192),
}) do
    equal(rejects(source, ALLOWED, "invalid_url").dns, 0)
end
local denied = rejects("https://outside.example.test/fixture", ALLOWED, "source_not_allowed")
equal(denied.dns, 0)
equal(denied.identity, 0)
equal(rejects(SOURCE, ALLOWED, "hwid_unavailable", { identity_failed = true }).identity, 1)
equal(rejects(SOURCE, { [HOST] = "true" }, "source_not_allowed").dns, 0)
equal(rejects(SOURCE, nil, "source_not_allowed").dns, 0)
local other_host = "outside.example.test"
local other_source = "https://" .. other_host .. "/fixture"
backend, calls = fixture(VLESS, { host = other_host })
servers = assert(backend.fetch(other_source, ALLOWED, other_host:upper()))
equal(servers[1].link, VLESS)
equal(calls.dns, 1)
equal(option(calls.argv, "--resolve"), other_host .. ":443:1.1.1.1,8.8.8.8")
for _, wrong in ipairs({ "example.test", other_host .. ".", HOST, true }) do
    equal(rejects(other_source, ALLOWED, "source_not_allowed", nil, wrong).dns, 0)
end
equal(rejects(SOURCE, ALLOWED, "source_not_allowed", nil, other_host).dns, 0)
equal(rejects(other_source, ALLOWED, "subscription_unavailable",
    { host = other_host, addresses = { "1.1.1.1", "10.0.0.1" } }, other_host).dns, 1)
equal(rejects("https://127.0.0.1/fixture", ALLOWED, "invalid_url", nil, "127.0.0.1").dns, 0)
for _, addresses in ipairs({
    {}, { "1.1.1.1", "10.0.0.1" }, { "127.0.0.1" }, { "169.254.169.254" },
    { "100.64.0.1" }, { "192.0.2.1" }, { "8.008.8.8" }, { "::ffff:127.0.0.1" },
}) do
    local unsafe = rejects(SOURCE, ALLOWED, "subscription_unavailable", { addresses = addresses })
    equal(unsafe.dns, 1)
    equal(unsafe.identity, 0)
end

local raw = VLESS .. "#Узел 🧪?\n"
local standard = base64(raw)
local urlsafe = standard:gsub("%+", "-"):gsub("/", "_"):gsub("=+$", "")
for _, body in ipairs({ standard, " " .. standard:sub(1, 40) .. "\r\n" .. standard:sub(41), urlsafe }) do
    backend = fixture(body)
    servers = assert(backend.fetch(SOURCE, ALLOWED))
    equal(servers[1].name, "Узел 🧪?")
    equal(servers[1].link, VLESS)
end

for _, name in ipairs({ "", "%C0%80", "x%00y", "x%E2%80%AEy", "x%0Ay", "%ZZ", ID, "vless%3A%2F%2Ffixture" }) do
    backend = fixture(VLESS .. "#" .. name .. "\n" .. VLESS .. "#duplicate")
    servers = assert(backend.fetch(SOURCE, ALLOWED))
    equal(#servers, 1)
    equal(servers[1].name, "Сервер 1")
end

local hy2 = "hysteria2://fixture%3Apass%2Bword@node.example.test:443/?sni=tls.example.test"
local alias = "hy2://other+fixture@node.example.test/?alpn=h3&insecure=0"
local mixed = VLESS .. "#VLESS\n" .. hy2 .. "#Hysteria%202\n" .. alias .. "#Alias"
for _, body in ipairs({ mixed, base64(mixed) }) do
    backend = fixture(body)
    servers = assert(backend.fetch(SOURCE, ALLOWED))
    equal(#servers, 3)
    equal(servers[2].link, hy2)
    equal(servers[2].name, "Hysteria 2")
    equal(servers[3].link, alias)
    equal(servers[3].name, "Alias")
    equal(backend.hysteria_auth(hy2), "fixture:pass+word")
    equal(backend.hysteria_auth(alias), "other+fixture")
end

for _, name in ipairs({ "fixture%3Apass%2Bword", "pass%2Bword", "fixture%253Apass%252Bword" }) do
    backend = fixture(hy2 .. "#" .. name)
    servers = assert(backend.fetch(SOURCE, ALLOWED))
    equal(servers[1].name, "Сервер 1")
end

for _, body in ipairs({
    "", "====", "a", "QQ==junk", "<html>\n" .. VLESS .. "\n</html>", "[\n" .. VLESS .. "\n]",
    "vmess://ignored", (VLESS:gsub("node.example.test", "10.0.0.1")),
    (VLESS:gsub(":443", ":65536")), (VLESS:gsub(":443", ":0443")),
    "hysteria2://node.example.test:443/", "hy2://fixture@192.168.1.1/",
    "hy2://fixture@node.example.test:443,444/", "hy2://fixture@node.example.test:65536/",
    "hy2://fixture@node.example.test:443/path", "hy2://fixture@node.example.test:/",
    "hy2://fixture%00@node.example.test/", "hy2://fixture%FF@node.example.test/",
    "hy2://fixture%ZZ@node.example.test/", "hy2://fixture@node.example.test/?sni=",
    "hy2://fixture@node.example.test/?alpn=h2",
    hy2 .. "&insecure=1", hy2 .. "&insecure=true", hy2 .. "&pinSHA256=deadbeef",
    hy2 .. "&obfs=salamander", hy2 .. "&%73ni=another.example.test", hy2 .. "&fm=%7B%7D",
}) do
    backend = fixture(body)
    local value, err = backend.fetch(SOURCE, ALLOWED)
    equal(value, nil)
    equal(err, "unsupported_subscription")
end

for _, options in ipairs({
    { status = "302", max_devices = "true" }, { status = "204" }, { status = "403" },
    { status = "2000" }, { exit_code = 28 }, { write_failed = true },
}) do
    backend = fixture(VLESS, options)
    local value, err = backend.fetch(SOURCE, ALLOWED)
    equal(value, nil)
    equal(err, "subscription_unavailable")
end
for _, case in ipairs({
    { status = "403", max_devices = "true", error = "hwid_limit_reached" },
    { limit = "TRUE", error = "hwid_limit_reached" },
    { rejected = "true", error = "hwid_rejected" },
}) do
    backend = fixture(VLESS, case)
    local value, err = backend.fetch(SOURCE, ALLOWED)
    equal(value, nil)
    equal(err, case.error)
end
backend = fixture(string.rep("a", BODY_LIMIT + 1))
local large, error_code = backend.fetch(SOURCE, ALLOWED)
equal(large, nil)
equal(error_code, "subscription_unavailable")

local many = {}
for i = 1, 257 do
    many[i] = VLESS:gsub("node.example.test", "node" .. i .. ".example.test") .. "#" .. i
end
backend = fixture(table.concat(many, "\n"))
servers = assert(backend.fetch(SOURCE, ALLOWED))
equal(#servers, 256)
equal(servers[1].name, "1")
equal(servers[256].name, "256")

print("subscription runtime tests passed")
