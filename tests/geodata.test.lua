local json = dofile("route_json.lua")
local core = assert(loadfile("route_core.lua"))(json)
local factory = dofile("luci/runtime/geodata.lua")
local cdn = "https://cdn.jsdelivr.net/gh/hydraponique/roscomvpn-"
local function url(kind, tag)
    return cdn .. kind .. "@" .. tag .. "/release/" .. kind .. ".dat"
end

local ip_url = url("geoip", "202611101104")
local site_url = url("geosite", "202610120948")
local next_site = url("geosite", "202611120948")
local hashes = { ip = string.rep("a", 64), site = string.rep("b", 64), updated = string.rep("c", 64) }
local fixtures = { [ip_url] = "ip", [site_url] = "site", [next_site] = "updated" }
local config = "/etc/vpn-routing"
local managed = config .. "/geodata"
local workspace = "/tmp/vpn-routing/work-fixture"
local files, directories, requests = {}, {}, {}
local corrupt, redirect, reject_write, foreign_path, sync_failure
local answers = { "8.8.8.8", "1.1.1.1" }
local resolves, persisted, validations = 0, 0, 0
local platform = {
    config_dir = config,
    lstat = function(path)
        if path == foreign_path then return { uid = 0, type = "lnk", modestr = "rwxrwxrwx" } end
        if directories[path] then return { uid = 0, type = "dir", modestr = "rwx------" } end
        if files[path] then return { uid = 0, type = "reg", modestr = "rw-------", size = #files[path] } end
    end,
    private_dir = function(path)
        assert(path:sub(1, #config) == config)
        if path == foreign_path then return nil end
        directories[path] = true
        return true
    end,
    read = function(path, limit)
        local bytes = files[path]
        if bytes and #bytes <= limit then return bytes end
    end,
    write = function(path, bytes, durable)
        assert(path:sub(1, #managed) == managed and durable)
        if path == reject_write then return nil end
        persisted = persisted + 1
        files[path] = bytes
        return true
    end,
    sync_persistent = function(path)
        assert(directories[path])
        return path ~= sync_failure
    end,
    resolve4 = function(host)
        resolves = resolves + 1
        assert(host == "cdn.jsdelivr.net")
        return answers
    end,
    run = function(argv, options)
        if argv[1] == "/bin/busybox" then
            assert(argv[2] == "sha256sum" and #argv == 4)
            files[options.stdout] = hashes[files[argv[3]]] .. "  " .. argv[3] .. "\n"
                .. hashes[files[argv[4]]] .. "  " .. argv[4] .. "\n"
            return 0
        end
        assert(argv[1] == "/usr/bin/curl" and argv[2] == "-q")
        local opts = {}
        for i = 3, #argv do opts[argv[i]] = argv[i + 1] end
        assert(opts["--proto"] == "=https" and opts["--max-redirs"] == "0")
        assert(opts["--noproxy"] == "*" and opts["--proxy"] == "" and opts["--ipv4"])
        assert(not opts["--location"] and not opts["--insecure"])
        assert(opts["--resolve"] == "cdn.jsdelivr.net:443:8.8.8.8,1.1.1.1")
        local requested = assert(opts["--url"])
        requests[#requests + 1] = requested
        local src = requested:gsub("%.sha256$", "")
        local kind = assert(src:match("/release/([a-z]+)%.dat$"))
        local file = assert(fixtures[src])
        if src == requested then
            assert(opts["--output"] == workspace .. "/" .. kind .. ".dat")
            assert(tonumber(opts["--max-filesize"]) == 2 * 1024 * 1024)
            files[opts["--output"]] = file
        else
            assert(opts["--output"] == workspace .. "/" .. kind .. ".dat.sha256")
            assert(tonumber(opts["--max-filesize"]) == 128)
            local hash = src == corrupt and hashes.ip or hashes[file]
            files[opts["--output"]] = hash .. "  release/" .. kind .. ".dat\n"
        end
        files[options.stdout] = requested == redirect and "302" or "200"
        return 0
    end,
}
local geodata = factory(json, platform, core)
local routing = dofile("luci/runtime/routing.lua")(json, platform, core, geodata)
local incy_url = "https://profiles.example.invalid/incy.json"
local policy = json.object({
    inboundTag = "example-tproxy", routeOrder = "block-proxy-direct", incySource = json.object({ url = incy_url }),
})
local profile = json.object({
    GlobalProxy = "true", DomainStrategy = "IPIfNonMatch",
    Geoipurl = ip_url, Geositeurl = site_url,
    DirectSites = json.array({ "geosite:category-ru", "regexp:\\.ru$" }),
    DirectIp = json.array({ "geoip:private" }),
    ProxySites = json.array({ "geosite:youtube" }),
    BlockSites = json.array({ "geosite:category-ads" }),
})
local headers = "autorouting: incy://autorouting/onadd/" .. incy_url .. "\n"
local function params()
    return { source = "incy", headers = headers, profile = json.encode(profile), policy = json.encode(policy) }
end
local function preview(geo)
    return core.preview("incy", headers, json.encode(policy), function() return json.encode(profile) end,
        nil, geo and geo.authorize)
end
local function reject(code, result, err)
    assert(not result and err == code, "expected " .. code .. ", got " .. tostring(err))
end
local function validate(dir, routes, assets)
    assert(dir == workspace and assets == workspace and routes.rules[1].inboundTag[1] == "vpn-routing-tproxy")
    assert(files[assets .. "/geoip.dat"] == "ip" and files[assets .. "/geosite.dat"])
    validations = validations + 1
    return true
end

local _, _, refs, _, urls = preview(factory(json))
assert(refs == 4 and urls.geoip == ip_url and urls.geosite == site_url and resolves == 0)
assert(not pcall(preview))
for _, bad in ipairs({
    "http://cdn.jsdelivr.net/gh/hydraponique/roscomvpn-geoip@202611101104/release/geoip.dat",
    "https://127.0.0.1/gh/hydraponique/roscomvpn-geoip@202611101104/release/geoip.dat",
    ip_url .. "?a=1", ip_url .. "#ref", ip_url:gsub("202611101104", "latest"), site_url,
}) do
    profile.Geoipurl = bad
    reject("routing_invalid", routing.import(params(), workspace, validate))
end
profile.Geoipurl = ip_url
profile.ProxySites[1] = "geosite:unapproved"
reject("routing_invalid", routing.import(params(), workspace, validate))
profile.ProxySites[1] = "geosite:youtube"
assert(resolves == 0 and persisted == 0)

answers = { "8.8.8.8", "169.254.169.254" }
reject("routing_assets_download", routing.import(params(), workspace, validate))
assert(#requests == 0 and persisted == 0)
answers = { "8.8.8.8", "1.1.1.1" }
redirect = ip_url .. ".sha256"
reject("routing_assets_download", routing.import(params(), workspace, validate))
assert(#requests == 1 and persisted == 0)
redirect = nil

requests = {}
local saved = assert(routing.import(params(), workspace, validate))
assert(table.concat(requests, " ") == table.concat({
    ip_url .. ".sha256", ip_url, site_url .. ".sha256", site_url,
}, " "))
assert(routing.validate(saved) and saved.geo.managed and saved.geo.geoip == hashes.ip
    and saved.geo.geosite == hashes.site and persisted == 2 and validations == 1)
assert(not json.encode(saved):find("https://", 1, true))
local path = managed .. "/" .. hashes.ip .. "-" .. hashes.site
local next_path = managed .. "/" .. hashes.ip .. "-" .. hashes.updated
assert(routing.asset_path(saved) == path)
local routes, err, assets = routing.configure(saved, workspace)
assert(json.equal(routes, saved.rules) and not err and assets == path and #requests == 4)

profile.Geositeurl, corrupt = next_site, next_site
reject("routing_assets_invalid", routing.import(params(), workspace, validate))
assert(persisted == 2 and validations == 1 and routing.configure(saved, workspace))
corrupt = nil
reject("routing_check_failed", routing.import(params(), workspace, function()
    return nil, "routing_check_failed"
end))
assert(not directories[next_path] and persisted == 2)
reject_write = next_path .. "/geosite.dat"
reject("storage_error", routing.import(params(), workspace, validate))
assert(routing.configure(saved, workspace) and files[path .. "/geosite.dat"] == "site")
assert(not geodata.verify(workspace, { managed = true, geoip = hashes.ip, geosite = hashes.updated }))
reject_write = nil
local updated = assert(routing.import(params(), workspace, validate))
assert(routing.asset_path(updated) == next_path and routing.configure(updated, workspace))
foreign_path = next_path .. "/geosite.dat"
reject("routing_assets", routing.configure(updated, workspace))
foreign_path = nil
sync_failure = next_path
local previous_writes = persisted
reject("storage_error", routing.import(params(), workspace, validate))
sync_failure = nil
assert(routing.import(params(), workspace, validate))
assert(persisted == previous_writes)

policy.geo = json.object({
    geoip = json.object({ sha256 = hashes.ip, categories = json.array({ "private" }) }),
    geosite = json.object({ sha256 = hashes.site, categories = json.array({ "category-ru", "youtube", "category-ads" }) }),
})
policy.allowedRegex = json.array({ "regexp:\\.ru$" })
local _, _, manual_refs, _, manual_urls = preview(factory(json))
assert(manual_refs == 4 and not manual_urls)

print("geodata runtime tests passed")
