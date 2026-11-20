local CDN = "cdn.jsdelivr.net"
local KINDS = { "geoip", "geosite" }
local DAT_LIMIT = 2 * 1024 * 1024
local SIDECAR_LIMIT = 128
local CATEGORIES = {
    geoip = { direct = true, private = true },
    geosite = {
        ["category-ads"] = true, ["category-ru"] = true, epicgames = true, escapefromtarkov = true,
        faceit = true, github = true, ["google-play"] = true, microsoft = true, pinterest = true,
        private = true, riot = true, steam = true, telegram = true, torrent = true,
        twitch = true, ["twitch-ads"] = true, whitelist = true, ["win-spy"] = true, youtube = true,
    },
}
local REGEXES = {
    ["regexp:\\.ru$"] = true, ["regexp:\\.su$"] = true, ["regexp:\\.xn--p1ai$"] = true,
}

local function allowed_url(url, kind)
    local tag = type(url) == "string" and url:match("^https://cdn%.jsdelivr%.net/gh/hydraponique/roscomvpn%-"
        .. kind .. "@([0-9]+)/release/" .. kind .. "%.dat$")
    return tag and #tag == 12
end

local function authorize(profile)
    if type(profile) ~= "table" then return nil end
    local geoip, geosite = profile.Geoipurl, profile.Geositeurl
    if allowed_url(geoip, "geoip") and allowed_url(geosite, "geosite") then
        return { urls = { geoip = geoip, geosite = geosite }, categories = CATEGORIES, regexes = REGEXES }
    end
end

local function valid_hash(hash)
    return type(hash) == "string" and #hash == 64 and hash:match("^[0-9a-f]+$")
end

return function(json, platform, core)
    local root = platform and platform.config_dir and platform.config_dir .. "/geodata"

    local function private_entry(path, kind, mode)
        local info = platform.lstat(path)
        if info and info.uid == 0 and info.type == kind and info.modestr == mode then return info end
    end

    local function asset_path(geo)
        if root and type(geo) == "table" and geo.managed == true and valid_hash(geo.geoip) and valid_hash(geo.geosite) then
            return root .. "/" .. geo.geoip .. "-" .. geo.geosite
        end
    end

    local function pin()
        local answers = platform.resolve4(CDN)
        if type(answers) ~= "table" or #answers == 0 or #answers > 16 then return nil end
        for _, address in ipairs(answers) do
            if type(address) ~= "string" or not core.public_ipv4(address) then return nil end
        end
        return CDN .. ":443:" .. table.concat(answers, ",")
    end

    local function download(dir, url, file, limit, pins)
        local status = dir .. "/geo-http"
        local code = platform.run({
            "/usr/bin/curl", "-q", "--silent", "--fail", "--globoff", "--path-as-is", "--ipv4",
            "--proto", "=https", "--noproxy", "*", "--proxy", "", "--max-redirs", "0",
            "--resolve", pins, "--connect-timeout", "4", "--max-time", "6", "--max-filesize", tostring(limit),
            "--output", file, "--write-out", "%{http_code}", "--url", url,
        }, { timeout = 7, stdout = status })
        return code == 0 and platform.read(status, 3) == "200"
    end

    local function check_pair(dir, assets, geo)
        local argv, expected = { "/bin/busybox", "sha256sum" }, {}
        for _, kind in ipairs(KINDS) do
            local path = assets .. "/" .. kind .. ".dat"
            local info = private_entry(path, "reg", "rw-------")
            if not info or type(info.size) ~= "number" or info.size <= 0 or info.size > DAT_LIMIT then return false end
            argv[#argv + 1] = path
            expected[#expected + 1] = geo[kind] .. "  " .. path .. "\n"
        end
        local output = dir .. "/geo-digests"
        return platform.run(argv, { timeout = 4, stdout = output }) == 0
            and platform.read(output, 1024) == table.concat(expected)
    end

    local function fetch_pair(dir, urls)
        if type(urls) ~= "table" or not allowed_url(urls.geoip, "geoip") or not allowed_url(urls.geosite, "geosite") then
            return nil, "routing_assets_invalid"
        end
        local pins = pin()
        if not pins then return nil, "routing_assets_download" end
        local geo = json.object({ managed = true })
        for _, kind in ipairs(KINDS) do
            local file = dir .. "/" .. kind .. ".dat"
            local sidecar = file .. ".sha256"
            if not download(dir, urls[kind] .. ".sha256", sidecar, SIDECAR_LIMIT, pins) then
                return nil, "routing_assets_download"
            end
            local bytes = platform.read(sidecar, SIDECAR_LIMIT)
            local hash = bytes and bytes:match("^([0-9A-Fa-f]+)  release/" .. kind .. "%.dat\n$")
            if not hash or #hash ~= 64 then return nil, "routing_assets_invalid" end
            geo[kind] = hash:lower()
            if not download(dir, urls[kind], file, DAT_LIMIT, pins) then return nil, "routing_assets_download" end
        end
        if not check_pair(dir, dir, geo) then return nil, "routing_assets_invalid" end
        return geo
    end

    local function verify(dir, geo)
        local assets = asset_path(geo)
        if assets and private_entry(platform.config_dir, "dir", "rwx------")
            and private_entry(root, "dir", "rwx------") and private_entry(assets, "dir", "rwx------")
            and check_pair(dir, assets, geo) then return assets end
    end

    local function store(dir, geo)
        local assets = asset_path(geo)
        if not assets then return nil end
        if not verify(dir, geo) then
            if not platform.private_dir(platform.config_dir) or not platform.private_dir(root)
                or not platform.private_dir(assets) then return nil end

            -- A saved profile only points at a pair after both files pass validation.
            for _, kind in ipairs(KINDS) do
                local name = "/" .. kind .. ".dat"
                local path = assets .. name
                if platform.lstat(path) and not private_entry(path, "reg", "rw-------") then return nil end
                local bytes = platform.read(dir .. name, DAT_LIMIT)
                if not bytes or not platform.write(path, bytes, true) then return nil end
            end
            if not verify(dir, geo) then return nil end
        end
        return platform.sync_persistent(assets) and platform.sync_persistent(root)
    end

    return { authorize = authorize, asset_path = asset_path, fetch_pair = fetch_pair, verify = verify, store = store }
end
