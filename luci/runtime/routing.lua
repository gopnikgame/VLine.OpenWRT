-- Store only the compiled LAN rules and optional hashes of the approved DAT pair.
local INBOUND = "vpn-routing-tproxy"
local DAT_KINDS = { "geoip", "geosite" }

return function(json, platform, core, geodata)
    local definitions, order = {}, 0
    for _, group in ipairs(core.groups) do
        for _, match in ipairs(core.matches) do
            order = order + 1
            definitions["vpn-routing-" .. group.tag .. "-" .. match.key] = {
                tag = group.tag, key = match.key, position = order,
            }
        end
    end
    definitions["vpn-routing-fallback"] = { tag = "proxy", position = order + 1 }

    local function checked(value)
        core.only_keys(value, { source = true, rules = true, geo = true }, "saved routing profile")
        if value.source ~= "happ" and value.source ~= "incy" then core.fail("invalid routing source") end
        local routes = value.rules
        core.only_keys(routes, { domainStrategy = true, rules = true }, "saved routing")
        local fallback = routes.domainStrategy == "AsIs"
        if (not fallback and routes.domainStrategy ~= "IPIfNonMatch") or not json.is_array(routes.rules)
            or #routes.rules < (fallback and 2 or 1) or #routes.rules > order + 1 then
            core.fail("invalid saved routing shape")
        end

        local last, uses_dat = 0, false
        for index, rule in ipairs(routes.rules) do
            local def = json.is_object(rule) and definitions[rule.ruleTag]
            if not def or def.position <= last or rule.type ~= "field" or rule.outboundTag ~= def.tag
                or not json.equal(rule.inboundTag, json.array({ INBOUND }))
                or (def.key == nil) ~= (fallback and index == #routes.rules) then
                core.fail("invalid saved routing rule")
            end
            local keys = { type = true, ruleTag = true, inboundTag = true, outboundTag = true }
            if def.key then
                keys[def.key] = true
                local entries = core.string_list(rule[def.key], "saved routing matches")
                if #entries == 0 then core.fail("empty saved routing rule") end
                for _, entry in ipairs(entries) do
                    local valid, needs_dat = core.valid_compiled_rule(entry, def.key == "domain")
                    if not valid then core.fail("invalid saved routing match") end
                    uses_dat = uses_dat or needs_dat
                end
            end
            core.only_keys(rule, keys, "saved routing rule")
            last = def.position
        end

        if uses_dat then
            core.only_keys(value.geo, { geoip = true, geosite = true, managed = true }, "saved DAT hashes")
            if value.geo.managed ~= nil and value.geo.managed ~= true then core.fail("invalid DAT mode") end
            for _, kind in ipairs(DAT_KINDS) do
                local hash = value.geo[kind]
                if type(hash) ~= "string" or #hash ~= 64 or not hash:match("^[0-9a-f]+$") then
                    core.fail("invalid saved DAT hash")
                end
            end
        elseif value.geo ~= nil then
            core.fail("unexpected saved DAT hashes")
        end
        return value
    end

    local function validate(value)
        local ok, profile = pcall(checked, value)
        if ok then return profile end
    end

    local function compile(params)
        if type(params) ~= "table" or (params.source == "happ" and params.profile ~= nil and params.profile ~= "") then
            return nil, "routing_invalid"
        end
        local read_incy = params.source == "incy" and function() return params.profile end or nil
        local ok, candidate, _, dat_refs, policy, managed_urls = pcall(core.preview,
            params.source, params.headers, params.policy, read_incy, nil, geodata and geodata.authorize)
        if not ok then return nil, "routing_invalid" end
        local routes = candidate.routing
        for _, rule in ipairs(routes.rules) do rule.inboundTag = json.array({ INBOUND }) end
        local profile = json.object({ source = params.source, rules = routes })
        if dat_refs > 0 and not managed_urls then
            profile.geo = json.object({ geoip = policy.geo.geoip.sha256, geosite = policy.geo.geosite.sha256 })
        end
        return profile, nil, managed_urls
    end

    local function trusted(path, kind)
        local info = platform.lstat(path)
        local mode = info and info.modestr
        return info and info.uid == 0 and info.type == kind and type(mode) == "string" and #mode == 9
            and mode:sub(5, 5) == "-" and mode:sub(8, 8) == "-"
    end

    local function verify_assets(hashes, dir)
        local assets = platform.xray_assets()
        local parent = ""
        for component in assets:gmatch("[^/]+") do
            parent = parent .. "/" .. component
            if not trusted(parent, "dir") then return false end
        end
        local argv, expected = { "/bin/busybox", "sha256sum" }, {}
        for _, kind in ipairs(DAT_KINDS) do
            local path = assets .. "/" .. kind .. ".dat"
            if not trusted(path, "reg") then return false end
            argv[#argv + 1] = path
            expected[#expected + 1] = hashes[kind] .. "  " .. path .. "\n"
        end
        local output = dir .. "/routing-assets.sha256"
        if platform.run(argv, { timeout = 4, stdout = output }) ~= 0 then return false end
        return platform.read(output, 512) == table.concat(expected)
    end

    local function configure(profile, dir)
        if not profile then return nil, "routing_invalid" end
        if profile.geo and profile.geo.managed then
            local assets = geodata and geodata.verify(dir, profile.geo)
            if not assets then return nil, "routing_assets" end
            return profile.rules, nil, assets
        end
        if profile.geo and not verify_assets(profile.geo, dir) then return nil, "routing_assets" end
        return profile.rules
    end

    local function import(params, dir, validate_routing)
        local profile, err, urls = compile(params)
        if not profile then return nil, err end

        local routes, assets
        if urls then
            profile.geo, err = geodata.fetch_pair(dir, urls)
            if not profile.geo then return nil, err end
            routes, assets = profile.rules, dir
        else
            routes, err, assets = configure(profile, dir)
            if not routes then return nil, err end
        end

        local valid
        valid, err = validate_routing(dir, routes, assets)
        if not valid then return nil, err end
        if urls and not geodata.store(dir, profile.geo) then return nil, "storage_error" end
        return profile
    end

    local function asset_path(profile)
        return profile and profile.geo and geodata and geodata.asset_path(profile.geo) or nil
    end

    local function summary(profile)
        local counts = json.object({ proxy = 0, direct = 0, block = 0 })
        local rules = json.array()
        for _, rule in ipairs(profile.rules.rules) do
            local kind = rule.domain and "domain" or rule.ip and "ip"
            if kind then
                local values = rule[kind]
                counts[rule.outboundTag] = counts[rule.outboundTag] + #values
                rules[#rules + 1] = json.object({ tag = rule.outboundTag, kind = kind, values = values })
            end
        end
        return counts, rules
    end

    return {
        compile = compile, import = import, validate = validate, configure = configure, summary = summary,
        asset_path = asset_path,
    }
end
