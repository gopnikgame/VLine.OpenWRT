-- Keep forwarding blocked even when Xray or the capture table disappears.
return function(json, platform, validate)
    local nft, name, signature = "/usr/sbin/nft", "vpn_guard", "VPN Routing forward guard v1"
    local null = json.decode("null")
    local object, array = json.object, json.array
    -- Match BYPASS_CIDRS4_DEFAULT in the pinned TPROXY Manager.
    local bypass = {
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
        "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4", "100.64.0.0/10",
    }

    local function read_rows(dir, what)
        local path = dir .. "/guard-output"
        local argv = { nft, "-j", "-a", "-nn", "list", what }
        if what == "table" then argv[7], argv[8] = "inet", name end
        if platform.run(argv, { timeout = 3, stdout = path }) ~= 0 then return nil end
        local bytes = platform.read(path, 256 * 1024)
        if not bytes then return nil end
        local ok, result = pcall(json.decode, bytes)
        if not ok or not json.is_object(result) or not json.is_array(result.nftables) then return nil end
        for key in pairs(result) do if key ~= "nftables" then return nil end end
        local rows = {}
        for i, row in ipairs(result.nftables) do
            if not json.is_object(row) then return nil end
            local kind, body = next(row)
            if not kind or next(row, kind) or not json.is_object(body) then return nil end
            if kind == "metainfo" then
                if i ~= 1 or json.integer(body.json_schema_version) ~= 1 then return nil end
            else
                rows[#rows + 1] = row
            end
        end
        return rows
    end

    local function decimal(value)
        if value == nil then return nil end
        local token = json.encode(value)
        if token:match("^%d+$") and (#token < 20 or (#token == 20 and token <= "18446744073709551615")) then
            return token
        end
    end

    local function handle(value)
        local token = decimal(value)
        if token and token ~= "0" then return token end
    end

    local function matches(body, expected)
        for key in pairs(body) do
            if key == "handle" then
                if not handle(body.handle) then return false end
            elseif expected[key] == nil then
                return false
            end
        end
        for key, value in pairs(expected) do
            if body[key] == nil or json.encode(body[key]) ~= json.encode(value) then return false end
        end
        return true
    end

    local function ipv4(value)
        if type(value) ~= "string" then return nil end
        local a, b, c, d = value:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
        if not a then return nil end
        local n = 0
        for _, part in ipairs({ a, b, c, d }) do
            if #part > 3 or (#part > 1 and part:sub(1, 1) == "0") or tonumber(part) > 255 then return nil end
            n = n * 256 + tonumber(part)
        end
        return n
    end

    local function bounds(addr, bits)
        local first = ipv4(addr)
        if not first or not bits or bits < 0 or bits > 32 then return nil end
        local width = 2 ^ (32 - bits)
        if first % width == 0 then return first, first + width - 1 end
    end

    local function range_key(first, last)
        if first and last and last >= first then return first .. ":" .. last end
    end

    local function prefix_key(cidr)
        local addr, bits = cidr:match("^([^/]+)/(%d+)$")
        return range_key(bounds(addr, tonumber(bits)))
    end

    local function elem_key(elem)
        if type(elem) == "string" then return prefix_key(elem) end
        if not json.is_object(elem) then return nil end
        local kind, value = next(elem)
        if kind == "prefix" and not next(elem, kind) and json.is_object(value) then
            for key in pairs(value) do if key ~= "addr" and key ~= "len" then return nil end end
            return range_key(bounds(value.addr, json.integer(value.len)))
        elseif kind == "range" and not next(elem, kind) and json.is_array(value) and #value == 2 then
            return range_key(ipv4(value[1]), ipv4(value[2]))
        end
    end

    local function exact_bypass(elements)
        if not json.is_array(elements) then return false end
        local seen = {}
        local multicast, reserved = prefix_key("224.0.0.0/4"), prefix_key("240.0.0.0/4")
        local combined = prefix_key("224.0.0.0/3")
        for _, elem in ipairs(elements) do
            local key = elem_key(elem)
            if not key then return false end
            if key == combined then
                if seen[multicast] or seen[reserved] then return false end
                seen[multicast], seen[reserved] = true, true
            else
                if seen[key] then return false end
                seen[key] = true
            end
        end
        for _, cidr in ipairs(bypass) do
            local key = prefix_key(cidr)
            if not seen[key] then return false end
            seen[key] = nil
        end
        return next(seen) == nil
    end

    local function exact_sources(elements, sources)
        if type(elements) == "string" then return #sources == 1 and elements == sources[1] end
        if not json.is_array(elements) or #elements ~= #sources then return false end
        local seen = {}
        for _, source in ipairs(sources) do seen[source] = true end
        for _, source in ipairs(elements) do
            if not seen[source] then return false end
            seen[source] = nil
        end
        return true
    end

    local function comparison(op, kind, fields, right)
        return object({ match = object({ op = op, left = object({ [kind] = object(fields) }), right = right }) })
    end

    local function exact_rule(expr, profile)
        local selected = profile.mode == "selected"
        local destination = selected and 4 or 3
        if not json.is_array(expr) or #expr ~= destination + 2 then return false end
        local counter = json.is_object(expr[destination + 1]) and expr[destination + 1].counter
        if not json.is_object(counter) or not decimal(counter.packets) or not decimal(counter.bytes) then return false end
        for key in pairs(counter) do if key ~= "packets" and key ~= "bytes" then return false end end
        local function source(op)
            return comparison(op, "payload", { protocol = "ip", field = "saddr" }, "@sources4")
        end
        return json.equal(expr[1], comparison("==", "meta", { key = "iifname" }, profile.interface))
            and json.equal(expr[2], comparison("!=", "meta", { key = "oifname" }, profile.interface))
            and (not selected or json.equal(expr[3], source("==")) or json.equal(expr[3], source("in")))
            and json.equal(expr[destination], comparison("!=", "payload", { protocol = "ip", field = "daddr" }, "@bypass4"))
            and json.equal(expr[destination + 1], object({ counter = counter }))
            and json.equal(expr[destination + 2], object({ drop = null }))
    end

    local function exact_table(rows, profile, table_handle)
        local seen = {}
        for _, row in ipairs(rows) do
            local kind, body = next(row)
            local key = kind == "set" and body.name or kind
            if seen[key] then return false end
            seen[key] = true
            if kind == "table" then
                if not matches(body, { family = "inet", name = name }) or handle(body.handle) ~= table_handle then return false end
            else
                local expected = { family = "inet", table = name }
                if kind == "chain" then
                    expected.name, expected.type, expected.hook, expected.prio, expected.policy =
                        "forward", "filter", "forward", -10, "accept"
                elseif kind == "set" then
                    expected.name, expected.type, expected.elem = key, "ipv4_addr", body.elem
                    if key == "sources4" then
                        if profile.mode ~= "selected" or not exact_sources(body.elem, profile.sources) then return false end
                    elseif key == "bypass4" then
                        expected.flags = array({ "interval" })
                        if not exact_bypass(body.elem) then return false end
                    else
                        return false
                    end
                elseif kind == "rule" then
                    expected.chain, expected.comment, expected.expr = "forward", signature, body.expr
                    if not exact_rule(body.expr, profile) then return false end
                else
                    return false
                end
                if not matches(body, expected) then return false end
            end
        end
        return seen.table and seen.chain and seen.bypass4 and seen.rule and (profile.mode == "all" or seen.sources4)
    end

    local function inspect_details(profile, dir)
        local rows = read_rows(dir, "tables")
        if not rows then return nil, "guard_failed" end
        local table_handle
        for _, row in ipairs(rows) do
            local body = row.table
            if not body or type(body.family) ~= "string" or type(body.name) ~= "string" then
                return nil, "guard_failed"
            end
            if body.family == "inet" and body.name == name then
                if table_handle or not handle(body.handle) then return nil, "guard_failed" end
                table_handle = handle(body.handle)
            end
        end
        if not table_handle then return "absent" end
        if not profile then return "conflict" end
        rows = read_rows(dir, "table")
        if not rows then return nil, "guard_failed" end
        if not exact_table(rows, profile, table_handle) then return "conflict" end
        return "active", table_handle
    end

    local function inspect(profile, dir)
        local state, detail = inspect_details(validate(profile), dir)
        if not state then return nil, detail end
        return state
    end

    local function start(profile, dir)
        profile = validate(profile)
        if not profile then return nil, "guard_failed" end
        local state, err = inspect_details(profile, dir)
        if state == "active" then return true end
        if state ~= "absent" then return nil, state == "conflict" and "guard_conflict" or err end
        local sources_set, sources_match = "", ""
        if profile.mode == "selected" then
            sources_set = string.format("add set inet vpn_guard sources4 { type ipv4_addr; elements = { %s }; }\n",
                table.concat(profile.sources, ", "))
            sources_match = "ip saddr @sources4 "
        end
        local batch = string.format([[create table inet vpn_guard
add chain inet vpn_guard forward { type filter hook forward priority -10; policy accept; }
%sadd set inet vpn_guard bypass4 { type ipv4_addr; flags interval; elements = { %s }; }
add rule inet vpn_guard forward iifname "%s" oifname != "%s" %sip daddr != @bypass4 counter drop comment "%s"
]], sources_set, table.concat(bypass, ", "), profile.interface, profile.interface, sources_match, signature)
        local path = dir .. "/guard.nft"
        if not platform.write(path, batch) then return nil, "guard_failed" end
        local code = platform.run({ nft, "-f", path }, { timeout = 3 })
        state = inspect_details(profile, dir)
        if state == "conflict" then return nil, "guard_conflict" end
        if code == 0 and state == "active" then return true end
        return nil, "guard_failed"
    end

    local function stop(profile, dir)
        profile = validate(profile)
        local state, detail = inspect_details(profile, dir)
        if state == "absent" then return true end
        if state ~= "active" then return nil, state == "conflict" and "guard_conflict" or detail end
        -- A table recreated under the same name has a different kernel handle.
        local code = platform.run({ nft, "delete", "table", "inet", "handle", detail }, { timeout = 3 })
        state = inspect_details(profile, dir)
        if state == "conflict" then return nil, "guard_conflict" end
        if code == 0 and state == "absent" then return true end
        return nil, "guard_failed"
    end

    return { inspect = inspect, start = start, stop = stop }
end
