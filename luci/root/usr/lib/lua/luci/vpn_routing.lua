local http = require("luci.http")
local dispatcher = require("luci.dispatcher")

local directory = "/usr/lib/vpn-routing/"
local body_limit = 96 * 1024
local policy_limit = 16 * 1024
local fields = { token = true, source = true, headers = true, policy = true, profile = true }

local function respond(status, body)
    http.status(status, ({
        [200] = "OK", [400] = "Bad Request", [403] = "Forbidden",
        [405] = "Method Not Allowed", [409] = "Conflict", [413] = "Content Too Large",
        [422] = "Unprocessable Content", [500] = "Internal Server Error",
        [502] = "Bad Gateway", [503] = "Service Unavailable",
    })[status])
    http.header("Cache-Control", "no-store")
    http.header("X-Content-Type-Options", "nosniff")
    http.prepare_content("application/json; charset=utf-8")
    http.write(body)
end

local function load_compiler()
    local json = dofile(directory .. "route_json.lua")
    return json, assert(loadfile(directory .. "route_core.lua"))(json)
end

local function compile(params)
    local loaded, json, core = pcall(load_compiler)
    if not loaded then return respond(500, '{"ok":false,"error":"internal_error"}') end
    if #params.headers > core.headers_limit or #params.profile > core.profile_limit or #params.policy > policy_limit then
        return respond(413, '{"ok":false,"error":"too_large"}')
    end
    local read_incy = params.source == "incy" and function() return params.profile end or nil
    local ok, candidate, _counts, _dat_refs, _policy, urls = pcall(function()
        local geodata = dofile(directory .. "geodata.lua")(json, nil, core)
        return core.preview(params.source, params.headers, params.policy, read_incy, nil, geodata.authorize)
    end)
    if not ok then
        if type(candidate) ~= "table" or type(candidate.message) ~= "string" then
            return respond(500, '{"ok":false,"error":"internal_error"}')
        end
        local rejected = json.encode(json.object({
            ok = false, error = "rejected", detail = candidate.message,
        }))
        respond(200, rejected)
        return
    end
    return respond(200, json.encode(json.object({
        ok = true, candidate = json.encode(candidate) .. "\n", managedGeo = urls and true or nil,
    })))
end

local function authorized_form()
    -- The LuCI dispatcher already applies admin login and the POST token gate.
    -- Keep the same requirements at the endpoint before reaching the compiler.
    local context = dispatcher.context
    if not context or context.authuser ~= "root" or type(context.authsession) ~= "string"
        or context.authsession == "" or type(context.authtoken) ~= "string" or context.authtoken == "" then
        respond(403, '{"ok":false,"error":"forbidden"}')
        return nil
    end
    if http.getenv("REQUEST_METHOD") ~= "POST" then
        http.header("Allow", "POST")
        respond(405, '{"ok":false,"error":"invalid_request"}')
        return nil
    end

    local content_type = (http.getenv("CONTENT_TYPE") or ""):match("^([^;]+)")
    local raw_length = http.getenv("CONTENT_LENGTH") or ""
    local length = raw_length:match("^%d+$") and tonumber(raw_length)
    if content_type ~= "application/x-www-form-urlencoded" or (http.getenv("QUERY_STRING") or "") ~= ""
        or not length or length < 1 then
        respond(400, '{"ok":false,"error":"invalid_request"}')
        return nil
    end
    if length > body_limit then
        respond(413, '{"ok":false,"error":"too_large"}')
        return nil
    end

    local params = http.formvalue()
    if type(params) ~= "table" or params.token ~= context.authtoken then
        respond(403, '{"ok":false,"error":"forbidden"}')
        return nil
    end
    return params
end

local function routing_form(params)
    for key in pairs(params) do
        if not fields[key] then return false end
    end
    for key in pairs(fields) do
        if type(params[key]) ~= "string" then return false end
    end
    return (params.source == "happ" and params.profile == "") or params.source == "incy"
end

local function preview()
    local params = authorized_form()
    if not params then return end
    if not routing_form(params) then return respond(400, '{"ok":false,"error":"invalid_request"}') end
    return compile(params)
end

local actions = {
    status = {},
    subscription = { url = 8192 },
    remove_subscription = {},
    save_reserve = { name = 160, link = 8192, snapshot = 128 },
    remove_reserve = { snapshot = 128 },
    connect = { server = 128, snapshot = 128, activeServer = 128, routingSource = 12 },
    disconnect = {},
    probe = { server = 128, snapshot = 128 },
    settings = {},
    dns_settings = {},
    check_dns = {},
    apply_dns = { profile = 20 },
    save_capture = {
        all = { interface = 15, mode = 3 },
        selected = { interface = 15, mode = 8, sources = 640 },
        legacy = { interface = 15, sources = 640 },
    },
    save_routing = { source = 12 },
}
local failures = {
    invalid_request = 400, invalid_url = 400, source_not_allowed = 400,
    hwid_limit_reached = 403,
    operation_pending = 409, stale_snapshot = 409, connection_changed = 409, capture_conflict = 409, settings_busy = 409,
    subscription_busy = 409, reserve_busy = 409, guard_conflict = 409,
    too_large = 413,
    unsupported_subscription = 422, invalid_server = 422, invalid_reserve_name = 422, capture_policy = 422, policy_invalid = 422,
    routing_invalid = 422, routing_assets = 422, routing_assets_invalid = 422, routing_check_failed = 422,
    routing_choice_required = 409, routing_missing = 422, routing_ambiguous = 422, routing_download = 502,
    internal_error = 500, storage_error = 500, rollback_failed = 500, disconnect_failed = 500,
    apply_failed = 502, capture_failed = 502, check_failed = 502, subscription_unavailable = 502, probe_failed = 502,
    guard_failed = 502, hwid_rejected = 502, routing_assets_download = 502,
    capture_not_configured = 503, capture_unavailable = 503, dependency_missing = 503, settings_unavailable = 503,
    hwid_unavailable = 503,
    dns_invalid = 422, dns_conflict = 409, dns_unavailable = 503, dns_dependency = 503,
    dns_check_failed = 502, dns_apply_failed = 502, dns_rollback_failed = 500,
}

local text_fields = { url = true, sources = true, address = true, name = true, link = true }

local function action_form(params, action)
    local required = actions[action]
    if action == "save_capture" then
        required = required[params.mode or "legacy"]
        if not required then return false end
    elseif action == "apply_dns" and params.profile == "custom" then
        required = { profile = 20, address = 512, bootstrap = 15 }
    end
    for key in pairs(params) do
        if key ~= "token" and not required[key] and not (action == "subscription" and key == "confirmHost") then
            return false
        end
    end
    for key, limit in pairs(required) do
        local value = params[key]
        local optional = key == "activeServer" or key == "routingSource" or key == "bootstrap"
            or (key == "snapshot" and action == "save_reserve")
        local omitted = optional and value == nil
        if not omitted and (type(value) ~= "string" or value == "" or #value > limit
            or (key == "address" and value:find("[%c%s]"))
            or ((key == "name" or key == "link") and value:find("[%c]"))
            or (not text_fields[key] and not value:match("^[a-zA-Z0-9_.%-]+$"))) then
            return false
        end
    end
    if action == "connect" and params.routingSource ~= nil and params.routingSource ~= "happ"
        and params.routingSource ~= "incy" and params.routingSource ~= "none" then return false end
    return true
end

local function connection(action)
    local params = authorized_form()
    if not params then return end
    local importing = action == "save_routing" and params.source ~= "none"
    if (importing and not routing_form(params)) or (not importing and not action_form(params, action)) then
        return respond(400, '{"ok":false,"error":"invalid_request"}')
    end

    local ok, body, reason = pcall(function()
        local json, core = load_compiler()
        if importing and (#params.headers > core.headers_limit or #params.profile > core.profile_limit
            or #params.policy > policy_limit) then return nil, "too_large" end
        if params.confirmHost ~= nil then
            local host = params.confirmHost
            if type(host) ~= "string" or not core.valid_domain(host) or not host:match("%.[A-Za-z][A-Za-z0-9%-]*$") then
                return nil, "invalid_request"
            end
            params.confirmHost = host:lower()
        end
        local backend = dofile(directory .. "backend.lua")(directory, json, core)
        local value, err = backend.handle(action, params)
        if not value then return nil, err end
        value.ok = true
        return json.encode(json.object(value))
    end)
    if ok and body then return respond(200, body) end
    local error_code = ok and failures[reason] and reason or "internal_error"
    return respond(failures[error_code], '{"ok":false,"error":"' .. error_code .. '"}')
end

return {
    preview = preview,
    status = function() return connection("status") end,
    subscription = function() return connection("subscription") end,
    remove_subscription = function() return connection("remove_subscription") end,
    save_reserve = function() return connection("save_reserve") end,
    remove_reserve = function() return connection("remove_reserve") end,
    probe = function() return connection("probe") end,
    connect = function() return connection("connect") end,
    disconnect = function() return connection("disconnect") end,
    settings = function() return connection("settings") end,
    dns_settings = function() return connection("dns_settings") end,
    check_dns = function() return connection("check_dns") end,
    apply_dns = function() return connection("apply_dns") end,
    save_capture = function() return connection("save_capture") end,
    save_routing = function() return connection("save_routing") end,
}
