return function(json, platform, core, subscription, probe, capture, service, routing, guard, device)
    local root = platform.runtime_dir
    local settings_path = platform.config_dir .. "/connection.json"
    local policy_path = platform.config_dir .. "/policy.json"
    local cache_path = root .. "/subscription.json"
    local refresh_path = root .. "/subscription-refresh.json"
    local journal_path = root .. "/operation.json"
    local cache_lifetime = 1800
    local recovery_delay = 45
    local settings_limit = 32 * 1024
    local policy_limit = 128 * 1024
    local default_capture = json.object({ mode = "all", interface = "br-lan" })

    local function load(path, limit)
        local info = platform.lstat(path)
        if not info then return nil end
        if info.type ~= "reg" or info.uid ~= 0 or info.modestr ~= "rw-------" then return nil, "storage_error" end
        local bytes = platform.read(path, limit)
        local ok, value = pcall(json.decode, bytes or "")
        if not ok or not json.is_object(value) then return nil, "storage_error" end
        return value
    end

    local function save(path, value, durable)
        local bytes = json.encode(json.object(value)) .. "\n"
        if path == settings_path and #bytes > settings_limit then return nil end
        return platform.write(path, bytes, durable)
    end

    local function policy()
        if platform.lstat(policy_path) and not platform.private_dir(platform.config_dir) then return nil, "policy_invalid" end
        local value, err = load(policy_path, policy_limit)
        if err then return nil, "policy_invalid" end
        local result = {
            hosts = {}, probe_url = "https://www.gstatic.com/generate_204",
            value = value or json.object(), capture = default_capture,
        }
        if not value then return result end
        for key in pairs(value) do
            if key ~= "subscriptionHosts" and key ~= "probeUrl" and key ~= "capture" and key ~= "routing" then
                return nil, "policy_invalid"
            end
        end
        if value.subscriptionHosts ~= nil then
            local hosts = value.subscriptionHosts
            if not json.is_array(hosts) or #hosts == 0 or #hosts > 16 then return nil, "policy_invalid" end
            result.hosts = {}
            for _, host in ipairs(hosts) do
                if type(host) ~= "string" or not core.valid_domain(host) then return nil, "policy_invalid" end
                result.hosts[host:lower()] = true
            end
        end
        if value.probeUrl ~= nil then
            if type(value.probeUrl) ~= "string" or #value.probeUrl > 2048 or not value.probeUrl:match("^https://") then
                return nil, "policy_invalid"
            end
            result.probe_url = value.probeUrl
        end
        if value.capture ~= nil then
            result.capture = capture.validate(value.capture)
            if not result.capture then return nil, "policy_invalid" end
        end
        if value.routing ~= nil then
            result.routing = routing and routing.validate(value.routing)
            if not result.routing then return nil, "policy_invalid" end
        end
        return result
    end

    local function stable(operation, previous)
        return previous and operation.generation == previous.generation
            and operation.activeSource == previous.activeSource and not operation.stopping
    end

    local function connection_ready(dir, operation, previous, asset_dir)
        return operation and stable(operation, previous) and previous.resume
            and operation.serviceArmed and operation.captureArmed
            and service.inspect(dir, operation.healthPort, asset_dir) == "ready"
            and capture.inspect(operation.scope, dir) == "active" and guard.inspect(operation.scope, dir) == "active"
    end

    local function settings_action(dir, action, params, operation, previous)
        local locked = operation or (previous and previous.resume) or guard.inspect(nil, dir) == "conflict"
        if locked and action ~= "settings" then return nil, "settings_busy" end
        local config, err = policy()
        if not config then return nil, err end
        local networks, inventory = capture.networks(dir)
        if not networks then return nil, "settings_unavailable" end

        if action == "save_capture" then
            local requested = json.object({ interface = params.interface, mode = params.mode })
            if params.sources ~= nil then
                requested.sources = json.array()
                for address in params.sources:gmatch("%S+") do requested.sources[#requested.sources + 1] = address end
            end
            local scope = capture.validate(requested)
            if not scope or not capture.scope_on_network(scope, inventory) then return nil, "capture_policy" end
            config.capture, config.value.capture = scope, scope
        elseif action == "save_routing" then
            local profile
            if params.source ~= "none" then
                profile, err = routing.import(params, dir, service.validate_routing)
                if not profile then return nil, err end
            end
            config.routing, config.value.routing = profile, profile
        end

        if action ~= "settings" then
            local bytes = json.encode(config.value) .. "\n"
            if #bytes > policy_limit then return nil, "routing_invalid" end
            if not platform.private_dir(platform.config_dir) or not platform.write(policy_path, bytes, true) then
                return nil, "storage_error"
            end
        end
        local routing_status = json.object({ state = locked and "unverified" or "inactive" })
        local asset_dir = config.routing and routing.asset_path(config.routing)
        if config.routing then routing_status.counts, routing_status.rules = routing.summary(config.routing) end
        if connection_ready(dir, operation, previous, asset_dir)
            and service.routing_matches(config.routing and config.routing.rules, operation.healthPort) then
            routing_status.state = config.routing and "applied" or "default"
        end
        return {
            editable = not locked, capture = config.capture, networks = networks, hwid = device.get(),
            routing = config.routing and json.object({ source = config.routing.source,
                managedGeo = asset_dir and true or nil }) or nil,
            routingStatus = routing_status,
        }
    end

    local function valid_id(id)
        return type(id) == "string" and #id <= 128 and id:match("^[a-zA-Z0-9_.%-]+$")
    end

    local function valid_source(host)
        return host == nil or (type(host) == "string" and host == host:lower() and core.valid_domain(host))
    end

    local function cache(path, saved_url)
        path = path or cache_path
        local value, err = load(path, 2 * 1024 * 1024)
        if not value then return nil, err end
        local created = json.integer(value.created)
        local now = platform.uptime()
        if not created or created < 0 or created > now then return nil end
        if path == cache_path and now - created >= cache_lifetime and (not saved_url or value.url ~= saved_url) then
            return nil
        end
        if not valid_id(value.snapshot) or type(value.url) ~= "string" or not json.is_array(value.servers)
            or not valid_source(value.sourceHost) then
            return nil, "storage_error"
        end
        for _, server in ipairs(value.servers) do
            if not json.is_object(server) or not valid_id(server.id) or type(server.name) ~= "string"
                or type(server.link) ~= "string" then return nil, "storage_error" end
        end
        return value
    end

    local function refreshed(previous)
        if not previous or not previous.url then return nil end
        local value, err = cache(refresh_path)
        if value and value.url == previous.url and value.sourceHost == previous.sourceHost then return value end
        return nil, err
    end

    local function revision(value)
        return value and json.integer(value.revision) or 0
    end

    local function snapshots(previous)
        local automatic, automatic_error = refreshed(previous)
        local manual, manual_error = cache(cache_path, automatic and automatic.url)
        if manual and automatic and manual.url == automatic.url then
            if revision(manual) > revision(automatic) then automatic = nil else manual = nil end
        end
        return manual, automatic, manual_error or automatic_error
    end

    local function saved()
        if platform.lstat(settings_path) and not platform.private_dir(platform.config_dir) then return nil, "storage_error" end
        local value, err = load(settings_path, settings_limit)
        if not value then return nil, err end
        local scope = value.scope ~= nil and capture.validate(value.scope)
        if value.url ~= nil then
            if type(value.url) ~= "string" or not valid_id(value.serverId) or type(value.serverName) ~= "string"
                or type(value.link) ~= "string" or not valid_source(value.sourceHost)
                or (value.primarySnapshot ~= nil and not valid_id(value.primarySnapshot)) then
                return nil, "storage_error"
            end
        elseif value.serverId ~= nil or value.serverName ~= nil or value.link ~= nil
            or value.sourceHost ~= nil or value.primarySnapshot ~= nil then
            return nil, "storage_error"
        end
        if value.reserve ~= nil then
            local reserve = value.reserve
            if not json.is_object(reserve) or not valid_id(reserve.id)
                or not reserve.id:match("^reserve%-%x+$") or #reserve.id ~= 40 then return nil, "storage_error" end
            local parsed = subscription.parse_reserve(reserve.name, reserve.link)
            if not parsed or parsed.name ~= reserve.name or parsed.link ~= reserve.link then return nil, "storage_error" end
        end
        local selected = value.url or value.activeSource == "reserve"
        if (value.activeSource ~= nil and (value.activeSource ~= "reserve" or not value.reserve))
            or (not selected and not value.reserve) or (value.resume and not selected)
            or ((selected or value.generation ~= nil) and not valid_id(value.generation))
            or (value.scope ~= nil and not scope) or (value.resume ~= nil and type(value.resume) ~= "boolean") then
            return nil, "storage_error"
        end
        value.scope = scope or nil
        return value
    end

    local function selected_server(previous)
        if previous and previous.activeSource == "reserve" then
            local reserve = previous.reserve
            return { id = reserve.id, name = reserve.name, link = reserve.link, source = "reserve" }
        elseif previous and previous.url then
            return { id = previous.serverId, name = previous.serverName, link = previous.link,
                url = previous.url, sourceHost = previous.sourceHost }
        end
    end

    local function journal()
        local value, err = load(journal_path, 16384)
        if not value then return nil, err end
        local started = json.integer(value.startedAt)
        local health_port = json.integer(value.healthPort)
        local scope = capture.validate(value.scope)
        if not started or started < 0 or not health_port or health_port < 1024 or health_port > 65535
            or not scope or not valid_id(value.generation)
            or not valid_id(value.serverId) or type(value.serverName) ~= "string"
            or (value.activeSource ~= nil and value.activeSource ~= "reserve")
            or type(value.serviceArmed) ~= "boolean" or type(value.captureArmed) ~= "boolean"
            or type(value.stopping) ~= "boolean" then
            return nil, "storage_error"
        end
        value.startedAt, value.scope, value.healthPort = started, scope, health_port
        return value
    end

    local function public_servers(value)
        local list = json.array()
        for _, entry in ipairs(value.servers) do
            list[#list + 1] = json.object({ id = entry.id, name = entry.name })
        end
        return list
    end

    local function server_endpoint(link)
        local scheme, authority = link:match("^([a-z0-9]+)://[^@/?]+@([^/?]+)")
        if not authority then return nil end
        if scheme == "hy2" then scheme = "hysteria2" end
        local host, port = authority:match("^([A-Za-z0-9.%-]+):([1-9]%d*)$")
        if not host and scheme == "hysteria2" then host, port = authority:match("^([A-Za-z0-9.%-]+)$"), "443" end
        if host then return scheme .. "://" .. host:lower() .. ":" .. port end
    end

    local function match_server(servers, previous, allow_changed)
        if not previous then return nil end
        for _, server in ipairs(servers) do
            if server.link == previous.link then return server end
        end
        if not allow_changed or previous.serverName:match("^Сервер %d+$") then return nil end
        local endpoint = server_endpoint(previous.link)
        if not endpoint then return nil end
        local match
        for _, server in ipairs(servers) do
            if server.name == previous.serverName and server_endpoint(server.link) == endpoint then
                if match then return nil end
                match = server
            end
        end
        return match
    end

    local function save_subscription(path, url, source_host, servers, previous, preferred, next_revision, current)
        if current and #current.servers == #servers then
            local same = true
            for index, server in ipairs(servers) do
                local old = current.servers[index]
                if old.name ~= server.name or old.link ~= server.link
                    or (server == preferred and old.id ~= previous.serverId) then same = false; break end
            end
            if same then
                current.created, current.revision = platform.uptime(), next_revision
                if not save(path, current) then return nil end
                return current
            end
        end
        local snapshot = platform.random_hex(16)
        if not snapshot then return nil end
        local ids, selected_id = {}, previous and previous.serverId
        for _, server in ipairs(current and current.servers or {}) do
            if server.id ~= selected_id then ids[server.link] = server.id end
        end
        for index, server in ipairs(servers) do
            server.id = server == preferred and selected_id or ids[server.link] or snapshot .. "-" .. index
            servers[index] = json.object(server)
        end
        local value = { snapshot = snapshot, url = url, servers = json.array(servers), created = platform.uptime(),
            sourceHost = source_host, revision = next_revision }
        if save(path, value) then return value end
    end

    local function load_subscription(url, config, confirm_host)
        local previous, err = saved()
        if err then return nil, err end
        local current = cache()
        local source_host = confirm_host
            or (previous and previous.url == url and previous.sourceHost)
            or (current and current.url == url and current.sourceHost) or nil
        local servers, fetch_error = subscription.fetch(url, config.hosts, source_host)
        if not servers then return nil, fetch_error end
        local preferred = previous and previous.url == url and match_server(servers, previous)
        local next_revision = math.max(revision(current), revision(cache(refresh_path))) + 1
        local path = cache_path
        if previous and previous.url == url and subscription.permitted(url, config.hosts, previous.sourceHost) then
            path, source_host = refresh_path, previous.sourceHost
        end
        local value = save_subscription(path, url, source_host, servers, previous, preferred, next_revision, nil)
        if not value then return nil, "storage_error" end
        return { snapshot = value.snapshot, servers = public_servers(value),
            preferredServerId = preferred and previous.serverId or nil }
    end

    local function select_server(params, hosts, previous)
        local reserve = previous and previous.reserve
        if reserve and reserve.id == params.snapshot and reserve.id == params.server then
            return { id = reserve.id, name = reserve.name, link = reserve.link, source = "reserve" }
        end
        local manual, automatic, err = snapshots(previous)
        local current = automatic or manual
        if previous and previous.url and (not current or current.url ~= previous.url)
            and params.snapshot == (previous.primarySnapshot or previous.generation)
            and params.server == previous.serverId then
            local allowed, denied = subscription.permitted(previous.url, hosts, previous.sourceHost)
            if not allowed then return nil, denied end
            return { id = previous.serverId, name = previous.serverName, link = previous.link,
                url = previous.url, sourceHost = previous.sourceHost }
        end
        if err then return nil, err end
        local value = manual and manual.snapshot == params.snapshot and manual or automatic
        if value and value.snapshot == params.snapshot then
            local allowed, denied = subscription.permitted(value.url, hosts, value.sourceHost)
            if not allowed then return nil, denied end
            for _, server in ipairs(value.servers) do
                if server.id == params.server then
                    return { id = server.id, name = server.name, link = server.link,
                        url = value.url, sourceHost = value.sourceHost }
                end
            end
        end
        return nil, "stale_snapshot"
    end

    local function pending(operation, previous)
        if stable(operation, previous) or operation.startedAt == 0 then return false end
        return platform.uptime() - operation.startedAt < recovery_delay
    end

    local function saved_scope(previous)
        if previous and previous.scope then return previous.scope end
        local config, err = policy()
        if not config then return nil, err end
        if previous and previous.resume and not config.value.capture then return nil, "capture_not_configured" end
        return config.capture
    end

    local function protect_saved(dir, previous)
        local scope, err = saved_scope(previous)
        if not scope then return nil, err end
        local protected, protect_error = guard.start(scope, dir)
        if not protected then return nil, protect_error end
        return scope
    end

    local function connection_details(result, previous)
        local reserve = previous and previous.reserve
        result.hasSavedSubscription = previous ~= nil and previous.url ~= nil
        result.hasSubscription = result.hasSavedSubscription or platform.lstat(cache_path) ~= nil
        if reserve then result.reserve = json.object({ id = reserve.id, name = reserve.name, snapshot = reserve.id }) end
        return result
    end

    local function status(dir, operation, previous)
        local result = connection_details({ state = "disconnected" }, previous)
        local selected = selected_server(previous)
        if operation then
            if pending(operation, previous) then return nil, "operation_pending" end
            result.serverId, result.serverName = operation.serverId, operation.serverName
            result.activeSource = operation.activeSource or "subscription"
            if connection_ready(dir, operation, previous) then
                result.state = "connected"
                result.serverName = selected.name
            else
                result.state = "degraded"
            end
        elseif previous and previous.resume then
            result.state = "restoring"
        else
            local config, err = policy()
            local scope = (previous and previous.scope) or (config and config.capture)
            local guarded, guard_error = guard.inspect(scope, dir)
            if selected and (guarded == "active" or guarded == "conflict") then
                result.state = "degraded"
            elseif guarded ~= "absent" then
                result.runtimeReason = guard_error or "guard_conflict"
            elseif not config then
                result.runtimeReason = err
            elseif not config.capture then
                result.runtimeReason = "capture_not_configured"
            elseif not service.available() then
                result.runtimeReason = "dependency_missing"
            end
            result.canConnect = not result.runtimeReason
        end
        if selected and not operation then
            result.serverId, result.activeSource = selected.id, selected.source or "subscription"
            if result.state ~= "disconnected" then result.serverName = selected.name end
        end
        local manual, automatic = snapshots(previous)
        local current = automatic or manual
        local displayed = result.hasSavedSubscription and previous or current
        if displayed then
            local info = json.object({ url = displayed.url })
            if current and current.url == displayed.url then
                info.snapshot = current.snapshot
                info.servers = public_servers(current)
            elseif result.hasSavedSubscription then
                info.snapshot = previous.primarySnapshot or previous.generation
                info.servers = json.array({ json.object({ id = previous.serverId, name = previous.serverName }) })
                info.savedOnly = true
            end
            result.subscription = info
        end
        return result
    end

    local function cleanup(dir, operation, remove_guard)
        -- Keep the proxy alive if removing our capture cannot be confirmed.
        if operation.captureArmed and not capture.stop(operation.scope, dir) then return nil end
        if operation.serviceArmed and not service.stop(dir) then return nil end
        if remove_guard and not guard.stop(operation.scope, dir) then return nil end
        return platform.remove(journal_path)
    end

    local function disconnect(dir, operation, previous)
        if operation and pending(operation, previous) then return nil, "operation_pending" end
        local storage_failure
        if previous and previous.resume then
            -- Cancel future boots even if power is lost before the runtime cleanup finishes.
            previous.resume = false
            local written, reason = save(settings_path, previous, true)
            if not written and reason ~= "not_synced" then return nil, "storage_error" end
            storage_failure = not written
        end
        if operation then
            operation.stopping = true
            operation.startedAt = platform.uptime()
            if not save(journal_path, operation) then return nil, "storage_error" end
            if not cleanup(dir, operation, true) then
                operation.startedAt = 0
                save(journal_path, operation)
                return nil, "disconnect_failed"
            end
        elseif not guard.stop(saved_scope(previous), dir) then
            return nil, "disconnect_failed"
        end
        if storage_failure then return nil, "storage_error" end
        return status(dir, nil, previous)
    end

    local function remove_subscription(dir, operation, previous)
        if operation or (previous and previous.resume) then
            if not previous or not previous.resume or previous.activeSource ~= "reserve"
                or (operation and not stable(operation, previous)) then return nil, "subscription_busy" end
        else
            local state, err = guard.inspect(saved_scope(previous), dir)
            if not state then return nil, err end
            if state ~= "absent" then return nil, "subscription_busy" end
        end
        if platform.lstat(cache_path) and not platform.remove(cache_path) then return nil, "storage_error" end
        if platform.lstat(refresh_path) and not platform.remove(refresh_path) then return nil, "storage_error" end
        if previous and previous.url then
            if previous.reserve then
                previous.url, previous.sourceHost, previous.link = nil, nil, nil
                previous.serverId, previous.serverName, previous.primarySnapshot = nil, nil, nil
                if not save(settings_path, previous, true) then return nil, "storage_error" end
            elseif not platform.remove(settings_path, true) then
                return nil, "storage_error"
            else
                previous = nil
            end
        end
        return status(dir, operation, previous)
    end

    local function reserve_action(dir, action, params, operation, previous)
        local reserve = previous and previous.reserve
        if operation and operation.activeSource == "reserve" then return nil, "reserve_busy" end
        if previous and previous.activeSource == "reserve" then
            if previous.resume then return nil, "reserve_busy" end
            local state, err = guard.inspect(saved_scope(previous), dir)
            if not state then return nil, err end
            if state ~= "absent" then return nil, "reserve_busy" end
        end
        if operation and pending(operation, previous) then return nil, "operation_pending" end

        local adding = action == "save_reserve"
        if params.snapshot ~= (reserve and reserve.id) or (not reserve and not adding) then return nil, "stale_snapshot" end
        if adding then
            local parsed, err = subscription.parse_reserve(params.name, params.link)
            if not parsed then return nil, err end
            local id = platform.random_hex(16)
            if not id or not platform.private_dir(platform.config_dir) then return nil, "storage_error" end
            parsed.id = "reserve-" .. id
            previous = previous or {}
            previous.reserve = json.object(parsed)
            if not save(settings_path, previous, true) then return nil, "storage_error" end
        elseif previous.url then
            previous.reserve, previous.activeSource = nil, nil
            if not save(settings_path, previous, true) then return nil, "storage_error" end
        elseif not platform.remove(settings_path, true) then
            return nil, "storage_error"
        else
            previous = nil
        end
        return status(dir, operation, previous)
    end

    local function healthy(response)
        return response and response.result == "response" and response.httpCode >= 200 and response.httpCode < 300
    end

    local function prepare(dir, config, link, precheck)
        local routes, err, asset_dir
        if config.routing then
            routes, err, asset_dir = routing.configure(config.routing, dir)
            if not routes then return nil, err end
        end
        local outbound
        outbound, err = probe.outbound(dir, link)
        if not outbound then return nil, err end
        if precheck and not healthy(probe.check(outbound, config.probe_url)) then return nil, "check_failed" end
        return service.stage(dir, outbound, routes, asset_dir)
    end

    local function connect(dir, config, server, previous, restore_generation, replacement)
        if not config.capture then return nil, "capture_not_configured" end
        if not service.available() then return nil, "dependency_missing" end
        if not platform.private_dir(platform.config_dir) then return nil, "storage_error" end
        local capture_state, capture_error = capture.inspect(config.capture, dir)
        if not capture_state or capture_error then return nil, capture_error end
        if capture_state ~= "absent" or not service.can_start(dir) then return nil, "capture_conflict" end
        local guarded, guard_error = guard.inspect(config.capture, dir)
        if not guarded then return nil, guard_error end
        if guarded ~= (restore_generation and "active" or "absent") then return nil, "guard_conflict" end
        local candidate, validation_error = replacement
        if not candidate then
            candidate, validation_error = prepare(dir, config, server.link)
            if not candidate then return nil, validation_error end
        end
        local generation = restore_generation or platform.random_hex(16)
        if not generation then return nil, "storage_error" end
        local new_settings
        if not restore_generation or replacement then
            new_settings = {}
            for key, value in pairs(previous or {}) do new_settings[key] = value end
            new_settings.generation, new_settings.resume, new_settings.scope = generation, true, config.capture
            new_settings.activeSource = server.source
            if not server.source then
                local unchanged = previous and previous.url == server.url and previous.sourceHost == server.sourceHost
                    and previous.serverId == server.id and previous.link == server.link
                if unchanged then
                    new_settings.primarySnapshot = previous.primarySnapshot or previous.generation
                else
                    local snapshot = platform.random_hex(16)
                    if not snapshot then return nil, "storage_error" end
                    new_settings.primarySnapshot = "saved-" .. snapshot
                end
                new_settings.url, new_settings.sourceHost = server.url, server.sourceHost
                new_settings.serverId, new_settings.serverName, new_settings.link = server.id, server.name, server.link
            end
        end
        local operation = {
            generation = generation, scope = config.capture, serverId = server.id, serverName = server.name,
            activeSource = server.source,
            startedAt = platform.uptime(), serviceArmed = false, captureArmed = false, stopping = restore_generation ~= nil,
            healthPort = candidate.health_port,
        }
        if not save(journal_path, operation) then return nil, "storage_error" end

        local function arm(field)
            operation[field] = true
            operation.startedAt = platform.uptime()
            if save(journal_path, operation) then return true end
            operation[field] = false
        end

        local remove_guard
        local function apply()
            local started, start_error = service.start(dir, candidate, function() return arm("serviceArmed") end)
            if not started then return nil, start_error end
            local health = probe.head(candidate.health_port, service.control_user, candidate.password, config.probe_url, dir)
            if not healthy(health) then return nil, "check_failed" end
            if not restore_generation then
                remove_guard = true
                local protected, protect_error = guard.start(operation.scope, dir)
                if not protected then return nil, protect_error end
            end
            local applied, apply_error = capture.start(operation.scope, dir, function() return arm("captureArmed") end)
            if not applied then return nil, apply_error end
            if service.inspect(dir, candidate.health_port, candidate.asset_dir) ~= "ready" then return nil, "apply_failed" end
            if guard.inspect(operation.scope, dir) ~= "active" then return nil, "guard_failed" end
            local connected = connection_details({
                state = "connected", serverId = server.id, serverName = server.name,
                activeSource = server.source or "subscription",
            }, new_settings or previous)
            local storage_error
            if new_settings then
                local written, reason = save(settings_path, new_settings, true)
                -- A visible rename is already the live intent. Keep the runtime consistent with it.
                if not written and reason ~= "not_synced" then return nil, "storage_error" end
                if not written then storage_error = "storage_error" end
            end
            if restore_generation then
                operation.stopping = false
                if not save(journal_path, operation) then return connected, "rollback_failed" end
            end
            return connected, storage_error
        end

        local ok, result, failure = pcall(apply)
        if ok and result then
            if failure then return nil, failure end
            return result
        end
        operation.stopping = true
        if not cleanup(dir, operation, remove_guard) then
            operation.startedAt = 0
            save(journal_path, operation)
            return nil, "rollback_failed"
        end
        return nil, ok and failure or "apply_failed"
    end

    local function restore(dir, operation, previous, guard_only)
        local protected_scope, protect_error = protect_saved(dir, previous)
        if not protected_scope then return nil, protect_error end
        if guard_only then return { state = "restoring" } end
        if operation then
            if not operation.stopping or operation.generation ~= previous.generation then
                return status(dir, operation, previous)
            end
            if not cleanup(dir, operation) then return nil, "rollback_failed" end
        end
        local config, config_error = policy()
        if not config then return nil, config_error end
        config.capture = protected_scope
        local server = selected_server(previous)
        if not server.source then
            local allowed, denied = subscription.permitted(server.url, config.hosts, server.sourceHost)
            if not allowed then return nil, denied end
        end
        return connect(dir, config, server, previous, previous.generation)
    end

    local function replace_server(dir, config, operation, previous, server)
        local scope, scope_error = saved_scope(previous)
        if not scope then return nil, scope_error end
        config.capture = scope
        local candidate, validation_error = prepare(dir, config, server.link, true)
        if not candidate then return nil, validation_error end
        local protected, protect_error = guard.start(scope, dir)
        if not protected then return nil, protect_error end
        if operation then
            operation.stopping, operation.startedAt = true, platform.uptime()
            if not save(journal_path, operation) then return nil, "storage_error" end
            if not cleanup(dir, operation) then return nil, "rollback_failed" end
        end
        local connected, err = connect(dir, config, server, previous, previous.generation, candidate)
        if connected then return connected end
        local saved_now, saved_error = saved()
        if saved_error or not saved_now then return nil, "rollback_failed" end
        -- A write can report a sync failure after the new intent becomes visible.
        local current = selected_server(saved_now)
        if saved_now.generation == previous.generation and current and current.source == server.source
            and current.id == server.id and current.link == server.link then return nil, err end
        local interrupted, journal_error = journal()
        if journal_error then return nil, "rollback_failed" end
        local restored = restore(dir, interrupted, previous)
        if not restored or restored.state ~= "connected" or restored.serverId ~= selected_server(previous).id then
            return nil, "rollback_failed"
        end
        return nil, err
    end

    local function refresh_subscription(dir, operation, previous)
        if not previous then return { state = "idle" } end
        if operation and (not previous.resume or operation.generation ~= previous.generation
            or pending(operation, previous)) then return nil, "operation_pending" end
        local restore_error
        if previous.resume and (not operation or operation.stopping) then
            local restored
            restored, restore_error = restore(dir, operation, previous)
            local journal_error
            operation, journal_error = journal()
            if journal_error or (operation and not restored) then return nil, "rollback_failed" end
        end
        if not previous.url then
            if restore_error then return nil, restore_error end
            return { state = "idle" }
        end
        local config, config_error = policy()
        if not config then return nil, config_error end
        local servers, fetch_error = subscription.fetch(previous.url, config.hosts, previous.sourceHost)
        if not servers then return nil, fetch_error end
        local selected = match_server(servers, previous, true)
        local current = refreshed(previous)
        local next_revision = math.max(revision(current), revision(cache(cache_path, previous.url))) + 1
        local value = save_subscription(refresh_path, previous.url, previous.sourceHost, servers, previous, selected,
            next_revision, current)
        if not value then return nil, "storage_error" end
        if previous.resume and not previous.activeSource and selected and selected.link ~= previous.link then
            local refreshed_server = { id = previous.serverId, name = selected.name, link = selected.link,
                url = previous.url, sourceHost = previous.sourceHost }
            local connected, err = replace_server(dir, config, operation, previous, refreshed_server)
            if not connected then return nil, err end
            return { state = "reconnected" }
        end
        if restore_error then return nil, restore_error end
        if not selected then return { state = "retained" } end
        if selected.link == previous.link and selected.name ~= previous.serverName then
            previous.serverName = selected.name
            if not save(settings_path, previous, true) then return nil, "storage_error" end
        end
        return { state = current and current.snapshot == value.snapshot and "unchanged" or "updated" }
    end

    local function handle(action, params)
        if action == "subscription" or action == "probe" then
            local config, err = policy()
            if not config then return nil, err end
            if action == "subscription" then return load_subscription(params.url, config, params.confirmHost) end
            local previous, saved_error = saved()
            if saved_error then return nil, saved_error end
            local server, select_error = select_server(params, config.hosts, previous)
            if not server then return nil, select_error end
            return platform.with_workspace(function(dir)
                local outbound, render_error = probe.outbound(dir, server.link)
                if not outbound then return nil, render_error end
                local checked, check_error = probe.check(outbound, config.probe_url)
                if not checked then return nil, check_error end
                return { method = "HEAD", serverId = server.id, result = checked.result,
                    httpCode = checked.httpCode, elapsedMs = checked.elapsedMs }
            end)
        end

        local operation, journal_error = journal()
        if journal_error then return nil, journal_error end
        local previous, previous_error = saved()
        local resume = previous and previous.resume
        if action == "settings" or action == "save_capture" or action == "save_routing" then
            return platform.with_workspace(function(dir)
                return settings_action(dir, action, params, operation, previous)
            end)
        end
        if previous_error and action ~= "disconnect" then return nil, previous_error end
        if (action == "restore" or action == "arm_guard") and not resume then return { state = "disconnected" } end
        return platform.with_workspace(function(dir)
            if action == "status" then return status(dir, operation, previous) end
            if action == "disconnect" then return disconnect(dir, operation, previous) end
            if action == "remove_subscription" then return remove_subscription(dir, operation, previous) end
            if action == "save_reserve" or action == "remove_reserve" then
                return reserve_action(dir, action, params, operation, previous)
            end
            if action == "refresh_subscription" then return refresh_subscription(dir, operation, previous) end
            if action == "restore" or action == "arm_guard" then
                return restore(dir, operation, previous, action == "arm_guard")
            end
            if action ~= "connect" then return nil, "invalid_request" end
            local switching = params.activeServer ~= nil
            if switching then
                local active = selected_server(previous)
                if not resume or not operation or not stable(operation, previous)
                    or not operation.serviceArmed or not operation.captureArmed
                    or operation.serverId ~= active.id or params.activeServer ~= active.id
                    or params.server == active.id then return nil, "connection_changed" end
            elseif operation or resume then
                return nil, "operation_pending"
            end
            local config, config_error = policy()
            if not config then return nil, config_error end
            local server, select_error = select_server(params, config.hosts, previous)
            if not server then return nil, select_error end
            if switching then
                if not server.source and previous.url
                    and (server.url ~= previous.url or server.sourceHost ~= previous.sourceHost) then
                    return nil, "connection_changed"
                end
                return replace_server(dir, config, operation, previous, server)
            end
            return connect(dir, config, server, previous)
        end)
    end

    return {
        handle = function(action, params)
            return platform.with_lock(function() return handle(action, params) end)
        end,
    }
end
