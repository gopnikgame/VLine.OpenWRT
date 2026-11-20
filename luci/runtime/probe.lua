-- Render one subscription outbound and exercise it using a private SOCKS listener.
local CURL = "/usr/bin/curl"
local REQUEST_LIMIT = 7
local UUID = "^%x%x%x%x%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x$"
local UNSUPPORTED_OPTIONS = {
    extra = true, fm = true, pcs = true, pinsha256 = true, vcn = true, pqv = true, ech = true, cs = true,
}

-- The Manager's seed assumes RAW + REALITY. Keep the URI placeholders here
-- and build only the transport and security blocks selected by the link.
local TEMPLATE = [[
{
  "outbounds": [{
    "tag": "proxy",
    "protocol": "vless",
    "settings": {"vnext": [{
      "address": "__ADDRESS__",
      "port": "__PORT__",
      "users": [{"id": "__UUID__", "encryption": "__ENCRYPTION__", "flow": "__FLOW__"}]
    }]},
    "network": "__NETWORK__",
    "security": "__SECURITY__",
    "headerType": "__HEADER_TYPE__",
    "host": "__HOST_HEADER__",
    "path": "__PATH__",
    "mode": "__MODE__",
    "authority": "__AUTHORITY__",
    "serviceName": "__SERVICE_NAME__",
    "serverName": "__SERVER_NAME__",
    "fingerprint": "__FINGERPRINT__",
    "publicKey": "__PUBLIC_KEY__",
    "shortId": "__SHORT_ID__",
    "spiderX": "__SPIDER_X__",
    "allowInsecure": "__ALLOW_INSECURE_BOOL__",
    "alpn": "__ALPN_ARRAY__"
  }]
}
]]

local HYSTERIA_TEMPLATE = [[
{
  "outbounds": [{
    "tag": "proxy",
    "protocol": "hysteria",
    "address": "__ADDRESS__",
    "port": "__PORT__",
    "auth": "__HY2_AUTH__",
    "serverName": "__SERVER_NAME__",
    "allowInsecure": "__ALLOW_INSECURE_BOOL__"
  }]
}
]]

local function safe_text(value, limit)
    return type(value) == "string" and #value <= limit and not value:find("[%z\1-\31\127]")
end

local function valid_port(port)
    return type(port) == "number" and port >= 1 and port <= 65535 and port % 1 == 0
end

local function valid_credential(value)
    return type(value) == "string" and #value <= 64 and value:match("^[A-Za-z0-9_.%-]+$")
end

local function has_unsupported_options(link)
    local query = link:match("%?(.*)$") or ""
    for pair in query:gmatch("[^&]+") do
        local key = pair:match("^[^=]+")
        if key then
            key = key:gsub("%%(%x%x)", function(byte) return string.char(tonumber(byte, 16)) end):lower()
            if UNSUPPORTED_OPTIONS[key] then return true end
        end
    end
    return false
end

return function(json, platform, core, hysteria_auth)
    local converter = platform.dependency("vless2json.sh")
    local xray = platform.dependency("xray")

    local function pinned_ipv4(address)
        if core.public_ipv4(address) then return address end
        if not core.valid_domain(address) or not address:find(".", 1, true) or address:match("^[%d.]+$") then return nil end
        local addresses = platform.resolve4(address)
        if not addresses or #addresses == 0 then return nil end
        for _, candidate in ipairs(addresses) do
            if not core.public_ipv4(candidate) then return nil end
        end
        return addresses[1]
    end

    local function valid_host_header(value)
        if value == "" then return true end
        if not safe_text(value, 259) then return false end
        local hostname, port = value:match("^([^:]+):(%d+)$")
        if hostname then return core.valid_domain(hostname) and valid_port(tonumber(port)) end
        return core.valid_domain(value)
    end

    local function transport_options(fields, stream)
        local network = fields.network
        if network == "websocket" then network = "ws" end
        if network == "tcp" or network == "raw" then
            if fields.headerType ~= "none" then return false end
            stream.network = "raw"
            return true
        end
        if network == "grpc" then
            if not valid_host_header(fields.authority) or not safe_text(fields.serviceName, 255)
                or (fields.mode ~= "" and fields.mode ~= "gun" and fields.mode ~= "multi") then return false end
            stream.network = "grpc"
            stream.grpcSettings = json.object({
                authority = fields.authority, serviceName = fields.serviceName, multiMode = fields.mode == "multi",
            })
            return true
        end
        if network ~= "ws" and network ~= "httpupgrade" and network ~= "xhttp" and network ~= "splithttp" then return false end
        if not valid_host_header(fields.host) or not safe_text(fields.path, 2048)
            or (fields.path ~= "" and fields.path:sub(1, 1) ~= "/") then return false end
        local options = json.object({ host = fields.host, path = fields.path })
        if network == "ws" then
            stream.network, stream.wsSettings = "ws", options
        elseif network == "httpupgrade" then
            stream.network, stream.httpupgradeSettings = "httpupgrade", options
        else
            -- The converter defaults mode to "gun" for gRPC when the URI omits it.
            local mode = (fields.mode == "" or fields.mode == "gun") and "auto" or fields.mode
            if mode ~= "auto" and mode ~= "packet-up" and mode ~= "stream-up" and mode ~= "stream-one" then return false end
            options.mode = mode
            stream.network, stream.xhttpSettings = "xhttp", options
        end
        return true
    end

    local function security_options(fields, address, stream)
        if fields.allowInsecure ~= false or not safe_text(fields.fingerprint, 32)
            or type(fields.serverName) ~= "string" then return false end
        local server_name = fields.serverName
        if server_name == "" and fields.security == "tls" then server_name = address end
        if not core.valid_domain(server_name) then return false end

        if fields.security == "tls" then
            if not json.is_array(fields.alpn) or #fields.alpn > 8 then return false end
            for _, protocol in ipairs(fields.alpn) do
                if not safe_text(protocol, 32) or protocol == "" then return false end
            end
            stream.tlsSettings = json.object({
                serverName = server_name, fingerprint = fields.fingerprint, alpn = fields.alpn,
                useSystemCA = true,
            })
        elseif fields.security == "reality" then
            if stream.network ~= "raw" and stream.network ~= "xhttp" and stream.network ~= "grpc" then return false end
            if type(fields.publicKey) ~= "string" or #fields.publicKey ~= 43
                or not fields.publicKey:match("^[A-Za-z0-9_%-]+$")
                or type(fields.shortId) ~= "string" or #fields.shortId > 16 or #fields.shortId % 2 ~= 0
                or fields.shortId:find("[^%x]") or not safe_text(fields.spiderX, 1024)
                or not fields.spiderX:match("^/[^?]*$") then return false end
            stream.realitySettings = json.object({
                serverName = server_name, fingerprint = fields.fingerprint, publicKey = fields.publicKey,
                shortId = fields.shortId, spiderX = fields.spiderX,
            })
        else
            return false
        end
        stream.security = fields.security
        return true
    end

    local function normalize(fields)
        if not json.is_object(fields) or fields.protocol ~= "vless" or fields.tag ~= "proxy"
            or not json.is_object(fields.settings) then return nil end
        local peers = fields.settings.vnext
        if not json.is_array(peers) or #peers ~= 1 or not json.is_object(peers[1]) then return nil end
        local peer = peers[1]
        if not safe_text(peer.address, 253) or not json.is_array(peer.users)
            or #peer.users ~= 1 or not json.is_object(peer.users[1]) then return nil end
        local user = peer.users[1]
        if type(user.id) ~= "string" or not user.id:match(UUID)
            or not safe_text(user.flow, 64) or not safe_text(user.encryption, 512) then return nil end
        local port = json.integer(peer.port)
        if not valid_port(port) then return nil end

        local stream = json.object()
        if not transport_options(fields, stream) or not security_options(fields, peer.address, stream) then return nil end
        local address = pinned_ipv4(peer.address)
        if not address then return nil end

        -- Retain no settings that can add a second dial path or a chained proxy.
        return json.object({
            tag = "proxy", protocol = "vless", streamSettings = stream,
            settings = json.object({ vnext = json.array({
                json.object({
                    address = address, port = port, users = json.array({
                        json.object({ id = user.id, flow = user.flow, encryption = user.encryption }),
                    }),
                }),
            }) }),
        })
    end

    local function normalize_hysteria(fields, auth)
        if not json.is_object(fields) or fields.protocol ~= "hysteria" or fields.tag ~= "proxy"
            or fields.auth ~= auth or fields.allowInsecure ~= false
            or not safe_text(fields.address, 253) or type(fields.serverName) ~= "string" then return nil end
        local port = json.integer(fields.port)
        local server_name = fields.serverName ~= "" and fields.serverName or fields.address
        if not valid_port(port) or not core.valid_domain(server_name) then return nil end
        local address = pinned_ipv4(fields.address)
        if not address then return nil end
        return json.object({
            tag = "proxy", protocol = "hysteria",
            settings = json.object({ version = 2, address = address, port = port }),
            streamSettings = json.object({
                network = "hysteria", security = "tls",
                tlsSettings = json.object({
                    serverName = server_name, useSystemCA = true, alpn = json.array({ "h3" }),
                }),
                hysteriaSettings = json.object({ version = 2, auth = auth }),
            }),
        })
    end

    local function outbound(dir, link)
        if type(link) ~= "string" or #link > 8192 or link:find("[^!-~]") or link:find("#", 1, true) then
            return nil, "invalid_server"
        end
        local vless = link:match("^vless://")
        local auth = not vless and hysteria_auth and hysteria_auth(link)
        if (vless and has_unsupported_options(link)) or (not vless and not auth) then return nil, "invalid_server" end
        if not platform.executable(converter) then return nil, "dependency_missing" end
        local source, template, rendered = dir .. "/selected.link", dir .. "/vless-template.json", dir .. "/outbound.json"
        -- The converter treats a literal plus as a form-encoded space.
        local uri = vless and link or link:gsub("%+", "%%2B")
        if not platform.write(source, uri .. "\n") or not platform.write(template, vless and TEMPLATE or HYSTERIA_TEMPLATE) then
            return nil, "probe_failed"
        end
        local code, reason = platform.run({
            converter, "-r", source, "-t", template, "--tag", "proxy", "--one-outbound",
        }, { timeout = 3, stdout = rendered })
        if reason == "dependency_missing" or code == 126 or code == 127 then return nil, "dependency_missing" end
        if not code then return nil, "probe_failed" end
        if code ~= 0 then return nil, "invalid_server" end
        local body = platform.read(rendered, 32768)
        if not body then return nil, "probe_failed" end
        local decoded, fields = pcall(json.decode, body)
        if not decoded then return nil, "invalid_server" end
        local result
        if vless then result = normalize(fields) else result = normalize_hysteria(fields, auth) end
        if not result then return nil, "invalid_server" end
        return result
    end

    local function valid_probe_url(url)
        if type(url) ~= "string" or #url > 2048 or url:find("[^!-~]") or url:find('[#\"\\]') then return false end
        local host = url:match("^https://([^/?]+)")
        if not host then return false end
        host = host:match("^([^:]+):443$") or host
        return core.valid_domain(host) and host:find(".", 1, true) and not host:match("^[%d.]+$")
    end

    local function head(port, user, password, url, dir)
        if not platform.executable(CURL) then return nil, "dependency_missing" end
        if not valid_port(port) or not valid_credential(user) or not valid_credential(password)
            or not valid_probe_url(url) then return nil, "probe_failed" end
        local options, result = dir .. "/head.curl", dir .. "/head.result"
        local private_options = 'url = "' .. url .. '"\nproxy-user = "' .. user .. ":" .. password .. '"\n'
        if not platform.write(options, private_options) then return nil, "probe_failed" end
        local command = {
            CURL, "-q", "--silent", "--head", "--globoff", "--proto", "=https", "--noproxy", "",
            "--proxy", "socks5h://127.0.0.1:" .. port, "--connect-timeout", "3", "--max-time", tostring(REQUEST_LIMIT),
            "--output", "/dev/null", "--write-out", "%{http_code}\t%{time_total}\t%{remote_ip}\t%{remote_port}\n",
            "--config", options,
        }
        local code, reason
        -- A just-started listener may refuse the local connection briefly.
        -- Retry that condition only, never repeat a completed HTTP request.
        for attempt = 1, 4 do
            code, reason = platform.run(command, { timeout = REQUEST_LIMIT + 1, stdout = result })
            if code ~= 7 or attempt == 4 then break end
            platform.sleep(0.15)
        end
        if code == 28 or (code == nil and reason == "timeout") then return { result = "timeout" } end
        if reason == "dependency_missing" or code == 1 or code == 2 or code == 4 or code == 48 or code == 77
            or code == 126 or code == 127 then return nil, "dependency_missing" end
        if code == nil or code == 3 or code == 23 or code == 26 then return nil, "probe_failed" end
        if code ~= 0 then return { result = "unreachable" } end
        local body = platform.read(result, 160)
        local status, elapsed, peer_port
        if body then
            status, elapsed, peer_port = body:match("^(%d%d%d)\t(%d+%.%d+)\t127%.0%.0%.1\t(%d+)\n$")
        end
        status, elapsed = tonumber(status), tonumber(elapsed)
        if not status or status < 100 or status > 599 or not elapsed or elapsed > REQUEST_LIMIT + 1
            or tonumber(peer_port) ~= port then return nil, "probe_failed" end
        return { result = "response", httpCode = status, elapsedMs = math.floor(elapsed * 1000 + 0.5) }
    end

    local function owned_head(process, port, user, password, url, dir)
        for attempt = 1, 11 do
            if platform.child_listener(process, port) then
                local outcome, reason = head(port, user, password, url, dir)
                if not platform.child_listener(process, port) then return nil, "probe_failed" end
                return outcome, reason
            end
            if attempt < 11 then platform.sleep(0.1) end
        end
        return nil, "probe_failed"
    end

    local function check(selected, url)
        if not json.is_object(selected) or selected.tag ~= "proxy"
            or (selected.protocol ~= "vless" and selected.protocol ~= "hysteria") then
            return nil, "invalid_server"
        end
        if not platform.executable(xray) or not platform.executable(CURL) then return nil, "dependency_missing" end
        if not valid_probe_url(url) then return nil, "probe_failed" end
        local outcome, reason = platform.with_workspace(function(dir)
            local port, user, password = platform.tcp_port(), "vpn-routing", platform.random_hex(16)
            if not valid_port(port) or not valid_credential(password) then return nil, "probe_failed" end
            local config_path = dir .. "/probe.json"
            local config = json.object({
                log = json.object({ loglevel = "none", access = "none", error = "none" }),
                inbounds = json.array({
                    json.object({
                        listen = "127.0.0.1", port = port, protocol = "socks",
                        settings = json.object({
                            auth = "password", udp = false,
                            users = json.array({ json.object({ user = user, pass = password }) }),
                        }),
                    }),
                }),
                outbounds = json.array({ selected }),
            })
            if not platform.write(config_path, json.encode(config)) then return nil, "probe_failed" end
            local process = platform.spawn({ xray, "run", "-config", config_path }, { lifetime = 14 })
            if not process then return nil, "probe_failed" end
            local ok, outcome, reason = pcall(owned_head, process, port, user, password, url, dir)
            local stopped = platform.stop(process)
            if not ok or not stopped then return nil, "probe_failed" end
            return outcome, reason
        end)
        if outcome then return outcome end
        return nil, reason == "dependency_missing" and reason or "probe_failed"
    end

    return { outbound = outbound, head = head, check = check }
end
