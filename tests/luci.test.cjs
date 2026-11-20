const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');

const root = path.resolve(__dirname, '..');
const lua = process.env.LUA_BIN || 'lua';
const handler = path.join(root, 'luci/root/usr/lib/lua/luci/vpn_routing.lua');
const cli = path.join(root, 'route-adapter.lua');
const fixturePath = path.join(root, 'examples');
const headers = fs.readFileSync(path.join(fixturePath, 'headers.txt'), 'utf8');
const policy = fs.readFileSync(path.join(fixturePath, 'policy.json'), 'utf8');
const incy = fs.readFileSync(path.join(fixturePath, 'profile.json'), 'utf8');
const token = 'local-test-token';

const luaHarness = [
    'local native_load = loadfile',
    'local root, handler, method = arg[1], arg[2], arg[3]',
    'local json = dofile(root .. "/route_json.lua")',
    'local fixture = json.decode(io.read("*a"))',
    'local reply, headers = { body = {} }, {}',
    'package.loaded["luci.http"] = {',
    '    status = function(code) reply.status = code end,',
    '    header = function(key, value) headers[key] = value end,',
    '    prepare_content = function(value) headers["Content-Type"] = value end,',
    '    write = function(value) reply.body[#reply.body + 1] = value end,',
    '    getenv = function(key) return fixture.env[key] end,',
    '    formvalue = function()',
    '        assert(not fixture.noParse, "denied request read the form")',
    '        return fixture.params',
    '    end,',
    '}',
    'package.loaded["luci.dispatcher"] = { context = fixture.context }',
    'loadfile = function(file)',
    '    local name = file:match("^/usr/lib/vpn%-routing/([a-z_]+%.lua)$")',
    '    return native_load(name and (root .. "/" .. name) or file)',
    'end',
    'dofile = function(file)',
    '    if file == "/usr/lib/vpn-routing/platform.lua" then',
    '        return {runtime_dir="/var/run/vpn-routing", dependency=function(name) return "/usr/bin/" .. name end,',
    '            xray_assets=function() return "/usr/share/xray" end, with_lock=function(fn) return fn() end,',
    '            with_workspace=function(fn) return fn("/test") end}',
    '    end',
    '    if file == "/usr/lib/vpn-routing/dns.lua" then',
    '        return function(json) return { handle = function(dir, action, params)',
    '            assert(dir == "/test" and action == method)',
    '            if fixture.failure then return nil, fixture.failure end',
    '            return { profile = params.profile or "dnscrypt", addresses = json.array({params.address or "127.0.0.10"}),',
    '                encryptedAvailable = true, checked = action == "check_dns" or nil }',
    '        end } end',
    '    end',
    '    if file == "/usr/lib/vpn-routing/guard.lua" then return function() return {} end end',
    '    if file == "/usr/lib/vpn-routing/connection.lua" then',
    '        return function(json)',
    '            return { handle = function(action, params)',
    '                assert(action == method)',
    '                if fixture.failure then return nil, fixture.failure end',
    '                if action == "probe" then return { result = "response", httpCode = 204, elapsedMs = 17 } end',
    '                if action == "status" then return { state = "disconnected" } end',
    '                if action == "connect" then',
    '                    assert(params.activeServer == fixture.expectedActive)',
    '                    return { state = "connected", serverId = params.server, serverName = "Fixture" }',
    '                end',
    '                if action == "remove_subscription" then return { state = "disconnected", hasSubscription = false } end',
    '                if action == "save_reserve" then',
    '                    assert(params.link:match("^vless://") and params.snapshot == fixture.expectedActive)',
    '                    return { state = "disconnected", reserve = json.object({ id = "reserve-fixture",',
    '                        name = params.name, snapshot = "reserve-fixture" }) }',
    '                end',
    '                if action == "remove_reserve" then return { state = "disconnected" } end',
    '                if action == "subscription" and params.confirmHost then',
    '                    assert(params.confirmHost == "outside.example.test")',
    '                    return { snapshot = "fixture", servers = json.array() }',
    '                end',
    '                if action == "settings" or action == "save_capture" or action == "save_routing" then',
    '                    return { editable = true, networks = json.array(), hwid = fixture.hwid }',
    '                end',
    '                return nil, "source_not_allowed"',
    '            end }',
    '        end',
    '    end',
    '    local runtime = file:match("^/usr/lib/vpn%-routing/(%a+%.lua)$")',
    '    if runtime then return assert(native_load(root .. "/luci/runtime/" .. runtime))() end',
    '    return assert(loadfile(file))()',
    'end',
    'local endpoint = assert(native_load(handler))()',
    'endpoint[method]()',
    'assert(headers["Cache-Control"] == "no-store" and headers["X-Content-Type-Options"] == "nosniff")',
    'assert(headers["Content-Type"] == "application/json; charset=utf-8")',
    'io.write(reply.status, "\\n", table.concat(reply.body), "\\n")',
].join('\n');

function fixtures(t) {
    const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'vpn-routing-luci-test-'));
    const script = path.join(temp, 'test.lua');
    fs.writeFileSync(script, luaHarness, { mode: 0o600 });
    t.after(() => fs.rmSync(temp, { recursive: true, force: true }));
    return (params, options = {}) => {
        const env = {
            REQUEST_METHOD: 'POST',
            CONTENT_TYPE: 'application/x-www-form-urlencoded;charset=UTF-8',
            CONTENT_LENGTH: String(new URLSearchParams(params).toString().length),
            ...options.env,
        };
        const context = {
            authuser: 'root', authsession: 'local-test-session', authtoken: token, ...options.context,
        };
        const result = spawnSync(lua, [script, root, handler, options.method || 'preview'], {
            input: JSON.stringify({
                params, env, context, noParse: !!options.noParse, failure: options.failure, hwid: options.hwid,
                expectedActive: options.expectedActive,
            }),
            encoding: 'utf8', timeout: 6000, windowsHide: true,
        });
        assert.ifError(result.error);
        assert.equal(result.status, 0, result.stderr);
        assert.equal(result.stderr, '');
        const end = result.stdout.indexOf('\n');
        return [Number(result.stdout.slice(0, end)), JSON.parse(result.stdout.slice(end + 1))];
    };
}

test('LuCI menu and POST paths inherit admin authentication', () => {
    const menu = JSON.parse(fs.readFileSync(path.join(root, 'luci/root/usr/share/luci/menu.d/luci-app-vpn-routing.json')));
    const base = 'admin/network/vpn-routing';
    assert.deepEqual(menu[base].action, { type: 'view', path: 'vpn-routing/preview' });
    assert.equal(menu[base + '/restore'], undefined);
    for (const suffix of ['preview', 'subscription', 'connect', 'disconnect', 'status', 'probe',
        'remove_subscription', 'save_reserve', 'remove_reserve',
        'settings', 'save_capture', 'save_routing', 'dns_settings', 'check_dns', 'apply_dns']) {
        assert.equal(menu[base + '/' + suffix].action.post, true);
        assert.equal(menu[base + '/' + suffix].action.module, 'luci.vpn_routing');
        assert.equal(menu[base + '/' + suffix].action.function, suffix);
        assert.equal(menu[base + '/' + suffix].auth, undefined);
        assert.equal(menu[base + '/' + suffix].cors, undefined);
    }
});

test('LuCI DNS actions enforce authenticated POST and a bounded form', (t) => {
    const call = fixtures(t);
    const read = { ok: true, profile: 'dnscrypt', addresses: ['127.0.0.10'], encryptedAvailable: true };
    assert.deepEqual(call({ token }, { method: 'dns_settings' }), [200, read]);
    assert.deepEqual(call({ token }, { method: 'check_dns' }), [200, { ...read, checked: true }]);
    const address = 'https://dns.example.test/dns-query';
    assert.deepEqual(call({ token, profile: 'custom', address, bootstrap: '1.1.1.1' }, { method: 'apply_dns' }),
        [200, { ...read, profile: 'custom', addresses: [address] }]);
    for (const [fields, expected] of [
        [{ profile: 'custom' }, 400],
        [{ profile: 'custom', address: 'bad\nserver' }, 400],
        [{ profile: 'custom', address: 'x'.repeat(513) }, 400],
        [{ profile: 'yandex', address: '77.88.8.8' }, 400],
        [{ profile: 'dnscrypt', extra: '1' }, 400],
        [{ token: 'other', profile: 'dnscrypt' }, 403],
    ]) {
        assert.equal(call({ token, ...fields }, { method: 'apply_dns' })[0], expected);
    }
    assert.deepEqual(call({ token, profile: 'adguard_doq' }, { method: 'apply_dns', failure: 'dns_dependency' }),
        [503, { ok: false, error: 'dns_dependency' }]);
    assert.deepEqual(call({ token, profile: 'yandex' }, { method: 'apply_dns', failure: 'dns_rollback_failed' }),
        [500, { ok: false, error: 'dns_rollback_failed' }]);
});

test('boot worker loads the routing compiler and retries until connected', () => {
    const script = `
local native_load = loadfile
local directory = "/usr/lib/vpn-routing/"
local attempts, delays = 0, {}
loadfile = function(file)
    if file == directory .. "route_core.lua" then return native_load("route_core.lua") end
    if file == directory .. "route_json.lua" then return native_load("route_json.lua") end
    return native_load(file)
end
dofile = function(file)
    if file == directory .. "backend.lua" then
        return function(base, json, core)
            assert(base == directory)
            local decoded = core.decode_object('{"ok":true}', "test")
            assert(decoded.ok and json.is_object(decoded))
            return { handle = function(action, params)
                assert(action == "restore" and next(params) == nil)
                attempts = attempts + 1
                if attempts <= 2 then return nil, "check_failed" end
                return { state = "connected" }
            end }, { sleep = function(delay) delays[#delays + 1] = delay end }
        end
    end
    return assert(loadfile(file))()
end
dofile("luci/runtime/restore.lua")
assert(attempts == 3 and table.concat(delays, ",") == "2,4")
`;
    const result = spawnSync(lua, ['-'], { cwd: root, input: script, encoding: 'utf8', timeout: 6000, windowsHide: true });
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout.trim(), 'VPN Routing connection restored.');
    assert.equal(result.stderr.trim(), 'VPN Routing restore will retry (check_failed)');
});

test('LuCI Happ and INCY return the exact CLI candidate', (t) => {
    const call = fixtures(t);
    for (const source of ['happ', 'incy']) {
        const params = { token, source, headers, policy, profile: source === 'incy' ? incy : '' };
        const [status, value] = call(params);
        assert.equal(status, 200);
        assert.equal(value.ok, true);
        const args = ['preview', '--source', source, '--headers', path.join(fixturePath, 'headers.txt'),
            '--policy', path.join(fixturePath, 'policy.json')];
        if (source === 'incy') args.push('--profile', path.join(fixturePath, 'profile.json'));
        const result = spawnSync(lua, [cli, ...args], { encoding: 'utf8', timeout: 6000, windowsHide: true });
        assert.ifError(result.error);
        assert.equal(result.status, 0, result.stderr);
        // Windows Lua writes CRLF to stdout in text mode.
        assert.equal(value.candidate, result.stdout.replace(/\r\n/g, '\n'));
    }
});

test('LuCI rejects missing session, bad CSRF, GET, query params and oversized body', (t) => {
    const call = fixtures(t);
    const params = { token, source: 'happ', headers, policy, profile: '' };
    for (const context of [{ authuser: 'operator' }, { authsession: '' }, { authtoken: '' }]) {
        assert.deepEqual(call(params, { context, noParse: true }), [403, { ok: false, error: 'forbidden' }]);
    }
    assert.equal(call({ ...params, token: 'wrong' })[0], 403);
    assert.equal(call(params, { env: { REQUEST_METHOD: 'GET' }, noParse: true })[0], 405);
    assert.equal(call(params, { env: { QUERY_STRING: 'token=x' }, noParse: true })[0], 400);
    assert.equal(call(params, { env: { CONTENT_TYPE: 'multipart/form-data' }, noParse: true })[0], 400);
    assert.deepEqual(call(params, { env: { CONTENT_LENGTH: String(96 * 1024 + 1) }, noParse: true }),
        [413, { ok: false, error: 'too_large' }]);
});

test('Web preview accepts only offline inputs and keeps errors free of input data', (t) => {
    const call = fixtures(t);
    const params = { token, source: 'happ', headers, policy, profile: '' };
    for (const extra of [{ fetch: 'true' }, { headers: ['duplicate', headers] }, { profile: incy }]) {
        assert.equal(call({ ...params, ...extra })[0], 400);
    }
    const [status, error] = call({ ...params, headers: 'routing: https://test.invalid/SECRET_CANARY' });
    assert.equal(status, 200);
    assert.equal(error.ok, false);
    assert.equal(error.error, 'rejected');
    assert.doesNotMatch(JSON.stringify(error), /SECRET_CANARY|test\.invalid/);
});

test('Connection actions enforce auth and exact fields and return safe response types', (t) => {
    const call = fixtures(t);
    for (const method of ['status', 'subscription', 'probe', 'connect', 'disconnect']) {
        assert.equal(call({ token }, { method, context: { authuser: 'operator' }, noParse: true })[0], 403);
        assert.equal(call({ token, injected: 'unexpected' }, { method })[0], 400);
    }
    assert.equal(call({ token, snapshot: 'a', server: '../../x' }, { method: 'connect' })[0], 400);
    assert.equal(call({ token, snapshot: 'a' }, { method: 'probe' })[0], 400);
    assert.deepEqual(call({ token, snapshot: 'a', server: 'b' }, { method: 'probe' }),
        [200, { ok: true, result: 'response', httpCode: 204, elapsedMs: 17 }]);
    assert.deepEqual(call({ token }, { method: 'status' }), [200, { ok: true, state: 'disconnected' }]);
    const denied = call({ token, url: 'https://test.invalid/SECRET_CANARY' }, { method: 'subscription' });
    assert.deepEqual(denied, [400, { ok: false, error: 'source_not_allowed' }]);
});

test('Only connect accepts an exact active-server ID for switching', (t) => {
    const call = fixtures(t);
    const method = 'connect';
    const params = { token, snapshot: 'list-1', server: 'target-2' };
    const expectedActive = 'router-active_1';
    const connected = [200, { ok: true, state: 'connected', serverId: 'target-2', serverName: 'Fixture' }];
    assert.deepEqual(call(params, { method }), connected);
    assert.deepEqual(call({ ...params, activeServer: expectedActive }, { method, expectedActive }), connected);
    assert.deepEqual(call({ ...params, activeServer: expectedActive }, { method, failure: 'connection_changed' }),
        [409, { ok: false, error: 'connection_changed' }]);
    assert.equal(call({ ...params, activeServer: expectedActive, token: 'wrong' }, { method })[0], 403);
    assert.equal(call({ ...params, activeServer: expectedActive }, { method: 'probe' })[0], 400);
    for (const activeServer of ['', 'a/b', 'a b', 'a'.repeat(129), ['one', 'two'], 1, null]) {
        assert.deepEqual(call({ ...params, activeServer }, { method }), [400, { ok: false, error: 'invalid_request' }]);
    }
});

test('LuCI removes subscriptions only through authenticated token-only POST', (t) => {
    const call = fixtures(t);
    const method = 'remove_subscription';
    assert.equal(call({ token }, { method, context: { authuser: 'operator' }, noParse: true })[0], 403);
    assert.equal(call({ token: 'wrong' }, { method })[0], 403);
    assert.equal(call({ token }, { method, env: { REQUEST_METHOD: 'GET' }, noParse: true })[0], 405);
    assert.equal(call({ token, confirmHost: 'outside.example.test' }, { method })[0], 400);
    assert.deepEqual(call({ token }, { method }), [200, { ok: true, state: 'disconnected', hasSubscription: false }]);
    assert.deepEqual(call({ token }, { method, failure: 'subscription_busy' }),
        [409, { ok: false, error: 'subscription_busy' }]);
});

test('LuCI reserve mutations enforce authenticated POST and bounded form fields', (t) => {
    const call = fixtures(t);
    const snapshot = 'reserve-fixture';
    const save = { token, name: 'Резерв', link: 'vless://synthetic' };
    const expected = [200, { ok: true, state: 'disconnected', reserve: { id: snapshot, name: save.name, snapshot } }];
    assert.deepEqual(call(save, { method: 'save_reserve' }), expected);
    assert.deepEqual(call({ ...save, snapshot }, { method: 'save_reserve', expectedActive: snapshot }), expected);
    assert.deepEqual(call({ token, snapshot }, { method: 'remove_reserve' }), [200, { ok: true, state: 'disconnected' }]);
    for (const [method, params] of [['save_reserve', save], ['remove_reserve', { token, snapshot }]]) {
        assert.equal(call(params, { method, context: { authuser: 'operator' }, noParse: true })[0], 403);
        assert.equal(call(params, { method, env: { REQUEST_METHOD: 'GET' }, noParse: true })[0], 405);
        assert.equal(call({ ...params, token: 'wrong' }, { method })[0], 403);
        assert.deepEqual(call(params, { method, failure: 'reserve_busy' }), [409, { ok: false, error: 'reserve_busy' }]);
        assert.deepEqual(call(params, { method, failure: 'stale_snapshot' }), [409, { ok: false, error: 'stale_snapshot' }]);
    }
    for (const fields of [{ name: '' }, { name: 'Я'.repeat(81) }, { name: 'Bad\rName' },
        { link: 'vless://one\nvless://two' }, { link: 'a'.repeat(8193) }, { link: [save.link] },
        { snapshot: 'a/b' }, { snapshot: null }, { extra: '1' }]) {
        assert.equal(call({ ...save, ...fields }, { method: 'save_reserve' })[0], 400);
    }
    assert.equal(call({ token }, { method: 'remove_reserve' })[0], 400);
    assert.equal(call({ token, snapshot, link: save.link }, { method: 'remove_reserve' })[0], 400);
    assert.deepEqual(call(save, { method: 'save_reserve', failure: 'invalid_reserve_name' }),
        [422, { ok: false, error: 'invalid_reserve_name' }]);
});

test('LuCI passes an optional, normalized DNS confirmation only for subscription import', (t) => {
    const call = fixtures(t);
    const method = 'subscription';
    const url = 'https://outside.example.test/fixture';
    const params = { token, url, confirmHost: 'OUTSIDE.example.test' };
    assert.deepEqual(call(params, { method }), [200, { ok: true, snapshot: 'fixture', servers: [] }]);
    assert.equal(call({ ...params, token: 'wrong' }, { method })[0], 403);
    assert.equal(call({ token, confirmHost: 'outside.example.test' }, { method })[0], 400);
    for (const confirmHost of ['', '127.0.0.1', '-outside.test', 'outside_.test', 'outside.test.', 'outside.test:443',
        'outside.test/fixture', 'https://outside.test', 'a'.repeat(64) + '.test', 'a.'.repeat(125) + 'test',
        ['outside.example.test', 'second.example.test']]) {
        assert.deepEqual(call({ ...params, confirmHost }, { method }), [400, { ok: false, error: 'invalid_request' }]);
    }
});

test('LuCI exposes the read-only identity to settings and maps device errors', (t) => {
    const call = fixtures(t);
    const hwid = 'ab'.repeat(16);
    assert.deepEqual(call({ token }, { method: 'settings', hwid }),
        [200, { ok: true, editable: true, networks: [], hwid }]);
    const url = 'https://outside.example.test/fixture';
    assert.equal(call({ token, hwid }, { method: 'settings' })[0], 400);
    assert.equal(call({ token, url, hwid }, { method: 'subscription' })[0], 400);
    for (const [failure, status] of [['hwid_limit_reached', 403], ['hwid_rejected', 502], ['hwid_unavailable', 503]]) {
        assert.deepEqual(call({ token, url }, { method: 'subscription', failure }),
            [status, { ok: false, error: failure }]);
    }
});

test('Settings actions require LuCI admin, CSRF and a bounded structured form', (t) => {
    const call = fixtures(t);
    for (const method of ['settings', 'save_capture', 'save_routing']) {
        assert.equal(call({ token }, { method, context: { authuser: 'operator' }, noParse: true })[0], 403);
        assert.equal(call({ token: 'bad' }, { method })[0], 403);
    }
    const response = [200, { ok: true, editable: true, networks: [] }];
    assert.deepEqual(call({ token }, { method: 'settings' }), response);
    assert.deepEqual(call({ token, interface: 'br-lan', sources: '192.168.1.7\n192.168.1.8' },
        { method: 'save_capture' }), response);
    assert.deepEqual(call({ token, mode: 'all', interface: 'br-lan' }, { method: 'save_capture' }), response);
    assert.deepEqual(call({ token, mode: 'selected', interface: 'br-lan', sources: '192.168.1.7' },
        { method: 'save_capture' }), response);
    for (const params of [
        { token, mode: 'all', interface: 'br-lan', sources: '192.168.1.7' },
        { token, mode: 'selected', interface: 'br-lan' },
        { token, mode: 'all' },
        { token, mode: 'legacy', interface: 'br-lan', sources: '192.168.1.7' },
        { token, mode: 'unknown', interface: 'br-lan' },
        { token, interface: 'br-lan;id', sources: '192.168.1.7' },
    ]) {
        assert.equal(call(params, { method: 'save_capture' })[0], 400);
    }
    assert.deepEqual(call({ token, source: 'happ', headers, policy, profile: '' }, { method: 'save_routing' }), response);
    assert.deepEqual(call({ token, source: 'none' }, { method: 'save_routing' }), response);
    assert.equal(call({ token, source: 'subscription' }, { method: 'save_routing' })[0], 400);
    for (const params of [
        { token, source: 'none', policy: '{}' },
        { token, source: 'subscription', profile: incy },
        { token, source: 'happ', headers, policy, profile: '', routing: '{}' },
        { token, source: 'incy', headers: [headers, headers], policy, profile: incy },
    ]) {
        assert.equal(call(params, { method: 'save_routing' })[0], 400);
    }
});
