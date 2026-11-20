const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');

const adapter = path.join(__dirname, '..', 'route-adapter.lua');
const lua = process.env.LUA_BIN || 'lua';
const xray = process.env.XRAY_BIN;
const url = 'https://routing.example.invalid/profiles/test.json';
const policy = { inboundTag: 'lab-tproxy', routeOrder: 'block-proxy-direct', incySource: { url } };
const profile = {
    Name: 'Стенд VPN Routing \u{1F9EA}',
    GlobalProxy: 'true',
    DomainStrategy: 'IPIfNonMatch',
    RouteOrder: 'block-proxy-direct',
    DirectSites: ['domain:local.test'],
    DirectIp: ['198.51.100.0/24', '2001:db8::1/128'],
    ProxySites: ['full:video.local.test'],
    BlockSites: ['full:ads.local.test'],
    DnsHosts: { 'ignored.test': '192.0.2.2' },
    RemoteDNSDomain: 'https://dns.example.invalid/dns-query',
    Geoipurl: 'https://dat.example.invalid/geoip.dat',
};

function happ(value) {
    const raw = typeof value === 'string' ? value : JSON.stringify(value);
    return 'happ://routing/onadd/' + Buffer.from(raw).toString('base64');
}

function fixture(t) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vpn-routing-route-test-'));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    const save = (name, value) => {
        const file = path.join(dir, name);
        fs.writeFileSync(file, typeof value === 'string' || Buffer.isBuffer(value) ? value : JSON.stringify(value),
            { mode: 0o600 });
        return file;
    };
    const run = ({
        command = 'preview', source = 'happ', headers = 'Routing: ' + happ(profile), local = policy, args = [],
        entry = adapter, leadingArgs = [],
    } = {}) => {
        const result = spawnSync(lua, [
            entry, ...leadingArgs, command, '--source', source,
            '--headers', save('headers.txt', headers), '--policy', save('policy.json', local), ...args,
        ], { encoding: 'utf8', timeout: 8000, windowsHide: true });
        assert.ifError(result.error);
        return result;
    };
    return { dir, save, run };
}

function accepted(result) {
    assert.equal(result.status, 0, result.stderr);
    return JSON.parse(result.stdout);
}

function rejected(result, message) {
    assert.equal(result.status, 1, result.stderr);
    assert.equal(result.stdout, '');
    assert.match(result.stderr, /^VPN Routing Adapter \| /);
    assert.match(result.stderr, message);
    assert.doesNotMatch(result.stderr, /happ:\/\/|https:\/\/|vless:\/\/|stack traceback|SECRET_CANARY/);
}

test('Happ preview keeps source, group order and match kinds separate', (t) => {
    const { run } = fixture(t);
    const headers = [
        'HTTP/2 200', 'X-Unrelated: fixture', 'rOuTiNg: \t' + happ(profile) + ' ', 'autorouting: ignored', '', '',
    ].join('\r\n');
    const result = run({ headers });
    const candidate = accepted(result);
    assert.equal(run({ headers }).stdout, result.stdout);
    assert.match(result.stderr, /candidate only.*IPIfNonMatch.*fallback=first-outbound:proxy/);
    assert.deepEqual(Object.keys(candidate), ['routing']);
    assert.deepEqual(Object.keys(candidate.routing), ['domainStrategy', 'rules']);
    assert.deepEqual(candidate.routing.rules.map(({ ruleTag }) => ruleTag),
        ['vpn-routing-block-domain', 'vpn-routing-proxy-domain', 'vpn-routing-direct-domain', 'vpn-routing-direct-ip']);
    for (const rule of candidate.routing.rules) {
        assert.deepEqual(rule.inboundTag, ['lab-tproxy']);
        assert.equal(rule.type, 'field');
        assert.notEqual(Object.hasOwn(rule, 'domain'), Object.hasOwn(rule, 'ip'));
    }
    assert.deepEqual(candidate.routing.rules.at(-1).ip, profile.DirectIp);
    assert.doesNotMatch(result.stdout, /example\.invalid|ignored\.test|Стенд/);
});

test('AsIs alone adds a scoped VPN fallback', (t) => {
    const { run } = fixture(t);
    const result = run({ headers: 'Routing: ' + happ({ ...profile, DomainStrategy: 'AsIs' }) });
    const { routing } = accepted(result);
    assert.equal(routing.domainStrategy, 'AsIs');
    assert.deepEqual(routing.rules.at(-1), {
        inboundTag: ['lab-tproxy'], outboundTag: 'proxy', ruleTag: 'vpn-routing-fallback', type: 'field',
    });
});

test('Selected header must be unique and from a single successful response', (t) => {
    const { run } = fixture(t);
    const selected = 'routing: ' + happ(profile);
    for (const [headers, expected] of [
        ['autorouting: ignored', /missing routing/],
        ['routing: happ://routing/off', /Happ routing add or onadd/],
        ['routing: happ://routing/add/YR==', /Base64 padding/],
        ['routing: happ://routing/add/AAAA-AA=', /Base64/],
        ['routing: happ://routing/add/' + 'A'.repeat(100 * 1024), /too large/],
        [selected + '\nROUTING: SECRET_CANARY', /duplicate routing/],
        ['HTTP/2 302\n' + selected, /HTTP 200/],
        [selected + '\n\nvless://SECRET_CANARY', /without a body/],
        [selected + '\n folded', /invalid HTTP header/],
        ['routing: happ://routing/add/AAAA\rAAAA', /control character/],
    ]) rejected(run({ headers }), expected);
});

test('JSON shape, duplicates, escapes and unsupported policies fail closed', (t) => {
    const { run } = fixture(t);
    const raw = JSON.stringify(profile);
    for (const [value, expected] of [
        [raw + '{}', /invalid JSON object/],
        [raw.replace('"GlobalProxy":"true"', '"GlobalProxy":"false","GlobalPro\\u0078y":"true"'), /invalid JSON object/],
        [raw.replace('"GlobalProxy":"true"', '"GlobalProxy":"true",'), /invalid JSON object/],
        [raw.replace('"GlobalProxy":"true"', '"GlobalProxy":"true\\u0000"'), /GlobalProxy/],
        ['{"Name":"\\ud800"}', /invalid JSON object/],
        ['{"Name":"' + 'a'.repeat(4) + '","bad":0e}', /invalid JSON object/],
        ['{"Name":' + '['.repeat(25) + '0' + ']'.repeat(25) + '}', /invalid JSON object/],
        [{ ...profile, GlobalProxy: 'false' }, /GlobalProxy/],
        [{ ...profile, GlobalProxy: true }, /GlobalProxy/],
        [{ ...profile, RouteOrder: 'direct-proxy-block' }, /RouteOrder/],
        [{ ...profile, DomainStrategy: 'IPOnDemand' }, /DomainStrategy/],
        [{ ...profile, FakeDNS: 'true' }, /FakeDNS/],
        [{ ...profile, outbounds: [], inbounds: [] }, /unsupported field/],
        [{ ...profile, DirectSites: {} }, /DirectSites must be an array/],
        [{ ...profile, DirectSites: [null] }, /DirectSites contains an invalid string/],
        [{ ...profile, DirectSites: ['domain:foo..test'] }, /unapproved rule in DirectSites/],
        [{ ...profile, DirectSites: ['local.test'] }, /unapproved rule in DirectSites/],
        [{ ...profile, DirectSites: ['ext:foreign.dat:direct'] }, /unapproved rule in DirectSites/],
        [{ ...profile, DirectIp: ['0.0.0.0/0'] }, /unapproved rule in DirectIp/],
        [{ ...profile, DirectIp: ['192.000.2.1'] }, /unapproved rule in DirectIp/],
        [{ ...profile, DirectIp: ['2001:::1'] }, /unapproved rule in DirectIp/],
        [{ ...profile, DirectIp: ['2001:db8::/129'] }, /unapproved rule in DirectIp/],
    ]) rejected(run({ headers: 'routing: ' + happ(value) }), expected);
    const invalidUtf8 = Buffer.concat([Buffer.from('{"Name":"'), Buffer.from([0xc0, 0xaf]), Buffer.from('"}')]);
    rejected(run({ headers: 'routing: happ://routing/onadd/' + invalidUtf8.toString('base64') }), /invalid JSON object/);
});

test('INCY uses only explicit local JSON with an exact URL match', (t) => {
    const { save, run } = fixture(t);
    const inc = { ...profile, DirectSites: ['full:incy-only.test'] };
    const headers = 'autorouting: ://autorouting/onadd/' + url + '\nrouting: ' + happ(profile);
    const args = ['--profile', save('incy.json', inc)];
    const incRules = accepted(run({ source: 'incy', headers, args })).routing.rules;
    assert.deepEqual(incRules.find((rule) => rule.ruleTag === 'vpn-routing-direct-domain').domain, inc.DirectSites);
    assert.deepEqual(accepted(run({ headers })).routing.rules[2].domain, profile.DirectSites);
    rejected(run({ source: 'incy', headers }), /exactly one/);
    rejected(run({ source: 'incy', headers, args: [...args, '--fetch'] }), /exactly one/);
    rejected(run({ source: 'incy', args }), /missing autorouting/);
    rejected(run({ source: 'incy', headers: headers.replace('/test.json', '/different.json'), args }), /approved HTTPS URL/);
    rejected(run({ source: 'incy', headers: 'autorouting: ' + url, args }), /autorouting add or onadd/);
    rejected(run({ source: 'incy', headers, args: ['--fetch'] }), /pinned public IPv4/);
    const bad = 'https://routing.example.invalid/profiles/../test.json';
    rejected(run({ source: 'incy', headers: 'autorouting: incy://autorouting/add/' + bad, args,
        local: { ...policy, incySource: { url: bad } } }), /dot segment/);
    rejected(run({ source: 'incy', headers, args,
        local: { ...policy, incySource: { url, ipv4: '169.254.169.254' } } }), /pinned public IPv4/);
});

test('INCY fetch checks pinned curl invocation, HTTP status, exit and size', (t) => {
    const { save, run } = fixture(t);
    const mock = save('mock-fetch.lua', [
        'package.config = "/"',
        'local adapter, response = arg[1], arg[2]',
        'local file = assert(io.open(response, "rb"))',
        'local payload = file:read("*a")',
        'file:close()',
        'io.popen = function(command, mode)',
        '    assert(mode == "r" and command:find("curl -q", 1, true))',
        '    assert(command:find("--resolve \'routing.example.invalid:443:8.8.8.8\'", 1, true))',
        '    assert(command:find("--noproxy \'*\'", 1, true))',
        '    assert(command:find("--proto \'=https\'", 1, true))',
        '    assert(command:find("--max-redirs 0", 1, true) and not command:find("--location", 1, true))',
        '    return { read = function(_, limit) return payload:sub(1, limit) end, close = function() end }',
        'end',
        'local forwarded = { [0] = adapter }',
        'for index = 3, #arg do forwarded[#forwarded + 1] = arg[index] end',
        'arg = forwarded',
        'dofile(adapter)',
    ].join('\n'));
    const headers = 'autorouting: incy://autorouting/onadd/' + url;
    const sourcePolicy = { ...policy, incySource: { url, ipv4: '8.8.8.8' } };
    const fetch = (body) => run({
        source: 'incy', headers, local: sourcePolicy, args: ['--fetch'],
        entry: mock, leadingArgs: [adapter, save('curl-output.txt', body)],
    });
    const raw = JSON.stringify(profile);
    assert.equal(accepted(fetch(raw + '\n200\nVPN_ROUTING_CURL_EXIT=0\n')).routing.domainStrategy, 'IPIfNonMatch');
    for (const body of [
        raw + '\n302\nVPN_ROUTING_CURL_EXIT=0\n', raw + '\n200\nVPN_ROUTING_CURL_EXIT=18\n',
        raw + '\n200', raw + ' '.repeat(65536) + '\n200\nVPN_ROUTING_CURL_EXIT=0\n',
    ]) rejected(fetch(body), /HTTPS fetch failed/);
});

function baseConfig() {
    return {
        inbounds: [{ tag: 'lab-tproxy', protocol: 'tunnel' }, { tag: 'watchdog', protocol: 'socks' }],
        outbounds: [
            { tag: 'proxy', protocol: 'vless' },
            { tag: 'direct', protocol: 'freedom' },
            { tag: 'block', protocol: 'blackhole' },
        ],
        dns: { servers: ['localhost'] },
    };
}

function verifyFixture(run, save, baseline, merged, options = {}) {
    const { args = [], ...rest } = options;
    return run({
        ...rest,
        command: 'verify',
        args: ['--baseline', save('baseline.json', baseline), '--merged', save('merged.json', merged), ...args],
    });
}

test('Verify rejects drift, foreign routing and invalid fallback without emitting a fragment', (t) => {
    const { save, run } = fixture(t);
    const candidate = accepted(run());
    const baseline = baseConfig();
    const merged = { ...baseline, ...candidate };
    const check = (before, after, options) => verifyFixture(run, save, before, after, options);
    const ok = check(baseline, merged);
    assert.equal(ok.status, 0, ok.stderr);
    assert.equal(ok.stdout, '');
    assert.match(ok.stderr, /merge verified/);

    const wrongFirst = { ...baseline, outbounds: [...baseline.outbounds].reverse() };
    rejected(check(wrongFirst, { ...wrongFirst, ...candidate }), /first merged outbound/);
    const missingTag = { ...baseline, outbounds: baseline.outbounds.slice(0, 2) };
    rejected(check(missingTag, { ...missingTag, ...candidate }), /expected merged outbound tags/);
    const missingInbound = { ...baseline, inbounds: baseline.inbounds.slice(1) };
    rejected(check(missingInbound, { ...missingInbound, ...candidate }), /approved inboundTag is missing/);
    rejected(check(baseline, { ...merged, dns: { servers: ['192.0.2.53'] } }), /outside routing/);
    rejected(check(baseline, { ...merged, routing: { rules: [] } }), /differs from the generated candidate/);
    rejected(check(merged, merged), /baseline already owns routing/);
    assert.equal(check(merged, merged, { args: ['--previous', save('previous.json', candidate)] }).status, 0);

    const foreign = { routing: { ...candidate.routing, balancers: [] } };
    rejected(check({ ...baseline, ...foreign }, merged, { args: ['--previous', save('previous.json', foreign)] }),
        /previous routing contains an unsupported field/);
    const wrongScope = structuredClone(candidate);
    wrongScope.routing.rules[0].inboundTag = ['watchdog'];
    rejected(check({ ...baseline, ...wrongScope }, merged, { args: ['--previous', save('previous.json', wrongScope)] }),
        /not scoped to the approved adapter inbound/);
});

test('Geo allowlist and SHA-256 pairing are independently enforced', (t) => {
    const { save, run } = fixture(t);
    const geo = {
        geoip: { sha256: 'a'.repeat(64), categories: ['private'] },
        geosite: { sha256: 'b'.repeat(64), categories: ['category-ads'] },
    };
    const expression = 'regexp:^([\\w\\-\\.]+\\.)test$';
    const local = { ...policy, geo, allowedRegex: [expression] };
    const headers = 'routing: ' + happ({
        ...profile, DirectSites: [expression], DirectIp: ['geoip:private'], BlockSites: ['geosite:category-ads'],
    });
    rejected(run({ headers }), /unapproved rule in BlockSites/);
    rejected(run({ headers, local: { ...local, allowedRegex: [] } }), /unapproved rule in DirectSites/);
    const candidate = accepted(run({ headers, local }));
    const baseline = baseConfig();
    const merged = { ...baseline, ...candidate };
    const check = (args = [], extra = {}) => verifyFixture(run, save, { ...baseline, ...extra }, { ...merged, ...extra },
        { headers, local, args });
    rejected(check(), /requires --dat-sha256/);
    const digests = '--dat-sha256';
    const valid = geo.geoip.sha256 + '  geoip.dat\n' + geo.geosite.sha256 + ' *geosite.dat\n';
    rejected(check([digests, save('dat.sha256', valid.replace(/^a/, 'c'))]), /DAT SHA-256 mismatch/);
    rejected(check([digests, save('dat.sha256', valid.split('\n')[0])]), /cover both files/);
    const args = [digests, save('dat.sha256', valid)];
    rejected(check(args, { env: { 'xray.location.asset': '/elsewhere' } }), /overrides the DAT directory/);
    rejected(check(args, { geodata: {} }), /without a geodata updater/);
    assert.equal(check(args).status, 0);
});

test('Verify checks the effective native Xray merge', { skip: !xray && 'Set XRAY_BIN' }, (t) => {
    const { dir, save, run } = fixture(t);
    const beforeDir = path.join(dir, 'before');
    const afterDir = path.join(dir, 'after');
    fs.mkdirSync(beforeDir);
    fs.mkdirSync(afterDir);
    const fullConfig = baseConfig();
    fullConfig.log = { access: 'none', error: 'none' };
    fullConfig.inbounds = [{ tag: 'lab-tproxy', protocol: 'socks', listen: '127.0.0.1', port: 18080 }];
    fullConfig.outbounds[0].settings = {
        vnext: [{ address: '127.0.0.1', port: 443, users: [{
            id: '00000000-0000-4000-8000-000000000000', encryption: 'none',
        }] }],
    };
    for (const name of ['before', 'after']) {
        save(name + '/01-base.json', { log: fullConfig.log, inbounds: fullConfig.inbounds, dns: fullConfig.dns });
        save(name + '/04_outbounds.json', { outbounds: fullConfig.outbounds });
    }
    save('after/05-routing.json', accepted(run()));

    const native = (flag, configDir) => {
        const result = spawnSync(xray, ['run', flag, '-format', 'json', '-confdir', configDir],
            { encoding: 'utf8', timeout: 8000, windowsHide: true });
        assert.ifError(result.error);
        assert.equal(result.status, 0, 'native Xray failed ' + flag + ' on a synthetic fixture\n'
            + result.stderr + result.stdout);
        return result.stdout;
    };
    native('-test', afterDir);
    const baseline = native('-dump', beforeDir);
    const ok = verifyFixture(run, save, baseline, native('-dump', afterDir));
    assert.equal(ok.status, 0, ok.stderr);

    save('after/99-routing.json', {
        routing: { rules: [{ type: 'field', inboundTag: ['lab-tproxy'], outboundTag: 'proxy' }] },
    });
    native('-test', afterDir);
    rejected(verifyFixture(run, save, baseline, native('-dump', afterDir)), /differs from the generated candidate/);
});
