const assert = require('node:assert/strict');
const { spawn, spawnSync } = require('node:child_process');
const { once } = require('node:events');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');
const { setTimeout: delay } = require('node:timers/promises');

const xray = process.env.XRAY_BIN;
const lua = process.env.LUA_BIN || 'lua';
const loopbackEnabled = process.env.XRAY_LOOPBACK === '1';
const loopbackOptions = { skip: !loopbackEnabled && 'Set XRAY_LOOPBACK=1 to run SOCKS probes' };
const adapter = path.join(__dirname, '..', 'route-adapter.lua');
const loopback = '127.0.0.1';
const lan = 'lab-tproxy';
const other = 'lab-other';
const routeOrder = 'block-proxy-direct';

function run(executable, args) {
  const result = spawnSync(executable, args, { encoding: 'utf8', timeout: 5000, windowsHide: true });
  assert.ifError(result.error);
  assert.equal(result.status, 0, `${path.basename(executable)} exited ${result.status}\n${result.stderr.slice(-500)}`);
  return result.stdout;
}

async function loopbackPorts() {
  const servers = [net.createServer(), net.createServer()];
  try {
    for (const server of servers) {
      server.listen(0, loopback);
      await once(server, 'listening');
    }
    return servers.map(server => server.address().port);
  } finally {
    await Promise.all(servers.filter(server => server.listening).map(server => new Promise(resolve => server.close(resolve))));
  }
}

async function waitFor(check, failure) {
  const deadline = Date.now() + 3000;
  while (Date.now() < deadline) {
    const result = check();
    if (result) return result;
    await delay(20);
  }
  assert.fail(failure());
}

async function withXray(args, exercise) {
  const child = spawn(xray, args, { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
  const state = { log: '', closed: false };
  const stopped = new Promise(resolve => child.once('close', () => {
    state.closed = true;
    resolve();
  }));
  child.once('error', error => { state.error = error; });
  for (const stream of [child.stdout, child.stderr]) {
    stream.setEncoding('utf8');
    stream.on('data', chunk => { state.log += chunk; });
  }

  try {
    await waitFor(() => {
      assert.ifError(state.error);
      assert.equal(state.closed, false, `Xray stopped before startup\n${state.log.slice(-500)}`);
      return state.log.includes('Xray 26.10.31 started');
    }, () => 'Xray did not start on loopback');
    await exercise(state);
  } finally {
    if (!state.closed) child.kill('SIGKILL');
    await stopped;
  }
}

async function assertRoute(state, port, target, expected, sniffedHost) {
  const address = net.isIPv4(target)
    ? Buffer.from([1, ...target.split('.').map(Number)])
    : Buffer.concat([Buffer.from([3, target.length]), Buffer.from(target, 'ascii')]);
  const offset = state.log.length;
  const socket = net.createConnection({ host: loopback, port });
  let connectionError;
  socket.on('error', error => { connectionError = error.code; });
  socket.once('connect', () => socket.write(Buffer.concat([
    Buffer.from([5, 1, 0]), // SOCKS5 greeting, no authentication
    Buffer.from([5, 1, 0]), address, Buffer.from([0, 80]), // CONNECT, target port 80
    Buffer.from(sniffedHost ? `GET / HTTP/1.1\r\nHost: ${sniffedHost}\r\n\r\n` : '', 'ascii'),
  ])));
  socket.resume();

  try {
    const line = await waitFor(() => {
      assert.equal(state.closed, false, 'Xray stopped during a SOCKS probe');
      assert.ok(connectionError !== 'EACCES' && connectionError !== 'EPERM',
        `TCP loopback connection denied (${connectionError})`);
      const lines = state.log.slice(offset).split(/\r?\n/);
      lines.pop(); // A final partial line may still be arriving from the child.
      return lines.find(entry => entry.includes(` accepted tcp:${target}:80 [`));
    }, () => `No route logged for ${target}${connectionError ? ` (${connectionError})` : ''}`);
    assert.ok(line.includes(`[${expected}]`), `Expected ${expected} for ${target}, saw ${line}`);
    if (sniffedHost) {
      await waitFor(() => state.log.slice(offset).includes(`sniffed domain: ${sniffedHost}`),
        () => `Xray did not sniff ${sniffedHost}`);
    }
  } finally {
    socket.destroy();
  }
}

test('Xray 26.10.31 validates and dispatches the generated Happ routing', {
  skip: !xray && 'Set XRAY_BIN to run the native Xray suite',
  timeout: 30000,
}, async t => {
  assert.match(run(xray, ['version']), /^Xray 26\.10\.31\b/);
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'vpn-routing-xray-test-'));
  const stage = path.join(work, 'conf.d');
  const files = new Set();
  t.after(() => {
    for (const file of files) fs.rmSync(file, { force: true });
    if (fs.existsSync(stage)) fs.rmdirSync(stage);
    fs.rmdirSync(work);
  });
  fs.mkdirSync(stage, { mode: 0o700 });
  function write(directory, name, contents) {
    const file = path.join(directory, name);
    files.add(file);
    fs.writeFileSync(file, contents, { mode: 0o600 });
    return file;
  }

  const profile = {
    GlobalProxy: 'true',
    DomainStrategy: 'IPIfNonMatch',
    RouteOrder: routeOrder,
    BlockSites: ['full:blocked.test'],
    BlockIp: ['198.51.100.30'],
    ProxySites: ['full:blocked.test', 'full:preferred-vpn.test'],
    ProxyIp: [],
    DirectSites: ['full:blocked.test', 'full:preferred-vpn.test', 'full:matched-domain.test'],
    DirectIp: ['198.51.100.20/32', '198.51.100.30'],
  };
  const encoded = Buffer.from(JSON.stringify(profile), 'utf8').toString('base64');
  const headers = write(work, 'fixture.headers', `HTTP/1.1 200 OK\r\nrouting: happ://routing/onadd/${encoded}\r\n\r\n`);
  const policy = write(work, 'policy.json', JSON.stringify({ inboundTag: lan, routeOrder }));
  const candidate = JSON.parse(run(lua, [adapter, 'preview', '--source', 'happ', '--headers', headers, '--policy', policy]));
  assert.deepEqual(Object.keys(candidate), ['routing']);
  assert.equal(candidate.routing.domainStrategy, 'IPIfNonMatch');
  const [lanPort, otherPort] = loopbackEnabled ? await loopbackPorts() : [31080, 31081];

  write(stage, '01-log.json', JSON.stringify({ log: { access: '', error: '', loglevel: 'info' } }));
  write(stage, '02-inbounds.json', JSON.stringify({ inbounds: [
    {
      tag: lan, listen: loopback, port: lanPort, protocol: 'socks', settings: { auth: 'noauth' },
      sniffing: { enabled: true, destOverride: ['http'], routeOnly: true },
    },
    { tag: other, listen: loopback, port: otherPort, protocol: 'socks', settings: { auth: 'noauth' } },
  ] }));
  write(stage, '03-dns.json', JSON.stringify({ dns: {
    hosts: {
      'matched-domain.test': '198.51.100.30',
      'lookup-only.test': '198.51.100.20',
      'unmatched.test': '198.51.100.80',
    },
    servers: [{ address: loopback, port: 9 }],
  } }));
  // Use real Xray dispatch while preventing every test outbound from opening a WAN connection.
  write(stage, '04_outbounds.json', JSON.stringify({ outbounds: ['proxy', 'direct', 'block'].map(tag => ({
    tag, protocol: 'blackhole',
  })) }));
  write(stage, '05-routing.json', JSON.stringify(candidate));
  const args = ['run', '-format', 'json', '-confdir', stage];

  await t.test('the full shadow config passes Xray -test', () => {
    assert.match(run(xray, [...args, '-test']), /Configuration OK\./);
  });

  await t.test('order, IP lookup, VPN fallback and inbound scope', loopbackOptions, async () => {
    await withXray(args, async state => {
      await assertRoute(state, lanPort, 'blocked.test', `${lan} -> block`);
      await assertRoute(state, lanPort, 'preferred-vpn.test', `${lan} -> proxy`);
      await assertRoute(state, lanPort, '198.51.100.20', `${lan} -> direct`);
      await assertRoute(state, lanPort, 'matched-domain.test', `${lan} -> direct`);
      await assertRoute(state, lanPort, '198.51.100.30', `${lan} -> block`, 'matched-domain.test');
      await assertRoute(state, lanPort, 'lookup-only.test', `${lan} -> direct`);
      await assertRoute(state, lanPort, 'unmatched.test', `${lan} >> proxy`);
      await assertRoute(state, otherPort, 'blocked.test', `${other} >> proxy`);
    });
  });

  await t.test('an explicit final catch-all suppresses the DNS pass', loopbackOptions, async () => {
    candidate.routing.rules.push({ type: 'field', inboundTag: [lan], network: 'tcp,udp', outboundTag: 'proxy' });
    write(stage, '05-routing.json', JSON.stringify(candidate));
    await withXray(args, state => assertRoute(state, lanPort, 'lookup-only.test', `${lan} -> proxy`));
  });
});
