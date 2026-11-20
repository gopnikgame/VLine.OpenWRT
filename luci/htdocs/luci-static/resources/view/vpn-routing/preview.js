'use strict';
'require view';

const PREFIX = 'vpn-routing-';
const LIMITS = { headers: 96 * 1024, profile: 64 * 1024, policy: 16 * 1024, body: 96 * 1024 };
const SOURCE_LIMIT = 32;
const ORDER = 'block-proxy-direct';
const GROUPS = [
	{ tag: 'block', badge: 'BLOCK', title: 'Блокировка' },
	{ tag: 'proxy', badge: 'VPN', title: 'Через VPN' },
	{ tag: 'direct', badge: 'DIRECT', title: 'Напрямую' },
];
const EDITOR = { autocomplete: 'off', autocapitalize: 'off', spellcheck: 'false' };
const DNS_PROFILES = [
	{ id: 'dnscrypt', label: 'DNSCrypt' },
	{ id: 'yandex', label: 'Яндекс DNS · обычный' },
	{ id: 'adguard_doh', label: 'AdGuard · DoH', encrypted: true },
	{ id: 'adguard_dot', label: 'AdGuard · DoT', encrypted: true },
	{ id: 'adguard_doq', label: 'AdGuard · DoQ', encrypted: true },
	{ id: 'cloudflare_doh', label: 'Cloudflare · DoH', encrypted: true },
	{ id: 'cloudflare_dot', label: 'Cloudflare · DoT', encrypted: true },
	{ id: 'custom', label: 'Свой DNS-сервер' },
];
const DNS_ACTIONS = new Set(['dns_settings', 'check_dns', 'apply_dns']);

function text(tag, className, value, attributes) {
	const node = E(tag, Object.assign({ class: className }, attributes));
	node.textContent = value;
	return node;
}

function setStatus(node, state, message) {
	node.dataset.state = state;
	node.textContent = message;
}

function field(name, label, options) {
	const id = PREFIX + name;
	const description = options.help ? text('p', 'vpn-routing-hint', options.help, { id: id + '-help' }) : null;
	const attributes = Object.assign({ id, class: 'vpn-routing-field' }, EDITOR);
	if (options.rows)
		attributes.rows = options.rows;
	else
		attributes.type = options.type || 'text';
	if (options.placeholder)
		attributes.placeholder = options.placeholder;
	if (description)
		attributes['aria-describedby'] = description.id;
	const input = E(options.rows ? 'textarea' : 'input', attributes);
	return {
		input,
		description,
		node: E('div', { class: 'vpn-routing-form-field' }, [
			text('label', 'vpn-routing-label', label, { for: id }),
			input,
			...(description ? [description] : []),
		]),
	};
}

function lines(value) {
	return value.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
}

function problem(message, input) {
	throw Object.assign(new Error(message), { input });
}

function parseCandidate(candidate, inboundTag) {
	if (typeof candidate !== 'string' || candidate.length > 256 * 1024)
		throw new Error('invalid candidate');
	const parsed = JSON.parse(candidate);
	const routing = parsed && parsed.routing;
	if (!routing || Object.keys(parsed).length !== 1 || Object.keys(routing).length !== 2 ||
	    !['AsIs', 'IPIfNonMatch'].includes(routing.domainStrategy) ||
	    !Array.isArray(routing.rules) || routing.rules.length < 1 || routing.rules.length > 7)
		throw new Error('invalid routing');

	const grouped = GROUPS.map(group => Object.assign({ domain: [], ip: [] }, group));
	let fallback = false;
	let position = -1;
	for (const [index, rule] of routing.rules.entries()) {
		if (!rule || rule.type !== 'field' || !Array.isArray(rule.inboundTag) ||
		    rule.inboundTag.length !== 1 || rule.inboundTag[0] !== inboundTag)
			throw new Error('invalid inbound');

		if (rule.ruleTag === 'vpn-routing-fallback') {
			if (index !== routing.rules.length - 1 || rule.outboundTag !== 'proxy' || Object.keys(rule).length !== 4)
				throw new Error('invalid fallback');
			fallback = true;
			continue;
		}

		const groupIndex = grouped.findIndex(group => group.tag === rule.outboundTag);
		const kind = Array.isArray(rule.domain) ? 'domain' : 'ip';
		const values = rule[kind];
		const next = groupIndex * 2 + (kind === 'ip' ? 1 : 0);
		if (groupIndex < 0 || next <= position || Object.keys(rule).length !== 5 ||
		    rule.ruleTag !== 'vpn-routing-' + rule.outboundTag + '-' + kind ||
		    !Array.isArray(values) || values.length === 0 || values.some(value => typeof value !== 'string'))
			throw new Error('invalid rule');
		grouped[groupIndex][kind] = values;
		position = next;
	}
	if (fallback !== (routing.domainStrategy === 'AsIs') || position < 0)
		throw new Error('invalid routing strategy');

	return { strategy: routing.domainStrategy, grouped };
}

function resultDetails(candidate) {
	const groups = candidate.grouped.map(group => {
		const entries = group.domain.concat(group.ip);
		const details = entries.length ? E('details', { class: 'vpn-routing-rule-details' }, [
			text('summary', '', 'Показать правила'),
			E('ul', {}, entries.map(entry => E('li', {}, [text('code', '', entry)]))),
		]) : null;
		return E('section', { class: 'vpn-routing-route-group', 'data-route': group.tag }, [
			E('h3', { class: 'vpn-routing-route-title' }, [
				text('span', 'vpn-routing-route-badge', group.badge),
				text('span', '', group.title),
			]),
			text('p', 'vpn-routing-hint', 'Домены · ' + group.domain.length + ' / IP · ' + group.ip.length),
			...(details ? [details] : []),
		]);
	});
	const strategy = candidate.strategy === 'IPIfNonMatch'
		? 'Если совпадения нет, Xray может повторить проверку по IP.'
		: 'Xray использует известный IP без дополнительного запроса DNS для правил.';
	const fallback = candidate.strategy === 'IPIfNonMatch'
		? 'VPN через первый выход Xray. Перед использованием проверьте, что это proxy.'
		: 'VPN через явное последнее правило для выхода proxy.';
	return [
		E('div', { class: 'vpn-routing-result-rules' }, groups),
		E('dl', { class: 'vpn-routing-summary' }, [
			E('div', {}, [text('dt', '', 'Проверка IP'), text('dd', '', strategy)]),
			E('div', {}, [text('dt', '', 'Если правила не подошли'), text('dd', '', fallback)]),
		]),
	];
}

function diagnostic(detail) {
	if (typeof detail !== 'string' || detail.includes('://'))
		return '';
	return detail.slice(0, 320).replace(/[^\x20-\x7e]/g, ' ').trim();
}

function exportCandidate(candidate) {
	const url = URL.createObjectURL(new Blob([candidate], { type: 'application/json' }));
	const anchor = E('a', { href: url, download: 'vpn-routing-draft.json', hidden: '' });
	document.body.appendChild(anchor);
	anchor.click();
	anchor.remove();
	window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function post(action, body, signal) {
	return fetch(L.url('admin', 'network', 'vpn-routing', action), {
		method: 'POST', body, signal, credentials: 'same-origin', mode: 'same-origin',
		cache: 'no-store', redirect: 'error',
	});
}

function validServerName(name) {
	return typeof name === 'string' && name.trim().length > 0 && name.length <= 160 &&
		!name.includes('://') && !/[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]/.test(name);
}

function validServerId(id) {
	return typeof id === 'string' && /^[a-zA-Z0-9_.-]{1,128}$/.test(id);
}

function subscriptionUrl(value) {
	if (typeof value !== 'string' || value.length > 8192 || !/^https:\/\//i.test(value) || /[\s\\]/.test(value))
		return null;
	try {
		const url = new URL(value);
		return url.protocol === 'https:' && !url.username && !url.password && !url.hash ? value : null;
	} catch {
		return null;
	}
}

function connectionPanel() {
	const subscriptionHelp = 'Вставьте HTTPS-ссылку на подписку VLESS или Hysteria2. После сохранения она обновляется каждые 6 часов.';
	const url = field('subscription-url', 'Ссылка подписки', {
		rows: 2, placeholder: 'https://…',
		help: subscriptionHelp,
	});
	url.input.classList.add('vpn-routing-subscription-url');
	url.input.inputMode = 'url';
	url.input.required = true;
	url.input.maxLength = 8192;
	const getServers = text('button', 'vpn-routing-button', 'Получить серверы', {
		id: PREFIX + 'get-servers', type: 'submit',
	});
	const removeSubscription = text('button', 'vpn-routing-button', 'Удалить подписку', {
		id: PREFIX + 'remove-subscription', type: 'button', hidden: '',
	});
	const reserveName = field('reserve-name', 'Название сервера', { placeholder: 'Мой резерв' });
	reserveName.input.required = true;
	reserveName.input.maxLength = 160;
	const reserveLink = field('reserve-link', 'Ссылка VLESS', { type: 'password', placeholder: 'vless://…' });
	reserveLink.input.required = true;
	reserveLink.input.maxLength = 8192;
	const saveReserve = text('button', 'vpn-routing-button', 'Сохранить резерв', {
		id: PREFIX + 'save-reserve', type: 'submit', disabled: '',
	});
	const removeReserve = text('button', 'vpn-routing-button', 'Удалить резерв', {
		id: PREFIX + 'remove-reserve', type: 'button', hidden: '',
	});
	const reserveHint = text('p', 'vpn-routing-hint', '');
	const reserveStatus = text('p', 'vpn-routing-hint', '', {
		id: PREFIX + 'reserve-status', role: 'status', 'aria-atomic': 'true',
	});
	const reserveForm = E('form', { class: 'vpn-routing-advanced-body vpn-routing-connection-form', novalidate: '',
		'aria-labelledby': PREFIX + 'reserve-title' }, [
		reserveHint, reserveName.node, reserveLink.node,
		E('div', { class: 'vpn-routing-actions' }, [saveReserve, removeReserve]), reserveStatus,
	]);
	const reserveEditor = E('details', { class: 'vpn-routing-advanced' }, [
		text('summary', '', 'Резерв VLESS', { id: PREFIX + 'reserve-title' }), reserveForm,
	]);
	const checkAll = text('button', 'vpn-routing-button', 'Проверить все', {
		id: PREFIX + 'check-all', type: 'button', title: 'Проверить каждый сервер через HTTP HEAD',
	});
	const check = text('button', 'vpn-routing-button', 'Проверить выбранный', {
		id: PREFIX + 'check-server', type: 'button', title: 'Проверить выбранный сервер через HTTP HEAD',
	});
	const connect = text('button', 'vpn-routing-button vpn-routing-primary', 'Подключить', {
		id: PREFIX + 'connect', type: 'button', 'aria-describedby': PREFIX + 'connect-help',
	});
	const serverList = E('div', {
		id: PREFIX + 'server-list', class: 'vpn-routing-server-list', role: 'radiogroup',
		'aria-labelledby': PREFIX + 'server-title',
	});
	const probeProgress = text('p', 'vpn-routing-hint vpn-routing-probe-progress', '', { role: 'status', hidden: '' });
	const controls = E('div', { class: 'vpn-routing-server-controls', hidden: '' }, [
		E('div', { class: 'vpn-routing-section-heading' }, [
			text('h3', '', 'Серверы', { id: PREFIX + 'server-title' }), checkAll,
		]),
		serverList, probeProgress,
	]);
	const listStatus = text('p', 'vpn-routing-hint', '', {
		id: PREFIX + 'server-status', role: 'status',
	});
	const connectHelp = text('p', 'vpn-routing-hint', '', { id: PREFIX + 'connect-help' });
	const status = text('p', 'vpn-routing-status', 'Уточняем состояние…', {
		id: PREFIX + 'connection-status', role: 'status', 'aria-atomic': 'true', 'data-state': 'busy',
	});
	const serverName = text('p', 'vpn-routing-connection-name', '', { hidden: '' });
	const notice = text('p', 'vpn-routing-hint', '', { role: 'status', hidden: '' });
	const refresh = text('button', 'vpn-routing-button', 'Обновить', { type: 'button', 'aria-label': 'Обновить статус подключения' });
	const form = E('form', { class: 'vpn-routing-connection-form', novalidate: '', 'aria-labelledby': PREFIX + 'subscription-title' }, [
		text('h2', '', 'Подписка', { id: PREFIX + 'subscription-title' }),
		url.node, E('div', { class: 'vpn-routing-actions' }, [getServers, removeSubscription]), listStatus,
	]);
	const sources = E('section', { class: 'vpn-routing-pane', 'aria-label': 'Источники подключения' }, [
		form, reserveEditor, controls,
		E('div', { class: 'vpn-routing-actions' }, [connect, check]), connectHelp, notice,
	]);
	const result = E('section', { class: 'vpn-routing-pane vpn-routing-result', 'aria-labelledby': PREFIX + 'connection-title' }, [
		E('div', { class: 'vpn-routing-section-heading' }, [
			text('h2', '', 'Статус подключения', { id: PREFIX + 'connection-title' }), refresh,
		]),
		status, serverName,
	]);
	const node = E('div', { class: 'vpn-routing-workbench' }, [sources, result]);

	let connection = null;
	let confirmed = false;
	let active = '';
	let refreshPending = false;
	let refreshTimer;
	let restore = true;
	let hasSubscription = false;
	let loadedSubscription = false;
	let subscriptionServers = null;
	let reserve = null;
	let selected = '';
	let rows = new Map();
	let scan = null;
	const failures = new Map(Object.entries({
		invalid_url: 'Нужна ссылка HTTPS на стандартном порту, без имени пользователя и пароля.',
		source_not_allowed: 'Источник подписки не подтверждён. Проверьте домен ссылки.',
		subscription_unavailable: 'Источник подписки не ответил. Проверьте ссылку и повторите запрос.',
		unsupported_subscription: 'В подписке нет поддерживаемых ссылок VLESS или Hysteria2.',
		hwid_limit_reached: 'Достигнут лимит устройств для этой подписки. Освободите место в списке устройств или обратитесь в поддержку.',
		hwid_rejected: 'Сервис подписки отклонил HWID роутера. Проверьте ссылку или обратитесь в поддержку.',
		hwid_unavailable: 'HWID роутера недоступен. Проверьте идентификатор во вкладке «Настройки».',
		subscription_busy: 'Сначала отключите VPN Routing, чтобы изменить подписку.',
		reserve_busy: 'Выберите сервер подписки или отключите VPN Routing, чтобы изменить резерв.',
		invalid_reserve_name: 'Укажите короткое название без ссылок и ключей.',
		stale_snapshot: 'Список изменился. Обновите статус и повторите действие.',
		connection_changed: 'Активное подключение изменилось. Уточните выбор и повторите.',
		capture_not_configured: 'Выберите локальную сеть во вкладке «Настройки».',
		capture_policy: 'Проверьте параметры выделенной сети VPN Routing.',
		capture_conflict: 'Обнаружен конфликт с другими правилами или службами.',
		capture_unavailable: 'Перехват VPN Routing недоступен. Проверьте зависимости на роутере.',
		guard_conflict: 'Обнаружен конфликт правил защиты от прямого выхода.',
		guard_failed: 'Не удалось применить защиту от прямого выхода.',
		policy_invalid: 'Проверьте настройки VPN Routing на роутере.',
		dependency_missing: 'На роутере отсутствует один из компонентов VPN Routing.',
		invalid_server: 'Параметры выбранного сервера не поддерживаются.',
		operation_pending: 'Операция ещё выполняется. Обновите статус через несколько секунд.',
		check_failed: 'Сервер не прошёл контрольный HTTP HEAD.',
		rollback_failed: 'Подключение не удалось. Отключите VPN Routing для завершения отката.',
		disconnect_failed: 'Отключение не подтверждено. Обновите статус и повторите.',
		storage_error: 'Не удалось надёжно сохранить состояние VPN Routing на роутере.',
	}));

	function switching() {
		return connection?.state === 'connected' && rows.has(selected) && selected !== connection.serverId;
	}

	function canRemoveSubscription() {
		return confirmed && hasSubscription && (connection.state === 'disconnected'
			|| (connection.activeSource === 'reserve' && ['connected', 'restoring'].includes(connection.state)));
	}

	function reserveInUse() {
		return connection?.activeSource === 'reserve' && connection.state !== 'disconnected';
	}

	function updateActions() {
		const running = connection && connection.state !== 'disconnected';
		const subscriptionLocked = running && (connection.activeSource !== 'reserve' || connection.hasSavedSubscription);
		const change = switching();
		const busy = active !== '' || scan !== null;
		getServers.disabled = busy;
		removeSubscription.hidden = !canRemoveSubscription();
		removeSubscription.disabled = busy;
		url.input.readOnly = busy || Boolean(subscriptionLocked);
		url.description.textContent = !subscriptionLocked ? subscriptionHelp
			: connection.activeSource === 'reserve' ? 'Для смены подписки удалите сохранённый источник.'
			: 'Для смены подписки сначала отключите VPN Routing.';
		const reserveLocked = reserveInUse();
		reserveName.input.readOnly = reserveLink.input.readOnly = busy || reserveLocked;
		saveReserve.disabled = busy || !confirmed || reserveLocked;
		removeReserve.hidden = !reserve;
		removeReserve.disabled = saveReserve.disabled;
		reserveHint.textContent = reserveLocked ? failures.get('reserve_busy')
			: reserve ? 'При замене резерва вставьте ссылку заново.'
			: 'Сохранённый резерв можно выбрать в списке серверов.';
		check.hidden = !rows.size;
		check.disabled = busy || !rows.has(selected);
		checkAll.disabled = scan ? scan.cancelled : busy || !rows.size;
		checkAll.textContent = scan ? 'Остановить проверку' : 'Проверить все';
		connect.disabled = busy || !confirmed || (!running && (!rows.has(selected) || connection.canConnect === false));
		connect.textContent = running && !change ? 'Отключить' : 'Подключить';
		connect.classList.toggle('vpn-routing-primary', !running || change);
		refresh.disabled = busy;
		connectHelp.textContent = change ? 'Выбранный сервер заменит текущий после проверки.'
			: connection?.state === 'connected' ? 'Для смены сервера выберите другую строку.'
			: running ? 'Кнопка «Отключить» отменит восстановление подключения.'
			: failures.get(connection?.runtimeReason) || 'Кнопка «Подключить» сохраняет и применяет параметры VPN Routing.';
		for (const [id, row] of rows) {
			const isActive = confirmed && connection.state === 'connected' && connection.serverId === id;
			row.input.checked = id === selected;
			row.input.disabled = active !== '' && active !== 'probe';
			row.node.dataset.selected = String(row.input.checked);
			row.badge.hidden = !isActive;
			row.input.setAttribute('aria-describedby', [row.source?.id, row.result.id, isActive && row.badge.id].filter(Boolean).join(' '));
		}
	}

	function updateConnection() {
		const connected = confirmed && connection.state === 'connected';
		const degraded = confirmed && connection.state === 'degraded';
		const restoring = confirmed && connection.state === 'restoring';
		const label = connected ? 'Подключено' : degraded ? 'Сбой подключения'
			: restoring ? 'Восстановление подключения' : 'Отключено';
		setStatus(status, connected ? 'ready' : restoring ? 'busy' : confirmed && !degraded ? 'idle' : 'error',
			confirmed ? label : 'Статус не подтверждён');
		serverName.textContent = connected ? (connection.activeSource === 'reserve' ? 'Активный резерв — ' : 'Активный сервер — ') + connection.serverName
			: degraded || restoring ? 'Последний сервер — ' + connection.serverName : '';
		serverName.hidden = !serverName.textContent;
	}

	function updateProbe(id, state, label, detail) {
		const row = rows.get(id);
		setStatus(row.result, state, label);
		row.result.title = detail || '';
	}

	function renderServers(preferred, fallback) {
		const entries = subscriptionServers?.servers.map(server => ({ ...server, snapshot: subscriptionServers.snapshot })) || [];
		if (reserve)
			entries.push(reserve);
		const next = new Map();
		for (const server of entries) {
			const existing = rows.get(server.id);
			if (existing?.snapshot === server.snapshot && existing.name === server.name) {
				next.set(server.id, existing);
				continue;
			}
			const name = text('bdi', 'vpn-routing-server-name', server.name, { id: PREFIX + 'name-' + server.id });
			const result = text('span', 'vpn-routing-server-result', 'Не проверен', { id: PREFIX + 'head-' + server.id });
			const badge = text('span', 'vpn-routing-server-active', 'Активный', { id: PREFIX + 'active-' + server.id, hidden: '' });
			const source = server === reserve ? text('span', 'vpn-routing-server-source', 'Резерв', { id: PREFIX + 'source-' + server.id }) : null;
			const input = E('input', {
				type: 'radio', name: PREFIX + 'server', value: server.id, 'aria-labelledby': name.id,
			});
			const row = E('label', { class: 'vpn-routing-server-row' }, [
				input, E('span', { class: 'vpn-routing-server-identity' }, [name, ...(source ? [source] : []), badge]), result,
			]);
			input.addEventListener('change', () => {
				if (input.checked) {
					selected = server.id;
					updateActions();
				}
			});
			next.set(server.id, { input, node: row, result, badge, source, name: server.name, snapshot: server.snapshot });
		}
		rows = next;
		selected = rows.has(preferred) ? preferred : rows.has(fallback) ? fallback
			: connection && connection.state !== 'disconnected' ? '' : rows.keys().next().value || '';
		serverList.replaceChildren(...Array.from(rows.values(), row => row.node));
		probeProgress.hidden = true;
		controls.hidden = !rows.size;
		updateActions();
	}

	function setServers(data, preferred, fallback) {
		if (data) {
			if (!validServerId(data.snapshot) || !Array.isArray(data.servers) || data.servers.length > 256)
				throw new Error('invalid subscription');
			const ids = new Set();
			for (const server of data.servers) {
				if (!server || !validServerId(server.id) || !validServerName(server.name) || ids.has(server.id) || server.id === reserve?.id)
					throw new Error('invalid server');
				ids.add(server.id);
			}
		}
		subscriptionServers = data;
		renderServers(preferred, fallback);
		setStatus(listStatus, 'idle', data?.savedOnly ? 'Сохранённый сервер подписки.'
			: data?.servers.length ? 'Серверов в подписке: ' + data.servers.length
			: data ? 'В подписке нет поддерживаемых серверов.' : '');
	}

	function setConnection(data, preferReserve) {
		if (data.state !== 'disconnected' &&
		    (!['connected', 'degraded', 'restoring'].includes(data.state) ||
		     !validServerId(data.serverId) || !validServerName(data.serverName)))
			throw new Error('invalid connection state');
		const saved = data.reserve;
		if (saved && (!validServerId(saved.id) || !validServerId(saved.snapshot) || !validServerName(saved.name)
		    || subscriptionServers?.servers.some(server => server.id === saved.id)))
			throw new Error('invalid reserve');
		if ((!selected || selected === connection?.serverId) && rows.has(data.serverId))
			selected = data.serverId;
		connection = data;
		confirmed = true;
		if (typeof data.hasSubscription === 'boolean')
			hasSubscription = data.hasSubscription;
		else if (data.subscription)
			hasSubscription = true;
		if (reserve?.snapshot !== saved?.snapshot) {
			reserve = saved ? { id: saved.id, snapshot: saved.snapshot, name: saved.name } : null;
			reserveName.input.value = reserve?.name || '';
			reserveLink.input.value = '';
			renderServers(preferReserve ? reserve?.id : selected, data.serverId);
		}
		updateConnection();
	}

	function refreshWhileRestoring() {
		refreshTimer = window.setTimeout(() => {
			if (!node.isConnected)
				return;
			if (active || scan)
				refreshPending = true;
			else
				requestConnection('status');
		}, 4000);
	}

	function setProbe(id, data) {
		if (data.serverId !== id || data.method !== 'HEAD')
			throw new Error('invalid probe');
		const { httpCode, elapsedMs } = data;
		if (data.result === 'response' && Number.isInteger(httpCode) && httpCode >= 200 && httpCode <= 599 &&
		    Number.isInteger(elapsedMs) && elapsedMs >= 0 && elapsedMs <= 15000) {
			const ok = httpCode < 300;
			updateProbe(id, ok ? 'ready' : 'error', ok ? 'Доступен' : 'Недоступен',
				'HTTP ' + httpCode + ' · ' + elapsedMs + '\u00a0мс');
		} else if (data.result === 'timeout' || data.result === 'unreachable') {
			updateProbe(id, 'error', 'Недоступен', data.result === 'timeout' ? 'Время ожидания истекло' : 'Нет HTTP-ответа');
		} else {
			throw new Error('invalid probe result');
		}
	}

	function clearUrlError() {
		url.input.removeAttribute('aria-invalid');
		url.input.setAttribute('aria-describedby', url.description.id);
	}

	function clearSubscription() {
		url.input.value = '';
		restore = false;
		loadedSubscription = false;
		clearUrlError();
		setServers(null, selected, connection?.serverId);
	}

	function finishRemoval() {
		clearSubscription();
		setStatus(listStatus, 'idle', 'Подписка удалена. Вставьте новую ссылку HTTPS.');
		url.input.focus();
	}

	url.input.addEventListener('input', () => {
		if (active || scan)
			return;
		restore = false;
		loadedSubscription = false;
		clearUrlError();
		setServers(null, selected, connection?.serverId);
	});

	const actions = {
		status: ['Уточняем состояние…', 'Не удалось получить статус подключения.', 8000],
		subscription: ['Получаем список серверов…', 'Не удалось получить серверы. Проверьте ссылку и повторите запрос.', 15000],
		remove_subscription: ['Удаляем подписку…', 'Не удалось подтвердить удаление подписки.', 10000],
		save_reserve: ['Сохраняем резерв…', 'Не удалось подтвердить сохранение резерва.', 10000],
		remove_reserve: ['Удаляем резерв…', 'Не удалось подтвердить удаление резерва.', 10000],
		connect: ['Сохраняем и применяем настройки…', 'Подключение не подтверждено.', 60000],
		disconnect: ['Отключаем…', 'Отключение не подтверждено.', 25000],
		probe: ['Отправляем HTTP HEAD…', 'Не удалось выполнить проверку сервера.', 20000],
	};
	async function requestConnection(action, values = {}) {
		const probing = action === 'probe';
		const reserveMutation = action === 'save_reserve' || action === 'remove_reserve';
		if (active || (scan && !probing))
			return false;
		const [busy, failed, deadline] = actions[action];
		const target = reserveMutation ? reserveStatus : action === 'subscription' ? listStatus : status;
		const mutation = reserveMutation || action === 'connect' || action === 'disconnect' || action === 'remove_subscription';
		if (action === 'status' || mutation)
			window.clearTimeout(refreshTimer);
		const controller = new AbortController();
		const timeout = window.setTimeout(() => controller.abort(), deadline);
		let reconcile = false;
		let reportedFailure = false;
		let checked = false;
		let skipped = false;
		let retryHost;
		let failure = failed;
		active = action;
		if (action === 'status' || mutation) {
			notice.hidden = true;
			notice.textContent = '';
		}
		updateActions();
		if (probing) {
			updateProbe(values.server, 'busy', 'Проверяем…');
			probeProgress.hidden = false;
			if (!scan)
				setStatus(probeProgress, 'busy', busy);
		} else {
			setStatus(target, 'busy', action === 'connect' && values.activeServer ? 'Переключаем сервер…' : busy);
		}
		try {
			if (!L.env.token) {
				failure = 'Сессия LuCI недоступна. Откройте страницу заново.';
				throw new Error('no session');
			}
			const params = new URLSearchParams(Object.assign({ token: L.env.token }, values));
			let reply = await post(action, params, controller.signal);
			let data = await reply.json().catch(() => null);
			for (let retry = 0; probing && data?.error === 'operation_pending' && !scan?.cancelled && retry < 3; retry++) {
				await new Promise(resolve => window.setTimeout(resolve, 1000));
				if (scan?.cancelled)
					break;
				reply = await post(action, params, controller.signal);
				data = await reply.json().catch(() => null);
			}
			if (reply.status === 401 || reply.status === 403) {
				reportedFailure = true;
				failure = 'Перезайдите в LuCI и проверьте права доступа.';
				if (reply.status === 403 && action === 'subscription' && data?.ok === false && data.error === 'hwid_limit_reached')
					failure = failures.get(data.error);
				throw new Error('denied');
			}
			if (!reply.ok || data?.ok !== true) {
				reportedFailure = data?.ok === false && typeof data.error === 'string';
				if (action === 'status' && data?.error === 'operation_pending')
					refreshWhileRestoring();
				if (probing && data?.error === 'stale_snapshot')
					refreshPending = true;
				if (probing && data?.error === 'invalid_server') {
					updateProbe(values.server, 'error', 'Недоступен', failures.get(data.error));
					checked = true;
				} else if (probing && data?.error === 'probe_failed' && scan) {
					updateProbe(values.server, 'idle', 'Не проверен', failed);
					skipped = true;
				} else if (action === 'subscription' && data?.error === 'source_not_allowed' && !values.confirmHost) {
					const host = new URL(values.url).hostname;
					if (window.confirm('Разрешить загрузку подписки с домена «' + host + '»?'))
						retryHost = host;
					else
						setStatus(listStatus, 'idle', 'Загрузка подписки отменена.');
				} else {
					failure = failures.get(data?.error) || failure;
					if (action === 'connect' && data?.error === 'check_failed' && rows.has(values.server))
						updateProbe(values.server, 'error', 'Недоступен', failure);
					throw new Error('request failed');
				}
			} else if (action === 'subscription') {
				setServers(data, selected, data.preferredServerId);
				hasSubscription = true;
				loadedSubscription = true;
			} else if (probing) {
				setProbe(values.server, data);
				checked = true;
			} else {
				if ((action === 'connect' && (data.state !== 'connected' || data.serverId !== values.server)) ||
				    (action === 'disconnect' && data.state !== 'disconnected') ||
				    (action === 'remove_subscription' && (data.hasSubscription !== false || data.subscription)) ||
				    (action === 'save_reserve' && !data.reserve) ||
				    (action === 'remove_reserve' && data.reserve))
					throw new Error(failed);
				setConnection(data, action === 'save_reserve');
				if (reserveMutation)
					setStatus(reserveStatus, 'ready', action === 'save_reserve' ? 'Резерв сохранён.' : 'Резерв удалён.');
				if (action === 'connect' && rows.has(values.server))
					updateProbe(values.server, 'ready', 'Доступен', 'Контрольный HTTP HEAD при подключении');
				if (action === 'remove_subscription') {
					finishRemoval();
				} else if (action === 'status' && data.hasSubscription === false && loadedSubscription) {
					clearSubscription();
				}
				if (data.state === 'restoring')
					refreshWhileRestoring();
				if (action === 'status' && data.subscription) {
					const savedUrl = subscriptionUrl(data.subscription.url);
					if (savedUrl && savedUrl !== url.input.value &&
					    (data.state !== 'disconnected' || (restore && !url.input.value))) {
						url.input.value = savedUrl;
						restore = false;
						loadedSubscription = true;
						clearUrlError();
						setServers(null, selected, data.serverId);
					}
					if (savedUrl === url.input.value && data.subscription.snapshot && data.subscription.snapshot !== subscriptionServers?.snapshot) {
						try {
							setServers(data.subscription, selected, data.serverId);
							loadedSubscription = true;
						} catch {
							setStatus(listStatus, 'error', 'Получите список серверов заново.');
						}
					}
				}
			}
		} catch (error) {
			const message = error.name === 'AbortError' ? 'LuCI не ответил вовремя.' : failure;
			if (probing) {
				updateProbe(values.server, 'idle', 'Не проверен', message);
				setStatus(probeProgress, 'error', scan ? scan.progress + ' ' + message : message);
			} else if (target === status) {
				confirmed = false;
				updateConnection();
				notice.hidden = false;
				notice.textContent = message;
				reconcile = mutation;
			} else {
				setStatus(target, 'error', message);
				reconcile = reserveMutation;
			}
		} finally {
			window.clearTimeout(timeout);
			active = '';
			updateActions();
		}
		if (retryHost)
			return requestConnection('subscription', { url: values.url, confirmHost: retryHost });
		if (!scan && (reconcile || refreshPending)) {
			refreshPending = false;
			const message = notice.textContent;
			await requestConnection('status');
			if (reconcile && confirmed && !reserveMutation) {
				if (action === 'remove_subscription' && connection.hasSubscription === false && !connection.subscription) {
					finishRemoval();
				} else if (action === 'connect' && !reportedFailure &&
				           connection.state === 'connected' && connection.serverId === values.server) {
					if (rows.has(values.server))
						updateProbe(values.server, 'ready', 'Доступен', 'Контрольный HTTP HEAD при подключении');
				} else {
					notice.hidden = false;
					notice.textContent = message;
				}
			}
		}
		if (checked && !scan)
			setStatus(probeProgress, 'idle', 'Проверка HEAD завершена.');
		return checked ? 'checked' : skipped ? 'skipped' : false;
	}

	async function checkServers() {
		if (scan) {
			scan.cancelled = true;
			setStatus(probeProgress, 'busy', 'Остановим проверку после текущего сервера.');
			updateActions();
			return;
		}
		if (active || !rows.size)
			return;
		const ids = [...rows.keys()];
		scan = { cancelled: false, progress: '' };
		let count = 0;
		let skipped = 0;
		const progress = () => 'Проверено ' + count + ' из ' + ids.length + '.' +
			(skipped ? ' Без результата: ' + skipped + '.' : '');
		probeProgress.hidden = false;
		for (const id of ids)
			updateProbe(id, 'idle', 'Не проверен');
		try {
			for (const id of ids) {
				if (scan.cancelled || !node.isConnected)
					break;
				scan.progress = progress();
				setStatus(probeProgress, 'busy', scan.progress);
				const result = await requestConnection('probe', { snapshot: rows.get(id).snapshot, server: id });
				if (!result)
					break;
				if (result === 'checked')
					count++;
				else
					skipped++;
			}
			if (scan.cancelled)
				setStatus(probeProgress, 'idle', 'Проверка остановлена. ' + progress());
			else if (count + skipped === ids.length)
				setStatus(probeProgress, 'idle', progress());
		} finally {
			scan = null;
			updateActions();
		}
		if (refreshPending && node.isConnected) {
			refreshPending = false;
			requestConnection('status');
		}
	}

	form.addEventListener('submit', event => {
		event.preventDefault();
		if (active || scan)
			return;
		restore = false;
		const value = subscriptionUrl(url.input.value.trim());
		if (!value) {
			listStatus.textContent = 'Вставьте полную ссылку HTTPS без пробелов.';
			url.input.setAttribute('aria-invalid', 'true');
			url.input.setAttribute('aria-describedby', url.description.id + ' ' + listStatus.id);
			url.input.focus();
			return;
		}
		clearUrlError();
		url.input.value = value;
		requestConnection('subscription', { url: value });
	});
	removeSubscription.addEventListener('click', () => {
		if (canRemoveSubscription() &&
		    window.confirm('Удалить ссылку подписки и список серверов с роутера?'))
			requestConnection('remove_subscription');
	});
	reserveForm.addEventListener('submit', event => {
		event.preventDefault();
		const name = reserveName.input.value.trim();
		const link = reserveLink.input.value.trim();
		reserveName.input.value = '';
		reserveLink.input.value = '';
		if (saveReserve.disabled)
			return;
		if (!validServerName(name) || new TextEncoder().encode(name).length > 160) {
			setStatus(reserveStatus, 'error', failures.get('invalid_reserve_name'));
			reserveName.input.focus();
		} else if (link.length > 8192 || !link.startsWith('vless://') || /[\r\n]/.test(link)) {
			setStatus(reserveStatus, 'error', 'Вставьте одну полную ссылку VLESS.');
			reserveLink.input.focus();
		} else {
			requestConnection('save_reserve', { name, link, ...(reserve ? { snapshot: reserve.snapshot } : {}) });
		}
	});
	removeReserve.addEventListener('click', () => {
		if (reserve && !removeReserve.disabled && window.confirm('Удалить резервный сервер с роутера?'))
			requestConnection('remove_reserve', { snapshot: reserve.snapshot });
	});
	connect.addEventListener('click', () => {
		if (!confirmed)
			return;
		const snapshot = rows.get(selected)?.snapshot;
		if (switching())
			requestConnection('connect', { snapshot, server: selected, activeServer: connection.serverId });
		else if (connection.state !== 'disconnected')
			requestConnection('disconnect');
		else if (rows.has(selected))
			requestConnection('connect', { snapshot, server: selected });
	});
	check.addEventListener('click', () => {
		if (rows.has(selected))
			requestConnection('probe', { snapshot: rows.get(selected).snapshot, server: selected });
	});
	checkAll.addEventListener('click', checkServers);
	refresh.addEventListener('click', () => requestConnection('status'));
	requestConnection('status');

	return {
		node,
		refresh() {
			if (active || scan)
				refreshPending = true;
			else
				requestConnection('status');
		},
	};
}

function validDevice(value) {
	return typeof value === 'string' && /^[a-zA-Z][a-zA-Z0-9_.-]{0,14}$/.test(value) && value !== 'lo';
}

function validIPv4(value) {
	return typeof value === 'string' && /^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$/.test(value) &&
		value.split('.').every(octet => Number(octet) <= 255);
}

function labelText(value) {
	return typeof value === 'string'
		? value.replace(/[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]/g, '').trim().slice(0, 96) : '';
}

function validRoutingRules(rules) {
	if (!Array.isArray(rules) || rules.length === 0 || rules.length > GROUPS.length * 2)
		return false;

	let position = -1;
	for (const rule of rules) {
		const group = GROUPS.findIndex(({ tag }) => tag === rule?.tag);
		if (group < 0 || !['domain', 'ip'].includes(rule.kind) || !Array.isArray(rule.values) ||
		    rule.values.length === 0 || rule.values.length > 512 || !rule.values.every(value =>
		        typeof value === 'string' && value.length > 0 && value.length <= 512 && !/[^!-~]/.test(value)))
			return false;
		const next = group * 2 + (rule.kind === 'ip' ? 1 : 0);
		if (next <= position)
			return false;
		position = next;
	}
	return true;
}

function readSettings(data) {
	if (typeof data.editable !== 'boolean' || !Array.isArray(data.networks) || data.networks.length > 128 ||
	    (data.routing != null && (!['happ', 'incy'].includes(data.routing.source) ||
	     (data.routing.managedGeo !== undefined && data.routing.managedGeo !== true))))
		throw new Error('invalid settings');
	const routing = data.routingStatus;
	if (routing != null && (!['applied', 'default', 'inactive', 'unverified'].includes(routing.state) ||
	    (routing.state === 'applied' && (!data.routing || !routing.counts)) ||
	    (routing.counts != null && (!data.routing || !GROUPS.every(({ tag }) =>
	        Number.isSafeInteger(routing.counts[tag]) && routing.counts[tag] >= 0)))))
		throw new Error('invalid routing status');
	if (routing?.rules !== undefined && (!data.routing || routing.state === 'default' || !validRoutingRules(routing.rules)))
		delete routing.rules;
	if (data.capture != null) {
		const { interface: device, mode = 'selected', sources } = data.capture;
		if (!validDevice(device) || !['all', 'selected'].includes(mode) ||
		    (mode === 'all' ? sources !== undefined : !Array.isArray(sources) ||
		     !sources.length || sources.length > SOURCE_LIMIT || !sources.every(validIPv4)))
			throw new Error('invalid capture settings');
		data.capture = { ...data.capture, mode };
	}
	const devices = new Set();
	for (const network of data.networks) {
		if (!network || !validDevice(network.device) || devices.has(network.device) || !Array.isArray(network.clients) ||
		    network.clients.length > 256 || !network.clients.every(client => client && validIPv4(client.address)))
			throw new Error('invalid networks');
		devices.add(network.device);
	}
	return data;
}

function capturePanel(saveCapture, refreshSettings) {
	const modeHint = text('p', 'vpn-routing-hint', '', { id: PREFIX + 'mode-help' });
	const mode = E('select', {
		id: PREFIX + 'mode', class: 'vpn-routing-field vpn-routing-server-select', 'aria-describedby': modeHint.id,
	}, [
		text('option', '', 'Вся локальная сеть', { value: 'all' }),
		text('option', '', 'Только выбранные устройства', { value: 'selected' }),
	]);
	const network = E('select', { id: PREFIX + 'network', class: 'vpn-routing-field vpn-routing-server-select', required: '' });
	const client = E('select', { id: PREFIX + 'client', class: 'vpn-routing-field vpn-routing-server-select' });
	const add = text('button', 'vpn-routing-button', 'Добавить', { type: 'button' });
	const refresh = text('button', 'vpn-routing-button', 'Обновить список', { type: 'button' });
	const save = text('button', 'vpn-routing-button vpn-routing-primary', 'Сохранить режим', { type: 'submit' });
	const sources = field('sources', 'IPv4-адреса устройств', {
		rows: 2, placeholder: '192.168.1.50',
		help: 'Добавьте устройства из списка или введите их IPv4-адреса через пробел или с новой строки.',
	});
	sources.input.maxLength = 512;
	const feedback = text('p', 'vpn-routing-status', '', {
		id: PREFIX + 'capture-status', role: 'status', 'aria-atomic': 'true', hidden: '',
	});
	network.setAttribute('aria-errormessage', feedback.id);
	sources.input.setAttribute('aria-errormessage', feedback.id);
	const fields = E('div', { class: 'vpn-routing-device-fields' }, [
		E('div', { class: 'vpn-routing-form-field' }, [text('label', 'vpn-routing-label', 'Режим', { for: mode.id }), mode]),
		E('div', { class: 'vpn-routing-form-field' }, [text('label', 'vpn-routing-label', 'Интерфейс LAN', { for: network.id }), network]),
	]);
	const deviceFields = E('div', { class: 'vpn-routing-device-fields', hidden: '' }, [
		E('div', { class: 'vpn-routing-form-field' }, [
			text('label', 'vpn-routing-label', 'Устройство из списка DHCP', { for: client.id }),
			E('div', { class: 'vpn-routing-device-picker' }, [client, add]),
		]), sources.node,
	]);
	const node = E('form', { class: 'vpn-routing-pane vpn-routing-devices', novalidate: '', 'aria-labelledby': PREFIX + 'device-title' }, [
		E('div', { class: 'vpn-routing-section-heading' }, [text('h2', '', 'Проксирование', { id: PREFIX + 'device-title' }), refresh]),
		fields, modeHint, deviceFields, E('div', { class: 'vpn-routing-actions' }, [save]), feedback,
	]);
	let networks = [];
	let changed = false;
	let editable = false;
	const selected = () => networks.find(item => item.device === network.value);
	const addresses = () => sources.input.value.trim().split(/\s+/).filter(Boolean);

	function syncControls() {
		const selectedMode = mode.value === 'selected';
		const writable = editable && networks.length > 0;
		deviceFields.hidden = !selectedMode;
		modeHint.textContent = selectedMode
			? 'Правила VPN Routing действуют для указанных IPv4-адресов.'
			: 'Правила VPN Routing действуют для всех устройств этой сети, включая новые. Локальный доступ сохраняется.';
		mode.disabled = network.disabled = save.disabled = !writable;
		sources.input.required = selectedMode;
		sources.input.disabled = !writable || !selectedMode;
		client.disabled = !writable || !selectedMode || !selected()?.clients.length;
		add.disabled = client.disabled || !client.value;
	}

	function syncClients() {
		const list = selected()?.clients || [];
		client.replaceChildren(text('option', '', list.length ? 'Выберите устройство' : 'Устройства DHCP не найдены', { value: '' }),
			...list.map(item => {
				const name = labelText(item.name);
				return text('option', '', name ? name + ' · ' + item.address : item.address, { value: item.address });
			}));
		syncControls();
	}

	function edited() {
		changed = true;
		network.removeAttribute('aria-invalid');
		sources.input.removeAttribute('aria-invalid');
		if (feedback.hidden || feedback.dataset.state !== 'idle') {
			feedback.hidden = false;
			setStatus(feedback, 'idle', 'Есть несохранённые изменения.');
		}
	}

	mode.addEventListener('change', () => {
		edited();
		syncControls();
	});
	network.addEventListener('change', () => {
		edited();
		syncClients();
	});
	client.addEventListener('change', () => { add.disabled = client.disabled || !client.value; });
	sources.input.addEventListener('input', edited);
	add.addEventListener('click', () => {
		if (client.disabled || !client.value)
			return;
		const next = new Set(addresses());
		if (next.has(client.value))
			return;
		next.add(client.value);
		if (next.size > SOURCE_LIMIT) {
			feedback.hidden = false;
			setStatus(feedback, 'error', 'Можно указать до ' + SOURCE_LIMIT + ' адресов.');
			return;
		}
		sources.input.value = Array.from(next).join('\n');
		edited();
	});
	refresh.addEventListener('click', refreshSettings);
	node.addEventListener('submit', event => {
		event.preventDefault();
		if (!editable)
			return;
		if (!selected()) {
			feedback.hidden = false;
			setStatus(feedback, 'error', 'Выберите доступный интерфейс LAN.');
			network.setAttribute('aria-invalid', 'true');
			network.focus();
			return;
		}
		const payload = { interface: network.value, mode: mode.value };
		if (mode.value === 'selected') {
			const values = Array.from(new Set(addresses()));
			if (!values.length || values.length > SOURCE_LIMIT || !values.every(validIPv4)) {
				feedback.hidden = false;
				setStatus(feedback, 'error', 'Укажите от 1 до ' + SOURCE_LIMIT + ' IPv4-адресов устройств.');
				sources.input.setAttribute('aria-invalid', 'true');
				sources.input.focus();
				return;
			}
			payload.sources = values.join(' ');
		}
		saveCapture(payload);
	});

	return {
		node, feedback,
		update(data, reset) {
			networks = data.networks;
			const useSaved = reset || !changed;
			const current = useSaved ? data.capture?.interface || 'br-lan' : network.value;
			network.replaceChildren(text('option', '', 'Выберите интерфейс', { value: '' }),
				...networks.map(item => {
					const label = labelText(item.label);
					return text('option', '', label && label !== item.device ? label + ' · ' + item.device : item.device,
						{ value: item.device });
				}));
			if (current && !networks.some(item => item.device === current))
				network.appendChild(text('option', '', current + ' · недоступен', { value: current, disabled: '' }));
			network.value = current;
			if (useSaved) {
				mode.value = data.capture?.mode || 'all';
				sources.input.value = (data.capture?.sources || []).join('\n');
				changed = false;
			}
			syncClients();
		},
		setControls(writable, busy) {
			editable = writable;
			syncControls();
			refresh.disabled = busy;
		},
	};
}

function hwidPanel() {
	const help = 'VPN Routing передаёт этот идентификатор при получении подписки.';
	const hwid = field('hwid', 'HWID', { placeholder: '—', help });
	hwid.input.readOnly = true;
	hwid.description.setAttribute('role', 'status');
	hwid.description.setAttribute('aria-atomic', 'true');
	const copy = text('button', 'vpn-routing-button', 'Копировать', {
		type: 'button', 'aria-label': 'Копировать HWID', disabled: '',
	});
	copy.addEventListener('click', async () => {
		const value = hwid.input.value;
		if (!value)
			return;
		let copied = false;
		try {
			if (navigator.clipboard?.writeText) {
				await navigator.clipboard.writeText(value);
				copied = true;
			}
		} catch {
			// Keep manual copying available when the browser denies clipboard access.
		}
		if (hwid.input.value !== value)
			return;
		if (!copied) {
			hwid.input.focus();
			hwid.input.select();
			try {
				copied = document.execCommand('copy');
			} catch {
				// The selected field is still available for manual copying.
			}
			if (copied)
				copy.focus();
		}
		hwid.description.textContent = copied ? 'HWID скопирован.'
			: 'HWID выделен. Скопируйте его вручную.';
	});
	return {
		node: E('section', { class: 'vpn-routing-pane vpn-routing-devices', 'aria-labelledby': PREFIX + 'hwid-title' }, [
			text('h2', '', 'Идентификатор роутера', { id: PREFIX + 'hwid-title' }),
			hwid.node, E('div', { class: 'vpn-routing-actions' }, [copy]),
		]),
		update(value, busy) {
			const id = typeof value === 'string' && /^[0-9a-f]{32}$/.test(value) ? value : '';
			if (id && hwid.input.value === id)
				return;
			hwid.input.value = id;
			copy.disabled = !id;
			hwid.description.textContent = id ? help
				: busy ? 'Загружаем HWID…' : 'HWID недоступен. Обновите настройки.';
		},
	};
}

function routingRuleGroups(rules) {
	return GROUPS.map(({ tag, title }) => {
		const conditions = rules.filter(rule => rule.tag === tag).flatMap(({ kind, values }) => [
			text('p', 'vpn-routing-hint', kind === 'domain' ? 'Домены' : 'IP-адреса и сети'),
			E('ul', {}, values.map(value => E('li', {}, [text('code', '', value)]))),
		]);
		return E('section', { class: 'vpn-routing-route-group', 'data-route': tag }, [
			text('h3', 'vpn-routing-route-title', title),
			...(conditions.length ? conditions : [text('p', 'vpn-routing-hint', 'Отдельных условий нет.')]),
		]);
	});
}

function routingOverview(editor, refreshSettings) {
	const heading = text('h2', '', 'Маршрутизация', { id: PREFIX + 'route-title' });
	const refresh = text('button', 'vpn-routing-button', 'Обновить статус', { type: 'button' });
	const status = text('p', 'vpn-routing-status', 'Загружаем статус маршрутизации…', {
		role: 'status', 'aria-atomic': 'true', 'data-state': 'busy',
	});
	const hint = text('p', 'vpn-routing-hint', '', { hidden: '' });
	const geodata = text('p', 'vpn-routing-hint', '', { hidden: '' });
	const counts = E('div', { class: 'vpn-routing-actions', 'aria-label': 'Условия профиля', hidden: '' });
	const rulesTitle = text('summary', '', '');
	const ruleGroups = E('div', {
		class: 'vpn-routing-advanced-body', tabindex: '0', role: 'region', 'aria-label': 'Условия по направлениям',
	});
	const rules = E('details', {
		class: 'vpn-routing-advanced vpn-routing-rules', id: PREFIX + 'current-rules', hidden: '',
	}, [rulesTitle, ruleGroups]);
	const remainder = text('p', 'vpn-routing-hint', '', { hidden: '' });
	const manual = E('details', { class: 'vpn-routing-advanced', id: PREFIX + 'manual-routing' }, [
		text('summary', '', 'Ручной импорт Happ или INCY'),
		E('div', { class: 'vpn-routing-advanced-body' }, [editor]),
	]);
	let displayedRules;
	refresh.addEventListener('click', refreshSettings);
	return {
		node: E('section', { class: 'vpn-routing-pane vpn-routing-devices', 'aria-labelledby': heading.id }, [
			E('div', { class: 'vpn-routing-section-heading' }, [heading, refresh]),
			status, hint, counts, rules, remainder, geodata, manual,
		]),
		update(settings, busy) {
			const saved = settings?.routing?.source;
			const source = saved === 'happ' ? 'Happ' : 'INCY';
			const runtime = settings?.routingStatus;
			let label = busy ? 'Загружаем статус маршрутизации…' : 'Статус маршрутизации недоступен';
			let detail = '', kind = busy ? 'busy' : 'empty';
			if (runtime?.state === 'applied') {
				label = 'Правила ' + source + ' применены';
				detail = 'Условия действуют для перехваченного трафика.';
				kind = 'ready';
			} else if (runtime?.state === 'default') {
				label = 'Весь перехваченный внешний трафик идёт через VPN';
				detail = 'Роутер и локальные адреса доступны напрямую.';
				kind = 'ready';
			} else if (runtime?.state === 'inactive') {
				label = saved ? 'Профиль ' + source + ' сохранён' : 'VPN отключён';
				detail = saved ? 'VPN отключён. Правила будут использованы при подключении.'
					: 'При подключении перехваченный трафик пойдёт через выбранный сервер.';
			} else if (runtime?.state === 'unverified') {
				label = 'Применение правил пока не подтверждено';
				detail = saved ? 'Сохранён профиль ' + source + '. Проверьте статус подключения.'
					: 'Проверьте статус подключения и обновите данные.';
				kind = 'warning';
			}
			if (label !== status.textContent || kind !== status.dataset.state)
				setStatus(status, kind, label);
			hint.hidden = !detail;
			hint.textContent = detail;
			counts.hidden = !runtime?.counts;
			counts.replaceChildren(...(runtime?.counts ? GROUPS.map(({ tag, title }) =>
				text('span', 'vpn-routing-scope', title + ' · ' + runtime.counts[tag])) : []));
			if (runtime?.rules !== displayedRules) {
				displayedRules = runtime?.rules;
				ruleGroups.replaceChildren(...(displayedRules ? [
					text('p', 'vpn-routing-hint', 'Срабатывает первое подходящее правило.'),
					...routingRuleGroups(displayedRules),
				] : []));
			}
			rules.hidden = !displayedRules;
			rulesTitle.textContent = runtime?.state === 'applied' ? 'Действующие правила' : 'Сохранённые правила';
			remainder.hidden = !runtime?.counts && !displayedRules;
			remainder.textContent = runtime?.state === 'applied' ? 'Остальной перехваченный трафик идёт через VPN.'
				: 'При применении профиля остальной перехваченный трафик пойдёт через VPN.';
			geodata.hidden = settings?.routing?.managedGeo !== true;
			geodata.textContent = runtime?.state === 'applied' ? 'Xray загрузил базы GeoIP и GeoSite.'
				: 'Для профиля выбраны базы GeoIP и GeoSite.';
			refresh.disabled = busy;
		},
	};
}

function readDnsSettings(data) {
	if (!['system', ...DNS_PROFILES.map(({ id }) => id)].includes(data.profile) ||
	    typeof data.encryptedAvailable !== 'boolean' ||
	    (data.configurable !== undefined && typeof data.configurable !== 'boolean') ||
	    !Array.isArray(data.addresses) || data.addresses.length > 16 ||
	    !data.addresses.every(value => typeof value === 'string' && value.length <= 512 && !/[\x00-\x20\x7f]/.test(value)) ||
	    (data.address !== undefined && (typeof data.address !== 'string' || data.address.length > 512)) ||
	    (data.bootstrap !== undefined && !validIPv4(data.bootstrap)))
		throw new Error('invalid DNS settings');
	return data;
}

function dnsPanel(request) {
	const heading = text('h2', '', 'Локальный DNS', { id: PREFIX + 'dns-title' });
	const current = text('p', 'vpn-routing-status', 'Загружаем текущий DNS…', {
		role: 'status', 'aria-atomic': 'true', 'data-state': 'busy',
	});
	const servers = E('ul', { class: 'vpn-routing-dns-addresses', 'aria-label': 'Действующие DNS-серверы', hidden: '' });
	const help = text('p', 'vpn-routing-hint', '', { id: PREFIX + 'dns-help', hidden: '' });
	const selection = E('select', {
		id: PREFIX + 'dns-profile', class: 'vpn-routing-field vpn-routing-server-select', 'aria-describedby': help.id,
	}, [
		text('option', '', 'Выберите DNS-сервер', { value: '' }),
		...DNS_PROFILES.map(({ id, label }) => text('option', '', label, { value: id })),
	]);
	const address = field('dns-address', 'Адрес сервера', {
		placeholder: '77.88.8.8 или https://…/dns-query',
		help: 'Поддерживаются IPv4, IPv4#порт и адреса с префиксом https://, tls:// или quic://.',
	});
	address.input.maxLength = 512;
	const bootstrap = field('dns-bootstrap', 'IPv4 для первого запроса', {
		placeholder: '1.1.1.1', help: 'Необязательно. Нужен для разрешения имени зашифрованного сервера.',
	});
	bootstrap.input.maxLength = 15;
	bootstrap.input.inputMode = 'decimal';
	const apply = text('button', 'vpn-routing-button vpn-routing-primary', 'Сохранить и применить DNS', { type: 'submit' });
	const check = text('button', 'vpn-routing-button', 'Проверить текущий DNS', { type: 'button' });
	const reload = text('button', 'vpn-routing-button', 'Обновить DNS', { type: 'button', hidden: '' });
	const feedback = text('p', 'vpn-routing-status', '', { role: 'status', 'aria-atomic': 'true', hidden: '' });
	const node = E('form', { class: 'vpn-routing-pane vpn-routing-devices', 'aria-labelledby': heading.id }, [
		heading, current, servers,
		text('p', 'vpn-routing-hint', 'Роутер использует этот сервер для запросов от устройств, которые получают DNS от OpenWrt.'),
		E('div', { class: 'vpn-routing-form-field' }, [text('label', 'vpn-routing-label', 'DNS-сервер', { for: selection.id }), selection]),
		help, address.node, bootstrap.node, E('div', { class: 'vpn-routing-actions' }, [apply, check, reload]), feedback,
	]);
	let value = null, busy = true, changed = false;
	const custom = () => selection.value === 'custom';
	const encrypted = () => /^(?:https|tls|quic):\/\//.test(address.input.value.trim());
	function sync() {
		const editable = !busy && value && value.configurable !== false;
		const profile = DNS_PROFILES.find(({ id }) => id === selection.value);
		const hasProxy = value?.encryptedAvailable === true;
		selection.disabled = !editable;
		for (const option of selection.options)
			option.disabled = !hasProxy && DNS_PROFILES.some(({ id, encrypted }) => id === option.value && encrypted);
		address.node.hidden = !custom();
		address.input.disabled = !editable || !custom();
		address.input.required = custom();
		bootstrap.node.hidden = !custom() || !encrypted();
		bootstrap.input.disabled = !editable || bootstrap.node.hidden;
		apply.disabled = !editable || !profile || ((profile.encrypted || (custom() && encrypted())) && !hasProxy);
		check.disabled = busy || !value;
		reload.hidden = !!value && value.configurable !== false;
		reload.disabled = busy;
		const message = value?.reason === 'dns_unavailable' ? 'Проверьте службу dnsmasq и обновите данные.'
			: value?.configurable === false ? 'Эту конфигурацию можно изменить в настройках OpenWrt.'
			: value && !hasProxy ? 'Для DoH, DoT и DoQ установите пакет dnsproxy из репозитория OpenWrt.' : '';
		help.hidden = !message;
		help.textContent = message;
	}
	function edited() {
		changed = true;
		feedback.hidden = true;
		sync();
	}
	selection.addEventListener('change', edited);
	address.input.addEventListener('input', edited);
	bootstrap.input.addEventListener('input', edited);
	check.addEventListener('click', () => request('check_dns'));
	reload.addEventListener('click', () => request('dns_settings'));
	node.addEventListener('submit', event => {
		event.preventDefault();
		if (apply.disabled)
			return;
		const values = { profile: selection.value };
		if (custom()) {
			values.address = address.input.value.trim();
			if (!bootstrap.node.hidden && bootstrap.input.value.trim())
				values.bootstrap = bootstrap.input.value.trim();
		}
		request('apply_dns', values);
	});
	sync();
	return {
		node, feedback,
		setBusy(active) {
			busy = active;
			sync();
		},
		update(data, applied = false) {
			value = data;
			if (applied)
				changed = false;
			const profile = DNS_PROFILES.find(({ id }) => id === data?.profile);
			if (!changed) {
				selection.value = profile?.id || '';
				address.input.value = data?.address || '';
				bootstrap.input.value = data?.bootstrap || '';
			}
			const known = data && (profile || data.addresses.length || data.configurable !== false);
			setStatus(current, known ? 'empty' : 'warning', profile ? 'Сейчас используется ' + profile.label
				: known ? 'DNS из настроек OpenWrt' : 'Текущий DNS не удалось определить');
			servers.replaceChildren(...(data?.addresses || []).map(item => text('li', '', item)));
			servers.hidden = !data?.addresses.length;
			sync();
		},
	};
}

function settingsPanel(routing, refreshConnection) {
	const identity = hwidPanel();
	const capture = capturePanel(values => request('save_capture', values), () => request('settings'));
	const overview = routingOverview(routing.node, () => request('settings'));
	const dns = dnsPanel(request);
	const errors = new Map(Object.entries({
		settings_busy: 'Отключите VPN Routing, чтобы сохранить настройки.',
		operation_pending: 'VPN Routing ещё выполняет операцию. Подождите и обновите настройки.',
		settings_unavailable: 'Не удалось получить список сетей. Обновите список.',
		capture_policy: 'Проверьте интерфейс LAN и, если выбран отдельный список устройств, их IPv4-адреса.',
		policy_invalid: 'LuCI не смог прочитать сохранённые настройки VPN Routing.',
		routing_invalid: 'Профиль не подходит для подключения VPN Routing. Проверьте правила.',
		routing_assets: 'Проверьте файлы геоданных на роутере и их контрольные суммы.',
		routing_assets_download: 'Не удалось скачать геоданные. Проверьте интернет на роутере и повторите сохранение.',
		routing_assets_invalid: 'Контрольная сумма геоданные не совпала. Повторите загрузку позже.',
		routing_check_failed: 'Xray отклонил правила. Проверьте профиль и повторите.',
		dependency_missing: 'На роутере отсутствует один из компонентов VPN Routing.',
		storage_error: 'LuCI не смог сохранить настройки. Повторите попытку.',
		request_too_large: 'Сократите входные данные и повторите попытку.',
		too_large: 'Сократите входные данные и повторите попытку.',
		dns_invalid: 'Проверьте адрес DNS-сервера и IPv4 для первого запроса.',
		dns_conflict: 'DNS уже управляется другой настройкой OpenWrt. Проверьте DHCP и DNS.',
		dns_unavailable: 'Локальный DNS OpenWrt недоступен. Проверьте службу dnsmasq.',
		dns_dependency: 'Для выбранного сервера требуется пакет dnsproxy.',
		dns_check_failed: 'DNS-сервер не ответил на контрольный запрос. Проверьте адрес и доступность.',
		dns_apply_failed: 'DNS не удалось применить. Предыдущая конфигурация восстановлена.',
		dns_rollback_failed: 'Не удалось подтвердить восстановление DNS. Проверьте настройки OpenWrt.',
	}));
	let settings = null;
	let busy = false;
	let refreshPending = false;
	let dnsRefreshPending = false;
	routing.bind(values => request('save_routing', values));
	updateControls();

	function updateControls() {
		capture.setControls(settings?.editable === true && !busy, busy);
		identity.update(settings?.hwid, busy);
		routing.update(settings, busy);
		overview.update(settings, busy);
		dns.setBusy(busy);
	}

	async function request(action, values = {}) {
		if (busy) {
			if (action === 'settings')
				refreshPending = true;
			if (action === 'dns_settings')
				dnsRefreshPending = true;
			return;
		}
		const reading = action === 'settings';
		const savingRouting = action === 'save_routing';
		const isDns = DNS_ACTIONS.has(action);
		const dnsMessages = {
			dns_settings: ['Загружаем DNS…', 'Не удалось получить текущий DNS. Обновите данные.'],
			check_dns: ['Проверяем текущий DNS…', 'Не удалось проверить DNS. Повторите запрос.'],
			apply_dns: ['Проверяем и применяем DNS…', 'Не удалось подтвердить применение DNS. Обновите данные.'],
		};
		const target = isDns ? dns.feedback : savingRouting ? routing.feedback : capture.feedback;
		const controller = new AbortController();
		const timeout = window.setTimeout(() => controller.abort(), isDns || savingRouting ? 45000 : 10000);
		let failure = isDns ? dnsMessages[action][1] : reading ? 'Не удалось загрузить настройки. Обновите список.'
			: 'Не удалось подтвердить сохранение. Обновите настройки.';
		let unknownDns = action === 'apply_dns';
		target.hidden = false;
		setStatus(target, 'busy', isDns ? dnsMessages[action][0] : reading ? 'Загружаем настройки…'
			: savingRouting ? 'Проверяем и сохраняем правила…' : 'Сохраняем настройки…');
		updateControls();
		try {
			if (!L.env.token) {
				failure = 'Сессия LuCI недоступна. Откройте страницу заново.';
				throw new Error('no session');
			}
			const body = new URLSearchParams(values);
			body.set('token', L.env.token);
			const reply = await post(action, body, controller.signal);
			if (reply.status === 401 || reply.status === 403) {
				failure = 'Перезайдите в LuCI и проверьте права доступа.';
				throw new Error('denied');
			}
			if (reply.status === 413) {
				failure = errors.get('request_too_large');
				throw new Error('too large');
			}
			const data = await reply.json();
			if (!reply.ok || data?.ok !== true) {
				failure = errors.get(data?.error) || failure;
				if (!isDns && (data?.error === 'settings_busy' || data?.error === 'operation_pending'))
					refreshPending = !reading;
				unknownDns = unknownDns && (!data?.error || data.error === 'dns_rollback_failed' || data.error === 'internal_error');
				throw new Error('settings request failed');
			}
			if (isDns) {
				const effective = readDnsSettings(data);
				if (action !== 'dns_settings' && effective.checked !== true)
					throw new Error('missing DNS response');
				dns.update(effective, action === 'apply_dns');
				target.hidden = action === 'dns_settings';
				if (action !== 'dns_settings')
					setStatus(target, 'ready', action === 'check_dns' ? 'DNS ответил на контрольный запрос.'
						: 'DNS сохранён и применён.');
				return;
			}
			settings = readSettings(data);
			capture.update(settings, action === 'save_capture');
			if (reading) {
				const message = !settings.editable ? errors.get('settings_busy')
					: !settings.networks.length ? 'Нет доступных интерфейсов LAN. Проверьте сеть и обновите список.'
					: !settings.networks.some(item => item.device === (settings.capture?.interface || 'br-lan'))
						? 'Текущий интерфейс LAN недоступен. Выберите доступную сеть.' : '';
				target.hidden = !message;
				if (message)
					setStatus(target, 'warning', message);
			} else {
				const message = savingRouting && !settings.routing ? 'Сохранённые правила убраны.'
					: 'Настройки сохранены. Они вступят в силу при следующем подключении.';
				setStatus(target, 'ready', message);
				if (action === 'save_capture')
					refreshConnection();
			}
		} catch (error) {
			if (!isDns && (reading || refreshPending || error.name === 'AbortError'))
				settings = null;
			if (action === 'dns_settings' || unknownDns)
				dns.update(null);
			setStatus(target, 'error', error.name === 'AbortError' && !isDns
				? 'LuCI не ответил вовремя. Обновите настройки.' : failure);
		} finally {
			window.clearTimeout(timeout);
			busy = false;
			updateControls();
			if (refreshPending) {
				refreshPending = false;
				request('settings');
			} else if (dnsRefreshPending) {
				dnsRefreshPending = false;
				request('dns_settings');
			}
		}
	}

	return {
		node: E('div', { class: 'vpn-routing-settings' }, [overview.node, dns.node, capture.node, identity.node]),
		async refresh() {
			await request('settings');
			await request('dns_settings');
		},
	};
}

function application(routing) {
	const hint = text('p', 'vpn-routing-hint', '');
	const connection = connectionPanel();
	const settings = settingsPanel(routing, connection.refresh);
	const tabs = [
		{ key: 'connection', title: 'Подключение', hint: 'Выберите сервер подписки или сохранённый резерв.', content: connection.node },
		{ key: 'settings', title: 'Настройки', hint: 'Маршрутизация, локальный DNS и устройства в сети.', content: settings.node },
	];
	const tablist = E('div', { class: 'vpn-routing-tabs', role: 'tablist', 'aria-label': 'Разделы VPN Routing' });

	function selectTab(index, focus) {
		tabs.forEach((tab, position) => {
			const selected = position === index;
			tab.button.setAttribute('aria-selected', selected ? 'true' : 'false');
			tab.button.tabIndex = selected ? 0 : -1;
			tab.panel.hidden = !selected;
		});
		hint.textContent = tabs[index].hint;
		if (tabs[index].key === 'settings')
			settings.refresh();
		if (focus)
			tabs[index].button.focus();
	}

	tabs.forEach((tab, index) => {
		const tabId = PREFIX + 'tab-' + tab.key;
		const panelId = PREFIX + 'panel-' + tab.key;
		tab.button = text('button', 'vpn-routing-tab', tab.title, {
			id: tabId, type: 'button', role: 'tab', 'aria-controls': panelId,
		});
		tab.panel = E('div', { id: panelId, role: 'tabpanel', 'aria-labelledby': tabId }, [tab.content]);
		tab.button.addEventListener('click', () => selectTab(index, false));
		tab.button.addEventListener('keydown', event => {
			let next;
			if (event.key === 'ArrowLeft' || event.key === 'ArrowRight')
				next = 1 - index;
			else if (event.key === 'Home' || event.key === 'End')
				next = event.key === 'Home' ? 0 : 1;
			else
				return;
			event.preventDefault();
			selectTab(next, true);
		});
		tablist.appendChild(tab.button);
	});
	selectTab(0, false);

	return E('div', { class: 'vpn-routing-preview' }, [
		E('link', { rel: 'stylesheet', href: L.resource('vpn-routing/preview.css') }),
		E('div', { class: 'vpn-routing-header' }, [
			E('div', { class: 'vpn-routing-heading' }, [
				text('h1', '', 'VPN-маршрутизация'), hint,
				text('a', 'vpn-routing-source-link', 'Исходный репозиторий', {
					href: 'https://github.com/gopnikgame/VLine.OpenWRT',
					target: '_blank', rel: 'noopener noreferrer',
				}),
			]),
		]),
		tablist,
		...tabs.map(tab => tab.panel),
	]);
}

return view.extend({
	handleSaveApply: null,
	handleSave: null,
	handleReset: null,

	render() {
		const modes = E('fieldset', { class: 'vpn-routing-source' }, [text('legend', 'vpn-routing-label', 'Источник правил')]);
		for (const [key, label] of [['happ', 'Happ'], ['incy', 'INCY']]) {
			const radio = E('input', { type: 'radio', name: 'source', value: key, id: PREFIX + key });
			radio.checked = key === 'happ';
			modes.appendChild(E('label', { class: 'vpn-routing-source-option', for: radio.id }, [radio, text('span', '', label)]));
		}

		const headers = field('headers', 'Сохранённые заголовки', { rows: 4, help: 'Вставьте строку routing: … из сохранённых заголовков Happ.' });
		const inbound = field('inbound', 'Тег входа Xray для черновика', {
			help: 'При сохранении VPN Routing назначает тег своего входа автоматически.',
		});
		inbound.input.value = 'vpn-routing-tproxy';
		headers.input.required = inbound.input.required = true;
		const profile = field('profile', 'Сохранённый JSON профиля INCY', { rows: 5, placeholder: '{ … }' });
		const address = field('source-url', 'Доверенный адрес JSON', {
			type: 'url', placeholder: 'https://profiles.example.invalid/routing.json',
			help: 'Укажите точный адрес профиля из autorouting. LuCI использует вставленный JSON.',
		});
		const incyFields = E('div', { class: 'vpn-routing-incy-fields', id: PREFIX + 'incy-fields', hidden: '' }, [
			profile.node, address.node,
		]);
		const regex = field('regex', 'Разрешённые regexp', { rows: 2, help: 'По одному правилу с префиксом regexp: на строку.' });
		const geo = ['geoip', 'geosite'].map(kind => ({
			kind,
			hash: field(kind + '-sha256', 'SHA-256 ' + kind + '.dat', { placeholder: '64 шестнадцатеричных символа' }),
			categories: field(kind + '-categories', 'Категории ' + kind, { rows: 2, help: 'По одной категории на строку, без префикса.' }),
		}));
		const advanced = E('details', { class: 'vpn-routing-advanced', id: PREFIX + 'advanced' }, [
			text('summary', '', 'Расширенные параметры'),
			E('div', { class: 'vpn-routing-advanced-body' }, [
				inbound.node, regex.node,
				text('p', 'vpn-routing-hint', 'Для профиля VPN Routing базы загрузятся при сохранении. Для своих DAT укажите хеши файлов и категории.'),
				...geo.flatMap(item => [item.hash.node, item.categories.node]),
			]),
		]);
		const check = text('button', 'vpn-routing-button vpn-routing-primary', 'Проверить профиль', { id: PREFIX + 'check', type: 'submit' });
		const fixture = text('button', 'vpn-routing-button', 'Подставить пример', { id: PREFIX + 'fixture', type: 'button' });
		const status = text('p', 'vpn-routing-status', 'Вставьте профиль или подставьте пример.', {
			id: PREFIX + 'status', role: 'status', 'aria-live': 'polite', 'aria-atomic': 'true', 'data-state': 'empty',
		});
		const debug = text('code', '', '');
		const diagnostics = E('details', { class: 'vpn-routing-rule-details', hidden: '' }, [
			text('summary', '', 'Диагностика'),
			E('p', { class: 'vpn-routing-diagnostic' }, [debug]),
		]);
		const output = E('div', { class: 'vpn-routing-result-content', id: PREFIX + 'result' });
		const download = text('button', 'vpn-routing-button', 'Выгрузить черновик JSON', {
			id: PREFIX + 'download', type: 'button', 'aria-describedby': status.id, disabled: '',
		});
		const savedRoute = text('p', 'vpn-routing-hint', '', { id: PREFIX + 'saved-routing', role: 'status' });
		const saveFeedback = text('p', 'vpn-routing-status', '', { id: PREFIX + 'routing-status', role: 'status', 'aria-atomic': 'true', hidden: '' });
		const save = text('button', 'vpn-routing-button vpn-routing-primary', 'Сохранить правила', {
			type: 'button', 'aria-describedby': savedRoute.id, disabled: '',
		});
		const clear = text('button', 'vpn-routing-button', 'Убрать сохранённые правила', {
			type: 'button', 'aria-describedby': savedRoute.id, disabled: '',
		});
		const result = E('section', { class: 'vpn-routing-pane vpn-routing-result', 'aria-labelledby': PREFIX + 'result-title' }, [
			text('h2', '', 'Правила для подключения', { id: PREFIX + 'result-title' }),
			savedRoute, status, diagnostics, output,
			E('div', { class: 'vpn-routing-actions' }, [save, download, clear]), saveFeedback,
		]);
		const form = E('form', { class: 'vpn-routing-pane vpn-routing-form', novalidate: '', 'aria-labelledby': PREFIX + 'form-title' }, [
			text('h2', '', 'Правила трафика', { id: PREFIX + 'form-title' }), modes, headers.node, incyFields, advanced,
			E('div', { class: 'vpn-routing-actions' }, [check, fixture]),
		]);

		let revision = 0;
		let active = null;
		let downloadable = null;
		let settings = null;
		let saving = false;
		const mode = () => modes.querySelector('input:checked').value;

		function updateSaveActions() {
			const writable = settings?.editable === true && !saving;
			save.disabled = !writable || !downloadable;
			clear.hidden = !settings?.routing;
			clear.disabled = !writable || !settings?.routing;
			check.classList.toggle('vpn-routing-primary', save.disabled);
		}

		function setStatus(kind, message, detail) {
			status.dataset.state = kind;
			status.textContent = message;
			debug.textContent = diagnostic(detail);
			diagnostics.hidden = !debug.textContent;
			diagnostics.open = false;
			output.setAttribute('aria-busy', kind === 'busy' ? 'true' : 'false');
			check.disabled = kind === 'busy';
			check.textContent = kind === 'busy' ? 'Проверяем…' : 'Проверить профиль';
		}

		function invalidate() {
			revision++;
			if (active) {
				active.abort();
				active = null;
			}
			downloadable = null;
			download.disabled = true;
			saveFeedback.hidden = true;
			updateSaveActions();
			output.replaceChildren();
			for (const input of form.querySelectorAll('[aria-invalid]'))
				clearFieldError(input);
			if (status.dataset.state !== 'empty')
				setStatus('idle', 'Данные изменены. Проверьте профиль ещё раз.');
		}

		function clearFieldError(input) {
			if (!input.hasAttribute('aria-invalid'))
				return;
			input.removeAttribute('aria-invalid');
			const refs = (input.getAttribute('aria-describedby') || '').split(/\s+/)
				.filter(ref => ref && ref !== status.id);
			if (refs.length)
				input.setAttribute('aria-describedby', refs.join(' '));
			else
				input.removeAttribute('aria-describedby');
		}

		function syncMode() {
			const isIncy = mode() === 'incy';
			incyFields.hidden = !isIncy;
			profile.input.required = address.input.required = isIncy;
			headers.description.textContent = isIncy
				? 'Вставьте строку autorouting: … из сохранённых заголовков INCY.'
				: 'Вставьте строку routing: … из сохранённых заголовков Happ.';
			headers.input.placeholder = isIncy ? 'autorouting: incy://autorouting/onadd/…' : 'routing: happ://routing/onadd/…';
		}

		function collect() {
			const source = mode();
			const inboundTag = inbound.input.value.trim();
			if (!headers.input.value.trim())
				problem('Вставьте сохранённый заголовок.', headers.input);
			if (!/^[a-zA-Z0-9_.-]{1,64}$/.test(inboundTag)) {
				advanced.open = true;
				problem('Укажите тег входа. Допустимы латинские буквы, цифры, точка, дефис и подчёркивание.', inbound.input);
			}
			const policy = { inboundTag, routeOrder: ORDER };
			const allowedRegex = lines(regex.input.value);
			if (allowedRegex.length)
				policy.allowedRegex = allowedRegex;
			if (geo.some(item => item.hash.input.value.trim() || item.categories.input.value.trim())) {
				policy.geo = {};
				for (const item of geo) {
					const sha256 = item.hash.input.value.trim().toLowerCase();
					if (!/^[a-f0-9]{64}$/.test(sha256)) {
						advanced.open = true;
						problem('Для DAT укажите SHA-256 обоих файлов. Хеш содержит 64 символа.', item.hash.input);
					}
					policy.geo[item.kind] = { sha256, categories: lines(item.categories.input.value) };
				}
			}
			if (source === 'incy') {
				if (!profile.input.value.trim())
					problem('Вставьте сохранённый JSON профиля INCY.', profile.input);
				const url = address.input.value.trim();
				if (!url.startsWith('https://') || url.length <= 'https://'.length)
					problem('Укажите HTTPS-адрес JSON из заголовка autorouting.', address.input);
				policy.incySource = { url };
			}

			const payload = {
				source,
				headers: headers.input.value,
				policy: JSON.stringify(policy),
				profile: source === 'incy' ? profile.input.value : '',
			};
			const utf8 = new TextEncoder();
			for (const [key, input] of [['headers', headers.input], ['profile', profile.input], ['policy']]) {
				if (utf8.encode(payload[key]).length > LIMITS[key])
					problem('Размер поля превышает лимит ' + LIMITS[key] / 1024 + ' КиБ.', input);
			}
			if (!L.env.token)
				problem('Сессия LuCI недоступна. Откройте страницу заново.');
			const body = new URLSearchParams(Object.assign({ token: L.env.token }, payload));
			if (body.toString().length > LIMITS.body)
				problem('Данные запроса превышают 96 КиБ после кодирования. Оставьте нужный заголовок и уберите лишние данные.');
			return { body, inboundTag };
		}

		form.addEventListener('input', event => {
			if (event.target.name === 'source')
				return;
			invalidate();
		});
		modes.addEventListener('change', () => {
			syncMode();
			invalidate();
		});
		fixture.addEventListener('click', () => {
			const sample = JSON.stringify({
				GlobalProxy: 'true', DomainStrategy: 'IPIfNonMatch', RouteOrder: ORDER,
				DirectSites: ['domain:demo.test'], DirectIp: ['192.0.2.8/32'],
				ProxySites: ['full:video.demo.test'], ProxyIp: [],
				BlockSites: ['full:ads.demo.test'], BlockIp: [],
			}, null, 2);
			const url = 'https://profiles.example.invalid/routing.json';
			headers.input.value = mode() === 'happ' ? 'routing: happ://routing/onadd/' + btoa(sample)
				: 'autorouting: incy://autorouting/onadd/' + url;
			profile.input.value = mode() === 'incy' ? sample : '';
			address.input.value = mode() === 'incy' ? url : '';
			inbound.input.value = 'vpn-routing-tproxy';
			for (const item of [regex, ...geo.flatMap(entry => [entry.hash, entry.categories])])
				item.input.value = '';
			advanced.open = false;
			invalidate();
			setStatus('idle', 'Пример подставлен. Можно проверить профиль.');
		});

		form.addEventListener('submit', async event => {
			event.preventDefault();
			invalidate();
			const current = revision;
			let prepared;
			try {
				prepared = collect();
			} catch (error) {
				setStatus('error', error.message);
				if (error.input) {
					const refs = error.input.getAttribute('aria-describedby');
					error.input.setAttribute('aria-invalid', 'true');
					error.input.setAttribute('aria-describedby', (refs ? refs + ' ' : '') + status.id);
					error.input.focus();
				}
				return;
			}

			const controller = active = new AbortController();
			const timeout = window.setTimeout(() => controller.abort(), 15000);
			setStatus('busy', 'Проверяем правила профиля…');
			try {
				const reply = await post('preview', prepared.body, controller.signal);
				if (current !== revision)
					return;
				if (reply.status === 403 || reply.status === 401) {
					setStatus('error', 'Проверка недоступна. Перезайдите в LuCI и проверьте права доступа.');
					return;
				}
				if (reply.status === 405 || reply.status === 413) {
					setStatus('error', reply.status === 413 ? 'LuCI отклонил размер запроса. Сократите входные данные.'
						: 'LuCI отклонил метод проверки. Откройте страницу заново.');
					return;
				}
				const received = await reply.json();
				if (current !== revision)
					return;
				if (!reply.ok || !received || received.ok !== true) {
					const messages = {
						invalid_request: 'LuCI отклонил запрос. Проверьте обязательные поля.',
						too_large: 'LuCI отклонил размер запроса. Сократите входные данные.',
						rejected: 'Профиль не прошёл проверку. Исправьте данные и проверьте ещё раз.',
					};
					const code = received && received.error;
					const message = Object.prototype.hasOwnProperty.call(messages, code) ? messages[code] : 'Сервис проверки недоступен. Попробуйте ещё раз.';
					setStatus('error', message, received && received.detail);
					return;
				}
				const candidate = parseCandidate(received.candidate, prepared.inboundTag);
				output.replaceChildren(...resultDetails(candidate));
				downloadable = { candidate: received.candidate, body: prepared.body };
				download.disabled = false;
				updateSaveActions();
				setStatus('ready', received.managedGeo === true
					? 'Черновик готов. GeoIP и GeoSite загрузятся при сохранении.'
					: 'Черновик правил готов.');
			} catch (error) {
				if (current === revision)
					setStatus('error', error.name === 'AbortError' ? 'LuCI не ответил вовремя. Повторите проверку.'
						: 'Не удалось получить черновик от LuCI. Повторите проверку.');
			} finally {
				window.clearTimeout(timeout);
				if (current === revision)
					active = null;
			}
		});
		download.addEventListener('click', () => {
			if (downloadable)
				exportCandidate(downloadable.candidate);
		});
		syncMode();

		return application({
			node: E('div', { class: 'vpn-routing-workbench' }, [form, result]),
			feedback: saveFeedback,
			update(data, busy) {
				settings = data;
				saving = busy;
				const summary = settings?.editable === false ? 'Отключите VPN Routing, чтобы изменить правила.'
					: 'Сохранённые правила вступят в силу при следующем подключении.';
				if (summary !== savedRoute.textContent)
					savedRoute.textContent = summary;
				updateSaveActions();
			},
			bind(saveRouting) {
				save.addEventListener('click', () => {
					if (!save.disabled && downloadable)
						saveRouting(downloadable.body);
				});
				clear.addEventListener('click', () => {
					if (!clear.disabled)
						saveRouting({ source: 'none' });
				});
			},
		});
	},
});
