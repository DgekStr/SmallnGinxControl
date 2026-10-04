'use strict';

const query = (selector) => document.querySelector(selector);
const all = (selector) => [...document.querySelectorAll(selector)];
const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[character]));
const icon = (name, extra = '') => `<i data-lucide="${name}" ${extra}></i>`;
const number = (value, digits = 1) => Number(value || 0).toLocaleString('ru-RU', {maximumFractionDigits: digits});
const time = (value) => new Date(value).toLocaleTimeString('ru-RU', {hour: '2-digit', minute: '2-digit', second: '2-digit'});
const state = {view: '', hosts: [], filter: 'all', search: '', logKind: 'access', overview: null, trafficTop: [], trafficFetchedAt: 0, config: null, editor: null, charts: {}, busy: false, polling: false, logContent: ''};
Object.assign(state, {servers: [], serverId: sessionStorage.getItem('snc-server') || 'local', serverRevision: null, generation: 0, switching: false, serverReady: false, inventoryLoaded: false, editingServer: null});
const titles = {
  servers: ['Серверы nginx', 'NGINX / SERVER CONNECTIONS', 'Серверы'],
  overview: ['Обзор сервера', 'NGINX / SERVER OVERVIEW', 'Обзор'],
  hosts: ['Виртуальные хосты', 'NGINX / VIRTUAL HOSTS', 'Виртуальные хосты'],
  proxies: ['Reverse proxy', 'NGINX / REVERSE PROXY', 'Reverse proxy'],
  logs: ['Журналы nginx', 'NGINX / LOG EXPLORER', 'Журналы nginx'],
  config: ['Конфигурация nginx', 'NGINX / CONFIGURATION', 'Конфигурация'],
  audit: ['История действий', 'NGINX / AUDIT TRAIL', 'История действий'],
  settings: ['Настройки', 'SMALLNGINXCONTROL / SETTINGS', 'Настройки'],
};

function icons() { lucide.createIcons(); }

async function request(resource, data, parameters = {}) {
  const scoped = !['servers', 'password', 'settings'].includes(resource);
  const generation = state.generation;
  const search = new URLSearchParams(parameters);
  if (scoped) search.set('server', state.serverId);
  if (scoped && state.serverRevision) search.set('server_revision', state.serverRevision);
  if (scoped && data !== undefined && !state.serverReady) throw new Error('Данные выбранного сервера ещё не загружены. Проверьте соединение.');
  const options = {headers: {'Accept': 'application/json'}, credentials: 'same-origin', signal: AbortSignal.timeout(100000)};
  if (data !== undefined) {
    options.method = 'POST';
    options.headers['Content-Type'] = 'application/json';
    options.headers['X-CSRFToken'] = decodeURIComponent(document.cookie.split('; ').find((value) => value.startsWith('csrftoken='))?.split('=')[1] || '');
    options.body = JSON.stringify(data);
  }
  const response = await fetch(`/api/${resource}/?${search}`, options).catch((error) => {
    if (scoped && generation !== state.generation) error.stale = true;
    throw error;
  });
  if (response.status === 401) {
    location.assign('/login/');
    throw new Error('Сессия истекла. Требуется вход.');
  }
  const result = await response.json().catch(() => ({error: `Ошибка HTTP ${response.status}. Обновите страницу.`}));
  if (scoped && generation !== state.generation) {
    const error = new Error('Ответ предыдущего сервера отклонён.');
    error.stale = true;
    throw error;
  }
  if (!response.ok) throw new Error(result.error || 'Операция не выполнена.');
  return result;
}

function toast(message, error = false) {
  const element = document.createElement('div');
  element.className = 'toast' + (error ? ' error' : '');
  element.setAttribute('role', error ? 'alert' : 'status');
  element.innerHTML = `${icon(error ? 'circle-alert' : 'circle-check')}<span>${escapeHtml(message)}</span>`;
  query('#toast-region').append(element);
  icons();
  setTimeout(() => element.remove(), error ? 12000 : 5500);
}

function showResult(selector, message, success = false) {
  const element = query(selector);
  element.hidden = false;
  element.textContent = message;
  element.classList.toggle('success', success);
}

function confirmAction(title, description, danger = false) {
  return new Promise((resolve) => {
    const dialog = query('#confirm-dialog');
    query('#confirm-title').textContent = title;
    query('#confirm-description').textContent = description;
    query('#confirm-accept').className = 'button ' + (danger ? 'danger' : 'primary');
    const finish = (answer) => {
      dialog.close();
      dialog.oncancel = null;
      resolve(answer);
    };
    query('#confirm-accept').onclick = () => finish(true);
    query('#confirm-cancel').onclick = () => finish(false);
    dialog.oncancel = (event) => { event.preventDefault(); finish(false); };
    dialog.showModal();
  });
}

async function runAction(button, operation, errorSelector) {
  if (state.busy || state.switching) return;
  state.busy = true;
  query('#server-select').disabled = true;
  if (button) button.disabled = true;
  try {
    await operation();
  } catch (error) {
    if (error.stale) return;
    if (errorSelector) showResult(errorSelector, error.message);
    else toast(error.message, true);
  } finally {
    state.busy = false;
    query('#server-select').disabled = state.switching;
    if (button) button.disabled = false;
  }
}

function hostTable(items) {
  if (!items.length) return `<div class="empty-state">${icon('folder-search')}<strong>Конфигурации не найдены</strong><span>Нет хостов, соответствующих выбранному фильтру.</span></div>`;
  const rows = items.map((item) => {
    const status = item.maintenance ? 'Обслуживание' : item.enabled ? 'Включён' : 'Отключён';
    const toggleLabel = item.maintenance ? 'Вернуть прокси' : item.enabled ? 'Отключить' : 'Включить';
    const toggleTitle = !item.toggleable ? 'Нестандартный include: изменение в nginx.conf' : item.maintenance ? 'Вернуть reverse-proxy' : item.enabled ? 'Перевести конфигурацию в обслуживание' : 'Включить конфигурацию';
    const deleteButton = !item.enabled && item.toggleable ? `<button class="icon-button danger" data-action="delete" aria-label="Удалить ${escapeHtml(item.name)}" title="Удалить отключённую конфигурацию">${icon('trash-2')}</button>` : '';
    const expiryDays = item.tls && Number.isInteger(item.certificate_days) ? item.certificate_days : null;
    const expiry = expiryDays === null ? '' : `<span class="certificate-expiry ${expiryDays < 0 ? 'expired' : expiryDays <= 14 ? 'warning' : ''}" title="${expiryDays < 0 ? 'Сертификат просрочен' : 'Осталось дней действия сертификата'}">${expiryDays < 0 ? `Просрочен ${Math.abs(expiryDays)} дн.` : expiryDays === 0 ? 'Истекает сегодня' : `${expiryDays} дн.`}</span>`;
    return `<tr data-id="${escapeHtml(item.id)}"><td><div class="domain-cell"><span class="domain-icon ${item.kind}">${icon(item.kind === 'proxy' ? 'network' : 'globe-2')}</span><span><span class="domain-name">${escapeHtml(item.name)}</span><span class="domain-path" title="${escapeHtml(item.id)}">${escapeHtml(item.id)}${item.servers > 1 ? ` · ${item.servers} блоков server` : ''}</span></span></div></td><td class="target-cell" title="${escapeHtml(item.target)}">${escapeHtml(item.target)}</td><td><div class="protocol-cell"><span class="protocol ${item.tls ? 'secure' : ''}">${icon(item.tls ? 'lock-keyhole' : 'globe')}${item.tls ? 'HTTPS' : 'HTTP'}</span>${expiry}</div></td><td><span class="badge ${item.enabled ? 'success' : 'neutral'}"><span class="status-dot ${item.enabled ? '' : 'off'}"></span>${status}</span></td><td><div class="row-actions"><button class="toggle" role="switch" aria-checked="${item.enabled}" aria-label="${toggleLabel} ${escapeHtml(item.name)}" data-action="toggle" title="${toggleTitle}" ${item.toggleable ? '' : 'disabled'}></button><button class="icon-button" data-action="edit" aria-label="Редактировать ${escapeHtml(item.name)}" title="Редактировать конфигурацию">${icon('square-pen')}</button><button class="icon-button" data-action="logs" aria-label="Журнал ${escapeHtml(item.name)}" title="Просмотреть журнал">${icon('scroll-text')}</button><button class="icon-button" data-action="reload" aria-label="Применить ${escapeHtml(item.name)}" title="Применить через reload nginx">${icon('rotate-cw')}</button>${deleteButton}</div></td></tr>`;
  }).join('');
  return `<div class="table-scroll"><table class="data-table"><thead><tr><th>ДОМЕН / КОНФИГУРАЦИЯ</th><th>НАЗНАЧЕНИЕ</th><th>ПРОТОКОЛ</th><th>СТАТУС</th><th>ДЕЙСТВИЯ</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

function renderHosts() {
  const kind = state.view === 'proxies' ? 'proxy' : 'host';
  const items = state.hosts.filter((item) => item.kind === kind)
    .filter((item) => state.filter === 'all' || item.enabled === (state.filter === 'enabled'))
    .filter((item) => `${item.name} ${item.target} ${item.id} ${item.domains.join(' ')}`.toLowerCase().includes(state.search))
    .sort((left, right) => left.name.localeCompare(right.name, 'ru', {sensitivity: 'base'}));
  query('#hosts-table').innerHTML = hostTable(items);
  query('#overview-hosts').innerHTML = hostTable(state.hosts.slice(0, 6));
  query('#table-count').textContent = `Показано ${items.length} из ${state.hosts.filter((item) => item.kind === kind).length}`;
  query('#overview-host-count').textContent = state.hosts.length;
  query('#hosts-count').textContent = state.hosts.filter((item) => item.kind === 'host').length;
  query('#proxy-count').textContent = state.hosts.filter((item) => item.kind === 'proxy').length;
  query('#active-hosts').textContent = `${state.hosts.filter((item) => item.enabled).length} / ${state.hosts.length}`;
  icons();
}

async function refreshHosts() {
  const result = await request('hosts');
  state.hosts = result.items;
  state.inventoryLoaded = true;
  query('#inventory-warnings').textContent = result.warnings.join('\n');
  query('#inventory-warnings').hidden = !result.warnings.length;
  const selected = query('#log-host').value;
  query('#log-host').innerHTML = '<option value="">Общий журнал nginx</option>' + state.hosts.map((item) => `<option value="${escapeHtml(item.id)}">${escapeHtml(item.name)}</option>`).join('');
  query('#log-host').value = state.hosts.some((item) => item.id === selected) ? selected : '';
  renderHosts();
}

function chartColors() {
  const style = getComputedStyle(document.documentElement);
  return {cyan: style.getPropertyValue('--cyan').trim(), violet: style.getPropertyValue('--violet').trim(), muted: style.getPropertyValue('--muted').trim(), grid: style.getPropertyValue('--grid').trim()};
}

function makeCharts() {
  Object.values(state.charts).forEach((chart) => chart.destroy());
  const colors = chartColors();
  Chart.defaults.font.family = 'Manrope';
  Chart.defaults.color = colors.muted;
  const dataset = (label, color, fill) => ({label, data: [], borderColor: color, backgroundColor: color + '0a', borderWidth: 2, pointRadius: 0, pointHitRadius: 9, tension: .3, fill});
  state.charts.traffic = new Chart(query('#traffic-chart'), {
    type: 'line', data: {labels: [], datasets: [dataset('Получено', colors.cyan, true), dataset('Отправлено', colors.violet, false)]},
    options: {responsive: true, maintainAspectRatio: false, animation: false, interaction: {mode: 'index', intersect: false}, plugins: {legend: {display: false}, tooltip: {callbacks: {label: (context) => `${context.dataset.label}: ${number(context.parsed.y, 2)} МБ/с`}}}, scales: {x: {grid: {display: false}, border: {display: false}, ticks: {maxTicksLimit: 7, maxRotation: 0, font: {size: 9}, padding: 9}}, y: {beginAtZero: true, suggestedMax: 6, border: {display: false}, grid: {color: colors.grid}, ticks: {maxTicksLimit: 5, font: {size: 9}, padding: 8}}}},
  });
  for (const [name, color] of [['cpu', colors.violet], ['lan', colors.cyan]]) {
    state.charts[name] = new Chart(query(`#${name}-spark`), {type: 'line', data: {labels: [], datasets: [dataset(name, color, true)]}, options: {responsive: true, maintainAspectRatio: false, animation: false, events: [], plugins: {legend: {display: false}, tooltip: {enabled: false}}, scales: {x: {display: false}, y: {display: false, beginAtZero: true}}}});
  }
}

function renderMetrics() {
  const result = state.overview;
  if (!result) return;
  const metrics = result.metrics;
  query('#nginx-version').textContent = result.nginx.version;
  query('#system-name').textContent = result.nginx.system;
  query('#health-badge').textContent = result.nginx.active ? 'Работает' : 'Остановлен';
  query('#health-badge').className = 'badge ' + (result.nginx.active ? 'success' : 'error');
  query('#connection-label').innerHTML = `<span class="status-dot ${metrics.stale ? 'off' : ''}"></span>${metrics.stale ? 'Нет свежих метрик' : result.mode === 'demo' ? 'Локальная среда' : 'Сервер доступен'}`;
  query('#side-status').innerHTML = `<span class="status-dot ${result.nginx.active ? '' : 'off'}"></span>${result.mode === 'demo' ? 'Демосервер' : result.nginx.active ? 'nginx работает' : 'nginx остановлен'}`;
  const current = metrics.current;
  if (!current) { query('#metric-period').textContent = 'Ожидание первого измерения'; return; }
  const days = Math.floor(current.uptime / 86400);
  const hours = Math.floor(current.uptime % 86400 / 3600);
  query('#metric-uptime').innerHTML = `${days}<small>дн</small> ${hours}<small>ч</small>`;
  query('#metric-cpu').innerHTML = `${number(metrics.peaks.cpu)}<small>%</small>`;
  query('#cpu-caption').textContent = `Наблюдение с ${new Date(metrics.since).toLocaleString('ru-RU', {day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit'})}`;
  query('#metric-lan').innerHTML = `${number(Math.max(metrics.peaks.rx, metrics.peaks.tx) * 8)}<small>Мбит/с</small>`;
  query('#metric-rx').textContent = number(current.rx_mb, 0);
  query('#metric-tx').textContent = number(current.tx_mb, 0);
  query('#current-cpu').textContent = number(current.cpu) + '%';
  query('#current-memory').textContent = number(current.memory) + '%';
  query('#cpu-bar').style.width = Math.min(100, current.cpu) + '%';
  query('#memory-bar').style.width = Math.min(100, current.memory) + '%';
  query('#rx-rate').textContent = number(current.rx_rate, 2);
  query('#tx-rate').textContent = number(current.tx_rate, 2);
  query('#network-interface').textContent = result.mode === 'demo' ? 'ens18 · демо' : metrics.interface;
  query('#last-update').textContent = time(current.created_at) + (metrics.stale ? ' · устарело' : '');
  query('#metric-period').textContent = metrics.stale ? 'Данные устарели' : (result.mode === 'demo' ? 'Синтетическая телеметрия' : 'Телеметрия сервера');
  const minutes = Number(query('#chart-range').value);
  const history = metrics.history.filter((sample) => new Date(sample.created_at).getTime() >= Date.now() - minutes * 60000);
  const labels = history.map((sample) => new Date(sample.created_at).toLocaleTimeString('ru-RU', {hour: '2-digit', minute: '2-digit'}));
  const chart = state.charts.traffic;
  chart.data.labels = labels;
  chart.data.datasets[0].data = history.map((sample) => sample.rx_rate);
  chart.data.datasets[1].data = history.map((sample) => sample.tx_rate);
  chart.update('none');
  for (const name of ['cpu', 'lan']) {
    state.charts[name].data.labels = labels;
    state.charts[name].data.datasets[0].data = history.map((sample) => name === 'cpu' ? sample.cpu : sample.rx_rate);
    state.charts[name].update('none');
  }
}

function trafficSize(bytes) {
  const units = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ'];
  let value = Number(bytes) || 0;
  let unit = 0;
  while (value >= 1000 && unit < units.length - 1) { value /= 1000; unit++; }
  return `${number(value, value < 10 ? 1 : 0)} ${units[unit]}`;
}

function renderTrafficTop(result) {
  const items = result.items || [];
  const container = query('#top-traffic-list');
  state.trafficTop = items;
  query('#top-traffic-period').textContent = `Последние ${trafficSize(result.sample_bytes_per_log)} каждого access log`;
  if (!items.length) {
    container.innerHTML = '<div class="traffic-top-empty">Нет данных access log для активных виртуальных хостов.</div>';
    return;
  }
  const maximum = Math.max(1, items[0].bytes);
  container.innerHTML = items.map((item, index) => {
    const width = Math.max(2, item.bytes / maximum * 100);
    const kind = item.kind === 'proxy' ? 'Reverse proxy' : 'Виртуальный хост';
    return `<div class="traffic-rank" data-bytes="${item.bytes}"><div class="traffic-rank-host"><span class="traffic-rank-number">0${index + 1}</span><span class="traffic-rank-name"><strong title="${escapeHtml(item.name)}">${escapeHtml(item.name)}</strong><small>${kind}</small></span></div><div class="traffic-rank-track"><span class="traffic-rank-fill rank-${index + 1}" style="width:${width}%"></span></div><strong class="traffic-rank-value">${trafficSize(item.bytes)}</strong></div>`;
  }).join('');
}

async function refreshTrafficTop() {
  try {
    renderTrafficTop(await request('traffic'));
  } catch (error) {
    if (error.stale) return;
    query('#top-traffic-period').textContent = 'Трафик access log';
    query('#top-traffic-list').textContent = `Не удалось загрузить рейтинг: ${error.message}`;
  } finally {
    state.trafficFetchedAt = Date.now();
  }
}

function ensureLogRetentionForm() {
  if (query('#log-retention-form')) return;
  const section = document.createElement('section');
  section.className = 'settings-section log-retention-section';
  section.innerHTML = '<div class="section-heading"><h2>Хранение логов</h2><i data-lucide="archive"></i></div><form id="log-retention-form"><label>Срок хранения, дней<input id="log-retention-days" name="log_retention_days" type="number" min="1" max="3650" step="1" required></label><p class="muted small">Хостовые access-логи ротируются и очищаются ежедневно.</p><div id="log-retention-result" class="operation-result" hidden></div><button class="button primary" type="submit"><i data-lucide="save"></i>Сохранить срок</button></form>';
  query('#view-settings .settings-layout').append(section);
  section.querySelector('#log-retention-form').addEventListener('submit', (event) => {
    event.preventDefault();
    runAction(event.submitter, async () => {
      const result = await request('settings', {log_retention_days: Number(query('#log-retention-days').value)});
      showResult('#log-retention-result', result.message, true);
    }, '#log-retention-result');
  });
  icons();
}

async function refreshLogRetentionSettings() {
  ensureLogRetentionForm();
  const result = await request('settings');
  query('#log-retention-days').value = result.log_retention_days;
  query('#log-retention-result').hidden = true;
}

async function refreshOverview() {
  state.overview = await request('overview');
  state.serverReady = state.inventoryLoaded;
  renderMetrics();
  query('#global-error').hidden = true;
}

function dirtyConfig() { return state.config && query('#main-config').value !== state.config.content; }

async function route() {
  const next = location.hash.slice(1) in titles ? location.hash.slice(1) : 'overview';
  if (state.view === 'config' && next !== 'config' && dirtyConfig()) {
    if (!await confirmAction('Выйти без сохранения?', 'Несохранённые изменения nginx.conf будут потеряны.')) {
      history.replaceState(null, '', '#config');
      return;
    }
  }
  state.view = next;
  query('.heading-actions').hidden = next === 'servers';
  all('.view').forEach((view) => { view.hidden = true; });
  query('#view-' + (next === 'proxies' ? 'hosts' : next)).hidden = false;
  query('#page-title').textContent = titles[next][0];
  query('#page-eyebrow').textContent = titles[next][1];
  query('#breadcrumb-current').textContent = titles[next][2];
  document.title = `${titles[next][2]} | SmallnGinxControl`;
  all('[data-view]').forEach((element) => element.classList.toggle('active', element.dataset.view === next));
  closeMenu();
  try {
    if (next === 'servers') await refreshServers();
    if (next === 'overview') { Object.values(state.charts).forEach((chart) => chart.resize()); renderMetrics(); await refreshTrafficTop(); }
    if (next === 'hosts' || next === 'proxies') renderHosts();
    if (next === 'logs') await loadLogs();
    if (next === 'config') await loadConfig();
    if (next === 'audit') await loadAudit();
    if (next === 'settings') await refreshLogRetentionSettings();
  } catch (error) { if (!error.stale) toast(error.message, true); }
}

async function loadLogs() {
  const response = await request('logs', undefined, {id: query('#log-host').value, kind: state.logKind, lines: query('#log-lines').value});
  state.logContent = response.content;
  query('#log-content').textContent = response.content || 'Нет записей.';
  query('#log-note').textContent = response.note;
  query('#log-source').textContent = response.sources.join(' · ') || `nginx / ${state.logKind}.log`;
  query('#log-timestamp').textContent = time(Date.now());
  if (query('#log-live').checked) query('#log-content').scrollTop = query('#log-content').scrollHeight;
}

async function loadConfig() {
  state.config = await request('config');
  state.config.serverId = state.serverId;
  query('#main-config').value = state.config.content;
  query('#config-state').textContent = 'Сохранено';
  query('#config-revision').textContent = 'SHA256 ' + state.config.revision.slice(0, 16);
  query('#config-result').hidden = true;
}

async function loadAudit() {
  const response = await request('audit');
  const names = {login: 'Вход', logout: 'Выход', password_change: 'Смена пароля', settings_update: 'Срок хранения логов', save_config: 'Изменение конфигурации', create: 'Создание хоста', toggle: 'Переключение хоста', reload: 'Применение nginx', restart: 'Перезапуск nginx', test: 'Проверка nginx', demo_initialized: 'Инициализация демо'};
  Object.assign(names, {server_create: 'Добавление сервера', server_update: 'Изменение сервера', server_delete: 'Удаление подключения', server_test: 'Проверка соединения'});
  query('#audit-table').innerHTML = `<div class="table-scroll"><table class="data-table"><thead><tr><th>ВРЕМЯ</th><th>ПОЛЬЗОВАТЕЛЬ</th><th>ОПЕРАЦИЯ</th><th>ОБЪЕКТ</th><th>РЕЗУЛЬТАТ</th></tr></thead><tbody>${response.events.map((event) => `<tr><td class="mono muted">${escapeHtml(new Date(event.created_at).toLocaleString('ru-RU'))}</td><td>${escapeHtml(event.actor)}</td><td class="audit-action">${escapeHtml(names[event.action] || event.action)}</td><td class="audit-target" title="${escapeHtml(event.target)}">${escapeHtml(event.target || '—')}${event.detail ? `<div class="audit-detail">${escapeHtml(event.detail)}</div>` : ''}</td><td><span class="badge ${event.success ? 'success' : 'error'}">${event.success ? 'Выполнено' : 'Ошибка'}</span></td></tr>`).join('') || '<tr><td colspan="5" class="empty-state">История пуста.</td></tr>'}</tbody></table></div>`;
}

async function openEditor(item) {
  state.editor = await request('config', undefined, {id: item.id});
  state.editor.serverId = state.serverId;
  query('#editor-title').textContent = item.name;
  query('#editor-path').textContent = `${serverLabel()} / ${item.id}`;
  query('#host-config').value = state.editor.content;
  query('#editor-error').hidden = true;
  query('#editor-dialog').showModal();
}

function closeMenu() {
  query('#sidebar').classList.remove('open');
  query('#sidebar-backdrop').hidden = true;
  query('#menu-toggle').setAttribute('aria-expanded', 'false');
}

document.addEventListener('click', async (event) => {
  const close = event.target.closest('[data-close]');
  if (close) {
    const dialog = query('#' + close.dataset.close);
    if (dialog.id === 'editor-dialog' && state.editor && query('#host-config').value !== state.editor.content) {
      if (!await confirmAction('Закрыть без сохранения?', 'Изменения конфигурации будут потеряны.')) return;
    }
    dialog.close();
  }
  const button = event.target.closest('[data-action]');
  if (!button || state.busy) return;
  const item = state.hosts.find((host) => host.id === button.closest('tr').dataset.id);
  if (!item) return;
  await runAction(button, async () => {
    if (button.dataset.action === 'edit') return openEditor(item);
    if (button.dataset.action === 'logs') {
      query('#log-host').value = item.id;
      if (state.view === 'logs') await loadLogs();
      else location.hash = 'logs';
      return;
    }
    const toggle = button.dataset.action === 'toggle';
    const deleting = button.dataset.action === 'delete';
    const enteringMaintenance = toggle && item.enabled && item.kind === 'proxy';
    const leavingMaintenance = toggle && item.maintenance;
    const title = deleting ? `Удалить ${item.name} из nginx?` : toggle ? `${leavingMaintenance ? 'Вернуть прокси' : item.enabled ? 'Отключить' : 'Включить'} ${item.name}?` : `Применить ${item.name}?`;
    const description = deleting ? `Файл ${item.id}${item.servers > 1 ? ` со всеми ${item.servers} блоками server` : ''} и его ссылки sites-enabled будут удалены из nginx, хост исчезнет из панели. Резервная копия останется в state-каталоге. После проверки конфигурации будет выполнен reload.` : `Сервер: ${serverLabel()}. Файл: ${item.id}. ${item.servers > 1 ? `Затронуты все ${item.servers} блоков server в файле. ` : ''}После проверки конфигурации будет выполнен reload всего nginx.${enteringMaintenance ? ' Reverse-proxy будет переведён в обслуживание с показом maitenance.html.' : toggle && item.enabled ? ' Хост перестанет обслуживаться.' : ''}`;
    if (!await confirmAction(title, description, deleting || toggle && item.enabled && !enteringMaintenance)) return;
    await request('hosts', {action: deleting ? 'delete' : toggle ? 'toggle' : 'reload', id: item.id, enabled: !item.enabled, revision: item.revision});
    toast(deleting ? 'Отключённый хост удалён из панели и nginx.' : toggle ? enteringMaintenance ? 'Reverse-proxy переведён в обслуживание.' : leavingMaintenance ? 'Reverse-proxy восстановлен.' : 'Состояние конфигурации изменено.' : 'Конфигурация применена через reload.');
    await refreshHosts();
  });
});

query('#host-filter').addEventListener('click', (event) => {
  const button = event.target.closest('[data-filter]');
  if (!button) return;
  state.filter = button.dataset.filter;
  all('[data-filter]').forEach((element) => element.classList.toggle('selected', element === button));
  renderHosts();
});
query('#host-search').addEventListener('input', (event) => { state.search = event.target.value.trim().toLowerCase(); renderHosts(); });

function ensureSslCreateFields() {
  let section = query('.ssl-create-options');
  if (!section) {
    section = document.createElement('section');
    section.className = 'ssl-create-options';
    section.innerHTML = '<label class="check-label"><input type="checkbox" id="host-ssl-issue">Выпустить SSL-сертификат через Certbot</label><p class="muted small"></p><label id="host-ssl-email-label" hidden>Email владельца домена<input id="host-ssl-email" type="email" autocomplete="email" placeholder="admin@example.com"></label>';
    query('#new-host-target').closest('label').after(section);
  }
  const checkbox = query('#host-ssl-issue');
  const demo = document.body.dataset.mode === 'demo';
  checkbox.disabled = demo;
  if (demo) checkbox.checked = false;
  section.querySelector('p').textContent = demo ? 'В demo сертификаты не выпускаются. Переключитесь на production nginx.' : 'Нужен публичный DNS, направленный на этот сервер, и доступный HTTP-порт 80.';
  const sync = () => {
    const enabled = checkbox.checked && !checkbox.disabled;
    query('#host-ssl-email-label').hidden = !enabled;
    query('#host-ssl-email').required = enabled;
  };
  checkbox.addEventListener('change', sync);
  sync();
}

query('#add-host').addEventListener('click', () => {
  ensureSslCreateFields();
  query('#host-form').reset();
  query('#host-ssl-email').value = '';
  query('#host-ssl-email-label').hidden = true;
  query('#host-ssl-email').required = false;
  query('#new-host-kind').value = state.view === 'proxies' ? 'proxy' : 'host';
  updateTarget();
  query('#host-form-error').hidden = true;
  query('#host-dialog').showModal();
});
function updateTarget() {
  const proxy = query('#new-host-kind').value === 'proxy';
  query('#target-label').textContent = proxy ? 'Адрес upstream' : 'Корневой каталог';
  query('#new-host-target').placeholder = proxy ? 'http://192.168.0.20:3000' : '/var/www/app';
}
query('#new-host-kind').addEventListener('change', updateTarget);
query('#host-form').addEventListener('submit', (event) => {
  event.preventDefault();
  runAction(event.submitter, async () => {
    query('#host-form-error').hidden = true;
    const data = Object.fromEntries(new FormData(event.target));
    data.issue_ssl = Boolean(query('#host-ssl-issue')?.checked);
    if (data.issue_ssl) data.ssl_email = query('#host-ssl-email').value.trim();
    await request('hosts', {action: 'create', ...data});
    query('#host-dialog').close();
    toast(data.issue_ssl ? 'Хост создан, сертификат выпущен и HTTPS включён.' : 'Конфигурация создана и включена.');
    await refreshHosts();
  }, '#host-form-error');
});
query('#save-host-config').addEventListener('click', (event) => runAction(event.currentTarget, async () => {
  if (!state.editor || state.editor.serverId !== state.serverId) throw new Error('Редактор относится к другому серверу. Откройте конфигурацию заново.');
  query('#editor-error').hidden = true;
  await request('config', {id: state.editor.id, content: query('#host-config').value, revision: state.editor.revision});
  query('#editor-dialog').close();
  toast('Конфигурация сохранена и применена.');
  await refreshHosts();
}, '#editor-error'));
query('#save-config').addEventListener('click', (event) => runAction(event.currentTarget, async () => {
  if (!state.config || state.config.serverId !== state.serverId) throw new Error('Откройте конфигурацию выбранного сервера заново.');
  if (!await confirmAction('Применить nginx.conf?', `Сервер: ${serverLabel()}. Будет создана резервная копия и выполнена проверка перед reload всех его хостов.`)) return;
  const result = await request('config', {id: state.config.id, content: query('#main-config').value, revision: state.config.revision});
  await loadConfig();
  showResult('#config-result', result.message, true);
  toast('Настройки nginx сохранены.');
}, '#config-result'));
query('#reset-config').addEventListener('click', (event) => runAction(event.currentTarget, async () => {
  if (!dirtyConfig() || await confirmAction('Сбросить изменения?', 'Будет загружена текущая конфигурация с диска.')) await loadConfig();
}));
query('#main-config').addEventListener('input', () => { query('#config-state').textContent = dirtyConfig() ? 'Не сохранено' : 'Сохранено'; });
for (const [selector, action] of [['#test-config', 'test'], ['#reload-nginx', 'reload'], ['#restart-nginx', 'restart']]) {
  query(selector).addEventListener('click', (event) => runAction(event.currentTarget, async () => {
    if (action !== 'test' && !await confirmAction(action === 'restart' ? 'Перезапустить весь nginx?' : 'Применить конфигурацию nginx?', `Сервер: ${serverLabel()}. ` + (action === 'restart' ? 'Все его виртуальные хосты будут перезапущены. Возможен разрыв активных соединений.' : 'Конфигурация будет проверена, затем перечитана всеми рабочими процессами nginx.'), action === 'restart')) return;
    await request('service', {action, confirmation: action === 'restart' ? 'restart nginx' : ''});
    toast(action === 'test' ? (document.body.dataset.mode === 'demo' ? 'Демо: синтаксис Crossplane корректен.' : 'nginx -t: конфигурация корректна.') : action === 'restart' ? 'Перезапуск выполнен.' : 'Конфигурация применена.');
    await refreshOverview();
  }));
}
query('#password-form').addEventListener('submit', (event) => {
  event.preventDefault();
  runAction(event.submitter, async () => {
    query('#password-result').hidden = true;
    const result = await request('password', Object.fromEntries(new FormData(event.target)));
    showResult('#password-result', result.message, true);
    event.target.reset();
  }, '#password-result');
});
query('#log-kind').addEventListener('click', (event) => {
  const button = event.target.closest('[data-kind]');
  if (!button) return;
  state.logKind = button.dataset.kind;
  all('[data-kind]').forEach((element) => element.classList.toggle('selected', element === button));
  runAction(null, loadLogs);
});
query('#log-host').addEventListener('change', () => runAction(null, loadLogs));
query('#log-lines').addEventListener('change', () => runAction(null, loadLogs));
query('#refresh-logs').addEventListener('click', (event) => runAction(event.currentTarget, loadLogs));
query('#refresh-audit').addEventListener('click', (event) => runAction(event.currentTarget, loadAudit));
query('#download-logs').addEventListener('click', () => {
  const anchor = document.createElement('a');
  const url = URL.createObjectURL(new Blob([state.logContent], {type: 'text/plain;charset=utf-8'}));
  anchor.href = url;
  anchor.download = `nginx-${state.logKind}.log`;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
query('#chart-range').addEventListener('change', renderMetrics);
query('#refresh-traffic-top').addEventListener('click', (event) => runAction(event.currentTarget, refreshTrafficTop));
query('#theme-toggle').addEventListener('click', () => {
  const theme = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
  document.documentElement.dataset.theme = theme;
  localStorage.setItem('snc-theme', theme);
  makeCharts();
  renderMetrics();
});
query('#menu-toggle').addEventListener('click', () => {
  const open = query('#sidebar').classList.toggle('open');
  query('#sidebar-backdrop').hidden = !open;
  query('#menu-toggle').setAttribute('aria-expanded', String(open));
});
query('#sidebar-backdrop').addEventListener('click', closeMenu);
window.addEventListener('hashchange', route);
window.addEventListener('beforeunload', (event) => {
  if (dirtyConfig() || (query('#editor-dialog').open && state.editor && query('#host-config').value !== state.editor.content)) {
    event.preventDefault();
    event.returnValue = '';
  }
});
query('#editor-dialog').addEventListener('cancel', (event) => {
  if (state.editor && query('#host-config').value !== state.editor.content) {
    event.preventDefault();
    confirmAction('Закрыть без сохранения?', 'Изменения конфигурации будут потеряны.').then((confirmed) => { if (confirmed) query('#editor-dialog').close(); });
  }
});

function currentServer() { return state.servers.find((server) => server.id === state.serverId); }
function serverLabel() { const server = currentServer(); return server ? `${server.name} (${server.host})` : state.serverId; }
function modeLabel(mode) { return {demo: 'Демо', local: 'Локальный', ssh: 'SSH'}[mode] || mode; }

function renderServerContext() {
  const server = currentServer();
  if (!server) return;
  document.body.dataset.mode = server.mode;
  query('.server-mini strong').textContent = server.host;
  query('#page-subtitle').innerHTML = `${escapeHtml(server.host)}<span class="dot-separator">·</span><span id="system-name">${escapeHtml(server.name)}</span>`;
  query('#demo-banner').hidden = server.mode !== 'demo';
  query('#demo-server-note').textContent = `Данные синтетические · ${server.host} не подключён`;
  query('#view-settings .settings-details > div:nth-child(2) dd').textContent = server.host;
  query('#view-settings .settings-details > div:nth-child(3) dd').textContent = modeLabel(server.mode);
  query('#view-settings .settings-details > div:nth-child(6) dd').textContent = server.mode === 'ssh' ? '/var/lib/smallnginxcontrol-ssh/backups/' : server.is_default ? 'var/backups/' : `var/servers/${server.id}/backups/`;
  query('#view-config .file-label .mono').textContent = `${server.nginx_root}/nginx.conf`;
  query('#footer-status').textContent = server.mode === 'demo' ? 'PREVIEW · NO REMOTE CHANGES' : `NGINX / ${server.host}`;
}

function renderServers() {
  query('#server-select').innerHTML = state.servers.map((server) => `<option value="${server.id}">${escapeHtml(server.name)} · ${escapeHtml(server.host)}${server.mode === 'demo' ? ' · Демо' : ''}</option>`).join('');
  query('#server-select').value = state.serverId;
  query('#servers-count').textContent = state.servers.length;
  query('#server-total').textContent = state.servers.length;
  query('#servers-table').innerHTML = `<div class="table-scroll server-table"><table class="data-table"><thead><tr><th>СЕРВЕР</th><th>ПОДКЛЮЧЕНИЕ</th><th>СОСТОЯНИЕ</th><th>ДЕЙСТВИЯ</th></tr></thead><tbody>${state.servers.map((server) => {
    const recent = server.last_seen && Date.now() - new Date(server.last_seen).getTime() < 30000;
    const status = server.last_error ? 'Ошибка соединения' : server.mode === 'demo' ? 'Демосервер' : recent ? 'Доступен' : 'Не проверен';
    return `<tr data-server-id="${server.id}" class="${server.id === state.serverId ? 'server-row-selected' : ''}"><td><div class="server-name">${escapeHtml(server.name)} ${server.is_default ? '<span class="badge neutral">Основной</span>' : ''}</div><div class="server-address mono">${escapeHtml(server.host)}${server.mode === 'ssh' ? ':' + server.port : ''}</div></td><td><span class="badge ${server.mode === 'demo' ? 'warning' : 'neutral'}">${modeLabel(server.mode)}</span>${server.mode === 'ssh' ? `<div class="server-address">${escapeHtml(server.username)} · ${{key: 'Ключ', password: 'Пароль', agent: 'SSH-агент'}[server.auth_method]}</div>` : ''}</td><td><span class="badge ${server.last_error ? 'error' : recent ? 'success' : 'neutral'}">${status}</span>${server.last_error ? `<div class="server-error">${escapeHtml(server.last_error)}</div>` : ''}</td><td><div class="row-actions"><button class="icon-button" data-server-action="select" title="Открыть сервер" aria-label="Открыть ${escapeHtml(server.name)}">${icon('arrow-up-right')}</button><button class="icon-button" data-server-action="test" title="Проверить соединение" aria-label="Проверить ${escapeHtml(server.name)}">${icon('plug-zap')}</button><button class="icon-button" data-server-action="edit" title="Редактировать подключение" aria-label="Редактировать ${escapeHtml(server.name)}">${icon('square-pen')}</button>${server.is_default ? '' : `<button class="icon-button" data-server-action="delete" title="Удалить подключение" aria-label="Удалить ${escapeHtml(server.name)}">${icon('trash-2')}</button>`}</div></td></tr>`;
  }).join('')}</tbody></table></div>`;
  icons();
}

async function refreshServers() {
  const result = await request('servers');
  state.servers = result.servers;
  renderServers();
}

function clearServerData() {
  state.hosts = [];
  state.trafficTop = [];
  state.trafficFetchedAt = 0;
  state.overview = state.config = state.editor = null;
  state.serverReady = state.inventoryLoaded = false;
  state.logContent = '';
  query('#main-config').value = '';
  query('#host-config').value = '';
  query('#log-content').textContent = 'Загрузка…';
  query('#log-source').textContent = 'nginx';
  query('#log-note').textContent = '';
  query('#log-host').innerHTML = '<option value="">Общий журнал nginx</option>';
  query('#audit-table').textContent = '';
  query('#config-state').textContent = 'Загрузка';
  query('#config-result').hidden = true;
  query('#inventory-warnings').hidden = true;
  query('#top-traffic-period').textContent = 'По access logs активных виртуальных хостов';
  query('#top-traffic-list').innerHTML = '<div class="traffic-top-empty">Загрузка…</div>';
  query('#config-revision').textContent = '';
  for (const id of ['metric-uptime', 'metric-cpu', 'metric-lan', 'metric-rx', 'metric-tx', 'current-cpu', 'current-memory', 'rx-rate', 'tx-rate', 'network-interface', 'last-update', 'nginx-version']) query('#' + id).textContent = '—';
  query('#cpu-caption').textContent = 'За период наблюдения';
  query('#metric-period').textContent = 'Ожидание данных';
  query('#cpu-bar').style.width = '0%';
  query('#memory-bar').style.width = '0%';
  query('#health-badge').textContent = 'Подключение';
  query('#health-badge').className = 'badge neutral';
  query('#side-status').textContent = 'Подключение…';
  for (const chart of Object.values(state.charts)) {
    chart.data.labels = [];
    chart.data.datasets.forEach((dataset) => { dataset.data = []; });
    chart.update('none');
  }
  renderHosts();
}

async function loadServerContext(identifier) {
  if (!state.servers.some((server) => server.id === identifier)) throw new Error('Выбранный сервер удалён. Выберите другой в списке.');
  state.switching = true;
  query('#server-select').disabled = true;
  state.serverId = identifier;
  state.serverRevision = currentServer().revision;
  state.generation++;
  sessionStorage.setItem('snc-server', identifier);
  clearServerData();
  renderServerContext();
  renderServers();
  try {
    await refreshHosts();
    await refreshOverview();
    if (state.view === 'overview') await refreshTrafficTop();
    if (state.view === 'config') await loadConfig();
    if (state.view === 'logs') await loadLogs();
    if (state.view === 'audit') await loadAudit();
  } catch (error) {
    if (!error.stale) {
      showResult('#global-error', `${serverLabel()}: ${error.message}`);
      query('#health-badge').textContent = 'Недоступен';
      query('#health-badge').className = 'badge error';
      query('#side-status').textContent = 'Нет соединения';
      query('#connection-label').textContent = 'Нет связи с сервером';
    }
  } finally {
    state.switching = false;
    query('#server-select').disabled = state.busy;
  }
}

async function selectServer(identifier) {
  if (identifier === state.serverId) return;
  query('#server-select').value = state.serverId;
  if (state.busy || state.switching) return;
  if (dirtyConfig() && !await confirmAction('Сменить nginx-сервер?', 'Несохранённые изменения конфигурации будут потеряны.')) return;
  await loadServerContext(identifier);
}

function updateServerFields() {
  const ssh = query('#server-mode').value === 'ssh';
  query('#ssh-fields').hidden = !ssh;
  query('#ssh-fields').disabled = !ssh;
  const auth = query('#server-auth').value;
  query('#server-key-field').hidden = auth !== 'key';
  query('#server-secret-field').hidden = auth === 'agent';
  query('#server-secret-label').textContent = auth === 'password' ? 'SSH-пароль' : 'Пароль ключа, если задан';
  query('#server-form [name="key_path"]').required = ssh && auth === 'key';
  query('#server-form [name="secret"]').required = ssh && auth === 'password' && !state.editingServer?.has_secret;
}

function openServerForm(server = null) {
  state.editingServer = server;
  const form = query('#server-form');
  form.reset();
  query('#server-dialog-title').textContent = server ? 'Подключение сервера' : 'Новый сервер';
  query('#server-form-error').hidden = true;
  query('#server-mode').disabled = Boolean(server?.is_default);
  if (server) for (const [name, value] of Object.entries(server)) if (form.elements.namedItem(name)) form.elements.namedItem(name).value = value ?? '';
  query('#server-key-trusted').checked = Boolean(server?.fingerprint);
  form.elements.secret.value = '';
  form.elements.secret.placeholder = server?.has_secret ? 'Сохранён; пустое поле оставляет прежний' : '';
  updateServerFields();
  query('#server-dialog').showModal();
}

query('#server-select').addEventListener('change', (event) => selectServer(event.target.value).catch((error) => toast(error.message, true)));
query('#add-server').addEventListener('click', () => openServerForm());
query('#refresh-servers').addEventListener('click', (event) => runAction(event.currentTarget, refreshServers));
query('#server-mode').addEventListener('change', updateServerFields);
query('#server-auth').addEventListener('change', updateServerFields);
for (const name of ['host', 'port', 'fingerprint']) query(`#server-form [name="${name}"]`).addEventListener('input', () => { query('#server-key-trusted').checked = false; });
query('#probe-server').addEventListener('click', (event) => runAction(event.currentTarget, async () => {
  const form = query('#server-form');
  const result = await request('servers', {action: 'probe', host: form.elements.host.value, port: form.elements.port.value});
  form.elements.fingerprint.value = result.fingerprint;
  query('#server-key-trusted').checked = false;
  toast('Отпечаток получен. Сверьте его с ключом сервера перед подтверждением доверия.');
}, '#server-form-error'));
query('#server-form').addEventListener('submit', (event) => {
  event.preventDefault();
  runAction(event.submitter, async () => {
    query('#server-form-error').hidden = true;
    const profile = state.editingServer;
    const result = await request('servers', {...Object.fromEntries(new FormData(event.target)), mode: query('#server-mode').value, action: profile ? 'update' : 'create', id: profile?.id, revision: profile?.revision});
    query('#server-dialog').close();
    event.target.elements.secret.value = '';
    await refreshServers();
    if (profile?.id === state.serverId) await loadServerContext(state.serverId);
    toast(profile ? 'Профиль сервера обновлён.' : 'Сервер добавлен.');
  }, '#server-form-error');
});
query('#servers-table').addEventListener('click', async (event) => {
  const button = event.target.closest('[data-server-action]');
  if (!button || state.busy || state.switching) return;
  const server = state.servers.find((item) => item.id === button.closest('[data-server-id]').dataset.serverId);
  if (!server) return;
  const action = button.dataset.serverAction;
  if (action === 'edit') return openServerForm(server);
  if (action === 'select') { await selectServer(server.id); location.hash = 'overview'; return; }
  await runAction(button, async () => {
    if (action === 'test') {
      try {
        const result = await request('servers', {action: 'test', id: server.id});
        toast(`${server.name}: ${result.message} ${result.nginx.version}`);
      } finally { await refreshServers(); }
    } else if (action === 'delete') {
      if (!await confirmAction(`Удалить ${server.name}?`, `Удалится только профиль ${server.host} в панели. nginx и его конфигурации останутся на сервере.`, true)) return;
      await request('servers', {action: 'delete', id: server.id, revision: server.revision});
      await refreshServers();
      if (state.serverId === server.id) await loadServerContext('local');
      toast('Подключение удалено.');
    }
  });
});

async function initialize() {
  document.documentElement.dataset.theme = localStorage.getItem('snc-theme') || 'dark';
  icons();
  makeCharts();
  try { await refreshServers(); await loadServerContext(state.serverId); }
  catch (error) { showResult('#global-error', error.message); }
  await route();
  let ticks = 0;
  setInterval(async () => {
    if (document.hidden || state.busy || state.polling || state.switching) return;
    state.polling = true;
    try {
      await refreshOverview();
      if (++ticks % 6 === 0) { await refreshHosts(); await refreshServers(); }
      if (state.view === 'overview' && Date.now() - state.trafficFetchedAt >= 60000) await refreshTrafficTop();
      if (state.view === 'logs' && query('#log-live').checked) await loadLogs();
    } catch (error) {
      if (error.stale) return;
      state.serverReady = false;
      showResult('#global-error', 'Нет свежих данных: ' + error.message);
      query('#connection-label').textContent = 'Нет связи с сервером';
    } finally { state.polling = false; }
  }, 5000);
}
initialize();