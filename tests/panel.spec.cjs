const {test, expect} = require('@playwright/test');

async function login(page, password = '12345') {
  await page.goto('/');
  await expect(page.locator('.login-heading .mono')).toHaveCount(0);
  await page.getByRole('textbox', {name: 'Логин', exact: true}).fill('admin');
  await page.locator('[name="password"]').fill(password);
  await page.getByRole('button', {name: 'Войти', exact: true}).click();
  await expect(page.locator('#overview-hosts tbody tr')).toHaveCount(6);
}

test('overview renders assets, metrics and responsive layouts', async ({page}) => {
  const errors = [];
  let trafficRequests = 0;
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('request', (request) => { if (new URL(request.url()).pathname === '/api/traffic/') trafficRequests++; });
  await login(page);
  expect(trafficRequests).toBe(1);
  await expect(page.locator('#nginx-version')).toHaveText('nginx/1.24.0');
  await expect(page.locator('#system-name')).toHaveText('Ubuntu · демо');
  await expect(page.locator('#metric-uptime')).toContainText('дн');
  await expect(page.locator('#current-disk')).toContainText('%');
  await expect(page.locator('#disk-capacity')).toHaveText('512 ГБ');
  await expect(page.locator('#disk-bar')).toHaveCSS('width', /.+/);
  await expect(page.locator('#top-traffic-list .traffic-rank')).toHaveCount(5);
  const trafficBytes = await page.locator('#top-traffic-list .traffic-rank').evaluateAll((rows) => rows.map((row) => Number(row.dataset.bytes)));
  expect(trafficBytes).toEqual([...trafficBytes].sort((left, right) => right - left));
  expect(trafficBytes[0]).toBeGreaterThan(trafficBytes[trafficBytes.length - 1]);
  await expect(page.locator('#global-error')).toBeHidden();
  for (const [width, height] of [[1440, 1000], [390, 844], [320, 740]]) {
    await page.setViewportSize({width, height});
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    if (width <= 760) {
      await expect.poll(() => page.locator('#sidebar').evaluate((element) => element.getBoundingClientRect().right <= 0)).toBe(true);
      await expect(page.locator('#menu-toggle')).toBeVisible();
    }
    const checks = await page.evaluate(() => ({
      images: [...document.images].every((image) => image.complete && image.naturalWidth > 0),
      metricFit: [...document.querySelectorAll('.metric-value')].every((element) => element.scrollWidth <= element.clientWidth),
      canvasPixels: [...document.querySelectorAll('canvas')].map((canvas) => {
        const pixels = canvas.getContext('2d').getImageData(0, 0, canvas.width, canvas.height).data;
        let painted = 0;
        for (let offset = 3; offset < pixels.length; offset += 4) if (pixels[offset]) painted++;
        return painted;
      }),
    }));
    expect(checks.images).toBe(true);
    expect(checks.metricFit).toBe(true);
    expect(checks.canvasPixels.every((count) => count > 100)).toBe(true);
    await page.screenshot({path: `test-results/overview-${width}.png`, fullPage: true, animations: 'disabled'});
  }
  await page.setViewportSize({width: 1440, height: 1000});
  await page.getByRole('button', {name: 'Переключить тему'}).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await page.screenshot({path: 'test-results/overview-light.png', fullPage: true});
  expect(errors).toEqual([]);
});

test('panel startup remains usable when the Lucide asset is unavailable', async ({page}) => {
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.stack || error.message));
  await page.route('**/static/vendor/lucide.js**', (route) => route.abort());
  await page.goto('/');
  await page.locator('#reveal-password').click();
  await expect(page.locator('[name="password"]')).toHaveAttribute('type', 'text');
  await login(page);
  await expect(page.locator('#overview-hosts tbody tr')).toHaveCount(6);
  await page.locator('[data-view="servers"]').click();
  await expect(page.locator('#servers-table tbody tr').first()).toBeVisible();
  await expect(page.locator('#server-select')).toBeEnabled();
  await expect(page.locator('#server-select option').first()).not.toHaveValue('');
  expect(errors).toEqual([]);
});

test('about page is the bottom service menu entry and explains license and billing', async ({page}) => {
  await login(page);
  await expect(page.locator('.sidebar-bottom [data-view="about"]')).toBeVisible();
  await page.locator('.sidebar-bottom [data-view="about"]').click();
  await expect(page.locator('#page-title')).toHaveText('О программе');
  await expect(page.locator('#view-about')).toContainText(require('../package.json').version);
  await expect(page.locator('#view-about')).toContainText('распространяется бесплатно');
  await expect(page.locator('#view-about')).toContainText('клиентский биллинг');
  await expect(page.locator('#view-about a[href="https://github.com/DgekStr/SmallnGinxControl"]')).toBeVisible();
  await expect(page.locator('#about-description')).toHaveAttribute('href', 'https://github.com/DgekStr/SmallnGinxControl/blob/main/doc/help.md');
  await expect(page.locator('#view-about a[href$="/LICENSE"]')).toBeVisible();
  await expect(page.locator('#view-about a[href="https://github.com/DgekStr"]')).toHaveText('DgekStr');
});

test('proxy creation, toggles, config validation and logs', async ({page}) => {
  await login(page);
  await page.locator('[data-view="proxies"]').click();
  await page.locator('#add-host').click();
  await page.locator('#host-form [name="name"]').fill('e2e.internal');
  await expect(page.locator('#host-ssl-issue')).toBeDisabled();
  await page.locator('#new-host-target').fill('http://127.0.0.1:3100');
  await page.getByRole('button', {name: 'Создать и включить'}).click();
  await expect(page.locator('#host-dialog')).not.toBeVisible();
  const row = page.locator('#hosts-table tbody tr').filter({hasText: 'e2e.internal'});
  await expect(row).toContainText('Включён');
  await expect(row.getByRole('button', {name: 'Удалить e2e.internal'})).toBeVisible();
  await row.locator('[data-action="toggle"]').click();
  await expect(page.locator('#confirm-description')).toContainText('maitenance.html');
  await page.locator('#confirm-accept').click();
  await expect(row).toContainText('Обслуживание');
  await page.screenshot({path: 'test-results/proxies-maintenance.png', fullPage: true, animations: 'disabled'});
  await row.locator('[data-action="toggle"]').click();
  await page.locator('#confirm-accept').click();
  await expect(row).toContainText('Включён');
  await row.locator('[data-action="nonpayment"]').click();
  await expect(page.locator('#confirm-accept')).toHaveText('Отключить');
  await expect(page.locator('#confirm-cancel')).toHaveText('Отменить');
  await expect(page.locator('#confirm-description')).toContainText('специальную страницу о неоплате');
  await page.locator('#confirm-cancel').click();
  await expect(row).toContainText('Включён');
  await row.locator('[data-action="nonpayment"]').click();
  await page.locator('#confirm-accept').click();
  await expect(row).toContainText('Отключён: неоплата');
  await row.locator('[data-action="edit"]').click();
  await expect(page.locator('#host-config')).toHaveValue(/alias .*smallnginxcontrol-nonpayment/);
  await expect(page.locator('#host-config')).not.toHaveValue(/<!doctype html/i);
  await page.locator('#editor-dialog .modal-heading [data-close="editor-dialog"]').click();
  await row.locator('[data-action="nonpayment"]').click();
  await expect(page.locator('#confirm-accept')).toHaveText('Восстановить');
  await page.locator('#confirm-accept').click();
  await expect(row).toContainText('Включён');
  await row.locator('[data-action="edit"]').click();
  const original = await page.locator('#host-config').inputValue();
  await page.locator('#host-config').fill('server {');
  await page.locator('#save-host-config').click();
  await expect(page.locator('#editor-error')).toBeVisible();
  await page.locator('#host-config').fill(original.replace('3100', '3101'));
  await page.locator('#save-host-config').click();
  await expect(page.locator('#editor-dialog')).not.toBeVisible();
  await expect(row).toContainText('3101');
  await row.locator('[data-action="logs"]').click();
  await expect(page.locator('#view-logs')).toBeVisible();
  await expect(page.locator('#log-content')).toContainText('Журнал ещё не создан');
  await page.locator('#log-host').selectOption('conf.d/api.focuslens.dev.conf');
  await expect(page.locator('#log-content')).toContainText('GET');
  const download = page.waitForEvent('download');
  await page.locator('#download-logs').click();
  expect((await download).suggestedFilename()).toBe('nginx-access.log');
  const xmlDownload = page.waitForEvent('download');
  await page.locator('#export-logs-xml').click();
  expect((await xmlDownload).suggestedFilename()).toBe('nginx-access.xml');
  await page.locator('[data-view="proxies"]').click();
  await expect(row.getByRole('button', {name: 'Удалить e2e.internal'})).toBeVisible();
  await row.getByRole('button', {name: 'Удалить e2e.internal'}).click();
  await expect(page.locator('#confirm-description')).toContainText('Хост активен');
  await expect(page.locator('#confirm-description')).toContainText('Резервная копия');
  await page.locator('#confirm-accept').click();
  await expect(row).toHaveCount(0);
});

test('nonpayment contact text can be edited from a settings modal', async ({page}) => {
  await login(page);
  await page.locator('[data-view="settings"]').click();
  await expect(page.locator('#nonpayment-contact-preview')).toHaveText('Свяжитесь с администратором хостинга');
  await page.locator('#nonpayment-contact-edit').click();
  await page.locator('#nonpayment-contact-input').fill('Свяжитесь с администратором');
  await page.locator('#nonpayment-contact-form button[type="submit"]').click();
  await expect(page.locator('#nonpayment-contact-preview')).toHaveText('Свяжитесь с администратором');
  await page.locator('#nonpayment-contact-edit').click();
  await page.locator('#nonpayment-contact-input').fill('Свяжитесь с администратором хостинга');
  await page.locator('#nonpayment-contact-form button[type="submit"]').click();
  await expect(page.locator('#nonpayment-contact-preview')).toHaveText('Свяжитесь с администратором хостинга');
});

test('certificate expiry is shown only for HTTPS hosts', async ({page}) => {
  await login(page);
  await page.locator('[data-view="hosts"]').click();
  const markup = await page.evaluate(() => hostTable([
    {id: 'conf.d/soon.example.com.conf', name: 'soon.example.com', domains: ['soon.example.com'], kind: 'host', target: '/var/www/soon', tls: true, certificate_days: 12, enabled: true, toggleable: true, servers: 1},
    {id: 'conf.d/expired.example.com.conf', name: 'expired.example.com', domains: ['expired.example.com'], kind: 'host', target: '/var/www/expired', tls: true, certificate_days: -3, enabled: true, toggleable: true, servers: 1},
    {id: 'conf.d/http.example.com.conf', name: 'http.example.com', domains: ['http.example.com'], kind: 'host', target: '/var/www/http', tls: false, certificate_days: 2, enabled: true, toggleable: true, servers: 1},
  ]));
  await page.locator('#hosts-table').evaluate((element, html) => {
    element.innerHTML = html;
  }, markup);
  const soon = page.locator('#hosts-table tbody tr').filter({hasText: 'soon.example.com'});
  const expired = page.locator('#hosts-table tbody tr').filter({hasText: 'expired.example.com'});
  const http = page.locator('#hosts-table tbody tr').filter({hasText: 'http.example.com'});
  await expect(soon.locator('.certificate-expiry')).toHaveText('12 дн.');
  await expect(soon.locator('.certificate-expiry')).toHaveClass(/warning/);
  await expect(expired.locator('.certificate-expiry')).toHaveText('Просрочен 3 дн.');
  await expect(expired.locator('.certificate-expiry')).toHaveClass(/expired/);
  await expect(http.locator('.certificate-expiry')).toHaveCount(0);
});

test('HTTPS lock opens certificate details and HTTP has no certificate action', async ({page}) => {
  await login(page);
  await page.locator('[data-view="hosts"]').click();
  await page.evaluate(() => {
    state.hosts = [
      {id: 'conf.d/secure.example.com.conf', name: 'secure.example.com', domains: ['secure.example.com'], kind: 'host', target: '/var/www/secure', tls: true, certificate_days: 12, certificate: {subject: 'CN=secure.example.com', issuer: 'CN=Example CA', serial: '01AB', valid_from: '2026-10-04T00:00:00+00:00', valid_until: '2026-10-20T00:00:00+00:00', file: '/etc/letsencrypt/live/secure.example.com/fullchain.pem', days_remaining: 12}, enabled: true, toggleable: true, servers: 1},
      {id: 'conf.d/plain.example.com.conf', name: 'plain.example.com', domains: ['plain.example.com'], kind: 'host', target: '/var/www/plain', tls: false, enabled: true, toggleable: true, servers: 1},
    ];
    state.view = 'hosts';
    renderHosts();
  });
  const secure = page.locator('#hosts-table tbody tr').filter({hasText: 'secure.example.com'});
  await secure.getByRole('button', {name: 'Сведения о сертификате secure.example.com'}).click();
  const dialog = page.locator('#certificate-dialog');
  await expect(dialog).toBeVisible();
  await expect(dialog.locator('#certificate-title')).toHaveText('TLS-сертификат · secure.example.com');
  await expect(dialog.locator('#certificate-subject')).toHaveText('CN=secure.example.com');
  await expect(dialog.locator('#certificate-issuer')).toHaveText('CN=Example CA');
  await expect(dialog.locator('#certificate-valid-from')).not.toHaveText('—');
  await expect(dialog.locator('#certificate-valid-until')).not.toHaveText('—');
  await expect(dialog.locator('#certificate-validity')).toHaveText('Действителен, осталось 12 дн.');
  const plain = page.locator('#hosts-table tbody tr').filter({hasText: 'plain.example.com'});
  await expect(plain.locator('.protocol-button')).toHaveCount(0);
  await expect(plain.locator('.protocol')).toHaveText('HTTP');
});

test('domain registration expiry uses 30, 20 and 10 day warning thresholds', async ({page}) => {
  await login(page);
  const markup = await page.evaluate(() => hostTable([
    {id: 'soon', name: '*.dgek.ru', domains: ['*.dgek.ru'], kind: 'host', target: '/var/www/soon', domain_expiry: [{domain: 'dgek.ru', days: 29}], enabled: true, toggleable: true, servers: 1},
    {id: 'urgent', name: 'shop.example.com', domains: ['shop.example.com'], kind: 'host', target: '/var/www/urgent', domain_expiry: [{domain: 'example.com', days: 19}], enabled: true, toggleable: true, servers: 1},
    {id: 'critical', name: 'api.example.net', domains: ['api.example.net'], kind: 'proxy', target: 'http://127.0.0.1:3000', domain_expiry: [{domain: 'example.net', days: 9}], enabled: true, toggleable: true, servers: 1},
    {id: 'safe', name: 'docs.example.org', domains: ['docs.example.org'], kind: 'host', target: '/var/www/docs', domain_expiry: [{domain: 'example.org', days: 30}], enabled: true, toggleable: true, servers: 1},
    {id: 'pending', name: 'new.example.dev', domains: ['new.example.dev'], kind: 'host', target: '/var/www/new', domain_expiry: [{domain: 'example.dev', status: 'checking', days: null}], enabled: true, toggleable: true, servers: 1},
    {id: 'internal', name: 'grafana.internal', domains: ['grafana.internal'], kind: 'proxy', target: 'http://127.0.0.1:3000', domain_expiry: [], enabled: true, toggleable: true, servers: 1},
  ]));
  await page.locator('#hosts-table').evaluate((element, html) => { element.innerHTML = html; }, markup);
  await expect(page.locator('#hosts-table tr[data-id="soon"] .domain-expiry')).toHaveClass(/warning/);
  await expect(page.locator('#hosts-table tr[data-id="urgent"] .domain-expiry')).toHaveClass(/urgent/);
  await expect(page.locator('#hosts-table tr[data-id="critical"] .domain-expiry')).toHaveClass(/critical/);
  await expect(page.locator('#hosts-table tr[data-id="safe"] .domain-expiry')).not.toHaveClass(/warning|urgent|critical/);
  await expect(page.locator('#hosts-table tr[data-id="pending"] .domain-expiry')).toHaveText('Проверяется…');
  await expect(page.locator('#hosts-table tr[data-id="pending"] .domain-expiry')).toHaveClass(/pending/);
  await expect(page.locator('#hosts-table tr[data-id="internal"] .domain-expiry')).toHaveCount(0);
});

test('hosts and proxies are sorted alphabetically', async ({page}) => {
  await login(page);
  for (const view of ['hosts', 'proxies']) {
    await page.locator(`[data-view="${view}"]`).click();
    const names = await page.locator('#hosts-table .domain-name').allTextContents();
    expect(names).toEqual([...names].sort((left, right) => left.localeCompare(right, 'ru', {sensitivity: 'base'})));
  }
});

test('host tables show sampled download and upload traffic', async ({page}) => {
  await login(page);
  await page.locator('[data-view="hosts"]').click();
  const markup = await page.evaluate(() => hostTable([
    {id: 'conf.d/known.example.com.conf', name: 'known.example.com', domains: ['known.example.com'], kind: 'host', target: '/var/www/known', tls: false, enabled: true, toggleable: true, servers: 1, traffic: {downloaded_bytes: 1024, uploaded_bytes: 512, uploaded_complete: true}},
    {id: 'conf.d/unknown.example.com.conf', name: 'unknown.example.com', domains: ['unknown.example.com'], kind: 'host', target: '/var/www/unknown', tls: false, enabled: true, toggleable: true, servers: 1, traffic: {downloaded_bytes: 2500, uploaded_bytes: null, uploaded_complete: false}},
  ]));
  await page.locator('#hosts-table').evaluate((element, html) => { element.innerHTML = html; }, markup);
  const known = page.locator('#hosts-table tbody tr[data-id="conf.d/known.example.com.conf"] .host-traffic');
  const unknown = page.locator('#hosts-table tbody tr[data-id="conf.d/unknown.example.com.conf"] .host-traffic');
  await expect(known).toContainText('↓ 1 КБ');
  await expect(known).toContainText('↑ 512 Б');
  await expect(unknown).toContainText('↓ 2,5 КБ');
  await expect(unknown).toContainText('↑ —');
});

test('host link emoji uses TLS and listener port', async ({page}) => {
  await login(page);
  const markup = await page.evaluate(() => hostTable([
    {id: 'conf.d/secure.example.com.conf', name: 'secure.example.com', domains: ['secure.example.com'], kind: 'host', target: '/var/www/secure', listen: '80, 443 ssl', tls: true, enabled: true, toggleable: true, servers: 1},
    {id: 'conf.d/dev.example.com.conf', name: 'dev.example.com', domains: ['dev.example.com'], kind: 'proxy', target: 'http://127.0.0.1:3000', listen: '127.0.0.1:8088', tls: false, enabled: true, toggleable: true, servers: 1},
    {id: 'conf.d/wildcard.example.com.conf', name: '*.example.com', domains: ['*.example.com'], kind: 'host', target: '/var/www/wildcard', listen: '80', tls: false, enabled: true, toggleable: true, servers: 1},
  ]));
  await page.locator('#hosts-table').evaluate((element, html) => { element.innerHTML = html; }, markup);
  await expect(page.locator('#hosts-table tr[data-id="conf.d/secure.example.com.conf"] .host-open-link')).toHaveAttribute('href', 'https://secure.example.com/');
  await expect(page.locator('#hosts-table tr[data-id="conf.d/dev.example.com.conf"] .host-open-link')).toHaveAttribute('href', 'http://dev.example.com:8088/');
  await expect(page.locator('#hosts-table tr[data-id="conf.d/wildcard.example.com.conf"] .host-open-link')).toHaveCount(0);
  const hostLink = page.locator('#hosts-table tr[data-id="conf.d/secure.example.com.conf"] .host-open-link');
  await expect(hostLink).toHaveText('🔗');
  const lineOffset = await page.locator('#hosts-table tr[data-id="conf.d/secure.example.com.conf"] .domain-name').evaluate((name) => Math.abs(name.getBoundingClientRect().top - name.nextElementSibling.getBoundingClientRect().top));
  expect(lineOffset).toBeLessThan(2);
});

test('main config, reload confirmation and audit', async ({page}) => {
  await login(page);
  await page.locator('[data-view="config"]').click();
  await expect(page.locator('#main-config')).toHaveValue(/worker_processes/);
  const original = await page.locator('#main-config').inputValue();
  await page.locator('#main-config').fill(original.replace('4096', '2048'));
  await page.locator('#save-config').click();
  await page.locator('#confirm-accept').click();
  await expect(page.locator('#config-result')).toHaveClass(/success/);
  await page.locator('#main-config').fill('events {');
  await page.locator('#reset-config').click();
  await page.locator('#confirm-accept').click();
  await expect(page.locator('#main-config')).toHaveValue(/2048/);
  await page.locator('#test-config').click();
  await expect(page.locator('#toast-region')).toContainText('синтаксис Crossplane корректен');
  await page.locator('#reload-nginx').click();
  await page.locator('#confirm-cancel').click();
  await page.locator('[data-view="audit"]').click();
  await expect(page.locator('#audit-table')).toContainText('Изменение конфигурации');
});

test('mobile navigation and search', async ({page}) => {
  await page.setViewportSize({width: 390, height: 844});
  await login(page);
  await page.locator('#menu-toggle').click();
  await page.locator('[data-view="proxies"]').click();
  await expect(page.locator('#sidebar')).not.toHaveClass(/open/);
  await page.locator('#host-search').fill('staging');
  await expect(page.locator('#hosts-table tbody tr')).toHaveCount(1);
  await page.locator('[data-filter="enabled"]').click();
  await expect(page.locator('#hosts-table')).toContainText('Конфигурации не найдены');
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

test('server profiles isolate hosts, config, logs and tab selection', async ({page}) => {
  await page.route('**/api/overview/**', async (route) => {
    const response = await route.fetch();
    const payload = await response.json();
    const serverId = new URL(route.request().url()).searchParams.get('server');
    const current = payload.metrics.current || {cpu: 10, memory: 20, rx_rate: 0, tx_rate: 0, rx_mb: 0, tx_mb: 0, uptime: 3600, created_at: new Date().toISOString()};
    payload.metrics.current = {...current, disk_used_bytes: serverId === 'local' ? 100 : 900, disk_total_bytes: 1000};
    payload.metrics.peaks = payload.metrics.peaks || {cpu: 10, rx: 0, tx: 0};
    payload.metrics.history = payload.metrics.history || [];
    payload.metrics.since = payload.metrics.since || current.created_at;
    await route.fulfill({response, json: payload});
  });
  await login(page);
  await expect(page.locator('#current-disk')).toHaveText('10%');
  await page.locator('[data-view="servers"]').click();
  await page.locator('#add-server').click();
  await page.locator('#server-mode').selectOption('demo');
  await page.locator('#server-form [name="name"]').fill('Nginx demo 02');
  await page.locator('#server-form [name="host"]').fill('192.0.2.16');
  await page.getByRole('button', {name: 'Сохранить сервер'}).click();
  await expect(page.locator('#server-dialog')).not.toBeVisible();
  const row = page.locator('#servers-table tr').filter({hasText: 'Nginx demo 02'});
  await expect(row).toBeVisible();
  const identifier = await row.getAttribute('data-server-id');
  await row.locator('[data-server-action="test"]').click();
  await expect(page.locator('#toast-region')).toContainText('Соединение установлено');
  await row.locator('[data-server-action="select"]').click();
  await expect(page.locator('#overview-hosts tbody tr')).toHaveCount(2);
  await expect(page.locator('#current-disk')).toHaveText('90%');
  await expect(page.locator('#page-subtitle')).toContainText('192.0.2.16');
  await expect(page.locator('#overview-hosts')).not.toContainText('focuslens.dev');
  await page.locator('[data-view="hosts"]').click();
  const host = page.locator('#hosts-table tbody tr').filter({hasText: 'welcome.demo'});
  await host.locator('[data-action="toggle"]').click();
  await expect(page.locator('#confirm-description')).toContainText('192.0.2.16');
  await page.locator('#confirm-accept').click();
  await expect(host).toContainText('Отключён');
  await page.locator('[data-view="config"]').click();
  await expect(page.locator('#main-config')).toHaveValue(/1024/);
  await page.locator('#main-config').fill('events {');
  await page.locator('#server-select').selectOption('local');
  await page.locator('#confirm-cancel').click();
  await expect(page.locator('#server-select')).toHaveValue(identifier);
  await expect(page.locator('#main-config')).toHaveValue('events {');
  await page.locator('#server-select').selectOption('local');
  await page.locator('#confirm-accept').click();
  await expect(page.locator('#main-config')).toHaveValue(/2048|4096/);
  await expect(page.locator('#current-disk')).toHaveText('10%');
  await page.locator('[data-view="hosts"]').click();
  await expect(page.locator('#hosts-table')).toContainText('focuslens.dev');
  await expect(page.locator('#hosts-table')).not.toContainText('welcome.demo');
  await page.locator('#server-select').selectOption(identifier);
  await page.reload();
  await expect(page.locator('#server-select')).toHaveValue(identifier);
  await expect(page.locator('#current-disk')).toHaveText('90%');
  await expect(page.locator('#hosts-table')).toContainText('welcome.demo');
  await page.locator('[data-view="logs"]').click();
  await expect(page.locator('#log-content')).toContainText('512');
  await expect(page.locator('#log-content')).not.toContainText('Mozilla');
  await page.locator('[data-view="servers"]').click();
  await row.locator('[data-server-action="edit"]').click();
  await page.locator('#server-form [name="name"]').fill('Nginx demo 02 renamed');
  await page.getByRole('button', {name: 'Сохранить сервер'}).click();
  await expect(page.locator('#server-dialog')).not.toBeVisible();
  await expect(row).toContainText('renamed');
  await page.screenshot({path: 'test-results/servers-desktop.png', fullPage: true});
  await page.setViewportSize({width: 390, height: 844});
  await expect(page.locator('#server-select')).toBeVisible();
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({path: 'test-results/servers-mobile.png', fullPage: true, animations: 'disabled'});
  await page.setViewportSize({width: 1440, height: 1000});
  await row.locator('[data-server-action="delete"]').click();
  await page.locator('#confirm-accept').click();
  await expect(row).toHaveCount(0);
  await expect(page.locator('#server-select')).toHaveValue('local');
});

test('unavailable SSH profile never falls back to local server', async ({page}) => {
  await login(page);
  await page.locator('[data-view="servers"]').click();
  await page.locator('#add-server').click();
  await page.locator('#server-form [name="name"]').fill('Unavailable SSH');
  await page.locator('#server-form [name="host"]').fill('127.0.0.1');
  await page.locator('#server-form [name="port"]').fill('1');
  await page.locator('#server-auth').selectOption('password');
  await page.locator('#server-form [name="secret"]').fill('synthetic-e2e-password');
  await page.locator('#server-form [name="fingerprint"]').fill('SHA256:' + 'x'.repeat(43));
  await page.locator('#server-key-trusted').check();
  await page.screenshot({path: 'test-results/server-ssh-form.png', fullPage: true});
  await page.getByRole('button', {name: 'Сохранить сервер'}).click();
  await expect(page.locator('#server-dialog')).not.toBeVisible();
  const row = page.locator('#servers-table tr').filter({hasText: 'Unavailable SSH'});
  await row.locator('[data-server-action="select"]').click();
  await expect(page.locator('#global-error')).toContainText('SSH');
  await expect(page.locator('#page-subtitle')).toContainText('127.0.0.1');
  await expect(page.locator('#overview-hosts tbody tr')).toHaveCount(0);
  await expect(page.locator('#metric-uptime')).toHaveText('—');
  await expect(page.locator('#demo-banner')).toBeHidden();
  await page.locator('[data-view="servers"]').click();
  await row.locator('[data-server-action="delete"]').click();
  await page.locator('#confirm-accept').click();
  await expect(page.locator('#server-select')).toHaveValue('local');
  await expect(page.locator('#overview-hosts tbody tr')).toHaveCount(6);
});

test('nginx log XML export preserves sources and escapes log text', async ({page}) => {
  await login(page);
  const result = await page.evaluate(() => {
    state.serverId = 'local';
    state.logKind = 'error';
    state.logSources = ['/var/log/nginx/error.log'];
    state.logContent = '[error.log]\nupstream sent <bad> & "quoted" data';
    const xml = buildLogsXml();
    const parsed = new DOMParser().parseFromString(xml, 'application/xml');
    return {
      hasParserError: Boolean(parsed.querySelector('parsererror')),
      kind: parsed.documentElement.getAttribute('kind'),
      path: parsed.querySelector('logfile')?.getAttribute('path'),
      entry: parsed.querySelector('entry')?.textContent,
    };
  });
  expect(result).toEqual({hasParserError: false, kind: 'error', path: '/var/log/nginx/error.log', entry: 'upstream sent <bad> & "quoted" data'});
});

test('administrator can start TOTP enrollment from settings modal', async ({page}) => {
  await login(page);
  await page.locator('[data-view="settings"]').click();
  await expect(page.locator('#two-factor-status')).toHaveText('Не подключена');
  await page.locator('#two-factor-toggle').click();
  const dialog = page.locator('#two-factor-dialog');
  await expect(dialog).toBeVisible();
  await expect(dialog.locator('#two-factor-instructions')).toContainText('Google Authenticator');
  await expect(dialog.locator('#two-factor-qr')).toHaveAttribute('src', /^data:image\/svg\+xml;base64,/);
  await expect(dialog.locator('#two-factor-secret')).toHaveValue(/^[A-Z2-7]{32}$/);
  await dialog.locator('#two-factor-cancel').click();
  await expect(dialog).not.toBeVisible();
  await expect(page.locator('#two-factor-status')).toHaveText('Не подключена');
});

test('access-log TOP-5 sample size is configurable up to 100 MB', async ({page}) => {
  await login(page);
  await page.locator('[data-view="settings"]').click();
  const sampleSize = page.locator('#access-log-sample-mib');
  try {
    await expect(sampleSize).toHaveAttribute('max', '100');
    expect(Number(await sampleSize.inputValue())).toBeCloseTo(0.131072, 6);
    await sampleSize.fill('1.5');
    await page.locator('#access-log-sample-form button[type="submit"]').click();
    await expect(page.locator('#access-log-sample-result')).toContainText('Настройки сохранены');
    await page.locator('[data-view="overview"]').click();
    await page.locator('[data-view="settings"]').click();
    expect(Number(await sampleSize.inputValue())).toBeCloseTo(1.5, 6);
  } finally {
    await page.locator('#access-log-sample-result').evaluate((element) => { element.hidden = true; element.textContent = ''; });
    await sampleSize.fill('0.131072');
    await page.locator('#access-log-sample-form button[type="submit"]').click();
    await expect(page.locator('#access-log-sample-result')).toBeVisible();
    await expect(page.locator('#access-log-sample-result')).toContainText('Настройки сохранены');
    await expect(page.locator('#access-log-sample-form button[type="submit"]')).toBeEnabled();
  }
});

test('Mattermost and domain scheduler settings render before the traffic sample controls', async ({page}) => {
  await login(page);
  const posts = [];
  await page.route('**/api/settings/**', async (route) => {
    if (route.request().method() !== 'POST') return route.continue();
    const payload = route.request().postDataJSON();
    posts.push(payload);
    const message = payload.action === 'test_mattermost_webhook' ? 'Проверочное сообщение отправлено.' : 'Настройки сохранены.';
    await route.fulfill({status: 200, contentType: 'application/json', body: JSON.stringify({ok: true, message})});
  });
  await page.locator('[data-view="settings"]').click();
  const orderedSections = page.locator('.mattermost-webhook-section, .domain-expiry-scheduler-section, .access-log-sample-section');
  await expect(orderedSections).toHaveCount(3);
  const topPositions = await orderedSections.evaluateAll((sections) => sections.map((section) => section.getBoundingClientRect().top));
  expect(topPositions[0]).toBeLessThan(topPositions[2]);
  expect(topPositions[1]).toBeLessThan(topPositions[2]);
  await expect(page.locator('#mattermost-webhook-url')).toHaveAttribute('type', 'password');
  await expect(page.locator('#domain-expiry-scheduler-enabled')).toBeDisabled();
  await expect(page.locator('#domain-expiry-interval-days')).toHaveValue('1');
  await expect(page.locator('#domain-expiry-send-time')).toHaveValue('09:00');

  await page.locator('#mattermost-webhook-url').fill('https://mattermost.example/hooks/test-token');
  await page.locator('#mattermost-webhook-test').click();
  await expect(page.locator('#mattermost-webhook-result')).toContainText('Проверочное сообщение отправлено');
  await page.locator('#mattermost-webhook-form button[type="submit"]').click();
  await expect(page.locator('#mattermost-webhook-result')).toContainText('Настройки сохранены');
  expect(posts).toEqual([
    {action: 'test_mattermost_webhook', mattermost_webhook_url: 'https://mattermost.example/hooks/test-token'},
    {mattermost_webhook_url: 'https://mattermost.example/hooks/test-token'},
  ]);
});

test('switching server clears previous SSD usage while new metrics load', async ({page}) => {
  await login(page);
  await expect(page.locator('#current-disk')).toBeAttached();
  const previousDisk = await page.locator('#current-disk').textContent();
  await page.evaluate(() => clearServerData());
  await expect(page.locator('#current-disk')).toHaveText('—');
  const width = await page.locator('#disk-bar').evaluate((element) => element.style.width);
  expect(width).toBe('0%');
  expect(previousDisk).toContain('%');
});

for (const width of [1440, 390]) {
  test(`API integration generates, copies, rotates and revokes a key at ${width}px`, async ({page}) => {
    await login(page);
    await page.locator('[data-view="settings"]').click();
    await expect(page.locator('#api-key-status')).toHaveText('Не создан');
    await page.setViewportSize({width, height: 1000});
    await expect(page.locator('#api-key-access')).toHaveValue('read');
    await expect(page.locator('#api-key-revoke')).toBeDisabled();
    await page.evaluate(() => Object.defineProperty(navigator, 'clipboard', {configurable: true, value: {writeText: async (value) => { window.copiedApiKey = value; }}}));
    await page.locator('#api-key-generate').click();
    const dialog = page.locator('#api-key-dialog');
    const secret = page.locator('#api-key-secret');
    await expect(dialog).toBeVisible();
    await expect(secret).toHaveValue(/^snc_[A-Za-z0-9_-]{43}$/);
    await expect(secret).toHaveAttribute('type', 'password');
    const oldKey = await secret.inputValue();
    await page.locator('#api-key-show').click();
    await expect(secret).toHaveAttribute('type', 'text');
    await page.locator('#api-key-copy').click();
    await expect(page.locator('#api-key-copy-result')).toContainText('Ключ скопирован');
    expect(await page.evaluate((key) => window.copiedApiKey === key, oldKey)).toBe(true);
    const layout = await dialog.evaluate((element) => {
      const modal = element.getBoundingClientRect();
      const copy = element.querySelector('#api-key-copy').getBoundingClientRect();
      return {overflow: document.documentElement.scrollWidth > innerWidth, copyFits: copy.right <= modal.right};
    });
    expect(layout).toEqual({overflow: false, copyFits: true});
    await dialog.locator('.modal-footer button').click();
    await expect(secret).toHaveValue('');
    await expect(secret).toHaveAttribute('type', 'password');
    await page.reload();
    await expect(page.locator('#api-key-status')).toHaveText('Активен');
    await expect(secret).toHaveValue('');
    await page.locator('#api-key-access').selectOption('manage');
    await page.locator('#api-key-generate').click();
    await expect(page.locator('#confirm-dialog')).toBeVisible();
    await page.locator('#confirm-cancel').click();
    expect((await page.request.get('/api/servers/', {headers: {Authorization: 'Bearer ' + oldKey}})).status()).toBe(200);
    await page.locator('#api-key-generate').click();
    await page.locator('#confirm-accept').click();
    await expect(dialog).toBeVisible();
    const newKey = await secret.inputValue();
    expect(newKey).not.toBe(oldKey);
    expect((await page.request.get('/api/servers/', {headers: {Authorization: 'Bearer ' + oldKey}})).status()).toBe(401);
    expect((await page.request.get('/api/servers/', {headers: {Authorization: 'Bearer ' + newKey}})).status()).toBe(200);
    await page.keyboard.press('Escape');
    await expect(dialog).not.toBeVisible();
    await expect(secret).toHaveValue('');
    await page.locator('#api-key-revoke').click();
    await page.locator('#confirm-accept').click();
    await expect(page.locator('#api-key-status')).toHaveText('Не создан');
    await expect(page.locator('#api-key-revoke')).toBeDisabled();
    expect((await page.request.get('/api/servers/', {headers: {Authorization: 'Bearer ' + newKey}})).status()).toBe(401);
  });
}

test('password change persists across logout and login', async ({page}) => {
  await login(page);
  await page.locator('[data-view="settings"]').click();
  await expect(page.locator('#view-settings .settings-layout > .settings-section')).toHaveCount(10);
  await expect(page.locator('#view-settings .settings-layout > .settings-section h2')).toHaveText(['Перезапуск nginx', 'Двухфакторная защита', 'Сессия администратора', 'API-интеграция', 'Хранение логов', 'Уведомления Mattermost', 'Сообщение при неоплате', 'Проверка доменов', 'TOP-5 по трафику', 'HTTPS панели']);
  await expect(page.locator('#panel-tls-status')).toHaveText('Только production');
  await expect(page.locator('#panel-tls-renew')).toBeDisabled();
  await expect(page.locator('#panel-tls-download')).toBeDisabled();
  await expect(page.locator('#traffic-maintenance-status')).toHaveText('Работает');
  await expect(page.locator('#traffic-maintenance-path')).toHaveText('/var/www/html/maitenance.html');
  await expect(page.locator('#traffic-maintenance-toggle')).toBeDisabled();
  await expect(page.locator('#password-form')).toBeVisible();
  await expect(page.locator('#log-retention-days')).toHaveValue('30');
  await expect(page.locator('#traffic-maintenance-status')).toHaveText('Работает');
  await expect(page.locator('#traffic-maintenance-toggle')).toBeDisabled();
  await expect(page.locator('#session-timeout-hours')).toHaveValue('24');
  expect(Number(await page.locator('#access-log-sample-mib').inputValue())).toBeCloseTo(0.131072, 6);
  await page.locator('#session-timeout-hours').fill('36');
  await page.locator('#session-timeout-form button[type="submit"]').click();
  await expect(page.locator('#session-timeout-result')).toContainText('Срок admin-сессии сохранён');
  await page.locator('#log-retention-days').fill('45');
  await page.locator('#log-retention-form button[type="submit"]').click();
  await expect(page.locator('#log-retention-result')).toContainText('Срок хранения журналов сохранён');
  await page.locator('[name="old_password"]').fill('12345');
  await page.locator('[name="new_password1"]').fill('Demo-Changed-2026!Secure');
  await page.locator('[name="new_password2"]').fill('Demo-Changed-2026!Secure');
  await page.getByRole('button', {name: 'Изменить пароль'}).click();
  await expect(page.locator('#password-result')).toContainText('Пароль изменён');
  await page.getByRole('button', {name: 'Выйти', exact: true}).click();
  await expect(page).toHaveURL(/login/);
  await login(page, 'Demo-Changed-2026!Secure');
});
