const {test, expect} = require('@playwright/test');

async function login(page, password = '12345') {
  await page.goto('/');
  await page.getByRole('textbox', {name: 'Логин', exact: true}).fill('admin');
  await page.locator('[name="password"]').fill(password);
  await page.getByRole('button', {name: 'Войти', exact: true}).click();
  await expect(page.locator('#overview-hosts tbody tr')).toHaveCount(6);
}

test('overview renders assets, metrics and responsive layouts', async ({page}) => {
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await login(page);
  await expect(page.locator('#metric-uptime')).toContainText('дн');
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

test('proxy creation, toggles, config validation and logs', async ({page}) => {
  await login(page);
  await page.locator('[data-view="proxies"]').click();
  await page.locator('#add-host').click();
  await page.locator('#host-form [name="name"]').fill('e2e.internal');
  await page.locator('#new-host-target').fill('http://127.0.0.1:3100');
  await page.getByRole('button', {name: 'Создать и включить'}).click();
  await expect(page.locator('#host-dialog')).not.toBeVisible();
  const row = page.locator('#hosts-table tbody tr').filter({hasText: 'e2e.internal'});
  await expect(row).toContainText('Включён');
  await expect(row.getByRole('button', {name: 'Удалить e2e.internal'})).toHaveCount(0);
  await row.getByRole('switch').click();
  await expect(page.locator('#confirm-description')).toContainText('maitenance.html');
  await page.locator('#confirm-accept').click();
  await expect(row).toContainText('Обслуживание');
  await page.screenshot({path: 'test-results/proxies-maintenance.png', fullPage: true, animations: 'disabled'});
  await row.getByRole('switch').click();
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
  await page.locator('[data-view="proxies"]').click();
  await row.getByRole('switch').click();
  await page.locator('#confirm-accept').click();
  await expect(row).toContainText('Обслуживание');
  await expect(row.getByRole('button', {name: 'Удалить e2e.internal'})).toBeVisible();
  await row.getByRole('button', {name: 'Удалить e2e.internal'}).click();
  await expect(page.locator('#confirm-description')).toContainText('Резервная копия');
  await page.locator('#confirm-accept').click();
  await expect(row).toHaveCount(0);
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
  await login(page);
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
  await expect(page.locator('#page-subtitle')).toContainText('192.0.2.16');
  await expect(page.locator('#overview-hosts')).not.toContainText('focuslens.dev');
  await page.locator('[data-view="hosts"]').click();
  const host = page.locator('#hosts-table tbody tr').filter({hasText: 'welcome.demo'});
  await host.getByRole('switch').click();
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
  await page.locator('[data-view="hosts"]').click();
  await expect(page.locator('#hosts-table')).toContainText('focuslens.dev');
  await expect(page.locator('#hosts-table')).not.toContainText('welcome.demo');
  await page.locator('#server-select').selectOption(identifier);
  await page.reload();
  await expect(page.locator('#server-select')).toHaveValue(identifier);
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

test('password change persists across logout and login', async ({page}) => {
  await login(page);
  await page.locator('[data-view="settings"]').click();
  await page.locator('[name="old_password"]').fill('12345');
  await page.locator('[name="new_password1"]').fill('Demo-Changed-2026!Secure');
  await page.locator('[name="new_password2"]').fill('Demo-Changed-2026!Secure');
  await page.getByRole('button', {name: 'Изменить пароль'}).click();
  await expect(page.locator('#password-result')).toContainText('Пароль изменён');
  await page.getByRole('button', {name: 'Выйти', exact: true}).click();
  await expect(page).toHaveURL(/login/);
  await login(page, 'Demo-Changed-2026!Secure');
});