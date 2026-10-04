const {defineConfig} = require('@playwright/test');

module.exports = defineConfig({
  testDir: './tests',
  timeout: 60000,
  workers: 1,
  fullyParallel: false,
  use: {
    baseURL: 'http://127.0.0.1:7446',
    browserName: 'chromium',
    channel: process.env.SNC_TEST_BROWSER || (process.platform === 'win32' ? 'chrome' : undefined),
    viewport: {width: 1440, height: 1000},
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
  },
  webServer: {command: 'node tools/e2e-server.mjs', url: 'http://127.0.0.1:7446/login/', reuseExistingServer: false, timeout: 90000},
});