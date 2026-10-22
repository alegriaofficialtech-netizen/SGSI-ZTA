// Anonymous external browser check. Does not retrieve or transmit credentials.
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require(process.env.NATIVE_PLAYWRIGHT_MODULE);

(async () => {
  const url = process.env.NATIVE_PUBLIC_URL;
  if (!/^https:\/\/[a-z0-9-]+\.trycloudflare\.com$/.test(url || '')) throw new Error('Expected Quick Tunnel URL');
  const output = path.resolve(__dirname, '../evidence/run-m2-public-windows');
  fs.mkdirSync(output, { recursive: true });
  const browser = await chromium.launch({ headless: true, executablePath: process.env.NATIVE_BROWSER_EXE });
  try {
    const context = await browser.newContext({ reducedMotion: 'reduce', locale: 'es-PE' });
    const page = await context.newPage();
    const errors = []; const origins = new Set();
    page.on('pageerror', error => errors.push(error.message));
    page.on('request', request => origins.add(new URL(request.url()).origin));
    for (const [name, width, height] of [['desktop',1440,900],['tablet',820,1180],['mobile',390,844]]) {
      await page.setViewportSize({ width, height });
      await page.goto(url + '/login');
      await page.getByRole('heading', { name: 'Inicia sesión' }).waitFor();
      await page.getByLabel('Usuario', { exact: true }).waitFor();
      await page.screenshot({ path: path.join(output, 'public-login-' + name + '.png'), fullPage: true });
      if (await page.evaluate(() => document.documentElement.scrollWidth > innerWidth)) throw new Error('Public mobile overflow');
    }
    const csrf = (await context.cookies()).find(cookie => cookie.name === 'sgsi_csrf');
    if (!csrf || !csrf.secure || csrf.sameSite !== 'Strict') throw new Error('Public CSRF cookie security mismatch');
    if (errors.length || [...origins].some(origin => origin !== url)) throw new Error('Browser errors or API origin mismatch');
    const report = { status: 'PASS', location: 'Windows external browser over Cloudflare HTTPS', login_visible: true, same_origin: true, csrf_secure: true, browser_errors: 0, viewports: ['desktop', 'tablet', 'mobile'] };
    fs.writeFileSync(path.join(output, 'public-browser.json'), JSON.stringify(report, null, 2));
    console.log(JSON.stringify(report));
  } finally { await browser.close(); }
})().catch(error => { console.error(error.message); process.exitCode = 1; });
