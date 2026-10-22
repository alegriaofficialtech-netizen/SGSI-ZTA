// Isolated M2 browser QA with ephemeral credentials and masked enrollment artifacts.
const fs = require('node:fs');
const path = require('node:path');
const cp = require('node:child_process');
const { chromium } = require(process.env.NATIVE_PLAYWRIGHT_MODULE);
function otp(secret, offset = 0) {
  return cp.execFileSync(process.env.NATIVE_UI_PYTHON, ['-c', 'import sys,json,time,pyotp; d=json.load(sys.stdin); print(pyotp.TOTP(d["secret"]).at(time.time()+d["offset"]))'], { input: JSON.stringify({ secret, offset }), encoding: 'utf8', windowsHide: true }).trim();
}
(async () => {
  const browser = await chromium.launch({ headless: true, executablePath: process.env.NATIVE_BROWSER_EXE });
  try {
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, locale: 'es-PE', timezoneId: 'America/Bogota', reducedMotion: 'reduce' });
    const page = await context.newPage();
    const errors = []; const checks = [];
    page.on('pageerror', error => errors.push(error.message));
    const output = process.env.NATIVE_UI_OUTPUT;
    async function shots(prefix, mask = []) {
      for (const [size, width, height] of [['desktop',1440,900],['tablet',820,1180],['mobile',390,844]]) {
        await page.setViewportSize({ width, height });
        await page.screenshot({ path: path.join(output, `${prefix}-${size}.png`), fullPage: true, mask, maskColor: '#e7eeea' });
        if (await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth)) throw new Error(`Overflow: ${prefix} ${size}`);
      }
      await page.setViewportSize({ width:1440,height:900 });
    }
    async function passwordLogin(username) {
      await page.getByLabel('Usuario', { exact:true }).fill(username);
      await page.getByLabel('Contraseña', { exact:true }).fill(process.env.NATIVE_UI_PASSWORD);
      await page.getByRole('button', { name:'Entrar al laboratorio' }).click();
    }
    await page.goto('http://127.0.0.1:5173/login');
    await page.getByRole('heading', { name:'Inicia sesión' }).waitFor();
    await shots('login'); checks.push('login responsive desktop tablet mobile');
    const setupResponse = page.waitForResponse(r => r.url().endsWith('/auth/mfa/setup') && r.status() === 200);
    await passwordLogin('admin.demo');
    const data = await (await setupResponse).json();
    const secret = new URL(data.provisioning_uri).searchParams.get('secret');
    await page.getByAltText('QR para configurar el autenticador').waitFor();
    await shots('mfa-setup', [page.getByAltText('QR para configurar el autenticador')]);
    checks.push('setup QR present and masked in evidence');
    const denied = await context.request.get('http://127.0.0.1:5173/api/v1/dashboard');
    if (denied.status() !== 401) throw new Error('Incomplete MFA accessed dashboard');
    checks.push('incomplete MFA denied');
    const current = otp(secret); const wrong = current === '000000' ? '111111' : '000000';
    await page.getByLabel('Código del autenticador').fill(wrong);
    await page.getByRole('button', { name:'Activar MFA' }).click();
    await page.getByRole('alert').waitFor(); checks.push('invalid OTP denied visibly');
    await page.getByLabel('Código del autenticador').fill(otp(secret));
    await page.getByRole('button', { name:'Activar MFA' }).click();
    await page.getByRole('heading', { name:'Guarda tus códigos de recuperación' }).waitFor();
    if (await page.getByRole('button', { name:'Continuar al panel' }).isEnabled()) throw new Error('Recovery acknowledgement missing');
    await page.getByLabel('He guardado mis códigos en un lugar seguro').check();
    await page.getByRole('button', { name:'Continuar al panel' }).click();
    await page.getByRole('heading', { name:'Vista general.' }).waitFor();
    await shots('dashboard'); checks.push('valid OTP allowed and responsive dashboard');
    await page.getByRole('button', { name:'Cerrar sesión' }).click();
    await page.getByRole('heading', { name:'Inicia sesión' }).waitFor();
    await passwordLogin('admin.demo');
    await page.getByRole('heading', { name:'Verificación en dos pasos' }).waitFor();
    await shots('mfa'); checks.push('enabled account challenges instead of exposing QR');
    await page.getByLabel('Código del autenticador').fill(otp(secret,30));
    await page.getByRole('button', { name:'Verificar',exact:true }).click();
    await page.getByRole('heading', { name:'Vista general.' }).waitFor();
    checks.push('repeat login with fresh OTP succeeds');
    await page.getByRole('button', { name:'Cerrar sesión' }).click();
    await page.getByRole('heading', { name:'Inicia sesión' }).waitFor();
    await passwordLogin('admision.demo');
    await page.getByText('Estás viendo únicamente la actividad de tu cuenta.').waitFor();
    checks.push('admision directly enters dashboard');
    if (errors.length) throw new Error(errors.join('\n'));
    const report = { status:'PASS', database:'isolated SQLite UI QA', checks, browser_errors:0, screenshots:'12; QR masked; no recovery code or password captured' };
    fs.writeFileSync(path.join(output,'ui-result.json'),JSON.stringify(report,null,2));
    console.log(JSON.stringify(report));
  } finally { await browser.close(); }
})().catch(error => { console.error(error.message); process.exitCode = 1; });
