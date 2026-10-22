// Browser acceptance: ephemeral local QA or real public PostgreSQL through captured SSH.
// Never print or persist credentials, cookies, QR, TOTP, browser storage or traces.
const fs = require('node:fs');
const path = require('node:path');
const cp = require('node:child_process');
const assert = require('node:assert/strict');
const { chromium } = require(process.env.NATIVE_PLAYWRIGHT_MODULE);
const publicMode = process.env.NATIVE_ASSETS_PUBLIC === 'true';
const visualOnly = publicMode && process.env.NATIVE_ASSETS_VISUAL_ONLY === 'true';
const output = publicMode ? path.resolve(__dirname, '../evidence/run-m3-public-browser') : process.env.NATIVE_UI_OUTPUT;
fs.mkdirSync(output, { recursive: true });
function bridge(username) {
  const command = 'cd /home/elcra/sgsi-zta-native-app && env -u DOCKER_HOST -u DOCKER_CONTEXT docker --context default compose --project-name sgsi-zta-native exec -T backend python -m app.assets.browser_session ' + username;
  // Captured machine stdout, consumed in memory; no secret-bearing output to logs.
  return JSON.parse(cp.execFileSync('ssh', ['-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=8','-o','ForwardAgent=no','elcra@192.168.1.36',command], { encoding:'utf8',windowsHide:true,timeout:90000,maxBuffer:65536 }));
}
function otp(secret) {
  return cp.execFileSync(process.env.NATIVE_UI_PYTHON,['-c','import sys,json,pyotp; print(pyotp.TOTP(json.load(sys.stdin)["secret"]).now())'],{input:JSON.stringify({secret}),encoding:'utf8',windowsHide:true}).trim();
}
function scanSessionArtifacts(sessions) {
  const values=sessions.flatMap(session=>session.cookies.map(cookie=>cookie.value));
  const root=path.resolve(__dirname,'..');const repo=path.resolve(root,'..');
  const files=new Set();const excluded=new Set(['node_modules','.venv','.private','__pycache__','.git','.pytest_cache','.ruff_cache','coverage']);
  function walk(directory){for(const entry of fs.readdirSync(directory,{withFileTypes:true})){if(excluded.has(entry.name)||entry.name.startsWith('.env'))continue;const file=path.join(directory,entry.name);if(entry.isDirectory())walk(file);else if(entry.isFile()&&!/\.(png|jpg|woff2?|enc)$/.test(file))files.add(file);}}
  walk(root);
  for(const name of cp.execFileSync('git',['ls-files','-z'],{cwd:repo,encoding:'utf8',windowsHide:true}).split('\0')){const file=path.join(repo,name);if(name&&fs.existsSync(file)&&fs.statSync(file).isFile())files.add(file);}
  for(const file of files){const content=fs.readFileSync(file,'utf8');assert.equal(values.some(value=>content.includes(value)),false,'QA cookie leaked in artifact: '+path.relative(repo,file));}
  return files.size;
}
(async()=>{
  const browser=await chromium.launch({headless:true,executablePath:process.env.NATIVE_BROWSER_EXE});
  const errors=[];const checks=[];const viewports=[['desktop',1440,900],['tablet',1024,1180],['mobile',390,844]];
  let stage='initialization';
  let url='http://127.0.0.1:5173';
  let admin; let auditor; let adminBridge; let auditorBridge;
  try {
    if(publicMode){adminBridge=bridge('admin.demo');url=adminBridge.url;}
    if(publicMode){
      const anonymous=await browser.newContext();const landing=await anonymous.newPage();
      await landing.goto(url+'/assets');await landing.getByRole('heading',{name:'Inicia sesión',exact:true}).waitFor();
      assert.equal((await anonymous.request.get(url+'/api/v1/assets')).status(),401);
      for(const route of ['/docs','/redoc','/openapi.json'])assert.ok([403,404].includes((await anonymous.request.get(url+route)).status()));
      await anonymous.close();checks.push('external anonymous UI redirects to login; API 401; docs blocked');
    }
    admin=await browser.newContext({viewport:{width:1440,height:900},locale:'es-PE',timezoneId:'America/Bogota',reducedMotion:'reduce'});
    if(publicMode)await admin.addCookies(adminBridge.cookies);
    const page=await admin.newPage();page.on('pageerror',e=>errors.push(e.message));
    async function shots(prefix) {
      stage='responsive '+prefix;
      for(const [size,width,height] of viewports){await page.setViewportSize({width,height});await page.screenshot({path:path.join(output,`${prefix}-${size}.png`),fullPage:true,animations:'disabled'});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,`Overflow ${prefix} ${size}`);}
      await page.setViewportSize({width:1440,height:900});
    }
    if(!publicMode){
      await page.goto(url+'/login');await page.getByLabel('Usuario',{exact:true}).fill('admin.demo');await page.getByLabel('Contraseña',{exact:true}).fill(process.env.NATIVE_UI_PASSWORD);
      const setup=page.waitForResponse(r=>r.url().endsWith('/auth/mfa/setup')&&r.status()===200);
      await page.getByRole('button',{name:'Entrar al laboratorio'}).click();
      const data=await(await setup).json();const secret=new URL(data.provisioning_uri).searchParams.get('secret');
      await page.getByLabel('Código del autenticador').fill(otp(secret));await page.getByRole('button',{name:'Activar MFA'}).click();
      await page.getByLabel('He guardado mis códigos en un lugar seguro').check();await page.getByRole('button',{name:'Continuar al panel'}).click();
    } else await page.goto(url+'/dashboard');
    await page.getByRole('heading',{name:'Vista general.'}).waitFor();
    await page.getByRole('heading',{name:'Activos del laboratorio'}).waitFor();
    await shots('M3-E05-dashboard');checks.push('real dashboard asset metrics and charts');
    await page.goto(url+'/assets');await page.getByRole('heading',{name:'Inventario de Activos.'}).waitFor();
    await page.getByText('SRV-HIS-01',{exact:true}).waitFor();
    assert.equal(await page.locator('.badge-orange').first().evaluate(element=>getComputedStyle(element).color),'rgb(155, 77, 18)','HIGH badge contrast');
    await shots('M3-E01-assets');
    // All filters call the real server; search is explicitly submitted.
    await page.getByLabel('Buscar activos').fill('srv-his-demo');
    const search=page.waitForResponse(r=>r.url().includes('/api/v1/assets?')&&r.url().includes('search=srv-his-demo'));
    await page.getByRole('button',{name:'Buscar',exact:true}).click();assert.equal((await search).status(),200);
    await page.getByText('1 activos encontrados').waitFor();
    await page.getByLabel('Filtrar por criticidad').selectOption('HIGH');await page.getByText('1 activos encontrados').waitFor();
    await page.getByRole('link',{name:'Ver SRV-HIS-01',exact:true}).click();await page.getByRole('heading',{name:'Servidor HIS Demo',exact:true}).waitFor();await shots('M3-E02-detail');
    checks.push('server search/filter/detail; responsive 1440 1024 390');
    await page.goto(url+'/assets/new');await page.getByLabel('Código *').waitFor();await shots('M3-E03-create');
    let code,detailPath,assetId;
    if(visualOnly){
      const stored=await(await admin.request.get(url+'/api/v1/assets?search=TEST-DEMO-01')).json();
      assetId=stored.items[0].id;code=stored.items[0].asset_code;detailPath='/assets/'+assetId;
      checks.push('final visual evidence uses existing retired test asset');
    } else {
    stage='asset form create';
    code='UI-DEMO-'+Date.now().toString().slice(-8);
    await page.getByLabel('Código *').fill(code);await page.getByLabel('Nombre *').fill('Equipo Temporal de Demostración UI');
    await page.getByLabel('Tipo *').selectOption({label:'Desktop'});await page.getByLabel('Área *').selectOption({label:'TI'});
    await page.getByLabel('Responsable *').selectOption({label:'Administrador Demo · admin.demo'});
    await page.getByLabel('IP demo',{exact:true}).fill('192.0.2.40');await page.getByRole('button',{name:'Guardar activo'}).click();
    await page.getByRole('heading',{name:'Equipo Temporal de Demostración UI',exact:true}).waitFor();
    detailPath=new URL(page.url()).pathname;assetId=Number(detailPath.split('/').at(-1));
    await page.getByText('Creó el activo',{exact:true}).waitFor();
    stage='asset form edit navigation';
    await page.getByRole('link',{name:'Editar activo',exact:true}).click();
    stage='asset form edit criticality';
    await page.getByLabel('Criticidad',{exact:true}).selectOption('CRITICAL');
    stage='asset form edit save';
    const edited=page.waitForResponse(r=>r.url().endsWith('/api/v1/assets/'+assetId)&&r.request().method()==='PATCH');
    await page.getByRole('button',{name:'Guardar activo'}).click();
    assert.equal((await edited).status(),200,'Asset update response');
    stage='asset form edit history';
    await page.getByText('Cambió la criticidad',{exact:true}).waitFor();
    await page.getByRole('button',{name:'Retirar',exact:true}).click();await page.getByRole('button',{name:'Confirmar retiro'}).click();await page.getByRole('status').filter({hasText:'Activo retirado'}).waitFor();
    checks.push('real UI create edit retirement and safe audit history');
    }
    await page.getByRole('button',{name:'Cerrar sesión'}).click();await page.getByRole('heading',{name:'Inicia sesión'}).waitFor();
    stage='auditor session and permissions';
    auditor=await browser.newContext({viewport:{width:1440,height:900},locale:'es-PE',reducedMotion:'reduce'});
    if(publicMode){auditorBridge=bridge('auditor.demo');await auditor.addCookies(auditorBridge.cookies);}
    const read=await auditor.newPage();read.on('pageerror',e=>errors.push(e.message));
    if(!publicMode){await read.goto(url+'/login');await read.getByLabel('Usuario',{exact:true}).fill('auditor.demo');await read.getByLabel('Contraseña',{exact:true}).fill(process.env.NATIVE_UI_PASSWORD);await read.getByRole('button',{name:'Entrar al laboratorio'}).click();await read.getByRole('heading',{name:'Vista general.'}).waitFor();}
    await read.goto(url+'/assets');await read.getByText('Acceso de solo lectura',{exact:true}).waitFor();assert.equal(await read.getByRole('link',{name:'Nuevo activo',exact:true}).count(),0);
    await read.screenshot({path:path.join(output,'M3-E04-auditor-read-only.png'),fullPage:true});
    const denial=await read.evaluate(async id=>{const token=await(await fetch('/api/v1/auth/csrf',{credentials:'include'})).json();const response=await fetch('/api/v1/assets/'+id,{method:'PATCH',credentials:'include',headers:{'Content-Type':'application/json','X-CSRF-Token':token.csrf_token},body:JSON.stringify({criticality:'LOW'})});return {status:response.status,detail:(await response.json()).detail};},assetId);
    assert.equal(denial.status,403);fs.writeFileSync(path.join(output,'M3-E04-denial.json'),JSON.stringify(denial,null,2));
    await read.goto(url+detailPath);await read.getByText('Solo lectura · auditor',{exact:true}).waitFor();assert.equal(await read.getByRole('link',{name:'Editar activo',exact:true}).count(),0);
    await read.goto(url+detailPath+'/edit');await read.getByRole('alert').filter({hasText:'Solo admin-ti'}).waitFor();
    await read.getByRole('button',{name:'Cerrar sesión'}).click();await read.getByRole('heading',{name:'Inicia sesión'}).waitFor();
    checks.push('auditor read-only UI and backend modification 403');
    assert.equal(errors.length,0,'Browser JavaScript errors');
    const cookieScan=publicMode?scanSessionArtifacts([adminBridge,auditorBridge]):null;
    const report={status:'PASS',environment:publicMode?'Public HTTPS / PostgreSQL / Windows browser':'Isolated SQLite browser QA',checks,viewports:[1440,1024,390],browser_errors:0,asset_code:code,asset_id:assetId,temporary_asset:'RETIRED',sessions:'revoked via logout',ephemeral_cookie_scan:publicMode?'PASS':null,cookie_artifacts_checked:cookieScan,screenshots:'13; no credentials, cookies, QR or OTP captured'};
    fs.writeFileSync(path.join(output,'ui-result.json'),JSON.stringify(report,null,2));console.log(JSON.stringify(report));
  } catch(error) {
    const report={status:'FAIL',stage,error_type:error.name,completed_checks:checks};
    if(stage.startsWith('asset form edit'))report.diagnostic=error.message.slice(0,1200);
    fs.writeFileSync(path.join(output,'ui-failure.json'),JSON.stringify(report,null,2));
    console.error(JSON.stringify(report));
    throw error;
  } finally {
    // Revoke test sessions even when a browser assertion fails.
    if(publicMode){for(const [context,data] of [[admin,adminBridge],[auditor,auditorBridge]])if(context&&data)await context.request.post(url+'/api/v1/auth/logout',{headers:{'X-CSRF-Token':data.csrf,Origin:url}}).catch(()=>{});}
    await browser.close();
  }
})().catch(()=>{console.error('Asset browser acceptance failed; inspect sanitized runtime or assertions locally.');process.exitCode=1;});
