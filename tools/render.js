const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');
const captcha = require('./captcha');

function browserCandidates() {
  const list = [];
  if (process.env.SDORK_BROWSER) list.push(process.env.SDORK_BROWSER);
  if (process.platform === 'win32') {
    list.push(
      path.join(process.env.LOCALAPPDATA || '', 'Google', 'Chrome', 'Application', 'chrome.exe'),
      path.join(process.env.LOCALAPPDATA || '', 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
      path.join(process.env.ProgramFiles || '', 'Google', 'Chrome', 'Application', 'chrome.exe'),
      path.join(process.env['ProgramFiles(x86)'] || '', 'Microsoft', 'Edge', 'Application', 'msedge.exe')
    );
  } else if (process.platform === 'darwin') {
    list.push('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge');
  } else {
    list.push('/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/microsoft-edge');
  }
  return list.filter(Boolean);
}

function detectBrowser() {
  for (const candidate of browserCandidates()) {
    try {
      if (fs.existsSync(candidate)) return candidate;
    } catch (err) {}
  }
  return null;
}

function renderWithBrowser(url, options) {
  options = options || {};
  const browser = options.browser || detectBrowser();
  if (!browser) return Promise.resolve(null);
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'sdork-chrome-'));
  const args = [
    '--headless=new',
    '--disable-gpu',
    '--disable-dev-shm-usage',
    '--user-data-dir=' + profile,
    '--virtual-time-budget=' + Math.max(1000, Number(options.waitMs) || 5000),
    '--dump-dom'
  ];
  if (options.renderUnsafe) args.push('--no-sandbox');
  if (options.proxy && options.proxy.host && options.proxy.port) {
    const scheme = options.proxy.type === 'socks5' ? 'socks5://' : 'http://';
    args.push('--proxy-server=' + scheme + options.proxy.host + ':' + options.proxy.port);
  }
  if (options.rejectUnauthorized === false) args.push('--ignore-certificate-errors');
  args.push(url);
  return new Promise((resolve, reject) => {
    execFile(browser, args, { timeout: options.timeoutMs || 20000, maxBuffer: 32 * 1024 * 1024 }, (err, stdout, stderr) => {
      try { fs.rmSync(profile, { recursive: true, force: true }); } catch (cleanupErr) {}
      if (err && !stdout) return reject(err);
      resolve(stdout || '');
    });
  });
}

async function renderWithJsdom(url, options) {
  let JSDOM;
  try {
    ({ JSDOM } = require('jsdom'));
  } catch (err) {
    return null;
  }
  const unsafe = Boolean(options && options.renderUnsafe);
  const dom = await JSDOM.fromURL(url, {
    runScripts: unsafe ? 'dangerously' : undefined,
    resources: unsafe ? 'usable' : undefined,
    pretendToBeVisual: true,
    virtualConsole: undefined
  });
  await new Promise((resolve) => {
    const timer = setTimeout(resolve, Math.max(1000, Number(options && options.waitMs) || 3000));
    dom.window.addEventListener('load', () => {
      clearTimeout(timer);
      resolve();
    });
  });
  const html = dom.serialize();
  dom.window.close();
  return html;
}

function detectCaptcha(html) {
  return /(?:recaptcha|hcaptcha|turnstile|captcha|cf-chl-|challenge-platform)/i.test(String(html || ''));
}

function injectCaptchaToken(html, token) {
  if (!token) return html;
  return String(html || '').replace(/CAPTCHA_TOKEN/g, String(token));
}

async function solveCaptcha(html, options) {
  options = options || {};
  if (options.captchaToken) return options.captchaToken;
  if (options.captchaProvider || options.captchaApiKey) {
    return captcha.solve({
      html,
      url: options.url || options.pageUrl,
      service: options.captchaProvider || '2captcha',
      apiKey: options.captchaApiKey,
      type: options.captchaType,
      sitekey: options.captchaSitekey,
      proxy: options.proxy,
      request: options.request,
      http2: options.http2,
      rejectUnauthorized: options.rejectUnauthorized,
      pollMs: options.captchaPollMs,
      solveTimeoutMs: options.captchaTimeoutMs
    });
  }
  if (!options.captchaCommand) return null;
  return new Promise((resolve, reject) => {
    const child = execFile(options.captchaCommand, [options.url || ''], {
      timeout: options.timeoutMs || 20000,
      maxBuffer: 4 * 1024 * 1024
    }, (err, stdout) => {
      if (err) return reject(err);
      resolve(String(stdout || '').trim() || null);
    });
    if (child.stdin) {
      child.stdin.end(String(html || ''));
    }
  });
}

async function render(url, options) {
  options = options || {};
  if (!options.renderJs) return null;
  const warnings = [];
  let html = null;
  try {
    html = await renderWithBrowser(url, options);
  } catch (err) {
    warnings.push('browser render failed: ' + err.message);
  }
  if (!html) {
    try {
      html = await renderWithJsdom(url, options);
    } catch (err) {
      warnings.push('jsdom render failed: ' + err.message);
    }
  }
  if (!html) {
    if (!warnings.length) warnings.push('no renderer available');
    if (typeof options.onWarning === 'function') {
      for (const warning of warnings) options.onWarning(warning + ' (' + url + ')');
    }
    return null;
  }
  const detected = detectCaptcha(html);
  let token = null;
  if (detected) token = await solveCaptcha(html, Object.assign({}, options, { url }));
  return { html: injectCaptchaToken(html, token), captcha: detected, token };
}

module.exports = { detectBrowser, render, renderWithBrowser, renderWithJsdom, detectCaptcha, injectCaptchaToken, solveCaptcha };
