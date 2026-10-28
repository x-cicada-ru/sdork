const rawhttp = require('./rawhttp');

const SERVICES = ['2captcha', 'anticaptcha', 'capmonster'];

function detectType(html) {
  const text = String(html || '');
  if (/turnstile|cf-chl-|challenge-platform/i.test(text)) return 'turnstile';
  if (/h-?captcha/i.test(text)) return 'hcaptcha';
  return 'recaptcha';
}

function extractSitekey(html) {
  const text = String(html || '');
  const patterns = [
    /data-sitekey=["']([^"']+)["']/i,
    /data-site-key=["']([^"']+)["']/i,
    /["']sitekey["']\s*:\s*["']([^"']+)["']/i,
    /sitekey=([A-Za-z0-9_-]{10,})/i
  ];
  for (const pattern of patterns) {
    const match = pattern.exec(text);
    if (match) return match[1];
  }
  return null;
}

function apiKey(options, service) {
  if (options.apiKey) return options.apiKey;
  const names = service === 'anticaptcha'
    ? ['ANTICAPTCHA_API_KEY', 'CAPTCHA_API_KEY']
    : service === 'capmonster'
      ? ['CAPMONSTER_API_KEY', 'CAPTCHA_API_KEY']
      : ['TWOCAPTCHA_API_KEY', 'CAPTCHA_API_KEY'];
  for (const name of names) if (process.env[name]) return process.env[name];
  return null;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function parseResponse(body) {
  const text = String(body || '').trim();
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch (err) {
    const match = /^OK\|(.+)$/.exec(text);
    if (match) return { status: 1, request: match[1] };
    if (/^ERROR_/.test(text)) return { status: 0, request: text };
    return { raw: text };
  }
}

async function request(options, url, body, headers) {
  const send = options.request || rawhttp.request;
  const res = await send({
    url,
    method: body === undefined ? 'GET' : 'POST',
    headers: Object.assign({ 'content-type': 'application/x-www-form-urlencoded' }, headers || {}),
    body,
    timeoutMs: options.requestTimeoutMs || 20000,
    proxy: options.proxy || null,
    maxRedirects: 2,
    followRedirects: true,
    rejectUnauthorized: options.rejectUnauthorized !== false,
    http2: Boolean(options.http2)
  });
  return { status: res.status, body: parseResponse(res.body) };
}

async function requestJson(options, url, payload) {
  return request(options, url, JSON.stringify(payload), { 'content-type': 'application/json' });
}

function pollOptions(options) {
  return {
    pollMs: Math.max(250, Number(options.pollMs) || 5000),
    timeoutMs: Math.max(1000, Number(options.solveTimeoutMs) || 120000)
  };
}

async function twoCaptcha(type, sitekey, pageUrl, options) {
  const key = apiKey(options, '2captcha');
  if (!key) throw new Error('2captcha API key is required');
  const method = type === 'hcaptcha' ? 'hcaptcha' : type === 'turnstile' ? 'turnstile' : 'userrecaptcha';
  const field = method === 'userrecaptcha' ? 'googlekey' : 'sitekey';
  const form = new URLSearchParams({
    key,
    method,
    pageurl: pageUrl,
    json: '1'
  });
  form.set(field, sitekey);
  const created = await request(options, 'https://2captcha.com/in.php', form.toString());
  if (Number(created.body.status) !== 1) throw new Error('2captcha create failed: ' + (created.body.request || created.body.raw || 'unknown'));
  const taskId = created.body.request;
  const poll = pollOptions(options);
  const deadline = Date.now() + poll.timeoutMs;
  while (Date.now() < deadline) {
    await sleep(poll.pollMs);
    const url = 'https://2captcha.com/res.php?key=' + encodeURIComponent(key) +
      '&action=get&id=' + encodeURIComponent(taskId) + '&json=1';
    const res = await request(options, url, undefined);
    if (Number(res.body.status) === 1) return String(res.body.request);
    if (res.body.request && res.body.request !== 'CAPCHA_NOT_READY') {
      throw new Error('2captcha solve failed: ' + res.body.request);
    }
  }
  throw new Error('2captcha solve timed out');
}

async function antiCaptcha(type, sitekey, pageUrl, options) {
  const key = apiKey(options, 'anticaptcha');
  if (!key) throw new Error('Anti-Captcha API key is required');
  const typeName = type === 'hcaptcha' ? 'HCaptchaTaskProxyless' : type === 'turnstile' ? 'TurnstileTaskProxyless' : 'RecaptchaV2TaskProxyless';
  const created = await requestJson(options, 'https://api.anti-captcha.com/createTask', {
    clientKey: key,
    task: { type: typeName, websiteURL: pageUrl, websiteKey: sitekey }
  });
  if (Number(created.body.errorId) !== 0 || !created.body.taskId) {
    throw new Error('Anti-Captcha create failed: ' + (created.body.errorDescription || created.body.errorCode || 'unknown'));
  }
  const poll = pollOptions(options);
  const deadline = Date.now() + poll.timeoutMs;
  while (Date.now() < deadline) {
    await sleep(poll.pollMs);
    const res = await requestJson(options, 'https://api.anti-captcha.com/getTaskResult', {
      clientKey: key,
      taskId: created.body.taskId
    });
    if (res.body.status === 'ready') {
      const solution = res.body.solution || {};
      return String(solution.gRecaptchaResponse || solution.token || solution.recaptchaToken || '');
    }
    if (res.body.status === 'processing') continue;
    throw new Error('Anti-Captcha solve failed: ' + (res.body.errorDescription || res.body.errorCode || 'unknown'));
  }
  throw new Error('Anti-Captcha solve timed out');
}

async function capMonster(type, sitekey, pageUrl, options) {
  const key = apiKey(options, 'capmonster');
  if (!key) throw new Error('CapMonster API key is required');
  const typeName = type === 'hcaptcha' ? 'HCaptchaTaskProxyless' : type === 'turnstile' ? 'TurnstileTaskProxyless' : 'RecaptchaV2TaskProxyless';
  const created = await requestJson(options, 'https://api.capmonster.cloud/createTask', {
    clientKey: key,
    task: { type: typeName, websiteURL: pageUrl, websiteKey: sitekey }
  });
  if (Number(created.body.errorId) !== 0 || !created.body.taskId) {
    throw new Error('CapMonster create failed: ' + (created.body.errorDescription || created.body.errorCode || 'unknown'));
  }
  const poll = pollOptions(options);
  const deadline = Date.now() + poll.timeoutMs;
  while (Date.now() < deadline) {
    await sleep(poll.pollMs);
    const res = await requestJson(options, 'https://api.capmonster.cloud/getTaskResult', {
      clientKey: key,
      taskId: created.body.taskId
    });
    if (res.body.status === 'ready') {
      const solution = res.body.solution || {};
      return String(solution.gRecaptchaResponse || solution.token || solution.recaptchaToken || '');
    }
    if (res.body.status === 'processing') continue;
    throw new Error('CapMonster solve failed: ' + (res.body.errorDescription || res.body.errorCode || 'unknown'));
  }
  throw new Error('CapMonster solve timed out');
}

async function solve(options) {
  options = options || {};
  if (options.token) return options.token;
  const service = String(options.service || '2captcha').toLowerCase();
  if (!SERVICES.includes(service)) throw new Error('unknown captcha service: ' + service);
  const type = String(options.type || detectType(options.html)).toLowerCase();
  const sitekey = options.sitekey || extractSitekey(options.html);
  const pageUrl = options.url || options.pageUrl;
  if (!sitekey) throw new Error('captcha sitekey not found');
  if (!pageUrl) throw new Error('captcha page URL is required');
  if (service === 'anticaptcha') return antiCaptcha(type, sitekey, pageUrl, options);
  if (service === 'capmonster') return capMonster(type, sitekey, pageUrl, options);
  return twoCaptcha(type, sitekey, pageUrl, options);
}

module.exports = { SERVICES, detectType, extractSitekey, solve, twoCaptcha, antiCaptcha, capMonster };
