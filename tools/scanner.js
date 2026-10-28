const rawhttp = require('./rawhttp');
const { loadSignatures, loadPayloads } = require('./loader');
const signatures = require('./signatures');
const dynamic = require('./dynamic');
const tamper = require('./tamper');
const ua = require('./ua');
const encode = require('./encode');
const render = require('./render');

const TIME_PAYLOAD_RE = /sleep|benchmark|waitfor|pg_sleep|delay|timeout/i;
const CONFIDENCE_ORDER = { low: 1, medium: 2, high: 3 };
const MIN_CONFIDENCE = { low: 1, medium: 2, high: 3 };
const UPLOAD_PATH_RE = /\/uploads?\/[^\s"'<>]+\.(php|phtml|php\d|jsp|asp|aspx|war)/i;
const SESSION_COOKIE_RE = /^(session|sess|sid|phpsessid|jsessionid|connect\.sid|asp\.net_sessionid)$/i;
const HEADER_FUZZ_BLOCKLIST = new Set([
  'authorization', 'connection', 'content-length', 'content-type', 'cookie',
  'host', 'proxy-authorization', 'transfer-encoding', 'upgrade'
]);
const LOGIN_HINT_RE = /(login|log-in|signin|sign-in|auth|session)/i;
const PASSIVE_TYPES = new Set(['info_disclosure', 'session_fixation']);
const NO_REPLAY_TYPES = new Set([
  'cmdi', 'code_injection', 'deserialization', 'file_upload', 'format_string',
  'logic_bypass', 'session_fixation', 'ssrf', 'xxe'
]);

const DEFAULT_HEADERS = {
  header_injection: [
    ['user-agent', 'sdork-FUZZ'],
    ['referer', 'https://example.com/FUZZ'],
    ['x-forwarded-for', 'FUZZ']
  ],
  crlf: [
    ['user-agent', 'sdork-FUZZ'],
    ['referer', 'https://example.com/FUZZ']
  ],
  jwt: [
    ['authorization', 'Bearer FUZZ']
  ]
};

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function parseCookiePairs(cookie) {
  if (!cookie) return [];
  return String(cookie)
    .split(';')
    .map((part) => part.trim())
    .filter((part) => part.indexOf('=') !== -1)
    .map((part) => {
      const idx = part.indexOf('=');
      return { name: part.slice(0, idx).trim(), value: part.slice(idx + 1).trim() };
    })
    .filter((pair) => pair.name);
}

function buildCookieString(pairs) {
  return pairs.map((pair) => pair.name + '=' + pair.value).join('; ');
}

function hasSessionCookie(cookie) {
  return parseCookiePairs(cookie).some((pair) => SESSION_COOKIE_RE.test(pair.name));
}

function hasCacheHeaders(res) {
  const headers = (res && res.headers) || {};
  return ['x-cache', 'cf-cache-status', 'age', 'x-varnish', 'x-proxy-cache']
    .some((name) => headers[name] && headers[name].length);
}

function isLoginRequest(opts) {
  return LOGIN_HINT_RE.test(String(opts.url || '')) || LOGIN_HINT_RE.test(String(opts.data || ''));
}

function isAccountFlow(res) {
  if (!res || res.status < 200 || res.status >= 400) return false;
  return /(reset|confirm|verify|token|password)/i.test(String(res.body || ''));
}

function isUploadPath(res) {
  return Boolean(res && UPLOAD_PATH_RE.test(String(res.body || '')));
}

function extractCsrfToken(html) {
  const inputs = String(html || '').match(/<input\b[^>]*>/gi) || [];
  for (const input of inputs) {
    const nameMatch = /\bname=["']([^"']+)["']/i.exec(input);
    if (!nameMatch || !/(csrf|token|authenticity)/i.test(nameMatch[1])) continue;
    const valueMatch = /\bvalue=["']([^"']*)["']/i.exec(input);
    if (valueMatch && valueMatch[1]) return valueMatch[1];
  }
  return null;
}

function replaceCsrfPlaceholder(value, token) {
  if (value === null || value === undefined) return value;
  return String(value).replace(/CSRF_TOKEN|CSRF/g, token);
}

function replaceCaptchaPlaceholder(value, token) {
  if (value === null || value === undefined) return value;
  return String(value).replace(/CAPTCHA_TOKEN/g, token);
}

function median(values) {
  const list = (values || []).map(Number).filter((value) => Number.isFinite(value)).sort((a, b) => a - b);
  if (!list.length) return 0;
  const middle = Math.floor(list.length / 2);
  return list.length % 2 ? list[middle] : Math.round((list[middle - 1] + list[middle]) / 2);
}

function payloadReflected(payload, res) {
  const body = String((res && res.body) || '');
  if (!body) return false;
  const values = new Set([String(payload)]);
  const decoded = encode.decodeOnce(payload);
  values.add(decoded);
  try {
    values.add(decodeURIComponent(String(payload)));
  } catch (err) {}
  try {
    values.add(JSON.stringify(decoded).slice(1, -1));
  } catch (err) {}
  for (const value of values) {
    if (value && value.length >= 4 && body.includes(value)) return true;
  }
  return false;
}

function isStaticAgainstBaseline(type, signal, ctx) {
  if (PASSIVE_TYPES.has(type)) return false;
  if (!['body', 'headers', 'raw_response'].includes(signal.source)) return false;
  if (!['regex', 'contains'].includes(signal.match)) return false;
  if (signal.allow_baseline) return false;
  const flags = signal.source === 'body' ? '' : 's';
  return signatures.baselineMatches(signal, ctx, flags);
}

function shouldReplay(type, signal, method) {
  if (PASSIVE_TYPES.has(type) || NO_REPLAY_TYPES.has(type)) return false;
  if (signal.source === 'oob' || signal.source === 'time') return false;
  return String(method || 'GET').toUpperCase() === 'GET';
}

function keepBestFindings(entries, minConfidence) {
  const best = new Map();
  for (const entry of entries) {
    const key = entry.type + '\0' + entry.point + '\0' + entry.signalId;
    const current = best.get(key);
    if (!current || (CONFIDENCE_ORDER[entry.confidence] || 1) > (CONFIDENCE_ORDER[current.confidence] || 1)) {
      best.set(key, entry);
    }
  }
  const findings = [];
  const observations = [];
  for (const entry of best.values()) {
    const bucket = (CONFIDENCE_ORDER[entry.confidence] || 1) >= minConfidence ? findings : observations;
    bucket.push(entry);
  }
  return { findings, observations };
}

function headersMap(list) {
  const out = {};
  for (const item of list || []) {
    const idx = item.indexOf(':');
    if (idx === -1) continue;
    out[item.slice(0, idx).trim().toLowerCase()] = item.slice(idx + 1).trim();
  }
  return out;
}

function buildQueryPoints(urlStr, targetParam) {
  if (urlStr.includes('FUZZ')) {
    return [{
      id: 'url-fuzz',
      label: 'query:FUZZ',
      location: 'query',
      sample: null,
      apply: (payload) => ({ url: encode.replaceFuzzUrl(urlStr, payload) })
    }];
  }
  const u = new URL(urlStr);
  const keys = Array.from(u.searchParams.keys());
  const makePoint = (name, label, sample) => ({
    id: 'query:' + name,
    label,
    location: 'query',
    sample,
    apply: (payload) => ({ url: encode.setQueryParam(urlStr, name, payload) })
  });

  if (targetParam) {
    return [makePoint(targetParam, 'query:' + targetParam, u.searchParams.get(targetParam))];
  }
  if (keys.length > 0) {
    return keys.map((key) => makePoint(key, 'query:' + key, u.searchParams.get(key)));
  }
  return [makePoint('q', 'query:q (appended)', null)];
}

function looksLikeForm(dataStr) {
  return /^[^=&\s]+=[^&]*(\&|$)/.test(dataStr.trim());
}

function isJsonBody(dataStr) {
  const trimmed = dataStr.trim();
  return trimmed.startsWith('{') || trimmed.startsWith('[');
}

function collectJsonLeaves(value, prefix, out, depth) {
  if (out.length >= 100 || depth > 8) return;
  if (Array.isArray(value)) {
    if (!value.length) return;
    value.forEach((item, index) => collectJsonLeaves(item, prefix.concat(String(index)), out, depth + 1));
    return;
  }
  if (value && typeof value === 'object') {
    for (const key of Object.keys(value)) {
      collectJsonLeaves(value[key], prefix.concat(key), out, depth + 1);
    }
    return;
  }
  if (prefix.length) out.push(prefix);
}

function setJsonPath(target, path, value) {
  let cursor = target;
  for (let i = 0; i < path.length - 1; i++) {
    cursor = cursor[path[i]];
    if (cursor === undefined || cursor === null) return;
  }
  cursor[path[path.length - 1]] = value;
}

function buildBodyPoints(dataStr, method, targetParam) {
  const points = [];
  if (!dataStr) return points;
  const requestMethod = method || 'POST';

  if (isJsonBody(dataStr)) {
    let obj;
    try {
      obj = JSON.parse(dataStr);
    } catch (err) {
      return points;
    }
    if (dataStr.includes('FUZZ')) {
      const apply = (payload) => ({
        body: dataStr.replace(/FUZZ/g, () => encode.jsonEmbedded(payload)),
        method: requestMethod,
        headers: { 'content-type': 'application/json' }
      });
      return [{
        id: 'body-json-fuzz',
        label: 'body:json.FUZZ',
        location: 'body',
        sample: null,
        apply
      }];
    }
    const leaves = [];
    collectJsonLeaves(obj, [], leaves, 0);
    for (const path of leaves) {
      const name = path.join('.');
      if (targetParam && name !== targetParam && !name.startsWith(targetParam + '.')) continue;
      let sample = obj;
      for (const part of path) sample = sample[part];
      points.push({
        id: 'body:json.' + name,
        label: 'body:json.' + name,
        location: 'body',
        sample: String(sample),
        apply: (payload) => {
          const clone = JSON.parse(JSON.stringify(obj));
          setJsonPath(clone, path, encode.coerceJson(payload));
          return { body: JSON.stringify(clone), method: requestMethod, headers: { 'content-type': 'application/json' } };
        }
      });
    }
    return points;
  }

  if (dataStr.includes('FUZZ')) {
    if (dataStr.trim().startsWith('<')) {
      return [{
        id: 'body-fuzz',
        label: 'body:FUZZ',
        location: 'body',
        sample: null,
        apply: (payload) => ({ body: dataStr.replace(/FUZZ/g, () => encode.rawHeader(payload)), method: requestMethod })
      }];
    }
    return [{
      id: 'body-fuzz',
      label: 'body:FUZZ',
      location: 'body',
      sample: null,
      apply: (payload) => ({ body: dataStr.replace(/FUZZ/g, () => encode.encodeForForm(payload)), method: requestMethod })
    }];
  }

  if (looksLikeForm(dataStr)) {
    const pairs = dataStr.split('&');
    for (let i = 0; i < pairs.length; i++) {
      const pair = pairs[i];
      const eq = pair.indexOf('=');
      if (eq === -1) continue;
      const key = encode.decodeOnce(pair.slice(0, eq));
      if (targetParam && key !== targetParam) continue;
      const original = pair.slice(eq + 1);
      points.push({
        id: 'body:' + key,
        label: 'body:' + key,
        location: 'body',
        sample: encode.decodeOnce(original),
        apply: (payload) => {
          const encoded = encode.encodeForForm(payload);
          const value = original.includes('FUZZ')
            ? original.split('FUZZ').join(encoded)
            : encoded;
          const copy = pairs.slice();
          copy[i] = encode.encodeForForm(key) + '=' + value;
          return { body: copy.join('&'), method: requestMethod };
        }
      });
    }
    return points;
  }

  points.push({
    id: 'body:raw',
    label: 'body:raw',
    location: 'body',
    sample: null,
    apply: (payload) => ({ body: encode.rawValue(payload), method: requestMethod })
  });
  return points;
}

function buildHeaderPoints(headersList, defaults) {
  const points = [];
  const provided = headersMap(headersList);
  const add = (name, value) => {
    if (HEADER_FUZZ_BLOCKLIST.has(String(name).toLowerCase()) && !String(value).includes('FUZZ')) return;
    points.push({
      id: 'header:' + name,
      label: 'header:' + name,
      location: 'header',
      sample: value,
      apply: (payload) => {
        const raw = encode.rawHeader(payload);
        const mapped = {};
        mapped[name] = value.includes('FUZZ') ? value.split('FUZZ').join(raw) : raw;
        return { headers: mapped };
      }
    });
  };

  for (const [name, value] of Object.entries(provided)) add(name, value);
  for (const [name, value] of defaults || []) {
    if (!provided[name]) add(name, value);
  }
  return points;
}

function buildCookiePoints(type, opts) {
  let pairs = parseCookiePairs(opts.cookie);
  if (!pairs.length) {
    if (type === 'session_fixation') pairs = [{ name: 'session', value: '' }];
    else if (type === 'jwt') pairs = [{ name: 'token', value: '' }];
    else return [];
  }
  let indexes = pairs.map((pair, index) => index);
  if (opts.param) {
    const found = pairs.findIndex((pair) => pair.name === opts.param);
    if (found === -1) {
      pairs = pairs.concat([{ name: opts.param, value: '' }]);
      indexes = [pairs.length - 1];
    } else {
      indexes = [found];
    }
  }
  const points = [];
  for (const index of indexes) {
    const name = pairs[index].name;
    const sample = pairs[index].value;
    points.push({
      id: 'cookie:' + name,
      label: 'cookie:' + name,
      location: 'cookie',
      sample,
      apply: (payload) => {
        const copy = pairs.map((pair) => ({ name: pair.name, value: pair.value }));
        copy[index].value = encode.rawHeader(payload);
        return { headers: { cookie: buildCookieString(copy) } };
      }
    });
  }
  return points;
}

function buildPathPoints(urlStr) {
  const u = new URL(urlStr);
  const rawPath = u.pathname || '/';
  const segments = rawPath.split('/');
  let index = -1;
  for (let i = segments.length - 1; i >= 0; i--) {
    const segment = segments[i];
    if (!segment) continue;
    if (/^\d+$/.test(segment) || /^[0-9a-f]{8,}$/i.test(segment) || /^[0-9a-f]{8}-[0-9a-f-]{27,}$/i.test(segment)) {
      index = i;
      break;
    }
  }
  const applyPath = (payload) => {
    const encoded = encode.encodeForUrl(payload);
    let next;
    if (index !== -1) {
      const copy = segments.slice();
      copy[index] = encoded;
      next = copy.join('/');
    } else {
      const base = rawPath.endsWith('/') ? rawPath : rawPath + '/';
      next = base + encoded;
    }
    return { url: u.origin + next + u.search + u.hash };
  };
  return [{
    id: 'path',
    label: index !== -1 ? 'path:' + segments[index] : 'path:appended',
    location: 'path',
    sample: index !== -1 ? segments[index] : null,
    apply: applyPath
  }];
}

function buildHostHeaderPoints() {
  return ['host', 'x-forwarded-host', 'x-host'].map((name) => ({
    id: 'header:' + name,
    label: 'header:' + name,
    location: 'header',
    sample: null,
    apply: (payload) => ({ headers: { [name]: encode.rawHeader(payload) } })
  }));
}

function buildMultipartFilePoint() {
  return {
    id: 'body:multipart.file',
    label: 'body:multipart.file',
    location: 'body',
    sample: null,
    apply: (payload) => {
      const boundary = '----sdork' + Math.random().toString(16).slice(2);
      const filename = String(payload || 'shell.php');
      const content = '<?php echo "sdork-upload"; phpinfo(); ?>';
      const body = '--' + boundary + '\r\n' +
        'Content-Disposition: form-data; name="file"; filename="' + filename.replace(/"/g, '') + '"\r\n' +
        'Content-Type: application/x-php\r\n\r\n' +
        content + '\r\n' +
        '--' + boundary + '--\r\n';
      return {
        body,
        method: 'POST',
        headers: { 'content-type': 'multipart/form-data; boundary=' + boundary }
      };
    }
  };
}

function buildPoints(type, spec, opts) {
  if (type === 'file_upload') return [buildMultipartFilePoint()];
  const allowed = new Set(spec.injection || ['query']);
  if (type === 'xxe') {
    return [{
      id: 'xxe-body',
      label: 'body(xml)',
      location: 'body',
      sample: null,
      apply: (payload) => ({ body: encode.rawValue(payload), method: 'POST', headers: { 'content-type': 'application/xml' } })
    }];
  }
  if (type === 'host_header_injection') return buildHostHeaderPoints();

  const points = [];
  if (allowed.has('query')) points.push(...buildQueryPoints(opts.url, opts.param));
  if (allowed.has('body') && opts.data) points.push(...buildBodyPoints(opts.data, opts.method, opts.param));
  if (allowed.has('header')) points.push(...buildHeaderPoints(opts.headers, DEFAULT_HEADERS[type]));
  if (allowed.has('cookie')) points.push(...buildCookiePoints(type, opts));
  if (allowed.has('path')) points.push(...buildPathPoints(opts.url));
  return points;
}

function twinOf(value) {
  const str = String(value);
  if (/%271%27%3D%271/i.test(str)) return str.replace(/%271%27%3D%271/i, '%271%27%3D%272');
  if (/'1'='1'/i.test(str)) return str.replace(/'1'='1'/i, "'1'='2'");
  if (/1%3D1/i.test(str)) return str.replace(/1%3D1/i, '1%3D2');
  if (/1=1/i.test(str)) return str.replace(/1=1/i, '1=2');
  if (/\$ne\b/i.test(str)) return str.replace(/\$ne\b/i, '$eq');
  return null;
}

function computeBooleanTwin(payload) {
  const decoded = encode.decodeOnce(payload);
  return twinOf(decoded) || twinOf(String(payload));
}

async function requestWith(point, payload, opts, baseHeaders, controls) {
  const mod = point.apply(payload);
  const reqUrl = mod.url || opts.url;
  const reqMethod = mod.method || opts.method || 'GET';
  const reqBody = mod.body !== undefined ? mod.body : (opts.data || undefined);
  const reqHeaders = Object.assign({}, baseHeaders, mod.headers || {});
  if (opts.randomAgents) {
    reqHeaders['user-agent'] = ua.randomAgent();
    reqHeaders['accept-language'] = ua.randomLanguage();
  }
  return rawhttp.request({
    url: reqUrl,
    method: reqMethod,
    headers: reqHeaders,
    body: reqBody,
    timeoutMs: opts.timeoutMs || 10000,
    proxy: opts.proxy || null,
    maxRedirects: 0,
    rejectUnauthorized: opts.rejectUnauthorized !== false,
    http2: Boolean(opts.http2)
  });
}

async function scanType(type, opts) {
  const { key, spec } = loadSignatures(type);
  const payloadData = loadPayloads(spec.payload_ref);
  const primaryPayloads = payloadData.groups[payloadData.key] || payloadData.payloads;
  let csrfRequests = 0;
  if (opts.csrf) {
    try {
      const preHeaders = {};
      if (opts.cookie) preHeaders.cookie = opts.cookie;
      if (Array.isArray(opts.headers)) {
        for (const h of opts.headers) {
          const idx = h.indexOf(':');
          if (idx !== -1) preHeaders[h.slice(0, idx).trim().toLowerCase()] = h.slice(idx + 1).trim();
        }
      }
      const page = await rawhttp.request({
        url: opts.url,
        method: 'GET',
        headers: preHeaders,
        timeoutMs: opts.timeoutMs || 10000,
        proxy: opts.proxy || null,
        maxRedirects: 3,
        followRedirects: true,
        rejectUnauthorized: opts.rejectUnauthorized !== false,
        http2: Boolean(opts.http2)
      });
      csrfRequests++;
      const token = extractCsrfToken(page.body);
      if (token) {
        opts = Object.assign({}, opts, {
          data: replaceCsrfPlaceholder(opts.data, token),
          cookie: replaceCsrfPlaceholder(opts.cookie, token),
          cookie2: replaceCsrfPlaceholder(opts.cookie2, token),
          headers: Array.isArray(opts.headers)
            ? opts.headers.map((h) => replaceCsrfPlaceholder(h, token))
            : opts.headers
        });
      }
    } catch (err) {}
  }
  let captchaRequests = 0;
  if (opts.captchaToken || opts.captchaCommand || opts.captchaProvider || opts.captchaApiKey) {
    let token = opts.captchaToken || null;
    if (!token && (opts.captchaCommand || opts.captchaProvider || opts.captchaApiKey)) {
      try {
        const page = await rawhttp.request({
          url: opts.url,
          method: 'GET',
          headers: opts.cookie ? { cookie: opts.cookie } : {},
          timeoutMs: opts.timeoutMs || 10000,
          proxy: opts.proxy || null,
          maxRedirects: 3,
          followRedirects: true,
          rejectUnauthorized: opts.rejectUnauthorized !== false,
          http2: Boolean(opts.http2)
        });
        captchaRequests++;
        token = await render.solveCaptcha(page.body || '', {
          captchaCommand: opts.captchaCommand,
          captchaToken: opts.captchaToken,
          captchaProvider: opts.captchaProvider,
          captchaApiKey: opts.captchaApiKey,
          captchaType: opts.captchaType,
          captchaSitekey: opts.captchaSitekey,
          captchaPollMs: opts.captchaPollMs,
          captchaTimeoutMs: opts.captchaTimeoutMs,
          url: opts.url,
          timeoutMs: opts.timeoutMs,
          proxy: opts.proxy,
          http2: opts.http2,
          rejectUnauthorized: opts.rejectUnauthorized
        });
      } catch (err) {}
    }
    if (token) {
      opts = Object.assign({}, opts, {
        data: replaceCaptchaPlaceholder(opts.data, token),
        cookie: replaceCaptchaPlaceholder(opts.cookie, token),
        cookie2: replaceCaptchaPlaceholder(opts.cookie2, token),
        headers: Array.isArray(opts.headers)
          ? opts.headers.map((h) => replaceCaptchaPlaceholder(h, token))
          : opts.headers
      });
    }
  }
  const points = buildPoints(type, spec, opts);
  const findings = [];
  const observations = [];
  const skipped = [];
  const skippedSeen = new Set();
  const minConfidence = MIN_CONFIDENCE[opts.minConfidence || 'medium'] || 2;

  if (!points.length) {
    return {
      type,
      key,
      url: opts.url,
      findings,
      observations,
      skipped: [{ id: 'injection_points', reason: 'no injectable points for the supplied request' }],
      points: [],
      requests: 0
    };
  }

  const baseHeaders = {};
  if (opts.cookie) baseHeaders.cookie = opts.cookie;
  if (Array.isArray(opts.headers)) {
    for (const h of opts.headers) {
      const idx = h.indexOf(':');
      if (idx !== -1) baseHeaders[h.slice(0, idx).trim().toLowerCase()] = h.slice(idx + 1).trim();
    }
  }
  if (!baseHeaders['user-agent'] && !opts.randomAgents) {
    baseHeaders['user-agent'] = ua.agents()[0];
  }

  let baseline;
  try {
    baseline = await requestWith({
      apply: () => ({})
    }, '', opts, baseHeaders);
    baseline.fp = signatures.fingerprint(baseline.body || '');
  } catch (err) {
    baseline = { status: 0, body: '', headers: {}, rawHead: '', rawText: '', ms: 0, fp: '' };
  }
  if (!baseline.status) {
    throw new Error('target did not respond to the baseline request');
  }

  const oob = opts.oob || null;
  const decoratedList = [];
  const seenPayloads = new Set();
  const addDecorated = (item) => {
    if (!item || typeof item.value !== 'string' || seenPayloads.has(item.value)) return;
    seenPayloads.add(item.value);
    decoratedList.push(item);
  };
  for (const payload of primaryPayloads) {
    const dec = dynamic.decorate(type, payload, oob);
    addDecorated({ value: dec.value, oobToken: dec.oobToken, oobChannel: dec.oobChannel, dynamic: dec.dynamic });
  }

  if (type === 'jwt') {
    for (const kid of payloadData.groups.jwt_kid || []) {
      const dec = dynamic.decorate('jwt', kid, oob);
      addDecorated({
        value: dynamic.buildJwtKid(dec.value),
        oobToken: dec.oobToken,
        oobChannel: dec.oobChannel,
        dynamic: dec.dynamic
      });
    }
  }

  if (oob) {
    for (const built of dynamic.builtins(type, oob)) addDecorated(built);
  }

  const tampers = tamper.parseList(opts.tampers);
  const cookieBefore = {};
  for (const pair of parseCookiePairs(opts.cookie)) cookieBefore[pair.name] = pair.value;
  const targetHost = new URL(opts.url).hostname.replace(/^\[|\]$/g, '');
  const needsSecondRequest = (spec.signals || [])
    .some((signal) => Array.isArray(signal.requires) && signal.requires.includes('second_request'));
  let requests = 1 + csrfRequests + captchaRequests;

  for (const point of points) {
    const pointControls = { valid_host_control: baseline };

    if (point.sample && /^-?\d+$/.test(point.sample)) {
      const adjacent = String(Number(point.sample) + (Number(point.sample) >= 0 ? 1 : -1));
      try {
        const adjacentRes = await requestWith(point, adjacent, opts, baseHeaders);
        adjacentRes.fp = signatures.fingerprint(adjacentRes.body || '');
        pointControls.adjacent_id = adjacentRes;
        requests++;
      } catch (err) {}
    }

    if (type === 'ssrf') {
      try {
        const externalRes = await requestWith(point, 'http://example.com/', opts, baseHeaders);
        externalRes.fp = signatures.fingerprint(externalRes.body || '');
        pointControls.external_control = externalRes;
        requests++;
      } catch (err) {}
    }

    for (const item of decoratedList) {
      let payloadValue = item.value;
      if (tampers.length > 0 && !item.dynamic) {
        payloadValue = tamper.apply(tampers, payloadValue).payload;
      }

      const tSend = Date.now();
      let res;
      try {
        res = await requestWith(point, payloadValue, opts, baseHeaders);
        res.fp = signatures.fingerprint(res.body || '');
        requests++;
      } catch (err) {
        continue;
      }

      let secondRequest = null;
      if (needsSecondRequest) {
        try {
          let secondUrl = null;
          if (type === 'file_upload') {
            const match = UPLOAD_PATH_RE.exec(String(res.body || ''));
            UPLOAD_PATH_RE.lastIndex = 0;
            if (match) {
              try { secondUrl = new URL(match[0], opts.url).toString(); } catch (err) {}
            }
          }
          if (secondUrl) {
            secondRequest = await rawhttp.request({
              url: secondUrl,
              method: 'GET',
              headers: Object.assign({}, baseHeaders),
              timeoutMs: opts.timeoutMs || 10000,
              proxy: opts.proxy || null,
              maxRedirects: 3,
              followRedirects: true,
              rejectUnauthorized: opts.rejectUnauthorized !== false,
              http2: Boolean(opts.http2)
            });
          } else {
            secondRequest = await requestWith(point, payloadValue, opts, baseHeaders);
          }
          requests++;
        } catch (err) {}
      }

      const payloadMs = [res.ms];
      const controlMs = [baseline.ms];
      const hasTimeSignal = (spec.signals || []).some((signal) => signal.source === 'time');
      if (hasTimeSignal && (TIME_PAYLOAD_RE.test(payloadValue) || res.ms >= 4000)) {
        for (let r = 0; r < 2; r++) {
          try {
            const repeat = await requestWith(point, payloadValue, opts, baseHeaders);
            payloadMs.push(repeat.ms);
            requests++;
          } catch (err) {}
        }
        const controlValue = point.sample !== null && point.sample !== undefined && point.sample !== ''
          ? point.sample
          : '1';
        for (let r = 0; r < 2; r++) {
          try {
            const controlRes = await requestWith(point, controlValue, opts, baseHeaders);
            controlMs.push(controlRes.ms);
            requests++;
          } catch (err) {}
        }
      }

      const controls = Object.assign({}, pointControls);
      const twinValue = computeBooleanTwin(payloadValue);
      if (twinValue && twinValue !== payloadValue) {
        try {
          const twinRes = await requestWith(point, twinValue, opts, baseHeaders);
          twinRes.fp = signatures.fingerprint(twinRes.body || '');
          controls.control_payload = twinRes;
          requests++;
        } catch (err) {}
      }

      let identity2 = null;
      if (opts.cookie2) {
        try {
          const identityHeaders = Object.assign({}, baseHeaders, { cookie: opts.cookie2 });
          const mod = point.apply(payloadValue);
          identity2 = await rawhttp.request({
            url: mod.url || opts.url,
            method: mod.method || opts.method || 'GET',
            headers: Object.assign({}, identityHeaders, mod.headers || {}),
            body: mod.body !== undefined ? mod.body : (opts.data || undefined),
            timeoutMs: opts.timeoutMs || 10000,
            proxy: opts.proxy || null,
            maxRedirects: 0,
            rejectUnauthorized: opts.rejectUnauthorized !== false,
            http2: Boolean(opts.http2)
          });
          identity2.fp = signatures.fingerprint(identity2.body || '');
          requests++;
        } catch (err) {}
      }

      let oobHits = [];
      if (oob && item.oobToken) {
        oobHits = await oob.waitFor({ tokens: [item.oobToken], since: tSend }, opts.oobWaitMs || 1500);
      }

      const differs = Boolean(identity2) && (
        identity2.status !== res.status ||
        identity2.fp !== res.fp ||
        signatures.similarityPercent(identity2.body || '', res.body || '') < 95
      );

      const ctx = {
        type,
        response: res,
        baseline,
        controls,
        timing: { payloadMs, controlMs: median(controlMs), controlSamples: controlMs },
        oobHits,
        oobToken: item.oobToken,
        cookieBefore,
        satisfied: {
          baseline: Boolean(baseline && baseline.status > 0),
          two_identities: Boolean(opts.cookie2) && differs,
          second_identity: Boolean(opts.cookie2) && Boolean(identity2),
          account_flow: isAccountFlow(res),
          cache_probe: hasCacheHeaders(res),
          controlled_remote_file: Boolean(oob),
          upload_path: isUploadPath(res),
          pre_login_cookie: hasSessionCookie(opts.cookie),
          login_response: isLoginRequest(opts),
          target_host_allowlist: true,
          second_request: Boolean(secondRequest && secondRequest.status >= 200 && secondRequest.status < 400)
        },
        host: targetHost
      };

      const evalResult = signatures.evaluate(spec, ctx);
      for (const skip of evalResult.skipped) {
        const dedupeKey = skip.id + ':' + skip.reason;
        if (!skippedSeen.has(dedupeKey)) {
          skippedSeen.add(dedupeKey);
          skipped.push(skip);
        }
      }

      const addSkip = (id, reason) => {
        const dedupeKey = id + ':' + reason;
        if (skippedSeen.has(dedupeKey)) return;
        skippedSeen.add(dedupeKey);
        skipped.push({ id, reason });
      };

      const reflected = payloadReflected(payloadValue, res);
      let matches = evalResult.verdict ? evalResult.matched.slice() : [];
      matches = matches.filter((match) => {
        if (isStaticAgainstBaseline(type, match.signal, ctx)) {
          addSkip(match.signal.id, 'signal already present in the baseline response');
          return false;
        }
        if (reflected && (match.signal.technique === 'boolean_blind' || match.signal.technique === 'time_based')) {
          addSkip(match.signal.id, 'payload is reflected; differential or timing evidence is not reliable');
          return false;
        }
        return true;
      });

      if (evalResult.policy === 'all' && matches.length !== evalResult.eligible) {
        addSkip(type, 'match_policy "all" not satisfied (' + matches.length + '/' + evalResult.eligible + ' signals)');
        matches = [];
      }

      const effectiveMethod = point.apply(payloadValue).method || opts.method || 'GET';
      const replayMatches = matches.filter((match) => shouldReplay(type, match.signal, effectiveMethod));
      const wantsReplay = replayMatches.length > 0 && !TIME_PAYLOAD_RE.test(payloadValue);
      if (wantsReplay) {
        try {
          const confirmationRes = await requestWith(point, payloadValue, opts, baseHeaders);
          confirmationRes.fp = signatures.fingerprint(confirmationRes.body || '');
          requests++;
          const confirmationEval = signatures.evaluate(spec, Object.assign({}, ctx, { response: confirmationRes }));
          const confirmedIds = new Set(confirmationEval.matched.map((match) => match.signal.id));
          matches = matches.filter((match) => {
            if (!replayMatches.includes(match)) return true;
            if (confirmedIds.has(match.signal.id)) return true;
            addSkip(match.signal.id, 'signal did not reproduce on the confirmation request');
            return false;
          });
        } catch (err) {
          matches = matches.filter((match) => {
            if (!replayMatches.includes(match)) return true;
            addSkip(match.signal.id, 'confirmation request failed');
            return false;
          });
        }
      }

      for (const match of matches) {
        const confidence = match.signal.confidence || evalResult.confidence || 'medium';
        const finding = {
          type,
          signalId: match.signal.id,
          technique: match.signal.technique || 'unknown',
          confidence,
          note: match.signal.note || '',
          point: point.label,
          payload: payloadValue,
          evidence: match.evidence,
          target: opts.url,
          url: res.url || opts.url,
          status: res.status,
          confirmation: match.signal.source === 'oob'
            ? 'oob'
            : match.signal.source === 'time'
              ? 'timing'
              : replayMatches.includes(match) && wantsReplay
                ? 'replay'
                : PASSIVE_TYPES.has(type) ? 'passive' : 'controls'
        };
        const bucket = (CONFIDENCE_ORDER[confidence] || 1) >= minConfidence ? findings : observations;
        if (!bucket.some((entry) => entry.signalId === finding.signalId && entry.point === finding.point)) {
          bucket.push(finding);
        }
      }

      if (opts.delayMs && opts.delayMs > 0) await sleep(opts.delayMs);
    }
  }

  const best = keepBestFindings(findings.concat(observations), minConfidence);
  return {
    type,
    key,
    url: opts.url,
    findings: best.findings,
    observations: best.observations,
    skipped,
    points: points.map((point) => point.label),
    requests
  };
}

module.exports = { scanType, computeBooleanTwin, buildPoints, buildQueryPoints, buildBodyPoints, buildCookiePoints, buildPathPoints, extractCsrfToken, replaceCsrfPlaceholder, replaceCaptchaPlaceholder };
