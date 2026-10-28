const crypto = require('crypto');
const rawhttp = require('./rawhttp');

function base32Decode(value) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = String(value || '').toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = '';
  for (const char of clean) {
    const index = alphabet.indexOf(char);
    if (index === -1) continue;
    bits += index.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return Buffer.from(bytes);
}

function hotp(secret, counter, options) {
  options = options || {};
  const digits = Math.max(6, Math.min(8, Number(options.digits) || 6));
  const key = Buffer.isBuffer(secret) ? secret : base32Decode(secret);
  const buffer = Buffer.alloc(8);
  buffer.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  buffer.writeUInt32BE(counter >>> 0, 4);
  const hmac = crypto.createHmac(options.algorithm || 'sha1', key).update(buffer).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code = ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return String(code % Math.pow(10, digits)).padStart(digits, '0');
}

function totp(secret, options) {
  options = options || {};
  const step = Math.max(1, Number(options.step) || 30);
  const now = options.now === undefined ? Date.now() : Number(options.now);
  return hotp(secret, Math.floor(now / 1000 / step), options);
}

function replaceMfa(value, code) {
  if (value === null || value === undefined) return value;
  return String(value).replace(/\{\{MFA\}\}|MFA_CODE/g, code);
}

function collectCookies(headers) {
  const value = headers && (headers['set-cookie'] || headers['Set-Cookie']);
  if (!value) return [];
  const list = Array.isArray(value) ? value : [value];
  return list.map((item) => String(item).split(';')[0].trim()).filter(Boolean);
}

function responseCookieHeader(res) {
  if (res && res.allCookieHeader) return res.allCookieHeader;
  if (res && res.cookieHeader) return res.cookieHeader;
  return collectCookies(res && res.headers).join('; ');
}

function sameOrigin(a, b) {
  try {
    return new URL(a).origin === new URL(b).origin;
  } catch (err) {
    return false;
  }
}

async function login(options) {
  options = options || {};
  if (!options.loginUrl) throw new Error('loginUrl is required');
  const request = options.request || rawhttp.request;
  const code = options.mfaCode || (options.mfaSecret ? totp(options.mfaSecret, { now: options.now }) : '');
  const headers = { 'content-type': 'application/x-www-form-urlencoded' };
  if (options.cookie) headers.cookie = options.cookie;
  if (Array.isArray(options.headers)) {
    for (const header of options.headers) {
      const idx = header.indexOf(':');
      if (idx !== -1) headers[header.slice(0, idx).trim().toLowerCase()] = header.slice(idx + 1).trim();
    }
  }
  const loginData = replaceMfa(options.loginData || '', code);
  const loginRes = await request({
    url: options.loginUrl,
    method: options.loginMethod || 'POST',
    headers,
    body: loginData || undefined,
    timeoutMs: options.timeoutMs || 10000,
    proxy: options.proxy || null,
    maxRedirects: 3,
    followRedirects: true,
    rejectUnauthorized: options.rejectUnauthorized !== false,
    http2: Boolean(options.http2)
  });
  let cookie = responseCookieHeader(loginRes);
  const responses = [loginRes];
  if (options.mfaUrl) {
    const crossOrigin = !sameOrigin(options.loginUrl, options.mfaUrl);
    const mfaHeaders = Object.assign({}, headers, { 'content-type': 'application/x-www-form-urlencoded' });
    if (cookie && !crossOrigin) mfaHeaders.cookie = cookie;
    const mfaData = replaceMfa(options.mfaData || '', code) ||
      ((options.mfaField || 'code') + '=' + encodeURIComponent(code));
    const mfaRes = await request({
      url: options.mfaUrl,
      method: 'POST',
      headers: mfaHeaders,
      body: mfaData,
      timeoutMs: options.timeoutMs || 10000,
      proxy: options.proxy || null,
      maxRedirects: 3,
      followRedirects: true,
      rejectUnauthorized: options.rejectUnauthorized !== false,
      http2: Boolean(options.http2)
    });
    responses.push(mfaRes);
    const mfaCookie = responseCookieHeader(mfaRes);
    if (mfaRes && (mfaRes.allCookieHeader || mfaRes.cookieHeader)) cookie = mfaCookie;
    else if (crossOrigin) cookie = mfaCookie;
    else if (mfaCookie) cookie = cookie ? cookie + '; ' + mfaCookie : mfaCookie;
  }
  return { cookie, code, responses };
}

module.exports = { base32Decode, hotp, totp, replaceMfa, login };
