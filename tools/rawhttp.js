const net = require('net');
const tls = require('tls');
const http2 = require('http2');
const zlib = require('zlib');
const socks5 = require('./socks5');

const DEFAULT_MAX_BYTES = 8 * 1024 * 1024;

function withoutBrackets(host) {
  return String(host).replace(/^\[|\]$/g, '');
}

function parseUrl(url) {
  const u = new URL(url);
  const protocol = u.protocol.replace(':', '');
  if (protocol !== 'http' && protocol !== 'https') {
    throw new Error('unsupported protocol: ' + protocol);
  }
  const host = withoutBrackets(u.hostname);
  const port = u.port ? Number(u.port) : protocol === 'https' ? 443 : 80;
  const bracketed = net.isIP(host) === 6 ? '[' + host + ']' : host;
  return {
    scheme: protocol,
    host,
    hostHeader: u.host,
    hostPort: bracketed + ':' + port,
    port,
    path: (u.pathname || '/') + u.search
  };
}

function isDefaultPort(target) {
  return (target.scheme === 'http' && target.port === 80) || (target.scheme === 'https' && target.port === 443);
}

function tcpConnect(host, port, timeoutMs) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host, port });
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => {
      socket.setTimeout(0);
      resolve(socket);
    });
    socket.once('error', reject);
    socket.once('close', () => reject(new Error('connection closed before connect')));
    socket.once('timeout', () => {
      socket.destroy();
      reject(new Error('connect timeout'));
    });
  });
}

function tlsWrap(socket, host, timeoutMs, rejectUnauthorized, alpnProtocols) {
  return new Promise((resolve, reject) => {
    const options = { socket, rejectUnauthorized: rejectUnauthorized !== false };
    if (!net.isIP(host)) options.servername = host;
    if (Array.isArray(alpnProtocols) && alpnProtocols.length) options.ALPNProtocols = alpnProtocols;
    const secure = tls.connect(options);
    secure.setTimeout(timeoutMs);
    secure.once('secureConnect', () => {
      secure.setTimeout(0);
      resolve(secure);
    });
    secure.once('error', reject);
    secure.once('close', () => reject(new Error('tls connection closed')));
    secure.once('timeout', () => {
      secure.destroy();
      reject(new Error('tls timeout'));
    });
  });
}

function connectHttpProxy(proxy, target, timeoutMs) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: proxy.host, port: proxy.port });
    let settled = false;
    socket.setTimeout(timeoutMs);
    const fail = (err) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(err);
    };
    socket.once('error', fail);
    socket.once('timeout', () => fail(new Error('proxy connect timeout')));
    socket.once('close', () => fail(new Error('proxy closed the connection')));
    socket.once('connect', () => {
      let head = Buffer.alloc(0);
      const onData = (chunk) => {
        head = Buffer.concat([head, chunk]);
        const sep = head.indexOf('\r\n\r\n');
        if (sep === -1) return;
        socket.removeListener('data', onData);
        const text = head.toString('latin1', 0, sep);
        const status = Number((text.match(/^HTTP\/\d\.\d\s+(\d+)/) || [])[1]);
        if (status !== 200) {
          fail(new Error('proxy CONNECT failed with status ' + status));
          return;
        }
        settled = true;
        socket.setTimeout(0);
        const rest = head.slice(sep + 4);
        if (rest.length) socket.unshift(rest);
        resolve(socket);
      };
      socket.on('data', onData);
      const auth = proxy.auth
        ? 'Proxy-Authorization: Basic ' + Buffer.from(proxy.auth).toString('base64') + '\r\n'
        : '';
      const hostPort = target.hostPort;
      socket.write(
        'CONNECT ' + hostPort + ' HTTP/1.1\r\n' +
        'Host: ' + hostPort + '\r\n' +
        auth + '\r\n'
      );
    });
  });
}

async function connectSocket(target, proxy, timeoutMs, rejectUnauthorized, alpnProtocols) {
  let socket;
  if (!proxy) socket = await tcpConnect(target.host, target.port, timeoutMs);
  else if (proxy.type === 'socks5') socket = await socks5.connect(proxy, target, timeoutMs);
  else if (target.scheme === 'https') socket = await connectHttpProxy(proxy, target, timeoutMs);
  else socket = await tcpConnect(proxy.host, proxy.port, timeoutMs);
  if (target.scheme === 'https') socket = await tlsWrap(socket, target.host, timeoutMs, rejectUnauthorized, alpnProtocols);
  return socket;
}

function dechunk(buf) {
  const parts = [];
  let offset = 0;
  while (offset < buf.length) {
    const lineEnd = buf.indexOf('\r\n', offset);
    if (lineEnd === -1) break;
    const size = parseInt(buf.toString('latin1', offset, lineEnd).split(';')[0].trim(), 16);
    if (!Number.isFinite(size) || size <= 0) break;
    const start = lineEnd + 2;
    if (start + size > buf.length) {
      parts.push(buf.slice(start));
      break;
    }
    parts.push(buf.slice(start, start + size));
    offset = start + size + 2;
  }
  return Buffer.concat(parts);
}

function chunkedComplete(body) {
  let offset = 0;
  while (offset < body.length) {
    const lineEnd = body.indexOf('\r\n', offset);
    if (lineEnd === -1) return false;
    const size = parseInt(body.toString('latin1', offset, lineEnd).split(';')[0].trim(), 16);
    if (!Number.isFinite(size)) return false;
    if (size === 0) return body.length >= lineEnd + 4;
    offset = lineEnd + 2 + size + 2;
    if (offset > body.length) return false;
  }
  return false;
}

function responseComplete(buf, method) {
  let offset = 0;
  while (true) {
    const sep = buf.indexOf('\r\n\r\n', offset);
    if (sep === -1) return false;
    const head = buf.toString('latin1', offset, sep);
    const status = Number((head.match(/^HTTP\/\d\.\d\s+(\d+)/) || [])[1]);
    if (status >= 100 && status < 200 && status !== 101) {
      offset = sep + 4;
      continue;
    }
    if (method === 'HEAD' || status === 204 || status === 304) return true;
    if (/transfer-encoding:\s*chunked/i.test(head)) return chunkedComplete(buf.slice(sep + 4));
    const match = /content-length:\s*(\d+)/i.exec(head);
    if (match) return buf.length >= sep + 4 + Number(match[1]);
    return false;
  }
}

function readAll(socket, timeoutMs, method, maxBytes) {
  const limit = maxBytes || DEFAULT_MAX_BYTES;
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    let done = false;

    const finish = (err, extra) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      const buf = Buffer.concat(chunks);
      socket.destroy();
      if (err && !buf.length) {
        reject(err);
        return;
      }
      resolve({ buffer: buf, timedOut: Boolean(extra && extra.timedOut), truncated: Boolean(extra && extra.truncated) });
    };

    const timer = setTimeout(() => finish(new Error('read timeout'), { timedOut: true }), timeoutMs);

    const onData = (chunk) => {
      chunks.push(chunk);
      total += chunk.length;
      if (total >= limit) {
        const joined = Buffer.concat(chunks);
        chunks.length = 0;
        chunks.push(joined.slice(0, limit));
        finish(null, { truncated: true });
        return;
      }
      if (responseComplete(Buffer.concat(chunks), method)) finish();
    };

    socket.on('data', onData);
    socket.once('end', () => finish());
    socket.once('close', () => finish());
    socket.once('error', (err) => finish(err));
  });
}

function parseResponse(buf) {
  let offset = 0;
  let head = '';
  while (true) {
    const sep = buf.indexOf('\r\n\r\n', offset);
    if (sep === -1) {
      head = buf.toString('latin1', offset);
      offset = buf.length;
      break;
    }
    const candidate = buf.toString('latin1', offset, sep);
    const code = Number((candidate.match(/^HTTP\/\d\.\d\s+(\d+)/) || [])[1]);
    if (code >= 100 && code < 200 && code !== 101) {
      offset = sep + 4;
      continue;
    }
    head = candidate;
    offset = sep + 4;
    break;
  }

  let bodyBuf = buf.slice(offset);
  const lines = head.split('\r\n');
  const statusLine = lines[0] || '';
  const status = Number((statusLine.match(/^HTTP\/\d\.\d\s+(\d+)/) || [])[1]);
  const headers = {};

  for (const line of lines.slice(1)) {
    const i = line.indexOf(':');
    if (i < 1) continue;
    const name = line.slice(0, i).trim();
    const value = line.slice(i + 1).trim();
    const key = name.toLowerCase();
    if (!headers[key]) headers[key] = [];
    headers[key].push(value);
  }

  if ((headers['transfer-encoding'] || []).join(',').toLowerCase().includes('chunked')) {
    bodyBuf = dechunk(bodyBuf);
  }

  const encoding = (headers['content-encoding'] || []).join(',').toLowerCase();
  try {
    if (encoding.includes('gzip')) bodyBuf = zlib.gunzipSync(bodyBuf);
    else if (encoding.includes('deflate')) bodyBuf = zlib.inflateSync(bodyBuf);
    else if (encoding.includes('br')) bodyBuf = zlib.brotliDecompressSync(bodyBuf);
  } catch (err) {}

  return {
    status,
    statusLine,
    headers,
    rawHead: head,
    rawText: buf.toString('latin1'),
    body: bodyBuf.toString('utf8'),
    bodyLength: bodyBuf.length
  };
}

function canonicalHeader(name) {
  return String(name).split('-').map((part) => part.charAt(0).toUpperCase() + part.slice(1)).join('-');
}

function lowerCaseKeys(headers) {
  const out = {};
  for (const [name, value] of Object.entries(headers || {})) out[name.toLowerCase()] = value;
  return out;
}

function headerValues(headers, name) {
  if (!headers) return [];
  const value = headers[name];
  if (value === undefined || value === null) return [];
  return Array.isArray(value) ? value : [value];
}

function cookieHost(url) {
  return withoutBrackets(new URL(url).hostname).toLowerCase();
}

function domainMatches(host, domain) {
  return host === domain || host.endsWith('.' + domain);
}

function pathMatches(requestPath, cookiePath) {
  if (!cookiePath || cookiePath === '/') return true;
  if (requestPath === cookiePath) return true;
  if (!requestPath.startsWith(cookiePath)) return false;
  return cookiePath.endsWith('/') || requestPath.charAt(cookiePath.length) === '/';
}

function parseSetCookie(line, url) {
  const parts = String(line).split(';');
  const pair = (parts.shift() || '').trim();
  const eq = pair.indexOf('=');
  if (eq <= 0) return null;
  const name = pair.slice(0, eq).trim();
  if (!name) return null;
  const value = pair.slice(eq + 1).trim();
  const host = cookieHost(url);
  let domain = host;
  let path = '/';
  let secure = false;
  let expires = null;
  for (const attr of parts) {
    const idx = attr.indexOf('=');
    const key = (idx === -1 ? attr : attr.slice(0, idx)).trim().toLowerCase();
    const val = idx === -1 ? '' : attr.slice(idx + 1).trim();
    if (key === 'domain' && val) domain = val.replace(/^\./, '').toLowerCase();
    else if (key === 'path' && val) path = val;
    else if (key === 'secure') secure = true;
    else if (key === 'max-age') {
      const seconds = Number(val);
      if (Number.isFinite(seconds)) expires = Date.now() + seconds * 1000;
    } else if (key === 'expires') {
      const at = Date.parse(val);
      if (Number.isFinite(at)) expires = at;
    }
  }
  if (!domainMatches(host, domain)) return null;
  return { name, value, domain, path, secure, expires };
}

class CookieJar {
  constructor() {
    this.cookies = new Map();
  }

  static fromHeader(header, url) {
    const jar = new CookieJar();
    if (!header) return jar;
    const host = cookieHost(url);
    const secure = new URL(url).protocol === 'https:';
    for (const part of String(header).split(';')) {
      const eq = part.indexOf('=');
      if (eq <= 0) continue;
      const name = part.slice(0, eq).trim();
      const value = part.slice(eq + 1).trim();
      if (!name) continue;
      jar.cookies.set(host + '\0/\0' + name, {
        name, value, domain: host, path: '/', secure, expires: null
      });
    }
    return jar;
  }

  absorb(headers, url) {
    for (const line of headerValues(headers, 'set-cookie')) {
      const cookie = parseSetCookie(line, url);
      if (!cookie) continue;
      const key = cookie.domain + '\0' + cookie.path + '\0' + cookie.name;
      if (cookie.expires !== null && cookie.expires <= Date.now()) this.cookies.delete(key);
      else this.cookies.set(key, cookie);
    }
  }

  header(url, options) {
    options = options || {};
    const target = new URL(url);
    const host = cookieHost(url);
    const path = target.pathname || '/';
    const secure = target.protocol === 'https:';
    const pairs = [];
    for (const cookie of this.cookies.values()) {
      if (!domainMatches(host, cookie.domain)) continue;
      if (!options.ignorePath && !pathMatches(path, cookie.path)) continue;
      if (cookie.secure && !secure) continue;
      if (cookie.expires !== null && cookie.expires <= Date.now()) continue;
      pairs.push(cookie.name + '=' + cookie.value);
    }
    return pairs.join('; ');
  }
}

function http2ResponseHeaders(hdrs) {
  const out = {};
  const lines = [];
  for (const [rawName, rawValue] of Object.entries(hdrs || {})) {
    if (rawName.startsWith(':')) continue;
    const name = rawName.toLowerCase();
    const values = Array.isArray(rawValue) ? rawValue.map(String) : [String(rawValue)];
    out[name] = values;
    for (const value of values) lines.push(canonicalHeader(name) + ': ' + value);
  }
  return { headers: out, lines };
}

async function http2Once(options) {
  const target = parseUrl(options.url);
  if (target.scheme !== 'https') throw new Error('http2 requires https');
  const started = Date.now();
  const timeoutMs = options.timeoutMs || 10000;
  const origin = target.scheme + '://' + target.hostHeader;
  let client;
  if (options.proxy) {
    const socket = await connectSocket(target, options.proxy, timeoutMs, options.rejectUnauthorized, ['h2']);
    if (socket.alpnProtocol && socket.alpnProtocol !== 'h2') {
      socket.destroy();
      throw new Error('http2 negotiation failed, target selected ' + socket.alpnProtocol);
    }
    client = http2.connect(origin, {
      rejectUnauthorized: options.rejectUnauthorized !== false,
      createConnection: () => socket
    });
  } else {
    client = http2.connect(origin, { rejectUnauthorized: options.rejectUnauthorized !== false });
  }

  return new Promise((resolve, reject) => {
    let settled = false;
    let timer = null;
    let req = null;
    const fail = (err) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      try { if (req) req.close(); } catch (e) {}
      try { client.close(); } catch (e) {}
      reject(err);
    };
    const headers = Object.assign({}, lowerCaseKeys(options.headers || {}));
    delete headers.connection;
    delete headers['proxy-connection'];
    delete headers['keep-alive'];
    delete headers['transfer-encoding'];
    delete headers.upgrade;
    delete headers.host;
    headers[':method'] = String(options.method || 'GET').toUpperCase();
    headers[':path'] = target.path || '/';
    headers[':scheme'] = target.scheme;
    headers[':authority'] = target.hostHeader;

    timer = setTimeout(() => fail(new Error('http2 timeout')), timeoutMs);
    client.on('error', fail);
    try {
      req = client.request(headers);
    } catch (err) {
      fail(err);
      return;
    }

    let data = Buffer.alloc(0);
    let status = 0;
    let responseHeaders = {};
    req.on('response', (hdrs) => {
      status = Number(hdrs[':status'] || 0);
      responseHeaders = hdrs;
    });
    req.on('data', (chunk) => { data = Buffer.concat([data, chunk]); });
    req.on('end', () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { client.close(); } catch (e) {}
      const normalized = http2ResponseHeaders(responseHeaders);
      const rawHead = ['HTTP/2 ' + status].concat(normalized.lines).join('\r\n') + '\r\n\r\n';
      let bodyBuf = data;
      const encoding = (normalized.headers['content-encoding'] || []).join(',').toLowerCase();
      try {
        if (encoding.includes('gzip')) bodyBuf = zlib.gunzipSync(bodyBuf);
        else if (encoding.includes('deflate')) bodyBuf = zlib.inflateSync(bodyBuf);
        else if (encoding.includes('br')) bodyBuf = zlib.brotliDecompressSync(bodyBuf);
      } catch (err) {}
      const text = bodyBuf.toString('utf8');
      resolve({
        status,
        statusLine: 'HTTP/2 ' + status,
        headers: normalized.headers,
        rawHead,
        rawText: rawHead + text,
        body: text,
        bodyLength: bodyBuf.length,
        ms: Date.now() - started,
        redirectChain: [status],
        timedOut: false,
        truncated: false,
        url: options.url,
        method: String(options.method || 'GET').toUpperCase()
      });
    });
    req.on('error', fail);
    const bodyBuf = options.body === undefined || options.body === null
      ? null
      : Buffer.isBuffer(options.body) ? options.body : Buffer.from(String(options.body));
    if (bodyBuf) req.write(bodyBuf);
    req.end();
  });
}

async function once(options) {
  const { url, method = 'GET', headers = {}, body, timeoutMs = 10000, proxy = null, rejectUnauthorized = true } = options;
  const target = parseUrl(url);
  if (options.http2 && target.scheme === 'https') {
    return http2Once(options);
  }
  const started = Date.now();
  const socket = await connectSocket(target, proxy, timeoutMs, rejectUnauthorized);
  const viaHttpProxy = proxy && proxy.type !== 'socks5' && target.scheme === 'http';

  const bodyBuf = body === undefined || body === null
    ? null
    : Buffer.isBuffer(body) ? body : Buffer.from(String(body));

  const finalHeaders = {
    host: target.hostHeader,
    connection: 'close',
    accept: '*/*',
    'accept-encoding': 'gzip, deflate, br'
  };
  Object.assign(finalHeaders, lowerCaseKeys(headers));
  if (bodyBuf) {
    finalHeaders['content-length'] = String(bodyBuf.length);
    if (!finalHeaders['content-type']) {
      finalHeaders['content-type'] = /^\s*[\[{]/.test(String(bodyBuf)) ? 'application/json' : 'application/x-www-form-urlencoded';
    }
  }
  if (viaHttpProxy && proxy.auth && !finalHeaders['proxy-authorization']) {
    finalHeaders['proxy-authorization'] = 'Basic ' + Buffer.from(proxy.auth).toString('base64');
  }

  const requestTarget = viaHttpProxy
    ? target.scheme + '://' + target.hostHeader + (target.path || '/')
    : (target.path || '/');
  const headLines = [String(method).toUpperCase() + ' ' + requestTarget + ' HTTP/1.1'];
  for (const [name, value] of Object.entries(finalHeaders)) {
    if (value === undefined || value === null) continue;
    headLines.push(canonicalHeader(name) + ': ' + value);
  }

  const payload = Buffer.concat([
    Buffer.from(headLines.join('\r\n') + '\r\n\r\n', 'latin1'),
    bodyBuf || Buffer.alloc(0)
  ]);

  try {
    socket.write(payload);
  } catch (err) {
    socket.destroy();
    throw err;
  }

  const read = await readAll(socket, timeoutMs, String(method).toUpperCase(), options.maxResponseBytes);
  const parsed = parseResponse(read.buffer);
  parsed.ms = Date.now() - started;
  parsed.url = url;
  parsed.method = String(method).toUpperCase();
  parsed.timedOut = read.timedOut;
  parsed.truncated = read.truncated;
  return parsed;
}

async function request(options) {
  const maxRedirects = options.maxRedirects === undefined ? 3 : options.maxRedirects;
  const chain = [];
  const allSetCookie = [];
  const baseHeaders = Object.assign({}, options.headers);
  const initialCookie = baseHeaders.cookie || baseHeaders.Cookie;
  delete baseHeaders.cookie;
  delete baseHeaders.Cookie;
  const jar = CookieJar.fromHeader(initialCookie, options.url);
  let current = Object.assign({}, options, { headers: baseHeaders });

  const finish = (res) => {
    res.redirectChain = chain;
    res.finalUrl = current.url;
    res.allSetCookie = allSetCookie;
    res.setCookies = allSetCookie;
    res.cookieHeader = jar.header(res.url || current.url) || '';
    res.allCookieHeader = jar.header(res.url || current.url, { ignorePath: true }) || '';
    return res;
  };

  for (let hop = 0; hop <= maxRedirects; hop++) {
    const hopHeaders = Object.assign({}, current.headers);
    const cookie = jar.header(current.url);
    if (cookie) hopHeaders.cookie = cookie;
    const res = await once(Object.assign({}, current, { headers: hopHeaders, rejectUnauthorized: options.rejectUnauthorized }));
    chain.push(res.status);
    for (const line of headerValues(res.headers, 'set-cookie')) allSetCookie.push(line);
    jar.absorb(res.headers, current.url);
    const location = (res.headers.location || [])[0];
    const shouldFollow = options.followRedirects && location && [301, 302, 303, 307, 308].includes(res.status);
    if (!shouldFollow || hop >= maxRedirects) return finish(res);
    const nextUrl = new URL(location, current.url).toString();
    const nextHeaders = Object.assign({}, current.headers);
    let sameOrigin = false;
    try {
      sameOrigin = new URL(nextUrl).origin === new URL(current.url).origin;
    } catch (err) {}
    if (!sameOrigin) {
      delete nextHeaders.host;
      delete nextHeaders.Host;
      delete nextHeaders.cookie;
      delete nextHeaders.Cookie;
    }
    current = Object.assign({}, current, {
      url: nextUrl,
      headers: nextHeaders,
      body: res.status === 303 ? undefined : current.body,
      method: res.status === 303 ? 'GET' : current.method,
      rejectUnauthorized: options.rejectUnauthorized
    });
  }

  return finish(await once(current));
}

module.exports = { request, once, parseUrl, parseResponse, connectSocket, CookieJar };
