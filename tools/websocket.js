const crypto = require('crypto');
const rawhttp = require('./rawhttp');

function isWebSocketUrl(value) {
  return /^wss?:\/\//i.test(String(value || ''));
}

function normalizeHeaders(headers) {
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

function encodeFrame(data, opcode) {
  const payload = Buffer.isBuffer(data) ? data : Buffer.from(String(data));
  const type = opcode === undefined ? 1 : opcode;
  const mask = crypto.randomBytes(4);
  let header;
  if (payload.length < 126) {
    header = Buffer.from([0x80 | type, 0x80 | payload.length]);
  } else if (payload.length < 65536) {
    header = Buffer.alloc(4);
    header[0] = 0x80 | type;
    header[1] = 0x80 | 126;
    header.writeUInt16BE(payload.length, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x80 | type;
    header[1] = 0x80 | 127;
    header.writeBigUInt64BE(BigInt(payload.length), 2);
  }
  const masked = Buffer.alloc(payload.length);
  for (let i = 0; i < payload.length; i++) masked[i] = payload[i] ^ mask[i % 4];
  return Buffer.concat([header, mask, masked]);
}

function decodeFrames(buffer) {
  const frames = [];
  let offset = 0;
  while (offset + 2 <= buffer.length) {
    const first = buffer[offset];
    const second = buffer[offset + 1];
    let length = second & 0x7f;
    let cursor = offset + 2;
    if (length === 126) {
      if (cursor + 2 > buffer.length) break;
      length = buffer.readUInt16BE(cursor);
      cursor += 2;
    } else if (length === 127) {
      if (cursor + 8 > buffer.length) break;
      length = Number(buffer.readBigUInt64BE(cursor));
      cursor += 8;
    }
    let mask = null;
    if (second & 0x80) {
      if (cursor + 4 > buffer.length) break;
      mask = buffer.slice(cursor, cursor + 4);
      cursor += 4;
    }
    if (cursor + length > buffer.length) break;
    const payload = Buffer.from(buffer.slice(cursor, cursor + length));
    if (mask) {
      for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i % 4];
    }
    frames.push({ fin: Boolean(first & 0x80), opcode: first & 0x0f, payload });
    offset = cursor + length;
  }
  return { frames, rest: buffer.slice(offset) };
}

function fakeConnect(url, options) {
  const Impl = options.WebSocket;
  return new Promise((resolve, reject) => {
    let ws;
    try {
      ws = new Impl(url, options.protocols);
    } catch (err) {
      reject(err);
      return;
    }
    const timer = setTimeout(() => {
      try { ws.close(); } catch (err) { /* ignore */ }
      reject(new Error('websocket connect timed out'));
    }, Number(options.timeoutMs) || 10000);
    ws.onopen = () => {
      clearTimeout(timer);
      resolve(ws);
    };
    ws.onerror = (event) => {
      clearTimeout(timer);
      reject(event && event.error ? event.error : new Error('websocket error'));
    };
    ws.onclose = (event) => {
      clearTimeout(timer);
      reject(new Error('websocket closed before open' + (event && event.code ? ' (' + event.code + ')' : '')));
    };
  });
}

async function rawConnect(url, options) {
  const parsed = new URL(url);
  if (parsed.protocol !== 'ws:' && parsed.protocol !== 'wss:') throw new Error('unsupported websocket protocol');
  const secure = parsed.protocol === 'wss:';
  const mapped = (secure ? 'https:' : 'http:') + '//' + parsed.host + (parsed.pathname || '/') + parsed.search;
  const target = rawhttp.parseUrl(mapped);
  const timeoutMs = Number(options.timeoutMs) || 10000;
  const socket = await rawhttp.connectSocket(target, options.proxy || null, timeoutMs, options.rejectUnauthorized !== false);
  const key = crypto.randomBytes(16).toString('base64');
  const expected = crypto.createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
  const headers = normalizeHeaders(options.headers);
  headers.host = headers.host || target.hostHeader;
  headers.upgrade = 'websocket';
  headers.connection = 'Upgrade';
  headers['sec-websocket-key'] = key;
  headers['sec-websocket-version'] = '13';
  if (options.origin) headers.origin = options.origin;
  if (options.cookie) headers.cookie = options.cookie;
  if (options.userAgent) headers['user-agent'] = options.userAgent;
  const lines = ['GET ' + (target.path || '/') + ' HTTP/1.1'];
  for (const [name, value] of Object.entries(headers)) lines.push(name + ': ' + value);
  socket.write(lines.join('\r\n') + '\r\n\r\n');

  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    let upgraded = false;
    let settled = false;
    let closed = false;
    let timer = null;
    let fragmentOpcode = 0;
    let fragmentPayload = Buffer.alloc(0);
    const queued = [];
    const client = {
      url,
      socket,
      onmessage: null,
      onerror: null,
      onclose: null,
      send(data) {
        if (!upgraded) throw new Error('websocket is not open');
        socket.write(encodeFrame(data, Buffer.isBuffer(data) ? 2 : 1));
      },
      ping(data) {
        if (upgraded) socket.write(encodeFrame(data || '', 0x9));
      },
      close(code, reason) {
        if (closed) return;
        closed = true;
        if (upgraded) {
          const payload = Buffer.alloc(2 + Buffer.byteLength(String(reason || '')));
          payload.writeUInt16BE(Number(code) || 1000, 0);
          payload.write(String(reason || ''), 2);
          try { socket.write(encodeFrame(payload, 0x8)); } catch (err) {}
        }
        try { socket.end(); } catch (err) {}
        try { if (typeof socket.destroySoon === 'function') socket.destroySoon(); } catch (err) {}
      },
      flushMessages() {
        while (queued.length && typeof client.onmessage === 'function') {
          client.onmessage({ data: queued.shift() });
        }
      }
    };
    const fail = (err) => {
      if (settled) {
        if (typeof client.onerror === 'function') client.onerror({ error: err });
        return;
      }
      settled = true;
      try { socket.destroy(); } catch (destroyErr) {}
      reject(err);
    };
    const emit = (data) => {
      if (typeof client.onmessage === 'function') client.onmessage({ data });
      else queued.push(data);
    };
    const handleFrame = (frame) => {
      if (frame.opcode === 0x9) {
        try { socket.write(encodeFrame(frame.payload, 0xA)); } catch (err) {}
        return;
      }
      if (frame.opcode === 0xA) return;
      if (frame.opcode === 0x8) {
        const code = frame.payload.length >= 2 ? frame.payload.readUInt16BE(0) : 1005;
        const reason = frame.payload.length > 2 ? frame.payload.slice(2).toString('utf8') : '';
        closed = true;
        try { socket.end(); } catch (err) {}
        try { if (typeof socket.destroySoon === 'function') socket.destroySoon(); } catch (err) {}
        if (typeof client.onclose === 'function') client.onclose({ code, reason });
        return;
      }
      if (frame.opcode === 0x0) {
        fragmentPayload = Buffer.concat([fragmentPayload, frame.payload]);
        if (frame.fin) {
          if (fragmentOpcode === 1) emit(fragmentPayload.toString('utf8'));
          else emit(fragmentPayload);
          fragmentOpcode = 0;
          fragmentPayload = Buffer.alloc(0);
        }
        return;
      }
      if (!frame.fin) {
        fragmentOpcode = frame.opcode;
        fragmentPayload = frame.payload;
        return;
      }
      if (frame.opcode === 1) emit(frame.payload.toString('utf8'));
      else if (frame.opcode === 2) emit(frame.payload);
    };
    const onData = (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (!upgraded) {
        const sep = buffer.indexOf('\r\n\r\n');
        if (sep === -1) return;
        const head = buffer.slice(0, sep).toString('latin1');
        const lines = head.split('\r\n');
        const status = Number((lines[0].match(/^HTTP\/\d\.\d\s+(\d+)/) || [])[1]);
        const responseHeaders = {};
        for (const line of lines.slice(1)) {
          const idx = line.indexOf(':');
          if (idx !== -1) responseHeaders[line.slice(0, idx).trim().toLowerCase()] = line.slice(idx + 1).trim();
        }
        if (status !== 101) return fail(new Error('websocket handshake returned HTTP ' + status));
        if (responseHeaders['sec-websocket-accept'] !== expected) return fail(new Error('websocket accept mismatch'));
        upgraded = true;
        settled = true;
        if (timer) clearTimeout(timer);
        buffer = buffer.slice(sep + 4);
        if (typeof client.onopen === 'function') client.onopen();
        resolve(client);
      }
      const parsedFrames = decodeFrames(buffer);
      buffer = parsedFrames.rest;
      for (const frame of parsedFrames.frames) handleFrame(frame);
    };
    socket.on('data', onData);
    socket.on('error', (err) => fail(err));
    socket.on('close', () => {
      if (!upgraded) return fail(new Error('websocket closed before open'));
      if (!closed) {
        closed = true;
        if (typeof client.onclose === 'function') client.onclose({ code: 1006, reason: '' });
      }
    });
    timer = setTimeout(() => fail(new Error('websocket connect timed out')), timeoutMs);
    socket.once('close', () => clearTimeout(timer));
    client._timer = timer;
  });
}

function connect(url, options) {
  options = options || {};
  if (!isWebSocketUrl(url)) return Promise.reject(new Error('not a websocket URL: ' + url));
  if (options.WebSocket) return fakeConnect(url, options);
  return rawConnect(url, options);
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function scan(url, options) {
  options = options || {};
  if (!isWebSocketUrl(url)) throw new Error('not a websocket URL: ' + url);
  const payloads = options.payloads && options.payloads.length
    ? options.payloads
    : [options.message || '{"jsonrpc":"2.0","id":1,"method":"ping"}'];
  const messages = [];
  const errors = [];
  let ws;
  try {
    ws = await connect(url, options);
    ws.onmessage = (event) => {
      messages.push(String(event && event.data !== undefined ? event.data : event));
    };
    ws.onerror = (event) => {
      errors.push(event && event.error ? String(event.error.message || event.error) : 'websocket error');
    };
    if (typeof ws.flushMessages === 'function') ws.flushMessages();
    for (const payload of payloads) {
      ws.send(typeof payload === 'string' ? payload : JSON.stringify(payload));
      await delay(Number(options.waitMs) || 150);
    }
    if (options.keepOpen) await delay(Number(options.keepOpenMs) || 500);
    return { connected: true, messages, errors, sent: payloads.length };
  } catch (err) {
    errors.push(err.message || String(err));
    return { connected: false, messages, errors, sent: 0 };
  } finally {
    if (ws) {
      try { ws.close(); } catch (err) { /* ignore */ }
    }
  }
}

module.exports = { isWebSocketUrl, connect, scan, encodeFrame, decodeFrames };
