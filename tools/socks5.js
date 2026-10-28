const net = require('net');

function createReader(socket) {
  let buffer = Buffer.alloc(0);
  let waiter = null;
  let failure = null;

  const wake = () => {
    if (waiter) {
      const resolve = waiter;
      waiter = null;
      resolve();
    }
  };

  const onData = (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);
    wake();
  };
  const onError = (err) => {
    failure = err;
    wake();
  };
  const onClose = () => {
    failure = failure || new Error('socks5: connection closed');
    wake();
  };

  socket.on('data', onData);
  socket.once('error', onError);
  socket.once('close', onClose);

  return {
    async read(n) {
      while (buffer.length < n) {
        if (failure) throw failure;
        await new Promise((resolve) => { waiter = resolve; });
      }
      const out = buffer.slice(0, n);
      buffer = buffer.slice(n);
      return out;
    },
    release() {
      socket.removeListener('data', onData);
      socket.removeListener('error', onError);
      socket.removeListener('close', onClose);
      if (buffer.length) socket.unshift(buffer);
      buffer = Buffer.alloc(0);
    }
  };
}

function parseAuth(auth) {
  if (!auth) return null;
  const str = String(auth);
  const idx = str.indexOf(':');
  if (idx === -1) return null;
  return { username: str.slice(0, idx), password: str.slice(idx + 1) };
}

function ipv6ToBytes(host) {
  const raw = String(host);
  const parts = raw.split('::');
  let groups;
  if (parts.length === 1) {
    groups = parts[0].split(':');
  } else {
    const head = parts[0] ? parts[0].split(':') : [];
    const tail = parts[1] ? parts[1].split(':') : [];
    const missing = 8 - head.length - tail.length;
    groups = head.concat(Array(Math.max(0, missing)).fill('0'), tail);
  }
  const out = Buffer.alloc(16);
  for (let i = 0; i < 8; i++) {
    out.writeUInt16BE(parseInt(groups[i] || '0', 16), i * 2);
  }
  return out;
}

function addressField(host) {
  const ipVersion = net.isIP(host);
  if (ipVersion === 4) {
    return Buffer.from([0x01].concat(host.split('.').map((part) => Number(part) & 0xff)));
  }
  if (ipVersion === 6) {
    return Buffer.concat([Buffer.from([0x04]), ipv6ToBytes(host)]);
  }
  const name = Buffer.from(String(host));
  if (!name.length || name.length > 255) throw new Error('socks5: invalid target hostname');
  return Buffer.concat([Buffer.from([0x03, name.length]), name]);
}

async function connect(proxy, target, timeoutMs = 10000) {
  const socket = net.connect({ host: proxy.host, port: proxy.port });
  socket.setTimeout(timeoutMs);

  await new Promise((resolve, reject) => {
    socket.once('connect', resolve);
    socket.once('error', reject);
    socket.once('timeout', () => {
      socket.destroy();
      reject(new Error('socks5: connect timeout'));
    });
  });

  const reader = createReader(socket);
  const auth = parseAuth(proxy.auth);
  const watchdog = setTimeout(() => {
    socket.destroy(new Error('socks5: handshake timeout'));
  }, timeoutMs);

  try {
    const methods = auth ? [0x00, 0x02] : [0x00];
    socket.write(Buffer.from([0x05, methods.length].concat(methods)));
    const greeting = await reader.read(2);
    if (greeting[0] !== 0x05) throw new Error('socks5: invalid greeting version');
    if (greeting[1] === 0xff) throw new Error('socks5: no acceptable auth method');
    if (greeting[1] === 0x02) {
      if (!auth) throw new Error('socks5: proxy requires authentication');
      const user = Buffer.from(auth.username);
      const pass = Buffer.from(auth.password);
      if (user.length > 255 || pass.length > 255) {
        throw new Error('socks5: username and password must be at most 255 bytes');
      }
      socket.write(Buffer.concat([
        Buffer.from([0x01, user.length]),
        user,
        Buffer.from([pass.length]),
        pass
      ]));
      const result = await reader.read(2);
      if (result[1] !== 0x00) throw new Error('socks5: authentication failed');
    } else if (greeting[1] !== 0x00) {
      throw new Error('socks5: unsupported auth method ' + greeting[1]);
    }

    const port = Buffer.alloc(2);
    port.writeUInt16BE(target.port, 0);
    socket.write(Buffer.concat([Buffer.from([0x05, 0x01, 0x00]), addressField(target.host), port]));

    const reply = await reader.read(4);
    if (reply[0] !== 0x05) throw new Error('socks5: invalid reply version');
    if (reply[1] !== 0x00) throw new Error('socks5: connect rejected, code ' + reply[1]);

    const atyp = reply[3];
    let extra;
    if (atyp === 0x01) extra = 6;
    else if (atyp === 0x04) extra = 18;
    else if (atyp === 0x03) {
      const length = (await reader.read(1))[0];
      extra = length + 2;
    } else {
      throw new Error('socks5: unknown address type ' + atyp);
    }
    await reader.read(extra);
  } catch (err) {
    reader.release();
    socket.destroy();
    throw err;
  } finally {
    clearTimeout(watchdog);
  }

  reader.release();
  socket.setTimeout(0);
  return socket;
}

module.exports = { connect };
