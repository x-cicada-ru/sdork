const http = require('http');
const net = require('net');
const dgram = require('dgram');
const crypto = require('crypto');

const TOKEN_ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789';
const TOKEN_RE = /^[a-z0-9]{6,32}$/;

function randomToken(len = 10) {
  const bytes = crypto.randomBytes(len);
  let out = '';
  for (let i = 0; i < len; i++) out += TOKEN_ALPHABET[bytes[i] % TOKEN_ALPHABET.length];
  return out;
}

function encodeDnsName(name) {
  const parts = name.split('.').filter(Boolean);
  const bufs = parts.map((part) => {
    const buf = Buffer.alloc(1 + part.length);
    buf[0] = part.length;
    buf.write(part, 1, 'latin1');
    return buf;
  });
  return Buffer.concat(bufs);
}

function parseDnsQuestion(buf) {
  if (buf.length < 12) return null;
  const qdcount = buf.readUInt16BE(4);
  if (qdcount < 1) return null;
  let offset = 12;
  const labels = [];
  while (offset < buf.length) {
    const len = buf[offset];
    if (len === 0) {
      offset += 1;
      break;
    }
    if (offset + 1 + len > buf.length) return null;
    labels.push(buf.toString('latin1', offset + 1, offset + 1 + len).toLowerCase());
    offset += 1 + len;
  }
  if (offset + 4 > buf.length) return null;
  const qtype = buf.readUInt16BE(offset);
  return { labels, qtype, end: offset + 4 };
}

class OobServer {
  constructor(options = {}) {
    this.domain = options.domain || null;
    this.httpPort = options.httpPort === undefined ? (this.domain ? 80 : 8080) : Number(options.httpPort);
    this.dnsPort = options.dnsPort === undefined ? 53 : Number(options.dnsPort);
    this.smtpPort = options.smtpPort === undefined || options.smtpPort === null ? null : Number(options.smtpPort);
    this.publicPort = options.publicPort === undefined ? this.httpPort : Number(options.publicPort);
    this.listenHost = options.host || '0.0.0.0';
    this.answerIp = options.answerIp || '127.0.0.1';
    this.protocol = options.protocol || 'http';
    this.hits = [];
    this.tokens = new Map();
    this.httpServer = null;
    this.dnsSocket = null;
    this.smtpServer = null;
    this.warnings = [];
  }

  async start() {
    await this.startHttp();
    if (this.domain) {
      try {
        await this.startDns();
      } catch (err) {
        this.warnings.push('dns listener unavailable: ' + err.message);
      }
    }
    if (this.smtpPort) {
      try {
        await this.startSmtp();
      } catch (err) {
        this.warnings.push('smtp listener unavailable: ' + err.message);
      }
    }
    return this;
  }

  startHttp() {
    return new Promise((resolve, reject) => {
      this.httpServer = http.createServer((req, res) => {
        const token = this.extractToken(req.headers.host, req.url);
        this.record({
          channel: 'http',
          token,
          path: req.url,
          method: req.method,
          remote: req.socket.remoteAddress,
          userAgent: req.headers['user-agent'] || null
        });
        res.writeHead(200, { 'content-type': 'text/plain' });
        res.end('RFI_OK\n');
      });
      this.httpServer.once('error', reject);
      this.httpServer.listen(this.httpPort, this.listenHost, () => {
        this.httpPort = this.httpServer.address().port;
        if (this.publicPort === 0) this.publicPort = this.httpPort;
        resolve(this);
      });
    });
  }

  startDns() {
    return new Promise((resolve, reject) => {
      this.dnsSocket = dgram.createSocket('udp4');
      this.dnsSocket.once('error', reject);
      this.dnsSocket.on('message', (msg, rinfo) => {
        const question = parseDnsQuestion(msg);
        if (!question) return;
        const qname = question.labels.join('.');
        const token = this.extractToken(qname, null);
        this.record({
          channel: 'dns',
          token,
          qname,
          remote: rinfo.address + ':' + rinfo.port
        });
        if (question.qtype === 1) {
          const answer = Buffer.alloc(10);
          answer.writeUInt16BE(60, 0);
          answer.writeUInt16BE(4, 4);
          answerIpToBytes(this.answerIp).copy(answer, 6);
          const header = Buffer.alloc(12);
          msg.copy(header, 0, 0, 2);
          header.writeUInt16BE(0x8180, 2);
          header.writeUInt16BE(1, 4);
          header.writeUInt16BE(1, 6);
          const response = Buffer.concat([
            header,
            msg.slice(12, question.end),
            Buffer.from([0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01]),
            answer
          ]);
          this.dnsSocket.send(response, rinfo.port, rinfo.address);
        } else {
          const header = Buffer.alloc(12);
          msg.copy(header, 0, 0, 2);
          header.writeUInt16BE(0x8180, 2);
          header.writeUInt16BE(1, 4);
          this.dnsSocket.send(Buffer.concat([header, msg.slice(12, question.end)]), rinfo.port, rinfo.address);
        }
      });
      this.dnsSocket.bind(this.dnsPort, this.listenHost, resolve);
    });
  }

  startSmtp() {
    return new Promise((resolve, reject) => {
      this.smtpServer = net.createServer((socket) => {
        let buffer = '';
        let inData = false;
        let dataLines = [];
        let rcpt = [];
        socket.write('220 sdork oob smtp\r\n');
        socket.on('data', (chunk) => {
          buffer += chunk.toString('utf8');
          let index;
          while ((index = buffer.indexOf('\r\n')) !== -1) {
            const line = buffer.slice(0, index);
            buffer = buffer.slice(index + 2);
            if (inData) {
              if (line === '.') {
                inData = false;
                this.record({
                  channel: 'email',
                  token: this.extractToken(null, null, rcpt.join(' ') + ' ' + dataLines.join('\n')),
                  rcpt: rcpt.slice(),
                  data: dataLines.join('\n').slice(0, 4000),
                  remote: socket.remoteAddress
                });
                rcpt = [];
                dataLines = [];
                socket.write('250 OK queued\r\n');
              } else {
                dataLines.push(line);
              }
              continue;
            }
            const upper = line.toUpperCase();
            if (upper.startsWith('EHLO') || upper.startsWith('HELO')) {
              socket.write('250-sdork\r\n250 OK\r\n');
            } else if (upper.startsWith('MAIL FROM')) {
              socket.write('250 OK\r\n');
            } else if (upper.startsWith('RCPT TO')) {
              const match = /<([^>]*)>/.exec(line) || [null, line.split(':').slice(1).join(':').trim()];
              rcpt.push(match[1]);
              socket.write('250 OK\r\n');
            } else if (upper.startsWith('DATA')) {
              inData = true;
              socket.write('354 End data with <CR><LF>.<CR><LF>\r\n');
            } else if (upper.startsWith('QUIT')) {
              socket.write('221 Bye\r\n');
              socket.end();
            } else {
              socket.write('250 OK\r\n');
            }
          }
        });
        socket.on('error', () => {});
      });
      this.smtpServer.once('error', reject);
      this.smtpServer.listen(this.smtpPort, this.listenHost, resolve);
    });
  }

  isIssued(token) {
    return Boolean(token && this.tokens.has(String(token).toLowerCase()));
  }

  extractToken(host, url, haystack) {
    if (host) {
      const hostname = String(host).split(':')[0].toLowerCase();
      if (this.domain && hostname.endsWith('.' + this.domain.toLowerCase())) {
        const candidate = hostname.slice(0, -(this.domain.length + 1)).split('.')[0];
        if (this.isIssued(candidate)) return candidate;
      }
      const first = hostname.split('.')[0];
      if (TOKEN_RE.test(first) && this.isIssued(first)) return first;
    }
    if (url) {
      const raw = String(url);
      const path = raw.split('?')[0];
      for (const segment of path.split('/').filter(Boolean)) {
        const candidate = segment.toLowerCase().split(/[._-]/)[0];
        if (TOKEN_RE.test(candidate) && this.isIssued(candidate)) return candidate;
      }
      const query = raw.includes('?') ? raw.slice(raw.indexOf('?') + 1) : '';
      for (const pair of query.split('&')) {
        let value = pair.split('=')[1] || '';
        try { value = decodeURIComponent(value); } catch (err) { value = ''; }
        const candidate = value.toLowerCase().split(/[._-]/)[0];
        if (TOKEN_RE.test(candidate) && this.isIssued(candidate)) return candidate;
      }
    }
    if (haystack) {
      const match = /([a-z0-9]{6,32})(?:\.[a-z0-9-]+){1,}/i.exec(haystack);
      if (match && TOKEN_RE.test(match[1].toLowerCase()) && this.isIssued(match[1])) {
        return match[1].toLowerCase();
      }
    }
    return null;
  }

  issue(meta = {}) {
    const token = randomToken(10);
    const record = this.describe(token);
    Object.assign(record, meta);
    this.tokens.set(token, record);
    return record;
  }

  describe(token) {
    if (this.domain) {
      const host = token + '.' + this.domain;
      const portSuffix = this.publicPort && this.publicPort !== 80 ? ':' + this.publicPort : '';
      return {
        token,
        host,
        hostWithPort: host + portSuffix,
        url: this.protocol + '://' + host + portSuffix + '/' + token
      };
    }
    const portSuffix = this.httpPort !== 80 ? ':' + this.httpPort : '';
    return {
      token,
      host: '127.0.0.1' + portSuffix,
      hostWithPort: '127.0.0.1' + portSuffix,
      url: 'http://127.0.0.1' + portSuffix + '/' + token
    };
  }

  record(hit) {
    hit.time = Date.now();
    if (hit.token === undefined) hit.token = null;
    this.hits.push(hit);
  }

  hitsFor(token) {
    if (!token) return [];
    return this.hits.filter((hit) => hit.token === token);
  }

  hitsSince(ts) {
    return this.hits.filter((hit) => hit.time >= ts);
  }

  matchHits({ tokens, since }) {
    const set = tokens ? new Set([].concat(tokens)) : null;
    return this.hits.filter((hit) => {
      if (since && hit.time < since) return false;
      if (set && !set.has(hit.token)) return false;
      return true;
    });
  }

  waitFor(query, timeoutMs) {
    const started = Date.now();
    return new Promise((resolve) => {
      const poll = () => {
        const hits = this.matchHits(query);
        if (hits.length) return resolve(hits);
        if (Date.now() - started >= timeoutMs) return resolve([]);
        setTimeout(poll, 250);
      };
      poll();
    });
  }

  stop() {
    if (this.httpServer) {
      try { this.httpServer.close(); } catch (err) {}
      this.httpServer = null;
    }
    if (this.dnsSocket) {
      try { this.dnsSocket.close(); } catch (err) {}
      this.dnsSocket = null;
    }
    if (this.smtpServer) {
      try { this.smtpServer.close(); } catch (err) {}
      this.smtpServer = null;
    }
  }
}

function answerIpToBytes(ip) {
  const parts = String(ip).split('.').map((part) => Number(part) & 0xff);
  while (parts.length < 4) parts.push(0);
  return Buffer.from(parts);
}

module.exports = { OobServer, randomToken };
