const fs = require('fs');
const os = require('os');
const net = require('net');
const path = require('path');
const { spawn } = require('child_process');
const { projectPath } = require('./loader');

const PROXY_PROTOCOLS = ['vless', 'vmess', 'trojan', 'shadowsocks'];

function vpnDir() {
  return projectPath('VPN');
}

function readConfig(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (err) {
    return null;
  }
}

function pickProxyOutbound(cfg) {
  const outbounds = Array.isArray(cfg && cfg.outbounds) ? cfg.outbounds : [];
  return outbounds.find((out) => PROXY_PROTOCOLS.includes(out.protocol)) || null;
}

function listProfiles() {
  let files = [];
  try {
    files = fs.readdirSync(vpnDir()).filter((file) => file.endsWith('.json')).sort();
  } catch (err) {
    return [];
  }
  return files.map((file) => {
    const full = path.join(vpnDir(), file);
    const cfg = readConfig(full);
    const outbound = pickProxyOutbound(cfg);
    const vnext = outbound && outbound.settings && Array.isArray(outbound.settings.vnext)
      ? outbound.settings.vnext[0]
      : null;
    return {
      file: full,
      name: path.basename(file, '.json'),
      remarks: (cfg && cfg.remarks) || path.basename(file, '.json'),
      protocol: outbound ? outbound.protocol : null,
      address: vnext ? vnext.address : null,
      port: vnext ? vnext.port : null,
      network: outbound && outbound.streamSettings ? outbound.streamSettings.network : null,
      security: outbound && outbound.streamSettings ? outbound.streamSettings.security : null
    };
  });
}

function resolveProfile(query) {
  if (!query) return null;
  const needle = String(query).trim().toLowerCase();
  const profiles = listProfiles();
  return profiles.find((p) => p.name.toLowerCase() === needle)
    || profiles.find((p) => p.remarks.toLowerCase() === needle)
    || profiles.find((p) => p.remarks.toLowerCase().includes(needle))
    || profiles.find((p) => p.name.toLowerCase().includes(needle))
    || null;
}

function findFreePort(start) {
  return new Promise((resolve, reject) => {
    const attempt = (port) => {
      if (port > start + 200) {
        reject(new Error('no free port found near ' + start));
        return;
      }
      const server = net.createServer();
      server.once('error', () => attempt(port + 1));
      server.listen(port, '127.0.0.1', () => {
        server.close(() => resolve(port));
      });
    };
    attempt(start);
  });
}

function xrayCandidates() {
  const candidates = [];
  if (process.env.SDORK_XRAY) candidates.push(process.env.SDORK_XRAY);
  const binDir = projectPath('tools/bin');
  const names = process.platform === 'win32' ? ['xray.exe', 'xray'] : ['xray', 'xray.exe'];
  for (const name of names) candidates.push(path.join(binDir, name));
  return candidates;
}

function which(binary) {
  const dirs = String(process.env.PATH || '').split(path.delimiter).filter(Boolean);
  const exts = process.platform === 'win32'
    ? String(process.env.PATHEXT || '.EXE;.CMD;.BAT;.COM').split(';').filter(Boolean)
    : [''];
  for (const dir of dirs) {
    for (const ext of exts) {
      const candidate = path.join(dir, binary + ext);
      try {
        if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) return candidate;
      } catch (err) {}
    }
  }
  return null;
}

function findXray() {
  for (const candidate of xrayCandidates()) {
    try {
      if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) return candidate;
    } catch (err) {}
  }
  return which('xray');
}

function waitForPort(port, timeoutMs) {
  const started = Date.now();
  return new Promise((resolve) => {
    const attempt = () => {
      const socket = net.connect({ host: '127.0.0.1', port });
      socket.once('connect', () => {
        socket.destroy();
        resolve(true);
      });
      socket.once('error', () => {
        socket.destroy();
        if (Date.now() - started >= timeoutMs) resolve(false);
        else setTimeout(attempt, 250);
      });
    };
    attempt();
  });
}

function buildConfig(cfg, socksPort, httpPort) {
  const config = JSON.parse(JSON.stringify(cfg || {}));
  config.log = Object.assign({ loglevel: 'warning' }, config.log, { loglevel: 'warning' });
  config.inbounds = [
    {
      tag: 'sdork-socks',
      listen: '127.0.0.1',
      port: socksPort,
      protocol: 'socks',
      settings: { auth: 'noauth', udp: false }
    },
    {
      tag: 'sdork-http',
      listen: '127.0.0.1',
      port: httpPort,
      protocol: 'http',
      settings: {}
    }
  ];
  const outbound = pickProxyOutbound(config);
  if (!outbound) throw new Error('no proxy outbound found in VPN profile');
  outbound.tag = outbound.tag || 'proxy';
  if (!Array.isArray(config.outbounds) || !config.outbounds.includes(outbound)) {
    config.outbounds = [outbound];
  }
  config.routing = config.routing || { domainStrategy: 'AsIs', rules: [] };
  return config;
}

function spawnXray(binary, configPath) {
  const variants = [
    ['run', '-c', configPath],
    ['-c', configPath]
  ];
  return new Promise((resolve, reject) => {
    let stderr = '';
    let attempt = 0;
    const tryVariant = () => {
      if (attempt >= variants.length) {
        reject(new Error('xray failed to start' + (stderr ? ': ' + stderr.trim().split('\n').slice(-3).join(' | ') : '')));
        return;
      }
      const args = variants[attempt++];
      const proc = spawn(binary, args, { stdio: ['ignore', 'ignore', 'pipe'], windowsHide: true });
      let exited = false;
      proc.stderr.on('data', (chunk) => {
        stderr += chunk.toString();
      });
      proc.once('error', (err) => {
        reject(new Error('cannot start xray (' + binary + '): ' + err.message + ' - install xray and set SDORK_XRAY or put xray.exe in tools/bin'));
      });
      proc.once('exit', () => {
        exited = true;
      });
      setTimeout(() => {
        if (!exited) resolve(proc);
        else tryVariant();
      }, 600);
    };
    tryVariant();
  });
}

async function start(profileQuery, options = {}) {
  const profile = resolveProfile(profileQuery);
  if (!profile) throw new Error('VPN profile not found: ' + profileQuery);
  const binary = findXray();
  if (!binary) {
    throw new Error('xray binary not found - set SDORK_XRAY=<path>, place xray(.exe) into tools/bin, or add it to PATH');
  }
  const cfg = readConfig(profile.file);
  if (!cfg) throw new Error('cannot parse VPN profile: ' + profile.file);

  const socksPort = await findFreePort(options.socksPort || 10808);
  const httpPort = await findFreePort(socksPort + 1);
  const config = buildConfig(cfg, socksPort, httpPort);
  const configPath = path.join(os.tmpdir(), 'sdork-xray-' + Date.now() + '-' + process.pid + '.json');
  fs.writeFileSync(configPath, JSON.stringify(config, null, 2));

  let proc = null;
  let ready = false;
  try {
    proc = await spawnXray(binary, configPath);
    ready = await waitForPort(socksPort, options.timeoutMs || 8000);
  } catch (err) {
    if (proc) {
      try { proc.kill(); } catch (killErr) {}
    }
    try { fs.unlinkSync(configPath); } catch (unlinkErr) {}
    throw err;
  } finally {
    if (!ready && proc) {
      try { proc.kill(); } catch (err) {}
    }
  }
  if (!ready) {
    try { fs.unlinkSync(configPath); } catch (err) {}
    throw new Error('xray started but socks port ' + socksPort + ' did not open');
  }

  return {
    profile,
    proxy: { type: 'socks5', host: '127.0.0.1', port: socksPort },
    httpProxy: { type: 'http', host: '127.0.0.1', port: httpPort },
    process: proc,
    configPath,
    stop() {
      try { if (proc) proc.kill(); } catch (err) {}
      try { fs.unlinkSync(configPath); } catch (err) {}
    }
  };
}

function parseProxy(value) {
  if (!value) return null;
  let raw = String(value).trim();
  let type = 'http';
  if (/^socks5?:\/\//i.test(raw)) {
    type = 'socks5';
    raw = raw.replace(/^socks5?:\/\//i, '');
  } else if (/^https?:\/\//i.test(raw)) {
    type = 'http';
    raw = raw.replace(/^https?:\/\//i, '');
  }
  let auth = null;
  const at = raw.lastIndexOf('@');
  if (at !== -1) {
    auth = raw.slice(0, at);
    raw = raw.slice(at + 1);
  }
  const match = /^\[?([^\]]+)\]?:(\d+)$/.exec(raw);
  if (!match) throw new Error('invalid proxy format: ' + value + ' (expected [socks5://][user:pass@]host:port)');
  return { type, host: match[1], port: Number(match[2]), auth };
}

module.exports = { listProfiles, resolveProfile, start, parseProxy, findXray, which };
