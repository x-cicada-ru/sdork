function tryDecode(value) {
  const str = String(value);
  if (str.indexOf('%') === -1) return str;
  try {
    return decodeURIComponent(str);
  } catch (err) {
    return null;
  }
}

function decodeOnce(value) {
  const decoded = tryDecode(value);
  return decoded === null ? String(value) : decoded;
}

function percent(ch) {
  return '%' + ch.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0');
}

function encodeUnsafe(value) {
  return String(value).replace(/%(?![0-9A-Fa-f]{2})|[^\x21-\x7e]|[&#<>"]/g, (ch) => {
    if (ch === '%') return '%25';
    return percent(ch);
  });
}

function encodeForUrl(value) {
  const decoded = tryDecode(value);
  if (decoded === null) return encodeUnsafe(value);
  return encodeURIComponent(decoded).replace(/[!'()*]/g, percent);
}

function encodeForForm(value) {
  return encodeForUrl(value).replace(/%20/g, '+');
}

function rawValue(value) {
  return decodeOnce(value);
}

function rawHeader(value) {
  const decoded = tryDecode(value);
  return decoded === null ? String(value) : decoded;
}

function coerceJson(value) {
  const decoded = decodeOnce(value);
  const trimmed = decoded.trim();
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      return JSON.parse(trimmed);
    } catch (err) {}
  }
  return decoded;
}

function jsonEmbedded(value) {
  return JSON.stringify(decodeOnce(value)).slice(1, -1);
}

function decodeKey(rawKey) {
  try {
    return decodeURIComponent(String(rawKey).replace(/\+/g, ' '));
  } catch (err) {
    return String(rawKey);
  }
}

function setQueryParam(urlStr, name, payload) {
  const u = new URL(urlStr);
  const encoded = encodeForUrl(payload);
  const rawQuery = u.search.startsWith('?') ? u.search.slice(1) : '';
  const pairs = rawQuery ? rawQuery.split('&') : [];
  let found = false;
  const rebuilt = pairs.map((pair) => {
    if (!pair) return pair;
    const eq = pair.indexOf('=');
    const rawKey = eq === -1 ? pair : pair.slice(0, eq);
    if (decodeKey(rawKey) !== name) return pair;
    found = true;
    return rawKey + '=' + encoded;
  });
  if (!found) rebuilt.push(encodeURIComponent(name) + '=' + encoded);
  return u.origin + u.pathname + '?' + rebuilt.join('&') + u.hash;
}

function replaceFuzzUrl(urlStr, payload) {
  const encoded = encodeForUrl(payload);
  return String(urlStr).replace(/FUZZ/g, () => encoded);
}

module.exports = {
  tryDecode,
  decodeOnce,
  encodeForUrl,
  encodeForForm,
  rawValue,
  rawHeader,
  coerceJson,
  jsonEmbedded,
  setQueryParam,
  replaceFuzzUrl,
  encodeUnsafe
};
