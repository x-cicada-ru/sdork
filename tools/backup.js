const rawhttp = require('./rawhttp');
const ua = require('./ua');
const { decodeEntities, stripTags } = require('./dork');

const BACKUP_EXTENSION_RE = /\.(?:sql|dump|bak|backup|bkp|old|orig|zip|rar|7z|tar|gz|tgz|bz2|xz|env)(?:\.gz)?$/i;
const BACKUP_NAME_RE = /(?:^|[._-])(?:backup|dump|database|db|users|customers|accounts|credentials)(?:[._-]|$)/i;
const BACKUP_TEXT_RE = /\.(?:txt|json|xml|csv|conf|ini|log)$/i;
const SIZE_RE = /(\d[\d\s.,]*)\s*(bytes?|kb|mb|gb|tb|k|m|g|t|b|кб|мб|гб)(?![a-zа-я])/i;

function safeDecode(value) {
  try {
    return decodeURIComponent(String(value || ''));
  } catch (err) {
    return String(value || '');
  }
}

function fileNameFromUrl(value) {
  try {
    const parsed = new URL(String(value || ''));
    const raw = parsed.pathname.split('/').filter(Boolean).pop() || '';
    return safeDecode(raw);
  } catch (err) {
    return '';
  }
}

function isBackupFile(name) {
  const value = String(name || '').toLowerCase();
  if (!value || value === '.' || value === '..') return false;
  if (BACKUP_EXTENSION_RE.test(value)) return true;
  if (/^(?:\.htaccess|\.env)(?:\.|$)/i.test(value)) return true;
  if (/^wp-config(?:\.|$)/i.test(value)) return true;
  return BACKUP_TEXT_RE.test(value) && BACKUP_NAME_RE.test(value);
}

function isBackupQuery(value) {
  return /(?:backup|dump|database\.sql|db\.sql|users\.sql|\.bak\b|\.old\b|\.zip\b|\.rar\b|\.tar\.gz\b|\.sql\b|\b(?:bak|bkp|dump|zip|rar)\b|(?:ext|filetype|inurl):sql\b)/i
    .test(String(value || ''));
}

function parseSizeKb(value) {
  const match = SIZE_RE.exec(String(value || ''));
  if (!match) return null;
  const unit = match[2].toLowerCase();
  const raw = match[1].replace(/\s+/g, '');
  const numeric = /^(?:bytes?|b)$/.test(unit)
    ? raw.replace(/,/g, '')
    : raw.replace(/,/g, '.');
  const amount = Number(numeric);
  if (!Number.isFinite(amount)) return null;
  if (/^(?:bytes?|b)$/.test(unit)) return amount / 1024;
  if (unit === 'k' || unit === 'kb' || unit === 'кб') return amount;
  if (unit === 'm' || unit === 'mb' || unit === 'мб') return amount * 1024;
  if (unit === 'g' || unit === 'gb' || unit === 'гб') return amount * 1024 * 1024;
  if (unit === 't' || unit === 'tb') return amount * 1024 * 1024 * 1024;
  return amount;
}

function formatSizeKb(value) {
  if (value === null || value === undefined || !Number.isFinite(Number(value))) return '?';
  const amount = Number(value);
  const rounded = amount >= 100 ? Math.round(amount) : Math.round(amount * 100) / 100;
  return String(rounded).replace('.', ',') + ' КБ';
}

function extractDirectoryEntries(html, baseUrl) {
  const source = String(html || '');
  let base;
  try {
    base = new URL(String(baseUrl || ''));
  } catch (err) {
    return [];
  }
  if (!base.pathname.endsWith('/') && !/\.[a-z0-9]+$/i.test(base.pathname)) base.pathname += '/';
  const anchors = [];
  const pattern = /<a\b([^>]*)>([\s\S]*?)<\/a>/gi;
  let match;
  while ((match = pattern.exec(source)) !== null) {
    anchors.push({
      start: match.index,
      end: pattern.lastIndex,
      attrs: match[1],
      text: match[2]
    });
  }

  const entries = [];
  const seen = new Set();
  for (let index = 0; index < anchors.length; index++) {
    const anchor = anchors[index];
    const hrefMatch = /\bhref\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(anchor.attrs);
    if (!hrefMatch) continue;
    const href = decodeEntities(hrefMatch[2] || hrefMatch[3] || hrefMatch[4] || '').trim();
    if (!href || href.startsWith('#') || href.startsWith('?')) continue;

    let target;
    try {
      target = new URL(href, base);
    } catch (err) {
      continue;
    }
    const targetHost = target.hostname.toLowerCase().replace(/^www\./, '');
    const baseHost = base.hostname.toLowerCase().replace(/^www\./, '');
    if (targetHost !== baseHost || target.pathname.endsWith('/')) continue;

    const name = fileNameFromUrl(target.toString());
    if (!name || !isBackupFile(name)) continue;
    const key = target.toString();
    if (seen.has(key)) continue;
    seen.add(key);

    const nextStart = index + 1 < anchors.length ? anchors[index + 1].start : source.length;
    const after = stripTags(source.slice(anchor.end, Math.min(nextStart, anchor.end + 2000)));
    const before = stripTags(source.slice(Math.max(0, anchor.start - 300), anchor.start));
    const sizeKb = parseSizeKb(after) === null ? parseSizeKb(before + ' ' + after) : parseSizeKb(after);
    entries.push({ name, url: key, sizeKb });
  }
  return entries;
}

function headerValue(headers, name) {
  const value = headers && headers[String(name).toLowerCase()];
  return Array.isArray(value) ? value[0] : value;
}

function requestOptions(url, method, options) {
  return {
    url,
    method,
    headers: {
      'User-Agent': options.userAgent || ua.randomAgent(),
      Accept: method === 'HEAD' ? '*/*' : 'text/html,text/plain,*/*'
    },
    timeoutMs: options.timeoutMs || 10000,
    proxy: options.proxy || null,
    maxRedirects: 3,
    followRedirects: true,
    rejectUnauthorized: options.rejectUnauthorized !== false,
    http2: Boolean(options.http2)
  };
}

async function fetchSizeKb(url, options) {
  try {
    const response = await options.request(requestOptions(url, 'HEAD', options));
    if (!response || response.status >= 400) return null;
    const length = Number(headerValue(response.headers, 'content-length'));
    return Number.isFinite(length) && length >= 0 ? length / 1024 : null;
  } catch (err) {
    return null;
  }
}

async function enrichResult(result, options) {
  if (!result || !/^https?:\/\//i.test(String(result.url || ''))) return result;
  let parsed;
  try {
    parsed = new URL(result.url);
  } catch (err) {
    return result;
  }

  const directName = fileNameFromUrl(result.url);
  if (isBackupFile(directName) && !parsed.pathname.endsWith('/')) {
    const sizeKb = await fetchSizeKb(result.url, options);
    result.files = [{ name: directName, url: result.url, sizeKb }];
    return result;
  }

  let response;
  try {
    response = await options.request(requestOptions(result.url, 'GET', options));
  } catch (err) {
    return result;
  }
  if (!response || response.status >= 400) return result;

  const contentType = String(headerValue(response.headers, 'content-type') || '');
  if (contentType && !/html|text\/plain|application\/xhtml/i.test(contentType)) return result;
  const body = String(response.body || '');
  if (!/(?:index of|directory listing|to parent directory|<a\b)/i.test(body)) return result;

  const pageUrl = response.finalUrl || result.url;
  const entries = extractDirectoryEntries(body, pageUrl);
  if (entries.length) {
    result.url = pageUrl;
    result.files = entries;
  }
  return result;
}

async function enrichResults(results, options) {
  const list = Array.isArray(results) ? results : [];
  const settings = Object.assign({}, options || {}, { request: (options && options.request) || rawhttp.request });
  const limit = Math.max(1, Math.min(list.length, Number(settings.maxPages || 20)));
  let cursor = 0;
  const worker = async () => {
    while (cursor < limit) {
      const current = list[cursor++];
      try {
        await enrichResult(current, settings);
      } catch (err) {}
    }
  };
  await Promise.all(Array.from({ length: Math.min(4, limit) }, worker));
  return list;
}

module.exports = {
  isBackupFile,
  isBackupQuery,
  parseSizeKb,
  formatSizeKb,
  extractDirectoryEntries,
  enrichResult,
  enrichResults
};
