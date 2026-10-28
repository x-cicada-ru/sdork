const { listDorkFiles, loadJson } = require('./loader');
const rawhttp = require('./rawhttp');
const ua = require('./ua');
const searchApi = require('./search-api');

let categoryCache = null;

function listCategories() {
  if (categoryCache) return categoryCache;
  const files = listDorkFiles();
  categoryCache = files.map((item) => {
    const data = loadJson(item.rel);
    const key = Object.keys(data)[0];
    const list = data[key] || [];
    return {
      name: key,
      file: item.file,
      count: list.length,
      dorks: list
    };
  });
  return categoryCache;
}

function findCategory(name) {
  if (!name) return null;
  const q = String(name).trim().toLowerCase();
  return listCategories().find((cat) => {
    const file = cat.file.toLowerCase();
    return cat.name.toLowerCase() === q || file === q || file.replace(/\.json$/, '') === q;
  }) || null;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

const NAMED_ENTITIES = {
  amp: '&',
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
  nbsp: ' '
};

function decodeEntities(value) {
  return String(value)
    .replace(/&#x([0-9a-f]+);/gi, (match, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (match, dec) => String.fromCharCode(Number(dec)))
    .replace(/&([a-z]+);/gi, (match, name) => NAMED_ENTITIES[name.toLowerCase()] || match);
}

function stripTags(value) {
  return decodeEntities(String(value || '').replace(/<[^>]+>/g, '')).replace(/\s+/g, ' ').trim();
}

function safeDecode(value) {
  try {
    return decodeURIComponent(String(value).replace(/\+/g, ' '));
  } catch (err) {
    return String(value);
  }
}


function canonicalizeUrl(value, options) {
  options = options || {};
  try {
    const parsed = new URL(String(value || ''));
    parsed.hash = '';
    parsed.hostname = parsed.hostname.toLowerCase();
    if (options.sortQuery !== false) {
      const entries = Array.from(parsed.searchParams.entries()).sort((a, b) => {
        if (a[0] === b[0]) return String(a[1]).localeCompare(String(b[1]));
        return a[0].localeCompare(b[0]);
      });
      parsed.search = '';
      for (const [key, val] of entries) parsed.searchParams.append(key, val);
    }
    return parsed.toString();
  } catch (err) {
    return String(value || '');
  }
}

function hostOf(value) {
  try { return new URL(String(value || '')).hostname.toLowerCase(); } catch (err) { return ''; }
}

function inScope(value, options) {
  options = options || {};
  const host = hostOf(value);
  if (!host) return false;
  const include = [].concat(options.includeDomains || options.include || []).map((x) => String(x).toLowerCase()).filter(Boolean);
  const exclude = [].concat(options.excludeDomains || options.exclude || []).map((x) => String(x).toLowerCase()).filter(Boolean);
  const matches = (list) => list.some((domain) => host === domain || host.endsWith('.' + domain));
  if (include.length && !matches(include)) return false;
  if (exclude.length && matches(exclude)) return false;
  return true;
}


function base64UrlDecode(value) {
  try {
    return Buffer.from(String(value).replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
  } catch (err) {
    return '';
  }
}

function unwrapRedirect(target) {
  const value = String(target || '');
  if (!value) return '';
  try {
    const parsed = new URL(value);
    const host = parsed.hostname.toLowerCase();
    if (/(^|\.)google\./.test(host)) {
      const q = parsed.searchParams.get('q') || parsed.searchParams.get('url');
      if (q && /^https?:\/\//i.test(q)) return q;
    }
    if (/(^|\.)bing\.com$/.test(host) && parsed.pathname.includes('/ck/a')) {
      const encoded = parsed.searchParams.get('u');
      if (encoded && encoded.startsWith('a1')) {
        const decoded = base64UrlDecode(encoded.slice(2));
        if (/^https?:\/\//i.test(decoded)) return decoded;
      }
    }
    if (/(^|\.)yandex\./.test(host)) {
      const q = parsed.searchParams.get('url');
      if (q && /^https?:\/\//i.test(q)) return q;
    }
    if (/(^|\.)yahoo\.com$/.test(host) && parsed.pathname.includes('/RU=')) {
      const match = /\/RU=([^/]+)\//.exec(parsed.pathname);
      if (match) {
        const decoded = safeDecode(match[1]);
        if (/^https?:\/\//i.test(decoded)) return decoded;
      }
    }
    if (/(^|\.)startpage\.com$/.test(host)) {
      const q = parsed.searchParams.get('url') || parsed.searchParams.get('target');
      if (q && /^https?:\/\//i.test(q)) return q;
    }
    if (/(^|\.)qwant\.com$/.test(host)) {
      const q = parsed.searchParams.get('url') || parsed.searchParams.get('u');
      if (q && /^https?:\/\//i.test(q)) return q;
    }
    return parsed.toString();
  } catch (err) {
    return value;
  }
}

function decodeResultUrl(href, base) {
  let target = decodeEntities(String(href || ''));
  if (!target) return '';
  if (target.startsWith('//')) target = 'https:' + target;
  try {
    const parsed = new URL(target, base || 'https://duckduckgo.com');
    const uddg = parsed.searchParams.get('uddg');
    if (uddg) return unwrapRedirect(uddg);
    return unwrapRedirect(parsed.toString());
  } catch (err) {
    return unwrapRedirect(target);
  }
}

function isSearchHost(url) {
  return /(^|\.)(duckduckgo\.com|google\.[a-z.]+|bing\.com|yandex\.[a-z.]+|search\.brave\.com|startpage\.com|mojeek\.com|search\.yahoo\.com|ecosia\.org|qwant\.com|searx\.[a-z.]+|marginalia\.nu|baidu\.com)$/i
    .test(String(url).replace(/^https?:\/\//i, '').split('/')[0]);
}

function isSponsored(url) {
  return /duckduckgo\.com\/y\.js|ad_domain|doubleclick|googleadservices|googlesyndication|bing\.com\/aclick|yandex\.[a-z.]+\/ads|qwant\.com\/redirect|ecosia\.org\/ads/i
    .test(String(url));
}

function addResult(results, seen, href, title, snippet, engine, base) {
  const url = decodeResultUrl(href, base);
  if (!url || !/^https?:\/\//i.test(url) || isSponsored(url) || isSearchHost(url)) return false;
  const normalized = url.replace(/#.*$/, '');
  if (!normalized || seen.has(normalized)) return false;
  const cleanTitle = stripTags(title);
  if (!cleanTitle) return false;
  seen.add(normalized);
  results.push({
    title: cleanTitle,
    url,
    snippet: stripTags(snippet),
    engine
  });
  return true;
}

function parseDdHtml(html) {
  const results = [];
  const seen = new Set();
  const blocks = String(html).split(/<div[^>]+class="[^"]*\bresult__body\b[^"]*"/i).slice(1);

  for (const block of blocks) {
    const link = /<a\b([^>]*\bclass="[^"]*\bresult__a\b[^"]*"[^>]*)>([\s\S]*?)<\/a>/i.exec(block);
    if (!link) continue;
    const href = /\bhref="([^"]+)"/i.exec(link[1]);
    if (!href) continue;
    const snippetMatch = /<a\b[^>]*\bclass="[^"]*\bresult__snippet\b[^"]*"[^>]*>([\s\S]*?)<\/a>/i.exec(block)
      || /<div\b[^>]*\bclass="[^"]*\bresult__snippet\b[^"]*"[^>]*>([\s\S]*?)<\/div>/i.exec(block);
    addResult(results, seen, href[1], link[2], snippetMatch ? snippetMatch[1] : '', 'duckduckgo', 'https://duckduckgo.com');
  }

  if (!results.length) {
    const source = String(html);
    const fallback = /<a\b([^>]*\bclass=["'][^"']*\b(?:result__a|result-link)\b[^"']*["'][^>]*)>([\s\S]*?)<\/a>/gi;
    let match;
    while ((match = fallback.exec(source)) !== null) {
      const href = /\bhref=["']([^"']+)["']/i.exec(match[1]);
      if (!href) continue;
      const tail = source.slice(fallback.lastIndex, fallback.lastIndex + 3000);
      const snippetMatch = /class=["'][^"']*\bresult(?:__snippet|-snippet)\b[^"']*["'][^>]*>([\s\S]*?)<\/(?:a|td|div)>/i.exec(tail);
      addResult(results, seen, href[1], match[2], snippetMatch ? snippetMatch[1] : '', 'duckduckgo', 'https://duckduckgo.com');
    }
  }

  return results;
}

function parseRss(xml, engine) {
  const results = [];
  const seen = new Set();
  const items = String(xml).match(/<item\b[\s\S]*?<\/item>/gi) || [];
  for (const item of items) {
    const title = /<title\b[^>]*>([\s\S]*?)<\/title>/i.exec(item);
    const link = /<link\b[^>]*>([\s\S]*?)<\/link>/i.exec(item);
    const description = /<description\b[^>]*>([\s\S]*?)<\/description>/i.exec(item);
    if (!link) continue;
    addResult(results, seen, link[1], title ? title[1] : '', description ? description[1] : '', engine, 'https://www.bing.com');
  }
  return results;
}

function parseGoogleHtml(html) {
  const results = [];
  const seen = new Set();
  const source = String(html);
  const anchors = /<a\b([^>]*)>([\s\S]*?)<\/a>/gi;
  let match;
  while ((match = anchors.exec(source)) !== null) {
    const href = /\bhref=["']([^"']+)["']/i.exec(match[1]);
    if (!href) continue;
    const heading = /<h3\b[^>]*>([\s\S]*?)<\/h3>/i.exec(match[2]);
    if (!heading) continue;
    const tail = source.slice(anchors.lastIndex, anchors.lastIndex + 1400);
    const snippet = /<div\b[^>]*class=["'][^"']*(?:VwiC3b|IsZvec|s3v9rd)[^"']*["'][^>]*>([\s\S]*?)<\/div>/i.exec(tail)
      || /<span\b[^>]*class=["'][^"']*(?:aCOpRe|st)[^"']*["'][^>]*>([\s\S]*?)<\/span>/i.exec(tail);
    addResult(results, seen, href[1], heading[1], snippet ? snippet[1] : '', 'google', 'https://www.google.com');
  }
  if (!results.length) return parseGenericHtml(html, 'google', 'https://www.google.com');
  return results;
}

function parseBingHtml(html) {
  const source = String(html);
  if (/<rss\b/i.test(source)) return parseRss(source, 'bing');
  const results = [];
  const seen = new Set();
  const blocks = source.split(/<li[^>]+class="[^"]*\bb_algo\b[^"]*"/i).slice(1);
  for (const block of blocks) {
    const link = /<h2\b[^>]*>\s*<a\b([^>]*)>([\s\S]*?)<\/a>/i.exec(block);
    if (!link) continue;
    const href = /\bhref=["']([^"']+)["']/i.exec(link[1]);
    if (!href) continue;
    const snippet = /<p\b[^>]*>([\s\S]*?)<\/p>/i.exec(block)
      || /<div\b[^>]*class=["'][^"']*(?:b_caption|b_snippet)[^"']*["'][^>]*>([\s\S]*?)<\/div>/i.exec(block);
    addResult(results, seen, href[1], link[2], snippet ? snippet[1] : '', 'bing', 'https://www.bing.com');
  }
  if (!results.length) return parseGenericHtml(html, 'bing', 'https://www.bing.com');
  return results;
}

function parseYandexHtml(html) {
  const results = [];
  const seen = new Set();
  const source = String(html);
  const blocks = source.split(/<li[^>]+class="[^"]*\bserp-item\b[^"]*"/i).slice(1);
  for (const block of blocks) {
    const links = /<a\b([^>]*)>([\s\S]*?)<\/a>/gi;
    let link;
    let chosen = null;
    while ((link = links.exec(block)) !== null) {
      const href = /\bhref=["']([^"']+)["']/i.exec(link[1]);
      if (!href) continue;
      if (/yandex\.[a-z.]+\/clck|^https?:\/\//i.test(href[1])) {
        chosen = { href: href[1], title: link[2] };
        break;
      }
    }
    if (!chosen) continue;
    const snippet = /<div\b[^>]*class=["'][^"']*(?:OrganicText|text-container|TextContainer)[^"']*["'][^>]*>([\s\S]*?)<\/div>/i.exec(block)
      || /<span\b[^>]*class=["'][^"']*(?:OrganicText|TextContainer)[^"']*["'][^>]*>([\s\S]*?)<\/span>/i.exec(block);
    addResult(results, seen, chosen.href, chosen.title, snippet ? snippet[1] : '', 'yandex', 'https://yandex.com');
  }
  if (!results.length) return parseGenericHtml(html, 'yandex', 'https://yandex.com');
  return results;
}

function parseBraveHtml(html) {
  const results = [];
  const seen = new Set();
  const source = String(html);
  const blocks = source.split(/<div[^>]+class="[^"]*\bsnippet\b[^"]*"/i).slice(1);
  for (const block of blocks) {
    const link = /<a\b([^>]*)>([\s\S]*?)<\/a>/i.exec(block);
    if (!link) continue;
    const href = /\bhref=["']([^"']+)["']/i.exec(link[1]);
    if (!href) continue;
    const snippet = /<div\b[^>]*class=["'][^"']*(?:snippet-description|snippet-content)[^"']*["'][^>]*>([\s\S]*?)<\/div>/i.exec(block);
    addResult(results, seen, href[1], link[2], snippet ? snippet[1] : '', 'brave', 'https://search.brave.com');
  }
  if (!results.length) return parseGenericHtml(html, 'brave', 'https://search.brave.com');
  return results;
}

function parseStartpageHtml(html) {
  const results = [];
  const seen = new Set();
  const source = String(html);
  const blocks = source.split(/<div[^>]+class="[^"]*(?:w-gl__result|result)\b[^"]*"/i).slice(1);
  for (const block of blocks) {
    const link = /<a\b([^>]*)>([\s\S]*?)<\/a>/i.exec(block);
    if (!link) continue;
    const href = /\bhref=["']([^"']+)["']/i.exec(link[1]);
    if (!href) continue;
    const snippet = /<p\b[^>]*class=["'][^"']*(?:w-gl__description|description)[^"']*["'][^>]*>([\s\S]*?)<\/p>/i.exec(block)
      || /<p\b[^>]*>([\s\S]*?)<\/p>/i.exec(block);
    addResult(results, seen, href[1], link[2], snippet ? snippet[1] : '', 'startpage', 'https://www.startpage.com');
  }
  if (!results.length) return parseGenericHtml(html, 'startpage', 'https://www.startpage.com');
  return results;
}

function parseMojeekHtml(html) {
  const results = [];
  const seen = new Set();
  const source = String(html);
  const links = /<a\b([^>]*\bclass=["'][^"']*\bob\b[^"']*["'][^>]*)>([\s\S]*?)<\/a>/gi;
  let match;
  while ((match = links.exec(source)) !== null) {
    const href = /\bhref=["']([^"']+)["']/i.exec(match[1]);
    if (!href) continue;
    const tail = source.slice(links.lastIndex, links.lastIndex + 1200);
    const snippet = /<p\b[^>]*class=["'][^"']*\bs\b[^"']*["'][^>]*>([\s\S]*?)<\/p>/i.exec(tail);
    addResult(results, seen, href[1], match[2], snippet ? snippet[1] : '', 'mojeek', 'https://www.mojeek.com');
  }
  if (!results.length) return parseGenericHtml(html, 'mojeek', 'https://www.mojeek.com');
  return results;
}

function parseYahooHtml(html) {
  const results = [];
  const seen = new Set();
  const source = String(html);
  const blocks = source.split(/<div[^>]+class="[^"]*\balgo\b[^"]*"/i).slice(1);
  for (const block of blocks) {
    const link = /<h3\b[^>]*>\s*<a\b([^>]*)>([\s\S]*?)<\/a>/i.exec(block);
    if (!link) continue;
    const href = /\bhref=["']([^"']+)["']/i.exec(link[1]);
    if (!href) continue;
    const snippet = /<div\b[^>]*class=["'][^"']*(?:compText|Text)[^"']*["'][^>]*>([\s\S]*?)<\/div>/i.exec(block)
      || /<p\b[^>]*>([\s\S]*?)<\/p>/i.exec(block);
    addResult(results, seen, href[1], link[2], snippet ? snippet[1] : '', 'yahoo', 'https://search.yahoo.com');
  }
  if (!results.length) return parseGenericHtml(html, 'yahoo', 'https://search.yahoo.com');
  return results;
}

function parseEcosiaHtml(html) {
  const results = [];
  const seen = new Set();
  const source = String(html);
  const links = /<a\b([^>]*\bclass=["'][^"']*\bresult__link\b[^"']*["'][^>]*)>([\s\S]*?)<\/a>/gi;
  let match;
  while ((match = links.exec(source)) !== null) {
    const href = /\bhref=["']([^"']+)["']/i.exec(match[1]);
    if (!href) continue;
    const tail = source.slice(links.lastIndex, links.lastIndex + 1600);
    const snippet = /<p\b[^>]*class=["'][^"']*(?:result__description|result__snippet)[^"']*["'][^>]*>([\s\S]*?)<\/p>/i.exec(tail)
      || /<p\b[^>]*>([\s\S]*?)<\/p>/i.exec(tail);
    addResult(results, seen, href[1], match[2], snippet ? snippet[1] : '', 'ecosia', 'https://www.ecosia.org');
  }
  if (!results.length) return parseGenericHtml(html, 'ecosia', 'https://www.ecosia.org');
  return results;
}

function parseBaiduHtml(html) {
  const results = [];
  const seen = new Set();
  const source = String(html);
  const blocks = source.split(/<div[^>]+class="[^"]*(?:result|c-container)\b[^"]*"/i).slice(1);
  for (const block of blocks) {
    const link = /<h3\b[^>]*>\s*<a\b([^>]*)>([\s\S]*?)<\/a>/i.exec(block);
    if (!link) continue;
    const href = /\bhref=["']([^"']+)["']/i.exec(link[1]);
    if (!href) continue;
    const snippet = /<div\b[^>]*class=["'][^"']*(?:c-abstract|content-right)[^"']*["'][^>]*>([\s\S]*?)<\/div>/i.exec(block)
      || /<span\b[^>]*class=["'][^"']*content-right[^"']*["'][^>]*>([\s\S]*?)<\/span>/i.exec(block);
    addResult(results, seen, href[1], link[2], snippet ? snippet[1] : '', 'baidu', 'https://www.baidu.com');
  }
  if (!results.length) return parseGenericHtml(html, 'baidu', 'https://www.baidu.com');
  return results;
}

function parseGenericHtml(html, engine, base) {
  const results = [];
  const seen = new Set();
  const source = String(html);
  const anchors = /<a\b([^>]*)>([\s\S]*?)<\/a>/gi;
  let match;
  while ((match = anchors.exec(source)) !== null) {
    const href = /\bhref=["']([^"']+)["']/i.exec(match[1]);
    if (!href) continue;
    const title = stripTags(match[2]);
    if (!title || title.length < 3) continue;
    const tail = source.slice(anchors.lastIndex, anchors.lastIndex + 1200);
    const snippet = /<p\b[^>]*>([\s\S]*?)<\/p>/i.exec(tail)
      || /<(?:div|span)\b[^>]*class=["'][^"']*(?:snippet|description|desc|summary)[^"']*["'][^>]*>([\s\S]*?)<\/(?:div|span)>/i.exec(tail);
    addResult(results, seen, href[1], title, snippet ? snippet[1] : '', engine, base);
  }
  return results;
}

function parseQwantJson(body) {
  const results = [];
  const seen = new Set();
  let data;
  try {
    data = JSON.parse(String(body || ''));
  } catch (err) {
    return parseGenericHtml(body, 'qwant', 'https://www.qwant.com');
  }
  const items = (data && data.data && data.data.result && data.data.result.items)
    || (data && data.data && data.data.items)
    || (data && data.items)
    || [];
  for (const item of items) {
    if (!item) continue;
    addResult(results, seen, item.url || item.link, item.title || item.name || '', item.desc || item.description || '', 'qwant', 'https://www.qwant.com');
  }
  return results;
}

function parseSearxJson(body, base) {
  const results = [];
  const seen = new Set();
  let data;
  try {
    data = JSON.parse(String(body || ''));
  } catch (err) {
    return parseGenericHtml(body, 'searx', base || 'https://searx.be');
  }
  if (!data || typeof data !== 'object') return [];
  for (const item of data.results || []) {
    if (!item) continue;
    addResult(results, seen, item.url || item.link, item.title || '', item.content || item.snippet || '', 'searx', base || 'https://searx.be');
  }
  return results;
}

function parseEngineHtml(engine, body, options) {
  const name = String(engine || '').toLowerCase();
  if (name === 'duckduckgo') return parseDdHtml(body);
  if (name === 'google') return parseGoogleHtml(body);
  if (name === 'bing') return parseBingHtml(body);
  if (name === 'yandex') return parseYandexHtml(body);
  if (name === 'brave') return parseBraveHtml(body);
  if (name === 'startpage') return parseStartpageHtml(body);
  if (name === 'mojeek') return parseMojeekHtml(body);
  if (name === 'yahoo') return parseYahooHtml(body);
  if (name === 'ecosia') return parseEcosiaHtml(body);
  if (name === 'qwant') return parseQwantJson(body);
  if (name === 'searx') return parseSearxJson(body, options && options.base);
  if (name === 'baidu') return parseBaiduHtml(body);
  const base = (options && options.base) || (name === 'marginalia' ? 'https://search.marginalia.nu' : undefined);
  return parseGenericHtml(body, name, base);
}

function duckduckgoAttempts(query, options) {
  options = options || {};
  const page = Math.max(1, Number(options.page) || 1);
  const encoded = encodeURIComponent(query);
  const offset = (page - 1) * 30;
  const attempts = [];
  if (page === 1) {
    attempts.push({
      method: 'POST',
      url: 'https://html.duckduckgo.com/html/',
      body: 'q=' + encoded + '&b=&kl=us-en',
      origin: 'https://html.duckduckgo.com',
      referer: 'https://html.duckduckgo.com/'
    });
  }
  attempts.push({
    method: 'GET',
    url: 'https://lite.duckduckgo.com/lite/?q=' + encoded + (offset ? '&s=' + offset : ''),
    referer: 'https://lite.duckduckgo.com/'
  });
  attempts.push({
    method: 'GET',
    url: 'https://html.duckduckgo.com/html/?q=' + encoded + (offset ? '&s=' + offset : ''),
    referer: 'https://html.duckduckgo.com/'
  });
  return attempts;
}

const ENGINE_DEFINITIONS = {
  duckduckgo: {
    label: 'DuckDuckGo',
    attempts: (query, options) => duckduckgoAttempts(query, options || {})
  },
  google: {
    label: 'Google',
    attempts: (query, options) => {
      options = options || {};
      const page = Math.max(1, Number(options.page) || 1);
      const encoded = encodeURIComponent(query);
      const region = String(options.region || 'us').toLowerCase();
      const hl = String(options.language || 'en').toLowerCase();
      const start = (page - 1) * 10;
      return [
        { url: 'https://www.google.com/search?q=' + encoded + '&num=10&start=' + start + '&hl=' + hl + '&gl=' + region + '&filter=0&pws=0', referer: 'https://www.google.com/' },
        { url: 'https://www.google.com/search?q=' + encoded + '&num=10&start=' + start + '&hl=' + hl + '&gbv=1', referer: 'https://www.google.com/' }
      ];
    }
  },
  bing: {
    label: 'Bing',
    attempts: (query, options) => {
      options = options || {};
      const page = Math.max(1, Number(options.page) || 1);
      const encoded = encodeURIComponent(query);
      const region = String(options.region || 'us').toLowerCase();
      const first = (page - 1) * 10 + 1;
      return [
        { url: 'https://www.bing.com/search?q=' + encoded + '&count=10&first=' + first + '&setlang=en&cc=' + region, referer: 'https://www.bing.com/' },
        { url: 'https://www.bing.com/search?q=' + encoded + '&format=rss&count=10&first=' + first, referer: 'https://www.bing.com/' }
      ];
    }
  },
  yandex: {
    label: 'Yandex',
    attempts: (query, options) => {
      options = options || {};
      const page = Math.max(1, Number(options.page) || 1);
      const encoded = encodeURIComponent(query);
      const p = page - 1;
      return [
        { url: 'https://yandex.com/search/?text=' + encoded + '&p=' + p + '&lr=84', referer: 'https://yandex.com/' },
        { url: 'https://yandex.ru/search/?text=' + encoded + '&p=' + p, referer: 'https://yandex.ru/' }
      ];
    }
  },
  brave: {
    label: 'Brave',
    attempts: (query, options) => {
      options = options || {};
      const page = Math.max(1, Number(options.page) || 1);
      const offset = (page - 1) * 20;
      return [{ url: 'https://search.brave.com/search?q=' + encodeURIComponent(query) + '&source=web&offset=' + offset, referer: 'https://search.brave.com/' }]
    }
  },
  startpage: {
    label: 'Startpage',
    attempts: (query, options) => {
      options = options || {};
      const page = Math.max(1, Number(options.page) || 1);
      return [{ url: 'https://www.startpage.com/sp/search?query=' + encodeURIComponent(query) + '&page=' + page, referer: 'https://www.startpage.com/' }]
    }
  },
  mojeek: {
    label: 'Mojeek',
    attempts: (query, options) => {
      options = options || {};
      const page = Math.max(1, Number(options.page) || 1);
      return [{ url: 'https://www.mojeek.com/search?q=' + encodeURIComponent(query) + '&page=' + page, referer: 'https://www.mojeek.com/' }]
    }
  },
  yahoo: {
    label: 'Yahoo',
    attempts: (query, options) => {
      options = options || {};
      const page = Math.max(1, Number(options.page) || 1);
      const b = (page - 1) * 10 + 1;
      return [{ url: 'https://search.yahoo.com/search?p=' + encodeURIComponent(query) + '&b=' + b, referer: 'https://search.yahoo.com/' }]
    }
  },
  ecosia: {
    label: 'Ecosia',
    attempts: (query, options) => {
      options = options || {};
      const page = Math.max(1, Number(options.page) || 1);
      return [{ url: 'https://www.ecosia.org/search?q=' + encodeURIComponent(query) + '&page=' + page, referer: 'https://www.ecosia.org/' }]
    }
  },
  qwant: {
    label: 'Qwant',
    attempts: (query, options) => {
      options = options || {};
      const page = Math.max(1, Number(options.page) || 1);
      const offset = (page - 1) * 20;
      return [{
        url: 'https://api.qwant.com/v3/search/web?q=' + encodeURIComponent(query) + '&count=20&locale=en_US&offset=' + offset + '&device=desktop&safesearch=0',
        referer: 'https://www.qwant.com/',
        accept: 'application/json,text/plain,*/*'
      }]
    }
  },
  searx: {
    label: 'SearXNG',
    attempts: (query, options) => {
      options = options || {};
      const page = Math.max(1, Number(options.page) || 1);
      const base = String((options && options.searxUrl) || 'https://searx.be').replace(/\/+$/, '');
      return [
        { url: base + '/search?q=' + encodeURIComponent(query) + '&format=json&pageno=' + page, referer: base + '/', accept: 'application/json,text/plain,*/*' },
        { url: base + '/search?q=' + encodeURIComponent(query) + '&pageno=' + page, referer: base + '/' }
      ];
    }
  },
  marginalia: {
    label: 'Marginalia',
    attempts: (query, options) => {
      options = options || {};
      const page = Math.max(1, Number(options.page) || 1);
      return [{ url: 'https://search.marginalia.nu/search?query=' + encodeURIComponent(query) + '&page=' + page, referer: 'https://search.marginalia.nu/' }]
    }
  },
  baidu: {
    label: 'Baidu',
    attempts: (query, options) => {
      options = options || {};
      const page = Math.max(1, Number(options.page) || 1);
      const pn = (page - 1) * 10;
      return [{ url: 'https://www.baidu.com/s?wd=' + encodeURIComponent(query) + '&rn=10&pn=' + pn, referer: 'https://www.baidu.com/' }]
    }
  }
};
const ENGINE_ALIASES = {
  ddg: 'duckduckgo',
  duck: 'duckduckgo',
  duckduckgo: 'duckduckgo',
  google: 'google',
  bing: 'bing',
  yandex: 'yandex',
  brave: 'brave',
  startpage: 'startpage',
  mojeek: 'mojeek',
  yahoo: 'yahoo',
  ecosia: 'ecosia',
  qwant: 'qwant',
  searx: 'searx',
  searxng: 'searx',
  marginalia: 'marginalia',
  baidu: 'baidu'
};

const DEFAULT_ENGINE_NAMES = ['duckduckgo', 'google', 'bing', 'yandex'];
const ALL_ENGINE_NAMES = Object.keys(ENGINE_DEFINITIONS);

function listEngines() {
  return ALL_ENGINE_NAMES.map((name) => ({ name, label: ENGINE_DEFINITIONS[name].label }));
}

function resolveEngines(value, options) {
  let names;
  if (Array.isArray(value)) {
    names = value.slice();
  } else if (value === undefined || value === null || value === '') {
    names = DEFAULT_ENGINE_NAMES.slice();
  } else {
    const raw = String(value).trim().toLowerCase();
    if (raw === 'default' || raw === 'major') names = DEFAULT_ENGINE_NAMES.slice();
    else if (raw === 'all') names = ALL_ENGINE_NAMES.slice();
    else names = String(value).split(',');
  }
  const resolved = [];
  for (const item of names) {
    const name = ENGINE_ALIASES[String(item).trim().toLowerCase()];
    if (!name) throw new Error('unknown search engine: ' + item + ' (available: ' + ALL_ENGINE_NAMES.join(', ') + ')');
    if (!resolved.includes(name)) resolved.push(name);
  }
  if (options && options.searxUrl && !resolved.includes('searx')) resolved.push('searx');
  if (!resolved.length) throw new Error('no search engines selected');
  return resolved;
}

function engineLabel(value, options) {
  return resolveEngines(value, options).map((name) => ENGINE_DEFINITIONS[name].label).join(', ');
}

async function searchEngine(name, query, options) {
  const definition = ENGINE_DEFINITIONS[name];
  if (!definition) throw new Error('unknown search engine: ' + name);
  const request = options.request || rawhttp.request;
  const retryDelayMs = options.retryDelayMs === undefined ? 2500 : Number(options.retryDelayMs);
  const pages = Math.max(1, Number(options.pages || options.maxPages || 1));
  const merged = [];
  const seen = new Set();
  let lastError = null;
  let successfulPage = false;

  for (let page = 1; page <= pages; page++) {
    const pageOptions = Object.assign({}, options, { page });
    let apiResults = null;
    try {
      apiResults = await searchApi(name, query, pageOptions);
    } catch (err) {
      lastError = err;
    }
    if (apiResults) {
      let added = 0;
      for (const result of apiResults) {
        const key = String(result.url || '').replace(/#.*$/, '');
        if (!key || seen.has(key)) continue;
        seen.add(key);
        merged.push(result);
        added++;
      }
      successfulPage = true;
      if (added === 0) break;
      if (page < pages && retryDelayMs > 0) await sleep(retryDelayMs);
      continue;
    }
    const attempts = definition.attempts(query, pageOptions);
    let pageHadResult = false;
    let pageError = null;

    for (let index = 0; index < attempts.length; index++) {
      const attempt = attempts[index];
      const headers = {
        'user-agent': options.agent || ua.randomAgent(),
        accept: attempt.accept || 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'accept-language': ua.randomLanguage(),
        'cache-control': 'no-cache',
        pragma: 'no-cache',
        'upgrade-insecure-requests': '1',
        referer: attempt.referer,
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'same-origin'
      };
      if (attempt.method === 'POST') {
        headers.origin = attempt.origin;
        headers['content-type'] = 'application/x-www-form-urlencoded';
      }

      try {
        const res = await request({
          url: attempt.url,
          method: attempt.method || 'GET',
          headers,
          body: attempt.body,
          timeoutMs: options.timeoutMs || 10000,
          proxy: options.proxy || null,
          maxRedirects: 3,
          followRedirects: true,
          rejectUnauthorized: options.rejectUnauthorized !== false,
          http2: Boolean(options.http2)
        });
        const results = parseEngineHtml(name, res.body || '', { base: attempt.url, searxUrl: options.searxUrl });
        let added = 0;
        for (const result of results) {
          const key = String(result.url || '').replace(/#.*$/, '');
          if (!key || seen.has(key)) continue;
          seen.add(key);
          merged.push(result);
          added++;
        }
        if (added > 0) pageHadResult = true;
        if (results.length || res.status === 200) {
          successfulPage = true;
          break;
        }
        const error = new Error(definition.label + ' returned HTTP ' + (res.status || 'error'));
        error.status = res.status;
        error.rateLimited = [202, 403, 429, 503].includes(res.status);
        pageError = error;
      } catch (err) {
        pageError = err;
      }

      if (index < attempts.length - 1 && retryDelayMs > 0) {
        await sleep(retryDelayMs * Math.pow(2, index));
      }
    }

    if (pageError) lastError = pageError;
    if (!pageHadResult) break;
    if (page < pages && retryDelayMs > 0) await sleep(retryDelayMs);
  }

  if (merged.length) return merged;
  if (successfulPage) return [];
  throw lastError || new Error(definition.label + ' search failed');
}

function dedupeResults(results) {
  const out = [];
  const seen = new Set();
  for (const result of results) {
    if (!result || !result.url) continue;
    const key = String(result.url).replace(/#.*$/, '');
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(result);
  }
  return out;
}

async function search(query, options = {}) {
  const q = String(query).trim();
  if (!q) return [];
  const engines = resolveEngines(options.engines !== undefined ? options.engines : options.engine, options);
  const results = [];
  const errors = [];
  let successful = 0;

  for (const name of engines) {
    try {
      const found = await searchEngine(name, q, options);
      successful++;
      results.push(...found);
    } catch (err) {
      errors.push({
        engine: name,
        error: err.message,
        status: err.status,
        rateLimited: Boolean(err.rateLimited)
      });
    }
  }

  const scoped = results.filter((result) => inScope(result.url, options));
  const merged = dedupeResults(scoped);
  const canonicalized = merged.map((result) => Object.assign({}, result, { url: canonicalizeUrl(result.url, { sortQuery: options.sortQuery !== false }) }));
  const deduped = dedupeResults(canonicalized);
  const finalResults = options.maxResults > 0 ? deduped.slice(0, Number(options.maxResults)) : deduped;
  finalResults.engineErrors = errors;
  if (!finalResults.length && errors.length && successful === 0) {
    const error = new Error('all selected search engines failed: ' + errors.map((item) => item.engine + ': ' + item.error).join('; '));
    error.engineErrors = errors;
    error.rateLimited = errors.every((item) => item.rateLimited);
    throw error;
  }
  return finalResults;
}

module.exports = {
  listCategories,
  findCategory,
  listEngines,
  resolveEngines,
  engineLabel,
  search,
  searchEngine,
  parseDdHtml,
  parseEngineHtml,
  parseGoogleHtml,
  parseBingHtml,
  parseYandexHtml,
  stripTags,
  decodeEntities,
  canonicalizeUrl,
  hostOf,
  inScope
};
