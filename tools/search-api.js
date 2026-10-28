const rawhttp = require('./rawhttp');

function decodeXml(value) {
  return String(value || '')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .replace(/<[^>]+>/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function apiKey(options, names) {
  for (const name of names) {
    if (options && options[name]) return options[name];
    if (process.env[name]) return process.env[name];
  }
  return null;
}

function normalize(items, engine) {
  return (items || []).map((item) => ({
    title: String(item.title || ''),
    url: String(item.url || item.link || ''),
    snippet: String(item.snippet || item.description || ''),
    engine
  })).filter((item) => /^https?:\/\//i.test(item.url));
}

async function requestJson(options, url, headers) {
  const request = options.request || rawhttp.request;
  const res = await request({
    url,
    method: 'GET',
    headers: Object.assign({ accept: 'application/json' }, headers || {}),
    timeoutMs: options.timeoutMs || 10000,
    proxy: options.proxy || null,
    maxRedirects: 3,
    followRedirects: true,
    rejectUnauthorized: options.rejectUnauthorized !== false,
    http2: Boolean(options.http2)
  });
  let payload;
  try {
    payload = JSON.parse(res.body || '{}');
  } catch (err) {
    throw new Error('search API returned invalid JSON');
  }
  if (res.status >= 400) {
    const error = new Error('search API returned HTTP ' + res.status);
    error.status = res.status;
    error.rateLimited = [403, 429].includes(res.status);
    throw error;
  }
  return payload;
}

async function google(query, options) {
  const key = apiKey(options, ['googleApiKey', 'GOOGLE_API_KEY', 'GOOGLE_CSE_KEY']);
  const cx = apiKey(options, ['googleCseId', 'GOOGLE_CSE_ID']);
  if (!key || !cx) return null;
  const page = Math.max(1, Number(options.page) || 1);
  const url = 'https://www.googleapis.com/customsearch/v1?key=' + encodeURIComponent(key) +
    '&cx=' + encodeURIComponent(cx) + '&q=' + encodeURIComponent(query) +
    '&num=10&start=' + ((page - 1) * 10 + 1);
  const payload = await requestJson(options, url);
  return normalize((payload.items || []).map((item) => ({
    title: item.title,
    url: item.link,
    snippet: item.snippet
  })), 'google');
}

async function bing(query, options) {
  const key = apiKey(options, ['bingApiKey', 'BING_SEARCH_KEY', 'BING_API_KEY']);
  if (!key) return null;
  const page = Math.max(1, Number(options.page) || 1);
  const url = 'https://api.bing.microsoft.com/v7.0/search?q=' + encodeURIComponent(query) +
    '&count=10&offset=' + ((page - 1) * 10);
  const payload = await requestJson(options, url, { 'ocp-apim-subscription-key': key });
  return normalize(((payload.webPages || {}).value || []).map((item) => ({
    title: item.name,
    url: item.url,
    snippet: item.snippet
  })), 'bing');
}

async function brave(query, options) {
  const key = apiKey(options, ['braveApiKey', 'BRAVE_SEARCH_KEY', 'BRAVE_API_KEY']);
  if (!key) return null;
  const page = Math.max(1, Number(options.page) || 1);
  const url = 'https://api.search.brave.com/res/v1/web/search?q=' + encodeURIComponent(query) +
    '&count=20&offset=' + ((page - 1) * 20);
  const payload = await requestJson(options, url, { 'x-subscription-token': key });
  return normalize((((payload.web || {}).results) || []).map((item) => ({
    title: item.title,
    url: item.url,
    snippet: item.description
  })), 'brave');
}

async function yandex(query, options) {
  const user = apiKey(options, ['yandexUser', 'YANDEX_XML_USER']);
  const key = apiKey(options, ['yandexKey', 'YANDEX_XML_KEY']);
  if (!user || !key) return null;
  const page = Math.max(1, Number(options.page) || 1);
  const url = 'https://yandex.com/search/xml?user=' + encodeURIComponent(user) +
    '&key=' + encodeURIComponent(key) + '&query=' + encodeURIComponent(query) +
    '&page=' + page + '&lr=' + encodeURIComponent(options.region || '');
  const request = options.request || rawhttp.request;
  const res = await request({
    url,
    method: 'GET',
    headers: { accept: 'application/xml' },
    timeoutMs: options.timeoutMs || 10000,
    proxy: options.proxy || null,
    maxRedirects: 3,
    followRedirects: true,
    rejectUnauthorized: options.rejectUnauthorized !== false,
    http2: Boolean(options.http2)
  });
  if (res.status >= 400) {
    const error = new Error('Yandex XML returned HTTP ' + res.status);
    error.status = res.status;
    error.rateLimited = [403, 429].includes(res.status);
    throw error;
  }
  const results = [];
  const docs = String(res.body || '').match(/<doc\b[\s\S]*?<\/doc>/gi) || [];
  for (const doc of docs) {
    const urlMatch = /<url>([\s\S]*?)<\/url>/i.exec(doc);
    const titleMatch = /<title>([\s\S]*?)<\/title>/i.exec(doc);
    const passageMatch = /<passages>([\s\S]*?)<\/passages>/i.exec(doc);
    if (!urlMatch) continue;
    results.push({
      title: decodeXml(titleMatch ? titleMatch[1] : ''),
      url: decodeXml(urlMatch[1]),
      snippet: decodeXml(passageMatch ? passageMatch[1] : ''),
      engine: 'yandex'
    });
  }
  return normalize(results, 'yandex');
}

async function serpapi(query, options) {
  const key = apiKey(options, ['serpApiKey', 'SERPAPI_KEY']);
  if (!key) return null;
  const page = Math.max(1, Number(options.page) || 1);
  const url = 'https://serpapi.com/search.json?engine=google&q=' + encodeURIComponent(query) +
    '&num=10&start=' + ((page - 1) * 10) + '&api_key=' + encodeURIComponent(key);
  const payload = await requestJson(options, url);
  return normalize((payload.organic_results || []).map((item) => ({
    title: item.title,
    url: item.link,
    snippet: item.snippet
  })), 'google');
}

const ADAPTERS = { google, bing, brave, yandex, serpapi };

async function searchApi(engine, query, options) {
  options = options || {};
  if (options.useApis === false) return null;
  const adapter = ADAPTERS[engine];
  if (!adapter) return null;
  return adapter(query, options);
}

function availableApis() {
  return {
    google: Boolean(process.env.GOOGLE_API_KEY || process.env.GOOGLE_CSE_KEY) && Boolean(process.env.GOOGLE_CSE_ID),
    bing: Boolean(process.env.BING_SEARCH_KEY || process.env.BING_API_KEY),
    brave: Boolean(process.env.BRAVE_SEARCH_KEY || process.env.BRAVE_API_KEY),
    yandex: Boolean(process.env.YANDEX_XML_USER && process.env.YANDEX_XML_KEY),
    serpapi: Boolean(process.env.SERPAPI_KEY)
  };
}

module.exports = { searchApi, availableApis, google, bing, brave, yandex, serpapi };
