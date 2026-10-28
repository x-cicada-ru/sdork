const rawhttp = require('./rawhttp');
const render = require('./render');

function resolveUrl(href, base) {
  try { return new URL(href, base).toString(); } catch (err) { return null; }
}

function extractLinks(html, base) {
  const out = new Set();
  const re = /<a\b[^>]*\bhref=["']([^"']+)["'][^>]*>/gi;
  let match;
  while ((match = re.exec(String(html || ''))) !== null) {
    const url = resolveUrl(match[1], base);
    if (url && /^https?:\/\//i.test(url)) out.add(url);
  }
  return Array.from(out);
}

function extractForms(html, base) {
  const forms = [];
  const formRe = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  let match;
  while ((match = formRe.exec(String(html || ''))) !== null) {
    const attrs = match[1] || '';
    const body = match[2] || '';
    const actionMatch = /\baction=["']([^"']*)["']/i.exec(attrs);
    const methodMatch = /\bmethod=["']([^"']*)["']/i.exec(attrs);
    const action = resolveUrl(actionMatch ? actionMatch[1] : '', base) || base;
    const method = methodMatch ? methodMatch[1].toUpperCase() : 'GET';
    const fields = [];
    const inputRe = /<input\b([^>]*)>/gi;
    let input;
    while ((input = inputRe.exec(body)) !== null) {
      const nameMatch = /\bname=["']([^"']*)["']/i.exec(input[1]);
      if (nameMatch && nameMatch[1]) fields.push(nameMatch[1]);
    }
    const data = fields.map((field) => field + '=FUZZ').join('&');
    forms.push({ action, method, fields, data });
  }
  return forms;
}

async function fetchPage(url, options) {
  if (options && options.renderJs) {
    try {
      const rendered = await render.render(url, options);
      if (rendered && rendered.html) {
        return { status: 200, body: rendered.html, headers: {}, rawHead: '', rawText: rendered.html, ms: 0 };
      }
    } catch (err) {}
  }
  const request = (options && options.request) || rawhttp.request;
  const res = await request({
    url,
    method: 'GET',
    headers: {
      'user-agent': (options && options.agent) || 'Mozilla/5.0',
      accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
    },
    timeoutMs: (options && options.timeoutMs) || 10000,
    proxy: (options && options.proxy) || null,
    maxRedirects: 3,
    followRedirects: true,
    rejectUnauthorized: (options && options.rejectUnauthorized) !== false,
    http2: Boolean(options && options.http2)
  });
  return res;
}

async function crawl(targets, options) {
  options = options || {};
  const visited = new Set();
  const queue = (Array.isArray(targets) ? targets : [targets]).map((url) => ({ url, depth: 0 }));
  const links = new Set();
  const forms = [];
  const warnings = [];
  const onWarning = (message) => {
    warnings.push(message);
    if (typeof options.onWarning === 'function') options.onWarning(message);
  };
  const maxDepth = Math.max(0, Number(options.depth || options.maxDepth || 1));
  const maxLinks = Math.max(1, Number(options.maxLinks || 50));
  const maxPages = Math.max(1, Number(options.maxPages || 100));

  while (queue.length && visited.size < maxPages && links.size < maxLinks) {
    const item = queue.shift();
    if (!item || !item.url || visited.has(item.url)) continue;
    visited.add(item.url);
    let res;
    try {
      res = await fetchPage(item.url, Object.assign({}, options, { onWarning }));
    } catch (err) {
      continue;
    }
    const pageLinks = extractLinks(res.body || '', item.url);
    const pageForms = extractForms(res.body || '', item.url);
    for (const form of pageForms) forms.push(form);
    for (const link of pageLinks) {
      if (links.size >= maxLinks) break;
      links.add(link);
      if (item.depth < maxDepth && !visited.has(link)) {
        queue.push({ url: link, depth: item.depth + 1 });
      }
    }
  }

  return {
    visited: Array.from(visited),
    links: Array.from(links),
    forms,
    warnings
  };
}

module.exports = { extractLinks, extractForms, crawl, fetchPage };