const dork = require('./dork');
const { crawl } = require('./crawl');

const TYPE_CATEGORIES = {
  sqli: ['sql_injection_dorks'],
  nosqli: ['nosqli_dorks'],
  xpath: ['xpath_dorks'],
  ldap: ['ldap_dorks'],
  xss: ['xss_dorks'],
  jsonp_xss: ['jsonp_xss_dorks'],
  cmdi: ['cmdi_dorks'],
  lfi: ['lfi_dorks'],
  rfi: ['rfi_dorks'],
  open_redirect: ['open_redirect_dorks'],
  ssrf: ['ssrf_dorks'],
  info_disclosure: ['secrets_and_credentials', 'backup_dorks', 'open_directories'],
  idor: ['idor_dorks'],
  jwt: ['jwt_dorks'],
  session_fixation: ['session_fixation_dorks'],
  file_upload: ['file_upload_dorks'],
  logic_bypass: ['logic_bypass_dorks', 'admin_panels'],
  ssti: ['ssti_dorks'],
  xxe: ['xxe_dorks'],
  crlf: ['crlf_dorks'],
  code_injection: ['code_injection_dorks'],
  deserialization: ['deserialization_dorks'],
  format_string: ['format_string_dorks'],
  header_injection: ['header_injection_dorks'],
  host_header_injection: ['host_header_injection_dorks']
};

function categoriesForType(type) {
  const categories = TYPE_CATEGORIES[type];
  if (!categories) throw new Error('no dork category mapped for ' + type);
  return categories.slice();
}

function unique(list) {
  return Array.from(new Set(list));
}

function normalizeTarget(value, options) {
  options = options || {};
  try {
    let candidate = value;
    if (options.canonicalize !== false && dork.canonicalizeUrl) {
      candidate = dork.canonicalizeUrl(candidate, { sortQuery: options.sortQuery !== false });
    }
    const parsed = new URL(String(candidate));
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;
    if (parsed.hostname === 'duckduckgo.com' || parsed.hostname.endsWith('.duckduckgo.com')) return null;
    if (dork.inScope && !dork.inScope(parsed.toString(), options)) return null;
    parsed.hash = '';
    return parsed.toString();
  } catch (err) {
    return null;
  }
}

function buildFormEntry(form, options) {
  if (!form || !form.action) return null;
  const method = String(form.method || 'GET').toUpperCase() === 'POST' ? 'POST' : 'GET';
  let target = form.action;
  let data = form.data || '';
  if (method === 'GET') {
    if (data) {
      try {
        const parsed = new URL(target);
        for (const pair of data.split('&')) {
          const idx = pair.indexOf('=');
          const name = idx === -1 ? pair : pair.slice(0, idx);
          const value = idx === -1 ? '' : pair.slice(idx + 1);
          if (name) parsed.searchParams.set(name, value);
        }
        target = parsed.toString();
      } catch (err) {
        return null;
      }
    }
    data = null;
  }
  target = normalizeTarget(target, options);
  if (!target) return null;
  return { target, method, data: data || null };
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function sleepInterruptible(ms, shouldStop) {
  return new Promise((resolve) => {
    const deadline = Date.now() + ms;
    const tick = () => {
      if (shouldStop && shouldStop()) {
        resolve(true);
        return;
      }
      const remaining = deadline - Date.now();
      if (remaining <= 0) {
        resolve(false);
        return;
      }
      setTimeout(tick, Math.min(100, remaining));
    };
    tick();
  });
}

function plan(types, options = {}) {
  const names = [];
  for (const type of types) {
    for (const name of categoriesForType(type)) {
      if (!names.includes(name)) names.push(name);
    }
  }
  let total = 0;
  const categories = [];
  for (const name of names) {
    const category = dork.findCategory(name);
    if (!category) throw new Error('dork category not found: ' + name);
    const count = Number(options.dorkLimit) > 0
      ? Math.min(Number(options.dorkLimit), category.dorks.length)
      : category.dorks.length;
    total += count;
    categories.push({ name: category.name, file: category.file, total: count });
  }
  return { total, categories };
}

async function searchQueries(dorkList, options = {}) {
  const category = options.category || { name: options.name || 'discovery', file: options.file || '' };
  const list = Array.isArray(dorkList) ? dorkList : [];
  const searchFn = options.search || dork.search;
  const onProgress = options.onProgress || (() => {});
  const delayMs = Number(options.delayMs) || 0;
  const maxConsecutiveErrors = options.maxConsecutiveErrors === undefined ? 0 : Number(options.maxConsecutiveErrors);
  const targets = [];
  const seen = new Set();
  const errors = [];
  const queries = [];
  const collected = [];
  let consecutiveErrors = 0;
  let stopped = false;
  let stopReason = null;

  for (let index = 0; index < list.length; index++) {
    if (options.shouldStop && options.shouldStop()) {
      stopped = true;
      stopReason = 'user';
      break;
    }
    const query = list[index];
    queries.push(query);
    let results = [];
    let error = null;
    try {
      results = await searchFn(query, {
        proxy: options.proxy || null,
        timeoutMs: options.timeoutMs,
        retryDelayMs: options.retryDelayMs,
        engines: options.engines,
        searxUrl: options.searxUrl,
        pages: options.pages || options.searchPages || 1,
        maxResults: options.maxResults || 0,
        region: options.region,
        language: options.language,
        includeDomains: options.includeDomains,
        excludeDomains: options.excludeDomains,
        canonicalize: options.canonicalize,
        sortQuery: options.sortQuery,
        http2: options.http2,
        rejectUnauthorized: options.rejectUnauthorized
      });
      consecutiveErrors = 0;
    } catch (err) {
      error = err.rateLimited
        ? 'Search engines are rate-limiting requests' + (err.status ? ' (HTTP ' + err.status + ')' : '') + '; increase --search-delay, use --proxy or switch --engine'
        : err.message;
      errors.push({ category: category.name, query, error, rateLimited: Boolean(err.rateLimited) });
      consecutiveErrors++;
    }

    if (results && Array.isArray(results.engineErrors)) {
      for (const engineError of results.engineErrors) {
        errors.push({
          category: category.name,
          query,
          engine: engineError.engine,
          error: engineError.error,
          rateLimited: Boolean(engineError.rateLimited),
          warning: true
        });
      }
    }

    let added = 0;
    const newTargets = [];
    for (const result of results || []) {
      const target = normalizeTarget(result && result.url, options);
      if (!target || seen.has(target)) continue;
      seen.add(target);
      targets.push(target);
      newTargets.push(target);
      added++;
      if (options.collectResults) collected.push(Object.assign({}, result, { url: target }));
    }

    onProgress({
      category: category.name,
      file: category.file,
      index: index + 1,
      total: list.length,
      query,
      added,
      newTargets,
      targets: targets.length,
      error
    });

    if (options.shouldStop && options.shouldStop()) {
      stopped = true;
      stopReason = 'user';
      break;
    }
    if (maxConsecutiveErrors > 0 && consecutiveErrors >= maxConsecutiveErrors) {
      stopped = true;
      stopReason = 'errors';
      break;
    }
    if (delayMs > 0 && index < list.length - 1) {
      const jitter = Math.floor(Math.random() * Math.min(750, delayMs));
      if (options.shouldStop) {
        const interrupted = await sleepInterruptible(delayMs + jitter, options.shouldStop);
        if (interrupted) {
          stopped = true;
          stopReason = 'user';
          break;
        }
      } else {
        await sleep(delayMs + jitter);
      }
    }
  }

  return {
    name: category.name,
    file: category.file,
    queries,
    targets,
    errors,
    stopped,
    stopReason,
    results: collected
  };
}

async function searchCategory(name, options = {}) {
  const category = dork.findCategory(name);
  if (!category) throw new Error('dork category not found: ' + name);

  const limit = Number(options.dorkLimit) > 0 ? Number(options.dorkLimit) : category.dorks.length;
  return searchQueries(category.dorks.slice(0, limit), Object.assign({}, options, { category }));
}

async function discover(types, options = {}) {
  const cache = new Map();
  const byType = new Map();
  const categoriesByType = new Map();
  const categories = [];
  const targetSet = new Set();
  const errors = [];
  let searches = 0;

  const loadCategory = async (name) => {
    if (cache.has(name)) return cache.get(name);
    const entry = await searchCategory(name, options);
    cache.set(name, entry);
    searches += entry.queries.length;
    categories.push({
      name: entry.name,
      file: entry.file,
      queries: entry.queries.length,
      targets: entry.targets.length,
      errors: entry.errors.length,
      stopped: entry.stopped
    });
    for (const error of entry.errors) errors.push(error);
    return entry;
  };

  for (const type of types) {
    const categoryNames = categoriesForType(type);
    const targets = [];
    for (const name of categoryNames) {
      const entry = await loadCategory(name);
      targets.push(...entry.targets);
    }
    let uniqueTargets = unique(targets);
    if (Number(options.maxTargets) > 0) {
      uniqueTargets = uniqueTargets.slice(0, Number(options.maxTargets));
    }
    for (const target of uniqueTargets) targetSet.add(target);
    byType.set(type, uniqueTargets);
    categoriesByType.set(type, categoryNames);
  }

  let crawlResult = null;
  const forms = [];
  if (options.crawl) {
    crawlResult = await crawl(Array.from(targetSet), {
      depth: options.crawlDepth,
      maxLinks: options.maxLinks,
      maxPages: options.crawlMaxPages,
      timeoutMs: options.timeoutMs,
      proxy: options.proxy || null,
      request: options.request,
      http2: options.http2,
      rejectUnauthorized: options.rejectUnauthorized,
      renderJs: options.renderJs,
      renderUnsafe: options.renderUnsafe,
      onWarning: options.onWarning,
      browser: options.browser,
      captchaToken: options.captchaToken,
      captchaCommand: options.captchaCommand,
      captchaProvider: options.captchaProvider,
      captchaApiKey: options.captchaApiKey,
      captchaType: options.captchaType,
      captchaSitekey: options.captchaSitekey,
      captchaPollMs: options.captchaPollMs,
      captchaTimeoutMs: options.captchaTimeoutMs
    });
    const newTargets = [];
    for (const link of crawlResult.links || []) {
      const target = normalizeTarget(link, options);
      if (target && !targetSet.has(target)) {
        targetSet.add(target);
        newTargets.push(target);
      }
    }
    const formKeys = new Set();
    for (const form of crawlResult.forms || []) {
      const entry = buildFormEntry(form, options);
      if (!entry) continue;
      const key = entry.method + '\0' + entry.target + '\0' + (entry.data || '');
      if (!formKeys.has(key)) {
        formKeys.add(key);
        forms.push(entry);
      }
      if (!targetSet.has(entry.target)) {
        targetSet.add(entry.target);
        newTargets.push(entry.target);
      }
    }
    if (newTargets.length) {
      for (const type of types) {
        const existing = byType.get(type) || [];
        byType.set(type, unique(existing.concat(newTargets)));
      }
    }
    if (Number(options.maxTargets) > 0) {
      for (const type of types) {
        const list = byType.get(type) || [];
        byType.set(type, list.slice(0, Number(options.maxTargets)));
      }
      const limited = new Set();
      for (const type of types) for (const target of byType.get(type) || []) limited.add(target);
      targetSet.clear();
      for (const target of limited) targetSet.add(target);
    }
  }

  return {
    byType,
    categoriesByType,
    categories,
    targets: Array.from(targetSet),
    forms,
    searches,
    errors,
    crawl: crawlResult ? {
      visited: crawlResult.visited.length,
      links: crawlResult.links.length,
      forms: forms.length,
      added: (crawlResult.links.length + forms.length),
      warnings: crawlResult.warnings || []
    } : null
  };
}

module.exports = {
  TYPE_CATEGORIES,
  categoriesForType,
  normalizeTarget,
  buildFormEntry,
  plan,
  searchQueries,
  searchCategory,
  discover
};
