const rawhttp = require('./rawhttp');

function joinUrl(base, path) {
  try {
    const b = base.endsWith('/') ? base.slice(0, -1) : base;
    return b + (path.startsWith('/') ? path : '/' + path);
  } catch (err) {
    return base + path;
  }
}

function baseUrl(spec, specUrl) {
  if (spec.servers && spec.servers.length) return spec.servers[0].url;
  if (spec.host) {
    const scheme = (spec.schemes && spec.schemes[0]) || 'https';
    const basePath = spec.basePath || '';
    return scheme + '://' + spec.host + basePath;
  }
  try {
    const u = new URL(specUrl);
    return u.origin;
  } catch (err) {
    return '';
  }
}

function parametersOf(operation, pathItem) {
  return [].concat(pathItem.parameters || [], operation.parameters || []);
}

function substitutePath(path, params) {
  let out = path;
  for (const param of params) {
    if (param.in === 'path') {
      out = out.replace(new RegExp('{' + param.name + '}', 'g'), '1');
    }
  }
  return out;
}

function buildQueryParams(params) {
  const names = params.filter((p) => p.in === 'query').map((p) => p.name);
  return names;
}

function buildBody(params, inject, operation) {
  const props = {};
  for (const param of params) {
    if (param.in === 'body') {
      if (param.schema && param.schema.properties) {
        for (const key of Object.keys(param.schema.properties)) {
          props[key] = inject === key ? 'FUZZ' : '1';
        }
      }
    }
  }
  const content = operation && operation.requestBody && operation.requestBody.content;
  if (content) {
    const media = content['application/json'] || Object.values(content)[0];
    const schema = media && media.schema;
    if (schema && schema.properties) {
      for (const key of Object.keys(schema.properties)) {
        props[key] = inject === key ? 'FUZZ' : '1';
      }
    }
  }
  return Object.keys(props).length ? JSON.stringify(props) : null;
}

async function loadSpec(url, options) {
  const res = await rawhttp.request({
    url,
    method: 'GET',
    headers: { accept: 'application/json' },
    timeoutMs: (options && options.timeoutMs) || 10000,
    proxy: (options && options.proxy) || null,
    maxRedirects: 3,
    followRedirects: true,
    rejectUnauthorized: (options && options.rejectUnauthorized) !== false,
    http2: Boolean(options && options.http2)
  });
  return JSON.parse(res.body || '{}');
}

async function generateJobs(specUrl, options) {
  options = options || {};
  const spec = options.spec || await loadSpec(specUrl, options);
  const base = baseUrl(spec, specUrl);
  const paths = spec.paths || {};
  const jobs = [];
  const types = options.types || [];
  const maxEndpoints = Math.max(1, Number(options.maxEndpoints) || 100);
  let count = 0;

  for (const path of Object.keys(paths)) {
    if (count >= maxEndpoints) break;
    const pathItem = paths[path] || {};
    for (const method of ['get', 'post', 'put', 'patch']) {
      if (!pathItem[method]) continue;
      if (count >= maxEndpoints) break;
      const operation = pathItem[method];
      const params = parametersOf(operation, pathItem);
      const substituted = substitutePath(path, params);
      const queryNames = buildQueryParams(params);
      const bodyTemplate = buildBody(params, null, operation);

      // GET query scanning: one job per query parameter (or a generic q)
      if (method === 'get') {
        const names = queryNames.length ? queryNames : ['q'];
        for (const name of names) {
          const url = new URL(joinUrl(base, substituted));
          for (const qn of queryNames) url.searchParams.set(qn, qn === name ? 'FUZZ' : '1');
          if (!queryNames.length) url.searchParams.set('q', 'FUZZ');
          for (const type of types) {
            jobs.push({ type, target: url.toString(), method: 'GET', data: null });
          }
          count++;
          if (count >= maxEndpoints) break;
        }
      } else {
        const body = bodyTemplate || JSON.stringify({ q: 'FUZZ' });
        let parsed = {};
        try { parsed = JSON.parse(body); } catch (err) {}
        const keys = Object.keys(parsed);
        const injectKeys = keys.length ? keys : ['q'];
        for (const key of injectKeys) {
          const clone = JSON.parse(JSON.stringify(parsed));
          if (Object.prototype.hasOwnProperty.call(clone, key)) clone[key] = 'FUZZ';
          else clone.q = 'FUZZ';
          for (const type of types) {
            jobs.push({ type, target: joinUrl(base, substituted), method: method.toUpperCase(), data: JSON.stringify(clone) });
          }
          count++;
          if (count >= maxEndpoints) break;
        }
      }
    }
  }

  return jobs;
}

module.exports = { loadSpec, generateJobs, baseUrl };