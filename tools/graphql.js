const rawhttp = require('./rawhttp');

const INTROSPECTION_QUERY = 'query SdorkIntrospection { __schema { queryType { fields { name args { name type { kind name ofType { kind name ofType { kind name } } } } } } } }';

function unwrapType(type) {
  let current = type;
  while (current && current.ofType) current = current.ofType;
  return current || null;
}

function typeRef(type) {
  if (!type) return 'String';
  if (type.kind === 'NON_NULL') return typeRef(type.ofType) + '!';
  if (type.kind === 'LIST') return '[' + typeRef(type.ofType) + ']';
  return type.name || 'String';
}

function injectableArgs(args) {
  return (args || []).filter((arg) => {
    const base = unwrapType(arg.type);
    return base && (base.name === 'String' || base.name === 'ID');
  });
}

function buildJobs(schema, endpoint, types, options) {
  options = options || {};
  const fields = (schema && schema.queryType && schema.queryType.fields) || [];
  const jobs = [];
  const maxFields = Math.max(1, Number(options.maxFields) || 50);
  let count = 0;
  for (const field of fields) {
    if (count >= maxFields) break;
    const args = injectableArgs(field.args);
    if (!args.length) continue;
    const arg = args[0];
    const varType = typeRef(arg.type);
    const query = 'query($v:' + varType + '){' + field.name + '(' + arg.name + ':$v){__typename}}';
    const data = JSON.stringify({ query, variables: { v: 'FUZZ' } });
    for (const type of types) jobs.push({ type, target: endpoint, method: 'POST', data });
    count++;
  }
  return jobs;
}

async function introspect(url, options) {
  options = options || {};
  const request = options.request || rawhttp.request;
  const res = await request({
    url,
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      accept: 'application/json',
      'user-agent': options.agent || 'sdork'
    },
    body: JSON.stringify({ query: INTROSPECTION_QUERY }),
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
    throw new Error('GraphQL introspection returned invalid JSON');
  }
  if (!payload.data || !payload.data.__schema) {
    throw new Error('GraphQL introspection is disabled or unavailable');
  }
  return payload.data.__schema;
}

module.exports = { INTROSPECTION_QUERY, typeRef, injectableArgs, buildJobs, introspect };
