const crypto = require('crypto');

const CONFIDENCE_ORDER = { low: 1, medium: 2, high: 3 };

function compilePattern(pattern, extraFlags = '') {
  let source = String(pattern);
  let flags = '';
  let match;
  while ((match = /^\(\?([a-zA-Z]+)\)/.exec(source))) {
    for (const flag of match[1].toLowerCase()) {
      if ('ims'.includes(flag) && !flags.includes(flag)) flags += flag;
    }
    source = source.slice(match[0].length);
  }
  for (const flag of extraFlags) {
    if (!flags.includes(flag)) flags += flag;
  }
  try {
    return { regex: new RegExp(source, flags), source, flags };
  } catch (err) {
    return { error: err.message, source, flags };
  }
}

function bindPlaceholders(text, ctx) {
  let out = String(text);
  if (ctx && ctx.host) {
    out = out.split('<target_host>').join(escapeRegex(ctx.host));
  }
  return out;
}

function escapeRegex(text) {
  return String(text).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function fingerprint(text) {
  return crypto.createHash('sha1').update(String(text)).digest('hex');
}

function shingles(text, size = 4) {
  const str = String(text);
  const limited = str.length > 120000 ? str.slice(0, 120000) : str;
  const set = new Set();
  if (limited.length <= size) {
    if (limited.length) set.add(limited);
    return set;
  }
  const step = limited.length > 40000 ? 3 : 1;
  for (let i = 0; i + size <= limited.length; i += step) {
    set.add(limited.slice(i, i + size));
  }
  return set;
}

function similarityPercent(a, b) {
  if (a === b) return 100;
  const setA = shingles(a);
  const setB = shingles(b);
  if (!setA.size || !setB.size) return 0;
  let shared = 0;
  for (const item of setA) {
    if (setB.has(item)) shared++;
  }
  return Math.round((2 * shared) / (setA.size + setB.size) * 1000) / 10;
}

function deltaPercent(lenA, lenB) {
  const max = Math.max(lenA, lenB, 1);
  return Math.round(Math.abs(lenA - lenB) / max * 1000) / 10;
}

function snippet(text, index, radius = 60) {
  const str = String(text);
  const start = Math.max(0, index - radius);
  const end = Math.min(str.length, index + radius);
  let out = str.slice(start, end);
  out = out.replace(/[\x00-\x1f]/g, (c) => '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0'));
  return (start > 0 ? '...' : '') + out + (end < str.length ? '...' : '');
}

function base64Candidates(text) {
  const out = [];
  const str = String(text);
  const compact = str.replace(/\s+/g, '');
  if (compact.length >= 12 && compact.length % 4 === 0 && /^[A-Za-z0-9+/=]+$/.test(compact)) {
    try {
      out.push(Buffer.from(compact, 'base64').toString('utf8'));
    } catch (err) {}
  }
  const re = /[A-Za-z0-9+/]{16,}={0,2}/g;
  let match;
  while ((match = re.exec(str))) {
    try {
      out.push(Buffer.from(match[0], 'base64').toString('utf8'));
    } catch (err) {}
  }
  return out;
}

function sourceText(source, ctx) {
  const res = ctx.response || {};
  switch (source) {
    case 'body': return res.body || '';
    case 'headers': return res.rawHead || '';
    case 'raw_response': return res.rawText || '';
    case 'cookie': return (res.headers && (res.headers['set-cookie'] || []).join('\n')) || '';
    default: return null;
  }
}

function parseCookieValue(setCookieLine, name) {
  const match = new RegExp('(?:^|;\\s*)' + escapeRegex(name) + '=([^;\\s]*)').exec(String(setCookieLine));
  return match ? match[1] : null;
}

function refResponse(against, ctx) {
  if (!against) return null;
  if (against === 'baseline') return ctx.baseline || null;
  if (ctx.controls && ctx.controls[against]) return ctx.controls[against];
  return null;
}

function regexTest(pattern, text, extraFlags, ctx) {
  const compiled = compilePattern(bindPlaceholders(pattern, ctx), extraFlags);
  if (compiled.error) return { error: compiled.error };
  const match = compiled.regex.exec(String(text));
  if (!match) return null;
  return { index: match.index, match: match[0], snippet: snippet(text, match.index) };
}

function testSignal(signal, ctx) {
  const source = signal.source;

  if (source === 'oob') {
    const hits = ctx.oobHits || [];
    const filtered = signal.channel ? hits.filter((hit) => hit.channel === signal.channel) : hits;
    if (!filtered.length) return null;
    const hit = filtered[0];
    return {
      type: 'oob_hit',
      channel: hit.channel,
      detail: hit.path || hit.qname || (hit.rcpt && hit.rcpt.join(',')) || '',
      token: hit.token,
      time: hit.time
    };
  }

  if (source === 'status') {
    const status = ctx.response.status;
    const values = (signal.values || (signal.value !== undefined ? [signal.value] : [])).map(Number);
    if (signal.match === 'equals' && values.length === 1) {
      if (status !== values[0]) return null;
    } else if (!values.includes(status)) {
      return null;
    }
    if (ctx.baseline && ctx.baseline.status === status) {
      const sim = similarityPercent(ctx.baseline.body || '', ctx.response.body || '');
      if (sim >= 95) return null;
    }
    return { type: 'status', status };
  }

  if (source === 'time') {
    const timing = ctx.timing;
    if (!timing || !Array.isArray(timing.payloadMs) || !timing.payloadMs.length) {
      return { skip: 'timing samples unavailable' };
    }
    const threshold = signal.threshold_ms || 4000;
    const controlMs = timing.controlMs || 0;
    const need = signal.repeats || 3;
    const payloadMs = timing.payloadMs.map(Number).filter((ms) => Number.isFinite(ms));
    const sorted = payloadMs.slice().sort((a, b) => a - b);
    const middle = Math.floor(sorted.length / 2);
    const payloadMedian = sorted.length % 2
      ? sorted[middle]
      : Math.round((sorted[middle - 1] + sorted[middle]) / 2);
    const exceeding = payloadMs.filter((ms) => ms - controlMs >= threshold);
    const requiredCount = need >= 3 ? Math.ceil(need * 0.66) : need;
    if (exceeding.length >= requiredCount && payloadMedian - controlMs >= threshold) {
      return {
        type: 'time_delta',
        payloadMs,
        controlMs,
        controlSamples: timing.controlSamples || [],
        payloadMedianMs: payloadMedian,
        threshold,
        exceeding: exceeding.length,
        required: requiredCount
      };
    }
    return null;
  }

  if (source === 'length') {
    if (signal.match !== 'diff') return null;
    const ref = refResponse(signal.against, ctx);
    if (!ref) return { skip: 'reference response "' + signal.against + '" unavailable' };
    const pct = deltaPercent((ctx.response.body || '').length, (ref.body || '').length);
    if (pct >= (signal.min_delta_percent || 10)) {
      return { type: 'length_delta', percent: pct };
    }
    return null;
  }

  if (source === 'cookie') {
    if (signal.match !== 'unchanged') return null;
    const names = Array.isArray(signal.cookie) ? signal.cookie : [signal.cookie || 'session'];
    const name = names.find((item) => ctx.cookieBefore && item in ctx.cookieBefore);
    if (!name) {
      return { skip: 'none of the tracked cookies (' + names.join(', ') + ') were captured before the request' };
    }
    const setCookies = (ctx.response.headers && ctx.response.headers['set-cookie']) || [];
    if (!setCookies.length) return null;
    const values = setCookies
      .map((line) => parseCookieValue(line, name))
      .filter((value) => value !== null);
    if (!values.length) return null;
    const unchanged = values.every((value) => value === ctx.cookieBefore[name]);
    if (unchanged) {
      return { type: 'cookie_unchanged', cookie: name, value: ctx.cookieBefore[name] };
    }
    return null;
  }

  const text = sourceText(source, ctx);
  if (text === null) return { skip: 'unknown source "' + source + '"' };
  const extraFlags = source === 'headers' || source === 'raw_response' ? 's' : '';

  if (signal.match === 'diff') {
    const ref = refResponse(signal.against, ctx);
    if (!ref) return { skip: 'reference response "' + signal.against + '" unavailable' };
    const min = signal.min_delta_percent || 10;
    const fpA = ctx.response.fp || fingerprint(ctx.response.body || '');
    const fpB = ref.fp || fingerprint(ref.body || '');
    if (fpA === fpB) return null;
    const pct = deltaPercent((ctx.response.body || '').length, (ref.body || '').length);
    const sim = similarityPercent(ctx.response.body || '', ref.body || '');
    if (pct >= min || sim <= 100 - min) {
      return { type: 'body_diff', percent: pct, similarity: sim };
    }
    return null;
  }

  if (signal.match === 'regex') {
    const candidates = source === 'body' && signal.transform === 'base64_decode'
      ? base64Candidates(text)
      : [text];
    for (const candidate of candidates) {
      const result = regexTest(signal.pattern, candidate, extraFlags, ctx);
      if (result && result.error) return { skip: 'invalid regex: ' + result.error };
      if (result) {
        if (hasBaselineRequirement(signal) && baselineMatches(signal, ctx, extraFlags)) {
          return { skip: 'baseline response already matches' };
        }
        return { type: 'regex', match: result.match, context: result.snippet, transformed: candidate !== text };
      }
    }
    return null;
  }

  if (signal.match === 'contains') {
    const value = bindPlaceholders(signal.value, ctx);
    const index = String(text).indexOf(value);
    if (index === -1) return null;
    if (hasBaselineRequirement(signal) && baselineMatches(signal, ctx, extraFlags)) {
      return { skip: 'baseline response already matches' };
    }
    return { type: 'contains', value, context: snippet(text, index) };
  }

  if (signal.match === 'equals') {
    if (String(text) !== bindPlaceholders(signal.value, ctx)) return null;
    return { type: 'equals', value: signal.value };
  }

  if (signal.match === 'hit') {
    const hits = ctx.oobHits || [];
    const filtered = signal.channel ? hits.filter((hit) => hit.channel === signal.channel) : hits;
    if (!filtered.length) return null;
    return { type: 'oob_hit', channel: filtered[0].channel, detail: filtered[0].path || filtered[0].qname || '' };
  }

  return { skip: 'unknown match type "' + signal.match + '"' };
}

function hasBaselineRequirement(signal) {
  return Array.isArray(signal.requires) && signal.requires.includes('baseline');
}

function baselineMatches(signal, ctx, extraFlags) {
  if (!ctx.baseline) return false;
  const text = sourceText(signal.source, Object.assign({}, ctx, { response: ctx.baseline }));
  if (text === null) return false;
  if (signal.match === 'regex') {
    const result = regexTest(signal.pattern, text, extraFlags, ctx);
    return Boolean(result && !result.error);
  }
  if (signal.match === 'contains') {
    return String(text).includes(bindPlaceholders(signal.value, ctx));
  }
  return false;
}

function evaluate(spec, ctx) {
  const matched = [];
  const skipped = [];
  let eligible = 0;
  for (const signal of spec.signals || []) {
    const missing = (signal.requires || []).filter((req) => !ctx.satisfied || !ctx.satisfied[req]);
    if (missing.length) {
      skipped.push({ id: signal.id, reason: 'requires ' + missing.join(', ') });
      continue;
    }
    eligible++;
    const result = testSignal(signal, {
      ...ctx,
      baseline: ctx.baseline,
      response: ctx.response
    });
    if (!result) continue;
    if (result.skip) {
      skipped.push({ id: signal.id, reason: result.skip });
      continue;
    }
    matched.push({ signal, evidence: result });
  }
  const policy = spec.match_policy || 'any';
  const verdict = policy === 'all'
    ? eligible > 0 && matched.length === eligible
    : matched.length > 0;
  const confidence = matched.reduce((acc, item) => {
    const value = CONFIDENCE_ORDER[item.signal.confidence] || 1;
    return value > acc ? value : acc;
  }, 0);
  return {
    verdict,
    matched,
    skipped,
    eligible,
    policy,
    confidence: confidence >= 3 ? 'high' : confidence === 2 ? 'medium' : confidence === 1 ? 'low' : null
  };
}

module.exports = {
  compilePattern,
  evaluate,
  testSignal,
  baselineMatches,
  similarityPercent,
  deltaPercent,
  fingerprint,
  escapeRegex,
  CONFIDENCE_ORDER
};
