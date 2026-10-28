const { paint } = require('../src/colors');
const backup = require('./backup');
const pkg = require('../package.json');

function truncate(value, max) {
  const str = String(value || '');
  return str.length > max ? str.slice(0, max) + '...' : str;
}

function renderEvidence(finding) {
  const evidence = finding.evidence || {};
  const parts = [];
  if (evidence.match) parts.push('match: ' + truncate(evidence.match, 180));
  if (evidence.context) parts.push('context: ' + truncate(evidence.context, 220));
  if (evidence.type === 'time_delta') parts.push('timing: ' + evidence.payloadMs.join('ms, ') + 'ms');
  if (evidence.type === 'body_diff') parts.push('delta: ' + evidence.percent + '% similarity: ' + evidence.similarity + '%');
  if (evidence.type === 'oob_hit') parts.push('callback: ' + (evidence.detail || evidence.channel));
  if (evidence.value) parts.push('value: ' + truncate(evidence.value, 120));
  return parts;
}

function renderFinding(finding) {
  const conf = finding.confidence === 'high'
    ? paint('HIGH', 'orange')
    : finding.confidence === 'medium' ? paint('MED', 'beige') : paint('LOW', 'gray');
  const lines = [
    paint('[+] VULN FOUND: ', 'bold') + paint(String(finding.type).toUpperCase(), 'orange') + ' (' + conf + ')',
    paint('    Point:     ', 'gray') + finding.point,
    paint('    URL:       ', 'gray') + finding.url,
    paint('    Technique: ', 'gray') + finding.technique,
    paint('    Payload:   ', 'gray') + truncate(finding.payload, 220)
  ];
  if (finding.confirmation) lines.push(paint('    Confirmed: ', 'gray') + finding.confirmation);
  if (finding.note) lines.push(paint('    Note:      ', 'gray') + finding.note);
  for (const part of renderEvidence(finding)) {
    lines.push(paint('    Evidence:  ', 'gray') + part);
  }
  return lines.join('\n');
}

function renderScanSummary(result) {
  const lines = [];
  lines.push(paint('--- Scan Report for ' + String(result.type).toUpperCase() + ' ---', 'bold'));
  lines.push(paint('Target: ' + result.url, 'gray'));
  lines.push(paint('Requests: ' + (result.requests || 0) + '  Points: ' + (result.points || []).join(', '), 'gray'));
  lines.push(paint('Findings: ' + result.findings.length, result.findings.length ? 'orange' : 'gray'));

  if (result.findings.length === 0) {
    lines.push(paint('[-] No vulnerabilities confirmed for ' + result.type, 'gray'));
  } else {
    for (const finding of result.findings) {
      lines.push('\n' + renderFinding(finding));
    }
  }

  if (result.observations && result.observations.length > 0) {
    lines.push(paint('\n[!] Observations below confidence threshold: ' + result.observations.length, 'beige'));
    for (const observation of result.observations) {
      lines.push(paint('    - ' + observation.type.toUpperCase() + ' / ' + observation.signalId + ' (' + observation.confidence + ') at ' + observation.point, 'gray'));
    }
  }

  if (result.skipped && result.skipped.length > 0) {
    lines.push(paint('\nSkipped signals: ' + result.skipped.length, 'gray'));
    for (const skip of result.skipped.slice(0, 10)) {
      lines.push(paint('    - ' + (skip.id || 'signal') + ': ' + skip.reason, 'gray'));
    }
    if (result.skipped.length > 10) {
      lines.push(paint('    - ...and ' + (result.skipped.length - 10) + ' more', 'gray'));
    }
  }
  return lines.join('\n');
}

function renderDorkResults(query, results, options) {
  options = options || {};
  const lines = [paint('--- ' + (options.title || ('Dork Search: ' + query)) + ' ---', 'bold')];
  if (!results || results.length === 0) {
    lines.push(paint('[-] No search results; selected engines returned nothing or were rate-limited.', 'gray'));
    return lines.join('\n');
  }
  for (let i = 0; i < results.length; i++) {
    const result = results[i];
    if (Array.isArray(result.files) && result.files.length) {
      lines.push('\n' + paint(result.url, 'orange'));
      for (let j = 0; j < result.files.length; j++) {
        const file = result.files[j];
        const branch = j === result.files.length - 1 ? '└–' : '├–';
        lines.push(paint(branch + ' ' + (file.name || '?') + ', ' + backup.formatSizeKb(file.sizeKb), 'gray'));
      }
      continue;
    }
    lines.push(
      '\n' + paint(String(i + 1) + '. ' + result.title, 'bold') + '\n' +
      paint('   [' + (result.engine || 'search') + '] ' + result.url, 'orange') +
      (result.snippet ? '\n   ' + paint(result.snippet, 'gray') : '')
    );
  }
  return lines.join('\n');
}

function renderFindingsTable(findings) {
  const header = ['#', 'TYPE', 'CONF', 'TARGET', 'SIGNAL', 'POINT'];
  const rows = findings.map((finding, index) => [
    String(index + 1),
    String(finding.type || '').toUpperCase(),
    String(finding.confidence || '').toUpperCase(),
    truncate(finding.target || finding.url || '', 56),
    String(finding.signalId || ''),
    String(finding.point || '')
  ]);
  const widths = header.map((title, index) => Math.max(
    title.length,
    ...rows.map((row) => row[index].length)
  ));
  const line = (cells) => cells.map((cell, index) => cell.padEnd(widths[index])).join('  ').replace(/\s+$/, '');
  const separator = '-'.repeat(widths.reduce((sum, width) => sum + width, 0) + (widths.length - 1) * 2);
  const lines = [paint('=== FINDINGS ===', 'bold'), paint(line(header), 'beige'), paint(separator, 'gray')];
  if (!rows.length) lines.push(paint('[-] No confirmed findings.', 'gray'));
  else for (const row of rows) lines.push(line(row));
  return lines.join('\n');
}

function renderSummary(stats) {
  const rows = [
    ['Dorks searched', stats.searches || stats.dorks || 0],
    ['Targets', stats.targets || 0],
    ['Scans', stats.scans || 0],
    ['Requests', stats.requests || 0],
    ['Findings', stats.findings || 0],
    ['Observations', stats.observations || 0],
    ['Errors', stats.errors || 0]
  ];
  const width = Math.max(...rows.map((row) => row[0].length));
  const lines = [paint('=== SUMMARY ===', 'bold')];
  for (const row of rows) {
    lines.push(paint('  ' + row[0].padEnd(width) + ' : ' + row[1], 'gray'));
  }
  return lines.join('\n');
}

function renderDorkCategories(categories) {
  const lines = [paint('--- Available Dork Categories ---', 'bold')];
  for (const category of categories) {
    lines.push(paint('• ' + category.name.padEnd(24), 'beige') + paint('(' + category.count + ' dorks in ' + category.file + ')', 'gray'));
  }
  lines.push(paint('\nRun: sdork --dork "query" to search, or sdork --dork=<category> to list dorks.', 'gray'));
  return lines.join('\n');
}


function csvEscape(value) {
  const str = String(value === null || value === undefined ? '' : value);
  if (/[",\n]/.test(str)) return '"' + str.replace(/"/g, '""') + '"';
  return str;
}

function renderCsvReport(output) {
  const rows = [['type', 'confidence', 'target', 'signal', 'point', 'technique', 'payload']];
  for (const finding of (output.findings || [])) {
    rows.push([
      finding.type,
      finding.confidence,
      finding.target || finding.url,
      finding.signalId,
      finding.point,
      finding.technique,
      finding.payload
    ]);
  }
  return rows.map((row) => row.map(csvEscape).join(',')).join('\n') + '\n';
}

function renderHtmlReport(output) {
  const findings = (output.findings || []).map((finding) => (
    '<tr><td>' + escapeHtml(finding.type) + '</td><td>' + escapeHtml(finding.confidence) + '</td><td>' + escapeHtml(finding.target || finding.url) + '</td><td>' + escapeHtml(finding.signalId) + '</td><td>' + escapeHtml(finding.point) + '</td></tr>'
  )).join('');
  return '<!DOCTYPE html><html><head><meta charset="utf-8"><title>sdork report</title></head><body>' +
    '<h1>sdork report</h1>' +
    '<p>Findings: ' + (output.findings || []).length + ', observations: ' + (output.observations || []).length + ', errors: ' + (output.errors || []).length + '</p>' +
    '<table border="1" cellspacing="0" cellpadding="4"><thead><tr><th>Type</th><th>Confidence</th><th>Target</th><th>Signal</th><th>Point</th></tr></thead><tbody>' + findings + '</tbody></table>' +
    '</body></html>\n';
}

function escapeHtml(value) {
  return String(value === null || value === undefined ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function renderSarifReport(output) {
  const results = (output.findings || []).map((finding) => ({
    ruleId: finding.signalId,
    level: finding.confidence === 'high' ? 'error' : (finding.confidence === 'medium' ? 'warning' : 'note'),
    message: { text: finding.type + ' at ' + (finding.target || finding.url) },
    locations: [{
      physicalLocation: {
        artifactLocation: { uri: finding.target || finding.url || '' }
      }
    }]
  }));
  return JSON.stringify({
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [{
      tool: { driver: { name: 'sdork', version: pkg.version } },
      results
    }]
  }, null, 2) + '\n';
}

module.exports = {
  renderFinding,
  renderScanSummary,
  renderFindingsTable,
  renderSummary,
  renderDorkResults,
  renderDorkCategories,
  renderCsvReport,
  renderHtmlReport,
  renderSarifReport
};
