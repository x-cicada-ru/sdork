const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');

function projectPath(rel) {
  return path.join(ROOT, rel);
}

function loadJson(rel) {
  const file = projectPath(rel);
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (err) {
    throw new Error('cannot read ' + rel + ': ' + err.message);
  }
  try {
    return JSON.parse(text);
  } catch (err) {
    throw new Error('invalid JSON in ' + rel + ': ' + err.message);
  }
}

function loadPayloads(ref) {
  const data = loadJson(ref);
  const groups = {};
  const payloads = [];
  for (const key of Object.keys(data)) {
    const list = Array.isArray(data[key]) ? data[key] : [];
    groups[key] = list;
    for (const item of list) payloads.push(item);
  }
  const key = Object.keys(data)[0];
  return { key, payloads, groups };
}

function loadSignatures(type) {
  const data = loadJson('signatures/' + type + '.json');
  const key = Object.keys(data)[0];
  if (!key) throw new Error('empty signature file for ' + type);
  return { key, spec: data[key] };
}

function listSignatureTypes() {
  return fs.readdirSync(projectPath('signatures'))
    .filter((file) => file.endsWith('.json'))
    .map((file) => file.replace(/\.json$/, ''))
    .sort();
}

function listDorkFiles() {
  return fs.readdirSync(projectPath('dorks'))
    .filter((file) => file.endsWith('.json'))
    .sort()
    .map((file) => ({ file, rel: 'dorks/' + file }));
}

module.exports = { ROOT, projectPath, loadJson, loadPayloads, loadSignatures, listSignatureTypes, listDorkFiles };
