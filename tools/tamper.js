function safeDecode(value) {
  try {
    return decodeURIComponent(value);
  } catch (err) {
    return value;
  }
}

function charEncode(value) {
  return value.replace(/[^A-Za-z0-9]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0'));
}

function randomCase(value) {
  return value.replace(/[a-z]/gi, (c) => (Math.random() < 0.5 ? c.toLowerCase() : c.toUpperCase()));
}

function randomComment(value) {
  return value.replace(/[a-z]/gi, (c) => (Math.random() < 0.3 ? '/**/' + c : c));
}

function randomSpace(value) {
  return value.replace(/(\s|%20)/g, () => (Math.random() < 0.5 ? '/**/' : '%09'));
}

const TAMPERS = {
  space2comment: (p) => p.replace(/ /g, '/**/').replace(/%20/g, '/**/'),
  space2plus: (p) => p.replace(/ /g, '+').replace(/%20/g, '+'),
  space2hash: (p) => p.replace(/ /g, '%23%0A').replace(/%20/g, '%23%0A'),
  space2dash: (p) => p.replace(/ /g, '--%0A').replace(/%20/g, '--%0A'),
  space2random: randomSpace,
  randomcase: randomCase,
  randomcomment: randomComment,
  equaltolike: (p) => p.replace(/%3D|=|\s=/g, ' LIKE '),
  between: (p) => p.replace(/(\s|%20)(AND|OR)(\s|%20)/gi, ' BETWEEN 0 AND 1 AND '),
  charencode: charEncode,
  chardoubleencode: (p) => charEncode(charEncode(p)),
  base64encode: (p) => Buffer.from(safeDecode(p), 'utf8').toString('base64'),
  utf8encode: (p) => encodeURIComponent(safeDecode(p)).replace(/%20/g, '%20'),
  htmlencode: (p) => p.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;'),
  apostrophehex: (p) => p.replace(/%27|'/g, '0x27'),
  uppercase: (p) => p.toUpperCase(),
  lowercase: (p) => p.toLowerCase(),
  concatenate: (p) => p.replace(/\/\*\*\//g, '/*!*/'),
  versionedcomment: (p) => p.replace(/\/\*\*\//g, '/*!50000*/')
};

function list() {
  return Object.keys(TAMPERS);
}

function parseList(value) {
  if (!value) return [];
  return String(value)
    .split('/')
    .map((item) => item.trim())
    .filter(Boolean);
}

function apply(names, payload) {
  const applied = [];
  let result = payload;
  for (const name of names) {
    const fn = TAMPERS[name];
    if (!fn) {
      applied.push({ name, ok: false });
      continue;
    }
    result = fn(result);
    applied.push({ name, ok: true });
  }
  return { payload: result, applied };
}

module.exports = { apply, list, parseList, TAMPERS };
