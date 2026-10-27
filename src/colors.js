const CODES = {
  gray: '\x1b[90m',
  orange: '\x1b[38;5;208m',
  beige: '\x1b[38;5;223m',
  bold: '\x1b[1m',
  italic: '\x1b[3m',
  reset: '\x1b[0m'
};

function colorEnabled() {
  return Boolean(process.stdout.isTTY) && !process.env.NO_COLOR;
}

function paint(text, color) {
  if (!colorEnabled()) return text;
  return CODES[color] + text + CODES.reset;
}

function link(text, url) {
  if (!colorEnabled()) return text;
  return '\x1b]8;;' + url + '\x1b\\' + text + '\x1b]8;;\x1b\\';
}

module.exports = { CODES, colorEnabled, paint, link };
