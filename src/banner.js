const pkg = require('../package.json');

function withVersion(lines) {
  const current = '(v.0.0.1)';
  const next = '(v.' + pkg.version + ')';
  const delta = next.length - current.length;
  return lines.map((line) => {
    if (!line.includes(current)) return line;
    let out = line.replace(current, next);
    if (delta > 0) {
      out = out.replace(/( +)(│   │)$/, (match, spaces, tail) => spaces.slice(Math.min(delta, spaces.length)) + tail);
    } else if (delta < 0) {
      out = out.replace(/( +)(│   │)$/, (match, spaces, tail) => spaces + ' '.repeat(-delta) + tail);
    }
    return out;
  });
}

const RAW_BANNER = withVersion([
  '┌──────────────────────────────────────────────────────────────────────────────────┐',
  '│  ██████ ▓█████▄  ▒█████   ██▀███   ██ ▄█▀    ┌───────────────────────────────┐   │',
  '│▒██    ▒ ▒██▀ ██▌▒██▒  ██▒▓██ ▒ ██▒ ██▄█▒     │  >_ sdork (v.0.0.1)           │   │',
  '│░ ▓██▄   ░██   █▌▒██░  ██▒▓██ ░▄█ ▒▓███▄░     │  License: MIT                 │   │',
  '│  ▒   ██▒░▓█▄   ▌▒██   ██░▒██▀▀█▄  ▓██ █▄     │  Author: @scope_moon          │   │',
  '│▒██████▒▒░▒████▓ ░ ████▓▒░░██▓ ▒██▒▒██▒ █▄    │  Organization: >_ scope coder │   │',
  '│▒ ▒▓▒ ▒ ░ ▒▒▓  ▒ ░ ▒░▒░▒░ ░ ▒▓ ░▒▓░▒ ▒▒ ▓▒    └───────────────────────────────┘   │',
  '│░ ░▒  ░ ░ ░ ▒  ▒   ░ ▒ ▒░   ░▒ ░ ▒░░ ░▒ ▒░                                        │',
  '│░  ░  ░   ░ ░  ░ ░ ░ ░ ▒    ░░   ░ ░ ░░ ░                                         │',
  '│      ░     ░        ░ ░     ░     ░  ░                                           │',
  '│          ░                                                                       │',
  '│sdork — CLI-фреймворк для поиска и подтверждения уязвимостей веб-приложений:      │',
  '│Google-дорки, автоматическая генерация целей, payload-тестирование и сигнатурное  │',
  '│подтверждение находок из коробки.                                                 │',
  '│Создан хакерской группировкой >_ scope coder и её владельцем @scope_moon.         │',
  '└──────────────────────────────────────────────────────────────────────────────────┘'
]);

function normalize(lines) {
  const width = lines[0].length;
  return lines.map((line) => {
    if (line.length >= width) return line;
    if (line.endsWith('│')) return line.slice(0, -1).padEnd(width - 1, ' ') + '│';
    return line.padEnd(width, ' ');
  });
}

const { CODES, colorEnabled, link } = require('./colors');

const ORG_URL = 'https://t.me/+wcVkkcrXJkk0ZDZk';
const ORG_NAME = '>_ scope coder';
const AUTHOR_URL = 'https://t.me/scope_moon';
const AUTHOR_NAME = '@scope_moon';
const DARK_GRAY = CODES.gray;
const ORANGE = CODES.orange;
const BEIGE = CODES.beige;
const ITALIC = CODES.italic;
const RESET = CODES.reset;
const BOX_CHARS = /[─│┌┐└┘]+/g;
const ART_CHARS = /[█▓▒░▄▀▌▐]+/g;
const INFO_LABELS = ['>_ sdork', 'License:', 'Author:', 'Organization:'];

function colorInfoContent(content) {
  const lead = content.match(/^ */)[0];
  const rest = content.slice(lead.length);
  const label = INFO_LABELS.find((item) => rest.startsWith(item));
  if (!label) return null;

  const remainder = rest.slice(label.length);

  let value;
  if (remainder.trim() === ORG_NAME) {
    value = remainder.replace(ORG_NAME, gray(link(ORG_NAME, ORG_URL)));
  } else if (remainder.trim() === AUTHOR_NAME) {
    value = remainder.replace(AUTHOR_NAME, gray(link(AUTHOR_NAME, AUTHOR_URL)));
  } else {
    value = remainder.replace(/\S+/g, (token) => DARK_GRAY + token + RESET);
  }

  return lead + BEIGE + label + RESET + value;
}

const INFO_LINE = /(│  (?=>_ sdork|License:|Author:|Organization:).*)$/;
const DESC_LINE = /^(│)([^─│█▓▒░]+)(│)$/;

function gray(value) {
  return DARK_GRAY + value + RESET;
}

function colorInfoLine(line) {
  const match = line.match(INFO_LINE);
  if (!match) return null;

  const tail = match[1];
  const prefix = line.slice(0, match.index);
  const parts = tail.match(/^(│)(.*?)(│)( +)(│)$/);
  if (!parts) return null;

  const [, open, content, close, gap, end] = parts;
  const coloredContent = colorInfoContent(content);
  if (!coloredContent) return null;

  const coloredPrefix = prefix
    .replace(BOX_CHARS, (run) => gray(run))
    .replace(ART_CHARS, (run) => ORANGE + run + RESET);

  return coloredPrefix + gray(open) + coloredContent + gray(close) + gap + gray(end);
}

function render(lines) {
  const normalized = normalize(lines);
  const enabled = colorEnabled();

  return normalized
    .map((line) => {
      if (!enabled) return line;

      const infoLine = colorInfoLine(line);
      if (infoLine) return infoLine;

      const descLine = line.match(DESC_LINE);
      if (descLine) {
        const content = descLine[2]
          .replace(ORG_NAME, link(ORG_NAME, ORG_URL))
          .replace(AUTHOR_NAME, link(AUTHOR_NAME, AUTHOR_URL));
        return gray(descLine[1]) + ITALIC + content + RESET + gray(descLine[3]);
      }

      return line
        .replace(BOX_CHARS, (run) => DARK_GRAY + run + RESET)
        .replace(ART_CHARS, (run) => ORANGE + run + RESET);
    })
    .join('\n');
}

const BANNER = render(RAW_BANNER);

module.exports = { BANNER, RAW_BANNER, render };
