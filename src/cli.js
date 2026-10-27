const { BANNER } = require('./banner');
const { paint } = require('./colors');
const { listSignatureTypes } = require('../tools/loader');
const scanner = require('../tools/scanner');
const proxy = require('../tools/proxy');
const { OobServer } = require('../tools/oob');
const dork = require('../tools/dork');
const backup = require('../tools/backup');
const discovery = require('../tools/discovery');
const { createDiscoveryProgress } = require('../tools/progress');
const report = require('../tools/report');
const fs = require('fs');
const pkg = require('../package.json');

const HELP = [
  '--help - Program documentation',
  '--version - Print the current version',
  '',
  '',
  'Built-in commands:',
  '--sqli                  - SQL Injection (Error-based, Time-based, Boolean)',
  '--nosqli                - NoSQL Injection (MongoDB)',
  '--xss                   - Cross-Site Scripting (Reflected, DOM)',
  '--ssti                  - Server-Side Template Injection',
  '--ssrf                  - Server-Side Request Forgery',
  '--lfi                   - Local File Inclusion',
  '--rfi                   - Remote File Inclusion',
  '--xxe                   - XML External Entity',
  '--cmdi                  - Command Injection',
  '--idor                  - Insecure Direct Object Reference',
  '--openredir             - Open Redirect',
  '--crlf                  - CRLF Injection / Header Injection',
  '--ldap                  - LDAP Injection',
  '--xpath                 - XPath Injection',
  '--code_injection        - Code Injection (eval/system sinks)',
  '--deserialization       - Insecure Deserialization',
  '--file_upload           - File Upload Bypass',
  '--format_string         - Format String Injection',
  '--header_injection      - Header Injection / Email Header Injection',
  '--host_header_injection - Host Header Injection',
  '--info_disclosure       - Information Disclosure',
  '--jsonp_xss             - JSONP Callback XSS',
  '--jwt                   - JWT Weaknesses (kid injection, alg confusion)',
  '--logic_bypass          - Business Logic Bypass',
  '--session_fixation      - Session Fixation',
  '--all                   - Search all dorks and check ALL vulnerability types',
  '',
  '',
  'Auxiliary commands:',
  '--random-agents   - Random User-Agent and Accept-Language rotation',
  '--vpn             - Route traffic through an xray VPN profile',
  '--vpn-list        - List available VPN/proxy profiles',
  '--dork          - List dork categories or search the web',
  '--dork=<query>  - Search selected engines with a query',
  '--dork=<category> - List dorks from a category',
  '--backup        - Search backup dorks and list files with sizes',
  '--backup=<query> - Search a custom backup dork and list files',
  '--engine          - Search engines: major, all, or comma-separated names (default major)',
  '                    Available: duckduckgo, google, bing, yandex, brave, startpage, mojeek,',
  '                    yahoo, ecosia, qwant, searx, marginalia, baidu',
  '--searx                  - SearXNG base URL; adds searx to the engine list',
  '--tamper                 - Payload obfuscation scripts separated by /',
  '--oob                    - Start an out-of-band callback listener',
  '--oob=<domain>           - Use a public domain for OOB callbacks',
  '--oob-host               - Interface for the OOB listener (default 0.0.0.0)',
  '--oob-port               - HTTP port for the OOB listener (default 8080)',
  '--smtp-port              - SMTP port for OOB callbacks (default disabled)',
  '--json                   - Emit machine-readable JSON',
  '--out                    - Write the JSON report to a file',
  '--min-confidence         - Minimum reported confidence: low, medium, high',
  '--dork-limit             - Max dorks per category (0 = all, default all)',
  '--max-targets            - Max discovered targets per scan type (0 = all, default all)',
  '--search-delay           - Delay between dork searches in milliseconds (default 2500)',
  '--max-consecutive-errors - Stop a category after N consecutive search errors (0 = exhaustive)',
  '--search-pages           - Search result pages per engine (default 1)',
  '--max-results            - Max merged results per dork (0 = all)',
  '--region                 - Search region code (default us)',
  '--language               - Search language code (default en)',
  '--include-domain         - Only keep targets from domain (repeatable)',
  '--exclude-domain         - Drop targets from domain (repeatable)',
  '--no-canonicalize        - Disable URL canonicalization',
  '--no-sort-query          - Keep query parameter order',
  '--crawl                  - Crawl discovered targets and extract links/forms',
  '--crawl-depth            - Crawl depth (default 1)',
  '--crawl-max-pages        - Max pages to crawl (default 100)',
  '--max-links              - Max links to collect while crawling (default 50)',
  '--concurrency            - Concurrent scan jobs (default 1)',
  '--max-requests           - Stop scan after N requests (0 = unlimited)',
  '--scan-timeout           - Global scan timeout in seconds (0 = unlimited)',
  '--checkpoint             - Save discovery results to a JSON file',
  '--resume                 - Load discovery results from a JSON file',
  '--insecure               - Disable TLS certificate verification',
  '--http2                  - Use HTTP/2 for HTTPS requests',
  '--graphql                - Introspect a GraphQL endpoint and scan string arguments',
  '--max-fields             - Max GraphQL fields to expand (default 50)',
  '--render-js              - Render crawled pages with a headless browser/jsdom',
  '--render-unsafe          - Allow Chrome --no-sandbox and jsdom script execution',
  '--browser                - Path to Chrome/Edge for JS rendering',
  '--captcha-token          - Replace CAPTCHA_TOKEN placeholders with this value',
  '--captcha-command        - External command that prints a CAPTCHA token',
  '--captcha-provider       - Solver service: 2captcha, anticaptcha or capmonster',
  '--captcha-api-key        - API key for the CAPTCHA solver service',
  '--captcha-type           - CAPTCHA type: recaptcha, hcaptcha or turnstile',
  '--captcha-sitekey        - Override the extracted CAPTCHA sitekey',
  '--captcha-poll           - Solver poll interval in milliseconds',
  '--captcha-timeout        - Solver wait timeout in milliseconds',
  '--summary                - Print final scan summary',
  '--findings-table         - Print final findings table',
  '--report-format          - Report format: text, json, html, csv, sarif',
  '--report-file            - Write report to a file',
  '--openapi                - Generate scan jobs from an OpenAPI/Swagger JSON spec',
  '--max-endpoints          - Max endpoints to expand from an OpenAPI spec (default 100)',
  '--delay                  - Delay between requests in milliseconds',
  '--timeout                - Per-request timeout in seconds (default 10)',
  '--verbose                - Print additional diagnostics',
  '',
  '',
  'Request options:',
  '-u, --url                 - Target URL (omit it to discover targets from dorks)',
  '-X, --method              - HTTP method (default GET)',
  '-d, --data                - Request body (form, JSON or raw)',
  '-H, --header              - Extra header, repeatable',
  '--param                   - Restrict injection to a named parameter/cookie',
  '--cookie                  - Cookie header used for authenticated scans',
  '--cookie2                 - Second identity cookie for IDOR comparisons',
  '--csrf                    - Fetch and inject CSRF_TOKEN into data/headers/cookies',
  '--bearer                  - Authorization: Bearer <token>',
  '--basic-auth              - HTTP Basic auth in user:password form',
  '--login-url               - Form login endpoint used before scanning',
  '--login-data              - Login body; supports {{MFA}} or MFA_CODE placeholders',
  '--login-method            - Login HTTP method (default POST)',
  '--mfa-secret              - Base32 TOTP secret for automatic MFA codes',
  '--mfa-code                - Explicit MFA code (overrides TOTP)',
  '--mfa-url                 - Optional second-step MFA endpoint',
  '--mfa-data                - MFA body; supports {{MFA}} or MFA_CODE placeholders',
  '--mfa-field               - MFA form field name (default code)',
  '--extract                 - Run boolean blind extraction mode',
  '--extract-dbms            - Built-in templates: mysql, postgres, mssql, sqlite, oracle',
  '--extract-query           - SQL subquery to extract',
  '--extract-template        - Payload template with {{QUERY}}, {{POS}}, {{MID}}',
  '--extract-length-template - Length payload template',
  '--extract-param           - Query parameter to inject into',
  '--extract-data            - Body template with FUZZ for extraction',
  '--extract-min-code        - Minimum ASCII code (default 32)',
  '--extract-max-code        - Maximum ASCII code (default 126)',
  '--ws                      - Connect to a ws:// or wss:// endpoint',
  '--ws-send                 - Message to send; repeat for multiple payloads',
  '--ws-wait                 - Delay between sends in milliseconds (default 150)',
  '--ws-timeout              - WebSocket connect timeout in milliseconds',
  '--ws-keep-open            - Keep collecting messages briefly after sends',
  '--proxy                   - Upstream proxy: [socks5://][user:pass@]host:port',
  '',
  '',
  'Command examples:',
  '--sqli                                - discover targets from sql_injection_dorks.json',
  '--all --dork-limit 5 --max-targets 10 - search all dorks and test all payloads',
  '--vpn=germany',
  '--dork "site:*.com inurl:admin"',
  '--dork "inurl:login" --engine google,bing,yandex',
  '--dork "inurl:admin" --engine all --searx=https://searx.example.com',
  '--tamper=space2comment/randomcase/equaltolike/base64encode',
  '--all -u "https://target/?q=FUZZ" --json --out report.json'
].join('\n');

const SECTION_HEADERS = ['Built-in commands:', 'Auxiliary commands:', 'Request options:', 'Command examples:'];

function colorizeHelp(help) {
  return help
    .split('\n')
    .map((line) => {
      if (SECTION_HEADERS.includes(line)) return paint(line, 'bold');
      const match = line.match(/^((?:-{1,2}|-u, | -X, |-d, |-H, )[a-z-]+)(.*)$/);
      if (!match) return line;
      const [, flag, rest] = match;
      return paint(flag, 'beige') + (rest ? paint(rest, 'gray') : '');
    })
    .join('\n');
}

function printHelp() {
  process.stdout.write(BANNER + '\n');
  process.stdout.write('\n' + colorizeHelp(HELP) + '\n');
}

const ALIASES = {
  openredir: 'open_redirect',
  hostheaderinjection: 'host_header_injection',
  headerinjection: 'header_injection',
  codeinjection: 'code_injection',
  jsonpxss: 'jsonp_xss',
  logicbypass: 'logic_bypass',
  sessionfixation: 'session_fixation'
};

function looksLikeUrl(value) {
  return /^https?:\/\//i.test(String(value));
}

function parseArgs(args) {
  const parsed = {
    vulns: [],
    errors: [],
    flags: {
      randomAgents: false,
      vpn: null,
      vpnList: false,
      dork: null,
      backup: false,
      backupQuery: null,
      engines: 'major',
      searxUrl: null,
      tamper: null,
      url: null,
      method: 'GET',
      data: null,
      headers: [],
      param: null,
      cookie: null,
      cookie2: null,
      csrf: false,
      bearer: null,
      basicAuth: null,
      proxy: null,
      oob: false,
      oobDomain: null,
      oobHost: '0.0.0.0',
      oobPort: 8080,
      smtpPort: null,
      timeoutMs: 10000,
      delayMs: 0,
      dorkLimit: 0,
      maxTargets: 0,
      maxConsecutiveErrors: 0,
      searchDelayMs: 2500,
      searchPages: 1,
      maxResults: 0,
      region: 'us',
      language: 'en',
      includeDomains: [],
      excludeDomains: [],
      canonicalize: true,
      sortQuery: true,
      crawl: false,
      crawlDepth: 1,
      maxLinks: 50,
      crawlMaxPages: 100,
      concurrency: 1,
      maxRequests: 0,
      scanTimeoutMs: 0,
      checkpoint: null,
      resume: null,
      insecure: false,
      http2: false,
      graphql: false,
      maxFields: 50,
      renderJs: false,
      renderUnsafe: false,
      captchaToken: null,
      captchaCommand: null,
      captchaProvider: null,
      captchaApiKey: null,
      captchaType: null,
      captchaSitekey: null,
      captchaPollMs: null,
      captchaTimeoutMs: 120000,
      browser: null,
      loginUrl: null,
      loginData: null,
      loginMethod: 'POST',
      mfaSecret: null,
      mfaCode: null,
      mfaField: 'code',
      mfaUrl: null,
      mfaData: null,
      extract: false,
      extractDbms: null,
      extractQuery: null,
      extractTemplate: null,
      extractLengthTemplate: null,
      extractParam: null,
      extractData: null,
      extractMaxLength: 64,
      extractMinCode: 32,
      extractMaxCode: 126,
      ws: false,
      wsPayloads: [],
      wsWaitMs: 150,
      wsTimeoutMs: 10000,
      wsKeepOpen: false,
      summary: false,
      findingsTable: false,
      reportFormat: null,
      reportFile: null,
      openapi: null,
      maxEndpoints: 100,
      json: false,
      out: null,
      minConfidence: 'medium',
      all: false,
      verbose: false,
      version: false
    },
    positionals: []
  };

  const sigTypes = listSignatureTypes();
  const seenVulns = new Set();

  const addVuln = (name) => {
    if (!seenVulns.has(name)) {
      seenVulns.add(name);
      parsed.vulns.push(name);
    }
  };

  const looksLikeOption = (value) => value.length > 1 && value.startsWith('-') && !/^-\d/.test(value);

  const valueAt = (index, flag) => {
    const value = args[index + 1];
    if (value === undefined || looksLikeOption(value)) {
      parsed.errors.push(flag + ' requires a value');
      return null;
    }
    return value;
  };

  const setNumber = (index, flag, target, multiplier, min) => {
    const value = Number(args[index + 1]);
    if (!Number.isFinite(value) || value < min) {
      parsed.errors.push(flag + ' requires a number >= ' + min);
      return;
    }
    parsed.flags[target] = value * multiplier;
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    if (arg === '--help' || arg === '-h' || arg === 'help') {
      parsed.help = true;
    } else if (arg === '--version' || arg === '-v') {
      parsed.flags.version = true;
    } else if (arg === '--all' || arg === '-a') {
      parsed.flags.all = true;
      for (const type of sigTypes) addVuln(type);
    } else if (arg === '--vpn-list') {
      parsed.flags.vpnList = true;
    } else if (arg === '--random-agents') {
      parsed.flags.randomAgents = true;
    } else if (arg === '--oob') {
      parsed.flags.oob = true;
    } else if (arg.startsWith('--oob=')) {
      parsed.flags.oob = true;
      parsed.flags.oobDomain = arg.slice(6) || null;
    } else if (arg === '--oob-host') {
      const value = valueAt(i, '--oob-host');
      if (value !== null) {
        parsed.flags.oobHost = value;
        i++;
      }
    } else if (arg === '--oob-port') {
      const value = valueAt(i, '--oob-port');
      if (value !== null) {
        const port = Number(value);
        if (!Number.isInteger(port) || port < 1 || port > 65535) parsed.errors.push('--oob-port must be 1-65535');
        else parsed.flags.oobPort = port;
        i++;
      }
    } else if (arg === '--smtp-port') {
      const value = valueAt(i, '--smtp-port');
      if (value !== null) {
        const port = Number(value);
        if (!Number.isInteger(port) || port < 1 || port > 65535) parsed.errors.push('--smtp-port must be 1-65535');
        else parsed.flags.smtpPort = port;
        i++;
      }
    } else if (arg === '--dork-limit' || arg === '--max-targets' || arg === '--search-delay' || arg === '--max-consecutive-errors') {
      const value = valueAt(i, arg);
      if (value !== null) {
        const number = Number(value);
        if (!Number.isInteger(number) || number < 0) {
          parsed.errors.push(arg + ' must be an integer >= 0');
        } else if (arg === '--dork-limit') {
          parsed.flags.dorkLimit = number;
        } else if (arg === '--max-targets') {
          parsed.flags.maxTargets = number;
        } else if (arg === '--max-consecutive-errors') {
          parsed.flags.maxConsecutiveErrors = number;
        } else {
          parsed.flags.searchDelayMs = number;
        }
        i++;
      }
    } else if (arg.startsWith('--vpn=')) {
      parsed.flags.vpn = arg.slice(6);
    } else if (arg === '--vpn') {
      const value = valueAt(i, '--vpn');
      if (value !== null) {
        parsed.flags.vpn = value;
        i++;
      }
    } else if (arg.startsWith('--dork=')) {
      parsed.flags.dork = arg.slice(7) || true;
    } else if (arg === '--dork') {
      const value = args[i + 1];
      if (value && !value.startsWith('-')) {
        parsed.flags.dork = value;
        i++;
      } else {
        parsed.flags.dork = true;
      }
    } else if (arg === '--backup') {
      parsed.flags.backup = true;
    } else if (arg.startsWith('--backup=')) {
      parsed.flags.backup = true;
      parsed.flags.backupQuery = arg.slice(9) || null;
    } else if (arg === '--engine' || arg === '--engines') {
      const value = valueAt(i, arg);
      if (value !== null) {
        try {
          dork.resolveEngines(value);
          parsed.flags.engines = value;
        } catch (err) {
          parsed.errors.push(err.message);
        }
        i++;
      }
    } else if (arg.startsWith('--engine=') || arg.startsWith('--engines=')) {
      const value = arg.slice(arg.indexOf('=') + 1);
      try {
        dork.resolveEngines(value);
        parsed.flags.engines = value;
      } catch (err) {
        parsed.errors.push(err.message);
      }
    } else if (arg === '--searx') {
      const value = valueAt(i, '--searx');
      if (value !== null) {
        if (!looksLikeUrl(value)) parsed.errors.push('--searx requires an http(s) URL');
        else parsed.flags.searxUrl = value.replace(/\/+$/, '');
        i++;
      }
    } else if (arg.startsWith('--searx=')) {
      const value = arg.slice(8);
      if (!looksLikeUrl(value)) parsed.errors.push('--searx requires an http(s) URL');
      else parsed.flags.searxUrl = value.replace(/\/+$/, '');
    } else if (arg === '--search-pages' || arg === '--max-links' || arg === '--crawl-depth' || arg === '--crawl-max-pages' || arg === '--concurrency' || arg === '--max-requests') {
      const value = valueAt(i, arg);
      if (value !== null) {
        const number = Number(value);
        if (!Number.isInteger(number) || number < 0) parsed.errors.push(arg + ' must be an integer >= 0');
        else if (arg === '--search-pages') parsed.flags.searchPages = Math.max(1, number || 1);
        else if (arg === '--max-links') parsed.flags.maxLinks = Math.max(1, number || 1);
        else if (arg === '--crawl-depth') parsed.flags.crawlDepth = number;
        else if (arg === '--crawl-max-pages') parsed.flags.crawlMaxPages = Math.max(1, number || 1);
        else if (arg === '--concurrency') parsed.flags.concurrency = Math.max(1, number || 1);
        else parsed.flags.maxRequests = number;
        i++;
      }
    } else if (arg === '--max-results') {
      const value = valueAt(i, '--max-results');
      if (value !== null) {
        const number = Number(value);
        if (!Number.isInteger(number) || number < 0) parsed.errors.push('--max-results must be an integer >= 0');
        else parsed.flags.maxResults = number;
        i++;
      }
    } else if (arg === '--scan-timeout') {
      const value = valueAt(i, '--scan-timeout');
      if (value !== null) {
        const number = Number(value);
        if (!Number.isFinite(number) || number < 0) parsed.errors.push('--scan-timeout must be a number >= 0');
        else parsed.flags.scanTimeoutMs = number * 1000;
        i++;
      }
    } else if (arg === '--region' || arg === '--language') {
      const value = valueAt(i, arg);
      if (value !== null) {
        if (arg === '--region') parsed.flags.region = value;
        else parsed.flags.language = value;
        i++;
      }
    } else if (arg === '--include-domain' || arg === '--exclude-domain') {
      const value = valueAt(i, arg);
      if (value !== null) {
        if (arg === '--include-domain') parsed.flags.includeDomains.push(value);
        else parsed.flags.excludeDomains.push(value);
        i++;
      }
    } else if (arg.startsWith('--include-domain=') || arg.startsWith('--exclude-domain=')) {
      const value = arg.slice(arg.indexOf('=') + 1);
      if (arg.startsWith('--include')) parsed.flags.includeDomains.push(value);
      else parsed.flags.excludeDomains.push(value);
    } else if (arg === '--openapi') {
      const value = valueAt(i, '--openapi');
      if (value !== null) {
        parsed.flags.openapi = value;
        i++;
      }
    } else if (arg.startsWith('--openapi=')) {
      parsed.flags.openapi = arg.slice(10);
    } else if (arg === '--max-endpoints') {
      const value = valueAt(i, '--max-endpoints');
      if (value !== null) {
        const number = Number(value);
        if (!Number.isInteger(number) || number < 1) parsed.errors.push('--max-endpoints must be an integer >= 1');
        else parsed.flags.maxEndpoints = number;
        i++;
      }
    } else if (arg === '--checkpoint' || arg === '--report-file' || arg === '--resume') {
      const value = valueAt(i, arg);
      if (value !== null) {
        if (arg === '--checkpoint') parsed.flags.checkpoint = value;
        else if (arg === '--resume') parsed.flags.resume = value;
        else parsed.flags.reportFile = value;
        i++;
      }
    } else if (arg.startsWith('--checkpoint=') || arg.startsWith('--resume=') || arg.startsWith('--report-file=')) {
      const value = arg.slice(arg.indexOf('=') + 1);
      if (arg.startsWith('--checkpoint')) parsed.flags.checkpoint = value;
      else if (arg.startsWith('--resume')) parsed.flags.resume = value;
      else parsed.flags.reportFile = value;
    } else if (arg === '--report-format') {
      const value = valueAt(i, '--report-format');
      if (value !== null) {
        const normalized = value.toLowerCase();
        if (!['text', 'json', 'html', 'csv', 'sarif'].includes(normalized)) parsed.errors.push('--report-format must be text, json, html, csv or sarif');
        else parsed.flags.reportFormat = normalized;
        i++;
      }
    } else if (arg.startsWith('--report-format=')) {
      const value = arg.slice(16);
      const normalized = value.toLowerCase();
      if (!['text', 'json', 'html', 'csv', 'sarif'].includes(normalized)) parsed.errors.push('--report-format must be text, json, html, csv or sarif');
      else parsed.flags.reportFormat = normalized;
    } else if (arg === '--crawl') {
      parsed.flags.crawl = true;
    } else if (arg === '--no-canonicalize') {
      parsed.flags.canonicalize = false;
    } else if (arg === '--no-sort-query') {
      parsed.flags.sortQuery = false;
    } else if (arg === '--insecure') {
      parsed.flags.insecure = true;
    } else if (arg === '--http2') {
      parsed.flags.http2 = true;
    } else if (arg === '--graphql') {
      parsed.flags.graphql = true;
    } else if (arg === '--max-fields') {
      const value = valueAt(i, '--max-fields');
      if (value !== null) {
        const number = Number(value);
        if (!Number.isInteger(number) || number < 1) parsed.errors.push('--max-fields must be an integer >= 1');
        else parsed.flags.maxFields = number;
        i++;
      }
    } else if (arg === '--render-js') {
      parsed.flags.renderJs = true;
    } else if (arg === '--render-unsafe') {
      parsed.flags.renderUnsafe = true;
    } else if (arg === '--browser') {
      const value = valueAt(i, '--browser');
      if (value !== null) {
        parsed.flags.browser = value;
        i++;
      }
    } else if (arg === '--captcha-token') {
      const value = valueAt(i, '--captcha-token');
      if (value !== null) {
        parsed.flags.captchaToken = value;
        i++;
      }
    } else if (arg.startsWith('--captcha-token=')) {
      parsed.flags.captchaToken = arg.slice(16);
    } else if (arg === '--captcha-command') {
      const value = valueAt(i, '--captcha-command');
      if (value !== null) {
        parsed.flags.captchaCommand = value;
        i++;
      }
    } else if (arg.startsWith('--captcha-command=')) {
      parsed.flags.captchaCommand = arg.slice(18);
    } else if (arg === '--captcha-provider') {
      const value = valueAt(i, '--captcha-provider');
      if (value !== null) {
        parsed.flags.captchaProvider = value.toLowerCase();
        i++;
      }
    } else if (arg.startsWith('--captcha-provider=')) {
      parsed.flags.captchaProvider = arg.slice(19).toLowerCase();
    } else if (arg === '--captcha-api-key') {
      const value = valueAt(i, '--captcha-api-key');
      if (value !== null) {
        parsed.flags.captchaApiKey = value;
        i++;
      }
    } else if (arg.startsWith('--captcha-api-key=')) {
      parsed.flags.captchaApiKey = arg.slice(18);
    } else if (arg === '--captcha-type') {
      const value = valueAt(i, '--captcha-type');
      if (value !== null) {
        parsed.flags.captchaType = value.toLowerCase();
        i++;
      }
    } else if (arg.startsWith('--captcha-type=')) {
      parsed.flags.captchaType = arg.slice(15).toLowerCase();
    } else if (arg === '--captcha-sitekey') {
      const value = valueAt(i, '--captcha-sitekey');
      if (value !== null) {
        parsed.flags.captchaSitekey = value;
        i++;
      }
    } else if (arg.startsWith('--captcha-sitekey=')) {
      parsed.flags.captchaSitekey = arg.slice(18);
    } else if (arg === '--captcha-poll') {
      const value = valueAt(i, '--captcha-poll');
      if (value !== null) {
        const number = Number(value);
        if (!Number.isInteger(number) || number < 250) parsed.errors.push('--captcha-poll must be an integer >= 250');
        else parsed.flags.captchaPollMs = number;
        i++;
      }
    } else if (arg === '--captcha-timeout') {
      const value = valueAt(i, '--captcha-timeout');
      if (value !== null) {
        const number = Number(value);
        if (!Number.isInteger(number) || number < 1000) parsed.errors.push('--captcha-timeout must be an integer >= 1000');
        else parsed.flags.captchaTimeoutMs = number;
        i++;
      }
    } else if (arg === '--summary') {
      parsed.flags.summary = true;
    } else if (arg === '--findings-table') {
      parsed.flags.findingsTable = true;
    } else if (arg.startsWith('--tamper=')) {
      parsed.flags.tamper = arg.slice(9);
    } else if (arg === '--tamper') {
      const value = valueAt(i, '--tamper');
      if (value !== null) {
        parsed.flags.tamper = value;
        i++;
      }
    } else if (arg === '-u' || arg === '--url') {
      const value = valueAt(i, '--url');
      if (value !== null) {
        parsed.flags.url = value;
        i++;
      }
    } else if (arg.startsWith('--url=')) {
      parsed.flags.url = arg.slice(6);
    } else if (arg === '-X' || arg === '--method') {
      const value = valueAt(i, '--method');
      if (value !== null) {
        parsed.flags.method = value.toUpperCase();
        i++;
      }
    } else if (arg === '-d' || arg === '--data') {
      const value = valueAt(i, '--data');
      if (value !== null) {
        parsed.flags.data = value;
        i++;
      }
    } else if (arg.startsWith('--data=')) {
      parsed.flags.data = arg.slice(7);
    } else if (arg === '-H' || arg === '--header') {
      const value = valueAt(i, '--header');
      if (value !== null) {
        parsed.flags.headers.push(value);
        i++;
      }
    } else if (arg.startsWith('--header=')) {
      parsed.flags.headers.push(arg.slice(9));
    } else if (arg === '--param') {
      const value = valueAt(i, '--param');
      if (value !== null) {
        parsed.flags.param = value;
        i++;
      }
    } else if (arg === '--cookie') {
      const value = valueAt(i, '--cookie');
      if (value !== null) {
        parsed.flags.cookie = value;
        i++;
      }
    } else if (arg === '--cookie2') {
      const value = valueAt(i, '--cookie2');
      if (value !== null) {
        parsed.flags.cookie2 = value;
        i++;
      }
    } else if (arg === '--csrf') {
      parsed.flags.csrf = true;
    } else if (arg === '--bearer') {
      const value = valueAt(i, '--bearer');
      if (value !== null) {
        parsed.flags.bearer = value;
        i++;
      }
    } else if (arg.startsWith('--bearer=')) {
      parsed.flags.bearer = arg.slice(9);
    } else if (arg === '--basic-auth') {
      const value = valueAt(i, '--basic-auth');
      if (value !== null) {
        parsed.flags.basicAuth = value;
        i++;
      }
    } else if (arg.startsWith('--basic-auth=')) {
      parsed.flags.basicAuth = arg.slice(13);
    } else if (arg === '--login-url') {
      const value = valueAt(i, '--login-url');
      if (value !== null) {
        parsed.flags.loginUrl = value;
        i++;
      }
    } else if (arg.startsWith('--login-url=')) {
      parsed.flags.loginUrl = arg.slice(12);
    } else if (arg === '--login-data') {
      const value = valueAt(i, '--login-data');
      if (value !== null) {
        parsed.flags.loginData = value;
        i++;
      }
    } else if (arg.startsWith('--login-data=')) {
      parsed.flags.loginData = arg.slice(13);
    } else if (arg === '--login-method') {
      const value = valueAt(i, '--login-method');
      if (value !== null) {
        parsed.flags.loginMethod = value.toUpperCase();
        i++;
      }
    } else if (arg.startsWith('--login-method=')) {
      parsed.flags.loginMethod = arg.slice(15).toUpperCase();
    } else if (arg === '--mfa-secret') {
      const value = valueAt(i, '--mfa-secret');
      if (value !== null) {
        parsed.flags.mfaSecret = value;
        i++;
      }
    } else if (arg.startsWith('--mfa-secret=')) {
      parsed.flags.mfaSecret = arg.slice(13);
    } else if (arg === '--mfa-code') {
      const value = valueAt(i, '--mfa-code');
      if (value !== null) {
        parsed.flags.mfaCode = value;
        i++;
      }
    } else if (arg.startsWith('--mfa-code=')) {
      parsed.flags.mfaCode = arg.slice(11);
    } else if (arg === '--mfa-url') {
      const value = valueAt(i, '--mfa-url');
      if (value !== null) {
        parsed.flags.mfaUrl = value;
        i++;
      }
    } else if (arg.startsWith('--mfa-url=')) {
      parsed.flags.mfaUrl = arg.slice(10);
    } else if (arg === '--mfa-data') {
      const value = valueAt(i, '--mfa-data');
      if (value !== null) {
        parsed.flags.mfaData = value;
        i++;
      }
    } else if (arg.startsWith('--mfa-data=')) {
      parsed.flags.mfaData = arg.slice(11);
    } else if (arg === '--mfa-field') {
      const value = valueAt(i, '--mfa-field');
      if (value !== null) {
        parsed.flags.mfaField = value;
        i++;
      }
    } else if (arg.startsWith('--mfa-field=')) {
      parsed.flags.mfaField = arg.slice(12);
    } else if (arg === '--extract') {
      parsed.flags.extract = true;
    } else if (arg === '--extract-dbms') {
      const value = valueAt(i, '--extract-dbms');
      if (value !== null) {
        parsed.flags.extractDbms = value.toLowerCase();
        i++;
      }
    } else if (arg.startsWith('--extract-dbms=')) {
      parsed.flags.extractDbms = arg.slice(15).toLowerCase();
    } else if (arg === '--extract-query') {
      const value = valueAt(i, '--extract-query');
      if (value !== null) {
        parsed.flags.extractQuery = value;
        i++;
      }
    } else if (arg.startsWith('--extract-query=')) {
      parsed.flags.extractQuery = arg.slice(16);
    } else if (arg === '--extract-template') {
      const value = valueAt(i, '--extract-template');
      if (value !== null) {
        parsed.flags.extractTemplate = value;
        i++;
      }
    } else if (arg.startsWith('--extract-template=')) {
      parsed.flags.extractTemplate = arg.slice(19);
    } else if (arg === '--extract-length-template') {
      const value = valueAt(i, '--extract-length-template');
      if (value !== null) {
        parsed.flags.extractLengthTemplate = value;
        i++;
      }
    } else if (arg.startsWith('--extract-length-template=')) {
      parsed.flags.extractLengthTemplate = arg.slice(26);
    } else if (arg === '--extract-param') {
      const value = valueAt(i, '--extract-param');
      if (value !== null) {
        parsed.flags.extractParam = value;
        i++;
      }
    } else if (arg.startsWith('--extract-param=')) {
      parsed.flags.extractParam = arg.slice(16);
    } else if (arg === '--extract-data') {
      const value = valueAt(i, '--extract-data');
      if (value !== null) {
        parsed.flags.extractData = value;
        i++;
      }
    } else if (arg.startsWith('--extract-data=')) {
      parsed.flags.extractData = arg.slice(15);
    } else if (arg === '--extract-max-length') {
      const value = valueAt(i, '--extract-max-length');
      if (value !== null) {
        const number = Number(value);
        if (!Number.isInteger(number) || number < 1) parsed.errors.push('--extract-max-length must be an integer >= 1');
        else parsed.flags.extractMaxLength = number;
        i++;
      }
    } else if (arg === '--extract-min-code' || arg === '--extract-max-code') {
      const value = valueAt(i, arg);
      if (value !== null) {
        const number = Number(value);
        if (!Number.isInteger(number) || number < 0 || number > 255) parsed.errors.push(arg + ' must be 0-255');
        else if (arg === '--extract-min-code') parsed.flags.extractMinCode = number;
        else parsed.flags.extractMaxCode = number;
        i++;
      }
    } else if (arg === '--ws') {
      parsed.flags.ws = true;
    } else if (arg === '--ws-send') {
      const value = valueAt(i, '--ws-send');
      if (value !== null) {
        parsed.flags.wsPayloads.push(value);
        i++;
      }
    } else if (arg.startsWith('--ws-send=')) {
      parsed.flags.wsPayloads.push(arg.slice(10));
    } else if (arg === '--ws-wait') {
      const value = valueAt(i, '--ws-wait');
      if (value !== null) {
        const number = Number(value);
        if (!Number.isInteger(number) || number < 0) parsed.errors.push('--ws-wait must be an integer >= 0');
        else parsed.flags.wsWaitMs = number;
        i++;
      }
    } else if (arg === '--ws-timeout') {
      const value = valueAt(i, '--ws-timeout');
      if (value !== null) {
        const number = Number(value);
        if (!Number.isInteger(number) || number < 1) parsed.errors.push('--ws-timeout must be an integer >= 1');
        else parsed.flags.wsTimeoutMs = number;
        i++;
      }
    } else if (arg === '--ws-keep-open') {
      parsed.flags.wsKeepOpen = true;
    } else if (arg === '--proxy') {
      const value = valueAt(i, '--proxy');
      if (value !== null) {
        parsed.flags.proxy = value;
        i++;
      }
    } else if (arg.startsWith('--proxy=')) {
      parsed.flags.proxy = arg.slice(8);
    } else if (arg === '--timeout') {
      if (args[i + 1] !== undefined && !looksLikeOption(args[i + 1])) {
        setNumber(i, '--timeout', 'timeoutMs', 1000, 0.1);
        i++;
      } else {
        parsed.errors.push('--timeout requires a value');
      }
    } else if (arg === '--delay') {
      if (args[i + 1] !== undefined && !looksLikeOption(args[i + 1])) {
        setNumber(i, '--delay', 'delayMs', 1, 0);
        i++;
      } else {
        parsed.errors.push('--delay requires a value');
      }
    } else if (arg === '--min-confidence') {
      const value = valueAt(i, '--min-confidence');
      if (value !== null) {
        const normalized = value.toLowerCase();
        if (!['low', 'medium', 'high'].includes(normalized)) {
          parsed.errors.push('--min-confidence must be low, medium or high');
        } else {
          parsed.flags.minConfidence = normalized;
        }
        i++;
      }
    } else if (arg === '--json') {
      parsed.flags.json = true;
    } else if (arg === '--verbose') {
      parsed.flags.verbose = true;
    } else if (arg === '-o' || arg === '--out') {
      const value = valueAt(i, '--out');
      if (value !== null) {
        parsed.flags.out = value;
        i++;
      }
    } else if (arg.startsWith('--out=')) {
      parsed.flags.out = arg.slice(6);
    } else if (arg.startsWith('--')) {
      const name = arg.slice(2);
      const resolved = ALIASES[name] || name;
      if (sigTypes.includes(resolved)) addVuln(resolved);
      else parsed.errors.push('unknown option: ' + arg);
    } else if (looksLikeUrl(arg) && !parsed.flags.url) {
      parsed.flags.url = arg;
    } else {
      parsed.positionals.push(arg);
    }
  }

  return parsed;
}

async function startProxy(flags) {
  const log = flags.json ? process.stderr : process.stdout;
  if (flags.vpn) {
    log.write(paint('[*] Starting VPN profile "' + flags.vpn + '" ...', 'beige'));
    try {
      const handle = await proxy.start(flags.vpn);
      log.write(paint(' [OK] socks5://127.0.0.1:' + handle.proxy.port + '\n', 'orange'));
      return { handle, proxy: handle.proxy };
    } catch (err) {
      log.write('\n');
      throw err;
    }
  }
  if (flags.proxy) return { handle: null, proxy: proxy.parseProxy(flags.proxy) };
  return { handle: null, proxy: null };
}

function mapToEntries(value) {
  if (value instanceof Map) return Array.from(value.entries());
  if (Array.isArray(value)) return value;
  if (value && typeof value === 'object') return Object.entries(value);
  return [];
}

function serializeDiscovery(result) {
  if (!result) return result;
  return Object.assign({}, result, {
    byType: mapToEntries(result.byType),
    categoriesByType: mapToEntries(result.categoriesByType)
  });
}

function hydrateDiscovery(result) {
  if (!result) return result;
  return Object.assign({}, result, {
    byType: new Map(mapToEntries(result.byType)),
    categoriesByType: new Map(mapToEntries(result.categoriesByType))
  });
}

async function runWs(flags) {
  const websocket = require('../tools/websocket');
  if (!flags.url || !websocket.isWebSocketUrl(flags.url)) {
    process.stderr.write(paint('[!] --ws requires -u ws://host/path or wss://host/path\n', 'orange'));
    process.exitCode = 1;
    return { sent: 0, messages: [], errors: [] };
  }
  const upstream = await startProxy(flags);
  try {
    const headers = flags.headers.slice();
    if (flags.bearer) headers.push('Authorization: Bearer ' + flags.bearer);
    if (flags.basicAuth) headers.push('Authorization: Basic ' + Buffer.from(flags.basicAuth).toString('base64'));
    const result = await websocket.scan(flags.url, {
      payloads: flags.wsPayloads,
      waitMs: flags.wsWaitMs,
      timeoutMs: flags.wsTimeoutMs,
      keepOpen: flags.wsKeepOpen,
      headers,
      cookie: flags.cookie,
      proxy: upstream.proxy,
      rejectUnauthorized: !flags.insecure
    });
    if (!result.connected) process.exitCode = 1;
    if (flags.json) {
      process.stdout.write(JSON.stringify(result, null, 2) + '\n');
    } else {
      process.stdout.write(paint('[*] WebSocket ' + (result.connected ? 'connected' : 'failed') + '\n', result.connected ? 'beige' : 'orange'));
      for (const message of result.messages) process.stdout.write(message + '\n');
      for (const error of result.errors) process.stderr.write(paint('[!] ' + error + '\n', 'orange'));
    }
    return result;
  } finally {
    if (upstream.handle) upstream.handle.stop();
  }
}

async function runExtract(flags) {
  const extract = require('../tools/extract');
  if (!flags.url || (!flags.extractTemplate && !flags.extractDbms)) {
    process.stderr.write(paint('[!] --extract requires --url and --extract-template or --extract-dbms\n', 'orange'));
    process.exitCode = 1;
    return { requests: 0 };
  }
  if (!flags.extractQuery) {
    process.stderr.write(paint('[!] --extract requires --extract-query\n', 'orange'));
    process.exitCode = 1;
    return { requests: 0 };
  }
  if (flags.extractDbms && !flags.extractTemplate && !extract.templates[flags.extractDbms]) {
    process.stderr.write(paint('[!] Unknown --extract-dbms: ' + flags.extractDbms + '\n', 'orange'));
    process.exitCode = 1;
    return { requests: 0 };
  }
  const upstream = await startProxy(flags);
  try {
    if (!flags.json) process.stdout.write(paint('[*] Extracting boolean-blind value...\n', 'beige'));
    const headers = flags.headers.slice();
    if (flags.bearer) headers.push('Authorization: Bearer ' + flags.bearer);
    if (flags.basicAuth) headers.push('Authorization: Basic ' + Buffer.from(flags.basicAuth).toString('base64'));
    const result = await extract.extract({
      url: flags.url,
      dbms: flags.extractDbms,
      template: flags.extractTemplate,
      lengthTemplate: flags.extractLengthTemplate,
      query: flags.extractQuery,
      param: flags.extractParam,
      data: flags.extractData || flags.data,
      maxLength: flags.extractMaxLength,
      minCode: flags.extractMinCode,
      maxCode: flags.extractMaxCode,
      headers,
      cookie: flags.cookie,
      timeoutMs: flags.timeoutMs,
      proxy: upstream.proxy,
      rejectUnauthorized: !flags.insecure,
      http2: flags.http2,
      onChar: (code) => {
        if (!flags.json) process.stdout.write(String.fromCharCode(code));
      }
    });
    if (flags.json) {
      process.stdout.write(JSON.stringify(result, null, 2) + '\n');
    } else {
      process.stdout.write('\n[+] Extracted: ' + result.value + '\n');
    }
    return result;
  } finally {
    if (upstream.handle) upstream.handle.stop();
  }
}

async function runDork(flags) {
  if (!flags.json) process.stdout.write(BANNER + '\n\n');
  const query = flags.dork;
  if (query === true) {
    process.stdout.write(report.renderDorkCategories(dork.listCategories()) + '\n');
    return { requests: 0 };
  }
  const category = dork.findCategory(query);
  if (category) {
    process.stdout.write(paint('--- Dorks in category: ' + category.name + ' (' + category.dorks.length + ') ---', 'bold') + '\n');
    for (const item of category.dorks) process.stdout.write(item + '\n');
    return { requests: 0 };
  }

  const upstream = await startProxy(flags);
  try {
    const engines = dork.engineLabel(flags.engines, { searxUrl: flags.searxUrl });
    process.stdout.write(paint('[*] Searching ' + engines + ' for: ' + query + ' ...\n', 'beige'));
    let results = await dork.search(query, {
      proxy: upstream.proxy,
      timeoutMs: flags.timeoutMs,
      engines: flags.engines,
      searxUrl: flags.searxUrl,
      pages: flags.searchPages,
      maxResults: flags.maxResults,
      region: flags.region,
      language: flags.language,
      includeDomains: flags.includeDomains,
      excludeDomains: flags.excludeDomains,
      canonicalize: flags.canonicalize,
      sortQuery: flags.sortQuery,
      http2: flags.http2,
      rejectUnauthorized: !flags.insecure
    });
    if (results.engineErrors && results.engineErrors.length) {
      process.stdout.write(paint('[!] Engine warnings: ' + results.engineErrors.map((item) => item.engine + ': ' + item.error).join('; ') + '\n', 'orange'));
    }
    if (backup.isBackupQuery(query)) {
      results = await backup.enrichResults(results, {
        proxy: upstream.proxy,
        timeoutMs: flags.timeoutMs,
        http2: flags.http2,
        rejectUnauthorized: !flags.insecure
      });
    }
    process.stdout.write(report.renderDorkResults(query, results) + '\n');
    return { requests: results.length ? 1 : 0 };
  } finally {
    if (upstream.handle) upstream.handle.stop();
  }
}

function uniqueSearchResults(results) {
  const seen = new Set();
  const unique = [];
  for (const result of results || []) {
    const key = String((result && result.url) || '').replace(/#.*$/, '');
    if (!key || seen.has(key)) continue;
    seen.add(key);
    unique.push(result);
  }
  return unique;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function createStopOnEnter() {
  let requested = false;
  let cleaned = false;
  let enabled = false;
  const stdin = process.stdin;
  const onData = (chunk) => {
    const text = String(chunk || '');
    if (text.includes('\x03')) {
      cleanup();
      process.exit(130);
      return;
    }
    if (text.includes('\r') || text.includes('\n')) requested = true;
  };
  const cleanup = () => {
    if (cleaned) return;
    cleaned = true;
    try { stdin.removeListener('data', onData); } catch (err) {}
    try { stdin.setRawMode(false); } catch (err) {}
    try { stdin.pause(); } catch (err) {}
    process.removeListener('exit', cleanup);
  };

  if (stdin && stdin.isTTY && typeof stdin.setRawMode === 'function') {
    try {
      stdin.setRawMode(true);
      stdin.resume();
      stdin.on('data', onData);
      process.once('exit', cleanup);
      enabled = true;
    } catch (err) {
      cleanup();
    }
  }

  return {
    enabled,
    shouldStop: () => requested,
    cleanup
  };
}

async function runBackup(flags) {
  if (!flags.json) process.stdout.write(BANNER + '\n\n');
  const requested = flags.backupQuery;
  const category = dork.findCategory(requested || 'backup_dorks');
  const label = category ? category.name : String(requested || 'backup_dorks');
  const queries = category ? category.dorks.slice() : (requested ? [requested] : []);
  if (!queries.length) {
    process.stderr.write(paint('[!] No backup dorks found. Use --backup=<query>.\n', 'orange'));
    process.exitCode = 1;
    return { requests: 0 };
  }

  const limit = flags.dorkLimit > 0 ? Math.min(flags.dorkLimit, queries.length) : queries.length;
  const selected = queries.slice(0, limit);
  const log = flags.json ? process.stderr : process.stdout;
  const upstream = await startProxy(flags);
  const progress = createDiscoveryProgress({
    total: selected.length,
    stream: log,
    interactive: Boolean(process.stdout.isTTY) && !flags.json
  });
  const stopper = createStopOnEnter();
  let searched;

  try {
    const searchOptions = {
      proxy: upstream.proxy,
      timeoutMs: flags.timeoutMs,
      dorkLimit: limit,
      maxConsecutiveErrors: flags.maxConsecutiveErrors,
      delayMs: flags.searchDelayMs,
      engines: flags.engines,
      searxUrl: flags.searxUrl,
      pages: flags.searchPages,
      maxResults: flags.maxResults,
      region: flags.region,
      language: flags.language,
      includeDomains: flags.includeDomains,
      excludeDomains: flags.excludeDomains,
      canonicalize: flags.canonicalize,
      sortQuery: flags.sortQuery,
      http2: flags.http2,
      rejectUnauthorized: !flags.insecure,
      collectResults: true,
      shouldStop: stopper.shouldStop,
      onProgress: (event) => progress.event(event)
    };
    try {
      searched = category
        ? await discovery.searchCategory(category.name, searchOptions)
        : await discovery.searchQueries(selected, Object.assign({}, searchOptions, {
          category: { name: label, file: 'backup_dorks.json' }
        }));
    } finally {
      stopper.cleanup();
      progress.stop();
      log.write('\n');
    }

    if (searched.stopReason === 'user') {
      process.stderr.write(paint('[!] Stopped by user; showing partial results.\n', 'orange'));
    } else if (searched.stopped) {
      log.write(paint('[!] Discovery stopped after repeated search errors.', 'orange') + '\n');
    }

    let merged = uniqueSearchResults(searched.results);
    if (flags.maxResults > 0) merged = merged.slice(0, flags.maxResults);
    const enriched = await backup.enrichResults(merged, {
      proxy: upstream.proxy,
      timeoutMs: flags.timeoutMs,
      http2: flags.http2,
      rejectUnauthorized: !flags.insecure,
      maxPages: flags.maxResults > 0 ? flags.maxResults : 20
    });

    if (flags.json) {
      process.stdout.write(JSON.stringify(enriched, null, 2) + '\n');
    } else {
      const files = enriched.filter((result) => Array.isArray(result.files) && result.files.length);
      if (files.length) {
        process.stdout.write(report.renderDorkResults(label, files, { title: 'Backup Files: ' + label }) + '\n');
      } else {
        const suffix = searched.stopReason === 'user' ? ' in partial results' : '';
        process.stdout.write(paint('[-] No backup file listings found' + suffix + '.\n', 'gray'));
      }
    }

    if (searched.errors.length) {
      process.stderr.write(paint('[!] Search warnings: ' + searched.errors.length + '\n', 'orange'));
      if (flags.verbose) {
        for (const item of searched.errors) {
          const detail = (item.engine ? item.engine + ': ' : '') + (item.error || 'unknown error');
          process.stderr.write(paint('    - ' + item.query + ': ' + detail + '\n', 'gray'));
        }
      }
    }
    return { requests: searched.targets.length };
  } finally {
    if (upstream.handle) upstream.handle.stop();
  }
}

function isLocalUrl(value) {
  try {
    return /^(127\.|localhost$|\[?::1\]?$)/i.test(new URL(value).hostname);
  } catch (err) {
    return false;
  }
}

async function runScan(flags, vulns) {
  if (!flags.json) process.stdout.write(BANNER + '\n\n');
  if (flags.url) {
    try {
      const parsedUrl = new URL(flags.url);
      if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
        throw new Error('unsupported protocol');
      }
    } catch (err) {
      process.stderr.write(paint('[!] Error: invalid target URL: ' + flags.url + '\n', 'orange'));
      process.exitCode = 1;
      return;
    }
  }

  const log = flags.json ? process.stderr : process.stdout;
  let proxyHandle = null;
  let oobServer = null;
  let upstream = { proxy: null };
  let discoveryResult = null;

  try {
    upstream = await startProxy(flags);
    proxyHandle = upstream.handle;

    const jobs = [];
    const reports = [];
    const findings = [];
    const observations = [];
    const errors = [];
    const scanHeaders = flags.headers.slice();
    if (flags.bearer) scanHeaders.push('Authorization: Bearer ' + flags.bearer);
    if (flags.basicAuth) scanHeaders.push('Authorization: Basic ' + Buffer.from(flags.basicAuth).toString('base64'));
    if (flags.loginUrl) {
      const auth = require('../tools/auth');
      const session = await auth.login({
        loginUrl: flags.loginUrl,
        loginData: flags.loginData || flags.data,
        loginMethod: flags.loginMethod,
        mfaSecret: flags.mfaSecret,
        mfaCode: flags.mfaCode,
        mfaField: flags.mfaField,
        mfaUrl: flags.mfaUrl,
        mfaData: flags.mfaData,
        cookie: flags.cookie,
        headers: scanHeaders,
        timeoutMs: flags.timeoutMs,
        proxy: upstream.proxy,
        rejectUnauthorized: !flags.insecure,
        http2: flags.http2
      });
      if (session.cookie) flags.cookie = session.cookie;
      log.write(paint('[*] Login completed' + (session.cookie ? '; session cookie captured' : '') + '.\n', 'beige'));
    }

    if (flags.url) {
      if (flags.graphql) {
        const graphql = require('../tools/graphql');
        try {
          const schema = await graphql.introspect(flags.url, {
            timeoutMs: flags.timeoutMs,
            proxy: upstream.proxy,
            rejectUnauthorized: !flags.insecure,
            http2: flags.http2
          });
          const generated = graphql.buildJobs(schema, flags.url, vulns, { maxFields: flags.maxFields });
          jobs.push(...generated);
          log.write(paint('[*] Expanded ' + generated.length + ' job(s) from GraphQL schema.\n', 'beige'));
          if (!generated.length) {
            for (const type of vulns) jobs.push({ type, target: flags.url });
          }
        } catch (err) {
          errors.push({ type: 'graphql', target: flags.url, error: err.message });
          process.stderr.write(paint('[!] GraphQL introspection failed: ' + err.message + '\n', 'orange'));
          for (const type of vulns) jobs.push({ type, target: flags.url });
        }
      } else {
        for (const type of vulns) jobs.push({ type, target: flags.url });
      }
    } else if (flags.openapi) {
      const openapi = require('../tools/openapi');
      try {
        const generated = await openapi.generateJobs(flags.openapi, {
          types: vulns,
          timeoutMs: flags.timeoutMs,
          proxy: upstream.proxy,
          maxEndpoints: flags.maxEndpoints,
          rejectUnauthorized: !flags.insecure,
          http2: flags.http2
        });
        jobs.push(...generated);
        log.write(paint('[*] Expanded ' + generated.length + ' job(s) from OpenAPI spec.\n', 'beige'));
      } catch (err) {
        errors.push({ type: 'openapi', target: flags.openapi, error: err.message });
        process.stderr.write(paint('[!] OpenAPI expansion failed: ' + err.message + '\n', 'orange'));
      }
    } else if (flags.resume) {
      const fs = require('fs');
      let loaded;
      try {
        loaded = JSON.parse(fs.readFileSync(flags.resume, 'utf8'));
      } catch (err) {
        throw new Error('failed to read resume file ' + flags.resume + ': ' + err.message);
      }
      discoveryResult = hydrateDiscovery(loaded);
      log.write(paint('[*] Resumed discovery from ' + flags.resume + '\n', 'beige'));
    } else {
      const plan = discovery.plan(vulns, { dorkLimit: flags.dorkLimit });
      const progress = createDiscoveryProgress({
        total: plan.total,
        stream: log,
        interactive: Boolean(process.stdout.isTTY) && !flags.json
      });
      try {
        discoveryResult = await discovery.discover(vulns, {
          proxy: upstream.proxy,
          timeoutMs: flags.timeoutMs,
          dorkLimit: flags.dorkLimit,
          maxTargets: flags.maxTargets,
          maxConsecutiveErrors: flags.maxConsecutiveErrors,
          delayMs: flags.searchDelayMs,
          engines: flags.engines,
          searxUrl: flags.searxUrl,
          pages: flags.searchPages,
          maxResults: flags.maxResults,
          region: flags.region,
          language: flags.language,
          includeDomains: flags.includeDomains,
          excludeDomains: flags.excludeDomains,
          canonicalize: flags.canonicalize,
          sortQuery: flags.sortQuery,
          http2: flags.http2,
          rejectUnauthorized: !flags.insecure,
          renderJs: flags.renderJs,
          renderUnsafe: flags.renderUnsafe,
          browser: flags.browser,
          captchaToken: flags.captchaToken,
          captchaCommand: flags.captchaCommand,
          captchaProvider: flags.captchaProvider,
          captchaApiKey: flags.captchaApiKey,
          captchaType: flags.captchaType,
          captchaSitekey: flags.captchaSitekey,
          captchaPollMs: flags.captchaPollMs,
          captchaTimeoutMs: flags.captchaTimeoutMs,
          crawl: flags.crawl,
          crawlDepth: flags.crawlDepth,
          maxLinks: flags.maxLinks,
          crawlMaxPages: flags.crawlMaxPages,
          onWarning: flags.verbose ? (message) => process.stderr.write(paint('[!] ' + message + '\n', 'orange')) : undefined,
          onProgress: (event) => progress.event(event)
        });
      } finally {
        progress.stop();
      }

      log.write('\n');

      if (flags.checkpoint) {
        const fs = require('fs');
        fs.writeFileSync(flags.checkpoint, JSON.stringify(serializeDiscovery(discoveryResult), null, 2), 'utf8');
        log.write(paint('[+] Saved discovery checkpoint to ' + flags.checkpoint + '\n', 'orange'));
      }


    if (!flags.url && discoveryResult) {
      const seenJobs = new Set();
      const addJob = (type, target, form) => {
        const method = form ? form.method : '';
        const data = form ? form.data : undefined;
        const key = [type, target, method, data || ''].join('\0');
        if (seenJobs.has(key)) return;
        seenJobs.add(key);
        const job = { type, target };
        if (form) {
          job.method = form.method;
          job.data = form.data;
        }
        jobs.push(job);
      };
      let forms = discoveryResult.forms || [];
      if (flags.maxTargets > 0) forms = forms.slice(0, flags.maxTargets);
      if (flags.all) {
        let targets = discoveryResult.targets;
        if (flags.maxTargets > 0) targets = targets.slice(0, flags.maxTargets);
        for (const target of targets) {
          for (const type of vulns) addJob(type, target);
        }
        for (const form of forms) {
          for (const type of vulns) addJob(type, form.target, form);
        }
      } else {
        for (const type of vulns) {
          const targets = discoveryResult.byType.get(type) || [];
          for (const target of targets) addJob(type, target);
          for (const form of forms) addJob(type, form.target, form);
        }
      }
    }

      if (!jobs.length) {
        log.write(paint('[!] No targets discovered. Use -u <url> or check search engine availability/proxy settings.\n', 'orange'));
        process.exitCode = 1;
      }
    }

    if (flags.oob && jobs.length) {
      oobServer = new OobServer({
        domain: flags.oobDomain,
        host: flags.oobHost,
        httpPort: flags.oobPort,
        smtpPort: flags.smtpPort
      });
      await oobServer.start();
      log.write(paint('[+] OOB callback listener started on port ' + oobServer.httpPort + (flags.oobDomain ? ' (domain: ' + flags.oobDomain + ')' : '') + '\n', 'orange'));
      for (const warning of oobServer.warnings) {
        process.stderr.write(paint('[!] OOB warning: ' + warning + '\n', 'orange'));
      }
      if (!flags.oobDomain && jobs.some((job) => !isLocalUrl(job.target))) {
        process.stderr.write(paint('[!] OOB warning: no --oob=<domain> supplied, callbacks target 127.0.0.1 and will not reach a remote scanner.\n', 'orange'));
      }
    }

    const scanStart = Date.now();
    let totalRequests = 0;
    const scanJob = async (job) => {
      if (flags.maxRequests > 0 && totalRequests >= flags.maxRequests) {
        return { skipped: true, reason: 'request budget exceeded' };
      }
      if (flags.scanTimeoutMs > 0 && Date.now() - scanStart > flags.scanTimeoutMs) {
        return { skipped: true, reason: 'scan timeout exceeded' };
      }
      try {
        const scanResult = await scanner.scanType(job.type, {
          url: job.target,
          method: job.method || flags.method,
          data: job.data !== undefined ? job.data : flags.data,
          headers: scanHeaders,
          param: flags.param,
          cookie: flags.cookie,
          cookie2: flags.cookie2,
          csrf: flags.csrf,
          captchaToken: flags.captchaToken,
          captchaCommand: flags.captchaCommand,
          captchaProvider: flags.captchaProvider,
          captchaApiKey: flags.captchaApiKey,
          captchaType: flags.captchaType,
          captchaSitekey: flags.captchaSitekey,
          captchaPollMs: flags.captchaPollMs,
          captchaTimeoutMs: flags.captchaTimeoutMs,
          tampers: flags.tamper,
          randomAgents: flags.randomAgents,
          timeoutMs: flags.timeoutMs,
          delayMs: flags.delayMs,
          proxy: upstream.proxy,
          oob: oobServer,
          oobWaitMs: 1500,
          minConfidence: flags.minConfidence,
          rejectUnauthorized: !flags.insecure,
          http2: flags.http2
        });
        totalRequests += Number(scanResult.requests) || 0;
        return { ok: true, scanResult };
      } catch (err) {
        return { ok: false, error: err };
      }
    };

    const concurrency = Math.max(1, Number(flags.concurrency) || 1);
    const jobResults = new Array(jobs.length);
    let nextJob = 0;
    async function runWorker() {
      while (true) {
        const index = nextJob++;
        if (index >= jobs.length) return;
        jobResults[index] = await scanJob(jobs[index]);
      }
    }
    await Promise.all(Array.from({ length: Math.min(concurrency, Math.max(1, jobs.length)) }, () => runWorker()));

    for (let index = 0; index < jobs.length; index++) {
      const job = jobs[index];
      const result = jobResults[index];
      if (!result) continue;
      if (result.skipped) {
        errors.push({ type: job.type, target: job.target, error: result.reason });
        process.stderr.write(paint('[!] ' + job.type.toUpperCase() + ' skipped for ' + job.target + ': ' + result.reason + '\n', 'orange'));
        continue;
      }
      if (result.ok) {
        reports.push(result.scanResult);
        findings.push(...result.scanResult.findings);
        observations.push(...(result.scanResult.observations || []));
        if (!flags.json) {
          for (const finding of result.scanResult.findings) {
            log.write(report.renderFinding(finding) + '\n\n');
          }
        }
      } else {
        const err = result.error;
        errors.push({ type: job.type, target: job.target, error: err.message });
        process.stderr.write(paint('[!] ' + job.type.toUpperCase() + ' scan failed for ' + job.target + ': ' + err.message + '\n', 'orange'));
        if (flags.verbose && err.stack) process.stderr.write(String(err.stack) + '\n');
      }
    }

    const dedupeEntries = (entries) => {
      const seen = new Set();
      const out = [];
      for (const entry of entries || []) {
        const key = [entry.type, entry.target || entry.url, entry.signalId, entry.point].join('\0');
        if (seen.has(key)) continue;
        seen.add(key);
        out.push(entry);
      }
      return out;
    };
    const uniqueFindings = dedupeEntries(findings);
    const uniqueObservations = dedupeEntries(observations);

    const recommendations = Array.from(new Set(uniqueFindings.map((finding) => {
      if (finding.type === 'sqli') return 'Use parameterized queries and strict input validation.';
      if (finding.type === 'xss') return 'Encode output contextually and apply a strong CSP.';
      if (finding.type === 'ssrf') return 'Restrict outbound requests with an allowlist.';
      if (finding.type === 'lfi' || finding.type === 'rfi') return 'Validate file paths and disable remote includes.';
      if (finding.type === 'cmdi') return 'Avoid shell execution; use safe APIs and allowlists.';
      if (finding.type === 'file_upload') return 'Validate file type, content, name, and store uploads outside the web root.';
      return 'Review the affected endpoint and apply least-privilege input handling.';
    })));

    const output = {
      target: flags.url || null,
      options: {
        method: flags.method,
        param: flags.param,
        minConfidence: flags.minConfidence,
        randomAgents: flags.randomAgents,
        proxy: Boolean(upstream.proxy),
        oob: Boolean(oobServer),
        dorkLimit: flags.dorkLimit,
        maxTargets: flags.maxTargets,
        engines: dork.resolveEngines(flags.engines, { searxUrl: flags.searxUrl }),
        searx: Boolean(flags.searxUrl),
        http2: flags.http2,
        graphql: Boolean(flags.graphql)
      },
      reports,
      findings: uniqueFindings,
      observations: uniqueObservations,
      errors,
      summary: {
        dorks: discoveryResult ? discoveryResult.searches : 0,
        targets: discoveryResult ? discoveryResult.targets.length : (flags.url ? 1 : 0),
        scans: reports.length,
        requests: reports.reduce((sum, report) => sum + (report.requests || 0), 0),
        findings: uniqueFindings.length,
        observations: uniqueObservations.length,
        errors: errors.length
      },
      recommendations
    };

    if (discoveryResult) {
      let scannedTargets = discoveryResult.targets;
      if (flags.all && flags.maxTargets > 0) scannedTargets = scannedTargets.slice(0, flags.maxTargets);
      output.discovery = {
        searches: discoveryResult.searches,
        targets: discoveryResult.targets.length,
        scannedTargets: scannedTargets.length,
        forms: discoveryResult.forms || [],
        crawl: discoveryResult.crawl || null,
        categories: discoveryResult.categories,
        engines: dork.resolveEngines(flags.engines, { searxUrl: flags.searxUrl }),
        types: vulns.map((type) => ({
          type,
          categories: discoveryResult.categoriesByType.get(type) || [],
          targets: flags.all ? scannedTargets : (discoveryResult.byType.get(type) || [])
        })),
        errors: discoveryResult.errors
      };
    }

    if (!flags.json) {
      if (flags.findingsTable) process.stdout.write('\n' + report.renderFindingsTable(uniqueFindings) + '\n');
      if (flags.summary) process.stdout.write('\n' + report.renderSummary(output.summary) + '\n');
    }

    const reportFormat = flags.reportFormat || (flags.reportFile ? 'json' : null);
    const reportDestination = flags.reportFile || flags.out;
    if (reportDestination) {
      let text = JSON.stringify(output, null, 2);
      if (reportFormat === 'html') text = report.renderHtmlReport(output);
      else if (reportFormat === 'csv') text = report.renderCsvReport(output);
      else if (reportFormat === 'sarif') text = report.renderSarifReport(output);
      else if (reportFormat === 'text') text = report.renderSummary(output.summary) + '\n\n' + (uniqueFindings.map((f) => report.renderFinding(f)).join('\n\n'));
      fs.writeFileSync(reportDestination, text, 'utf8');
      process.stderr.write(paint('[+] Saved ' + (reportFormat || 'json') + ' report to ' + reportDestination + '\n', 'orange'));
    } else if (flags.json) {
      process.stdout.write(JSON.stringify(output, null, 2) + '\n');
    }

    if (!flags.json && errors.length) {
      process.stdout.write(paint('[!] ' + errors.length + ' scan(s) failed.\n', 'orange'));
    }

    if (errors.length) process.exitCode = 1;
  } finally {
    if (proxyHandle) proxyHandle.stop();
    if (oobServer) oobServer.stop();
  }
}

async function run(args) {
  const parsed = parseArgs(args);

  if (args.length === 0 || parsed.help) {
    printHelp();
    return;
  }

  if (parsed.errors.length > 0) {
    for (const error of parsed.errors) process.stderr.write(paint('[!] ' + error + '\n', 'orange'));
    process.exitCode = 1;
    return;
  }

  if (parsed.flags.version) {
    process.stdout.write('sdork ' + pkg.version + '\n');
    return;
  }

  if (parsed.flags.vpnList) {
    const profiles = proxy.listProfiles();
    if (!profiles.length) {
      process.stderr.write(paint('[!] No VPN profiles found in VPN/.\n', 'orange'));
      return;
    }
    process.stdout.write(paint('--- Available VPN / Proxy Profiles ---', 'bold') + '\n');
    for (const profile of profiles) {
      process.stdout.write(paint('• ' + profile.name.padEnd(16), 'beige') + paint(profile.remarks + ' (' + profile.address + ':' + profile.port + ')', 'gray') + '\n');
    }
    process.stdout.write(paint('\nRun: sdork --vpn=<name> -u <url> --all', 'gray') + '\n');
    return;
  }

  try {
    if (parsed.flags.ws) {
      await runWs(parsed.flags);
      return;
    }

    if (parsed.flags.extract) {
      await runExtract(parsed.flags);
      return;
    }

    if (parsed.flags.backup) {
      await runBackup(parsed.flags);
      return;
    }

    if (parsed.flags.dork) {
      await runDork(parsed.flags);
      return;
    }

    if (parsed.vulns.length > 0) {
      await runScan(parsed.flags, parsed.vulns);
      return;
    }

    process.stderr.write(paint('[!] No valid command specified. Run "sdork --help" for usage.\n', 'orange'));
    process.exitCode = 1;
  } catch (err) {
    process.stderr.write(paint('[!] ' + err.message + '\n', 'orange'));
    process.exitCode = 1;
  }
}

module.exports = { run, printHelp, parseArgs, serializeDiscovery, hydrateDiscovery, HELP };
