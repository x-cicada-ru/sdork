<p align="center">
  <img src="src/sdork-mascot.gif" alt="sdork mascot">
</p>

# sdork

`sdork` — CLI-фреймворк для поиска целей через поисковые дорки и подтверждения веб-уязвимостей сигнатурными payload-проверками. Он объединяет разведку, формирование запросов, проверку гипотез, OOB-подтверждение и отчёты в одном Node.js-инструменте.

## Важно: только авторизованное использование

Используйте `sdork` только против систем, которыми вы владеете, или против целей, на которые у вас есть явное письменное разрешение (пентест, bug bounty scope, учебный стенд). Вы отвечаете за соблюдение законов, условий поисковых сервисов и границ engagement. Авторы не разрешают и не несут ответственности за несанкционированное использование.

## Что это и для чего

`sdork` нужен, когда требуется:

- найти публичные цели по доркам (`--dork`, `--backup`);
- проверить конкретный URL или параметр на распространённые классы уязвимостей (`--sqli`, `--xss`, `--ssrf` и т.д.);
- автоматически собрать ссылки и формы с найденных страниц (`--crawl`);
- подтвердить уязвимость сигнатурой, повтором и контролем ложных срабатываний;
- получить отчёт в text/JSON/HTML/CSV/SARIF;
- проверить OpenAPI/Swagger, GraphQL, WebSocket, формы логина и MFA;
- выполнить blind extraction, OOB-проверку или CAPTCHA-сценарий в рамках разрешённого теста.

Это не «однокнопочный взлом»: результаты поиска и сигнатуры требуют ручной валидации, а многие проверки зависят от контекста приложения.

## Когда и где использовать

### Когда

- На этапе внешней разведки: собрать кандидатов по доркам и открытым каталогам.
- На этапе проверки: прогнать конкретные параметры/формы по разрешённым типам проверок.
- При bug bounty: в пределах программы и её правил, с ограничением нагрузки.
- При внутреннем пентесте или регрессе: воспроизводимые проверки и отчёты.
- На собственных стендах: для отладки сигнатур и обучения.

### Где

- На локальной машине или в изолированной лаборатории.
- В сети, где разрешён исходящий трафик к цели и поисковым сервисам.
- Через `--proxy`/`--vpn`, если этого требует сеть или scope.
- В CI — только для тестов самого проекта (`npm test`), не для сканирования чужих систем.

### Когда не использовать

- Без письменного разрешения на цель.
- Для массового сканирования интернета или обхода лимитов поисковиков.
- Для скачивания и распространения чужих дампов, конфигов и персональных данных.
- Для атак на инфраструктуру, не входящую в scope, включая поисковые сервисы и прокси.
- Для обхода CAPTCHA/ToS цели без разрешения.

## Требования

- Node.js **20 или новее**.
- npm — для установки/запуска скриптов (сам CLI не требует внешних npm-зависимостей).
- Windows, Linux или macOS.
- Для JS-рендеринга: установленный Chrome/Edge или модуль `jsdom` (не входит в пакет).
- Для VPN-профилей: бинарник `xray` в `tools/bin`, в `PATH` или в `SDORK_XRAY`.
- Для официальных поисковых API и CAPTCHA-сервисов — соответствующие ключи (см. ниже).

## Установка и запуск

Из папки проекта:

```powershell
cd C:\path\to\sdork
npm link
sdork --version
sdork --help
```

Варианты без глобальной установки:

```powershell
node bin/sdork.js --help
npm install -g .
```

Проверка проекта:

```powershell
npm test
```

`npm test` запускает unit-проверки и интеграционные сценарии на локальном HTTP-сервере; живые поисковики и платные API для тестов не нужны.

## Быстрый старт

```powershell
# Список категорий дорков
sdork --dork

# Поиск по одному дорку
sdork --dork 'intitle:"index of" "database.sql" OR "db.sql" OR "users.sql"' --engine google,bing

# Показать дорки категории
sdork --dork=backup_dorks

# Поиск бекап-файлов с деревом ссылок и размеров
sdork --backup --engine google,bing --dork-limit 5

# Проверка конкретного URL
sdork --sqli -u "https://target.example/?id=1"

# Разведка по доркам + проверка
sdork --xss --dork-limit 5 --max-targets 10

# Все типы проверок (тяжело; сначала ограничьте лимиты)
sdork --all --dork-limit 2 --max-targets 5 --concurrency 1
```

## Как это работает

1. **Discovery.** `sdork` берёт категорию дорков (или ваш запрос), опрашивает выбранные поисковые движки, нормализует URL, убирает дубли и применяет include/exclude-фильтры.
2. **Targets/forms.** Найденные страницы могут краулиться; ссылки и формы превращаются в задания. GET-поля становятся query-параметрами, POST-поля — телом запроса.
3. **Scanning.** Для каждого задания строятся точки инъекции (query/body/header/cookie/path), снимается baseline, отправляются payload-группы, проверяются сигнатуры и контрольные запросы.
4. **Confirmation.** Срабатывания фильтруются по уверенности, повторяемости, отражениям, differential-проверкам, timing-контролю и OOB-колбэкам. Ложные срабатывания отбрасываются.
5. **Reporting.** Результаты выводятся в консоль или сохраняются в JSON/text/HTML/CSV/SARIF. Discovery можно сохранить в checkpoint и продолжить позже.

`--backup` — отдельный режим разведки: он ищет по `backup_dorks` (или вашему запросу), открывает найденные каталоги/файлы, парсит `Index of`-листинги и показывает только файлы с размерами в КБ. Если листинг разобрать не удалось, выводится сообщение, что бекап-файлы не найдены.

## Команды

### Дорки и поиск

```powershell
sdork --dork
sdork --dork=backup_dorks
sdork --dork 'inurl:admin' --engine google,bing,yandex
sdork --dork 'inurl:login' --engine all --searx=https://searx.example.com
sdork --dork 'site:example.com inurl:api' --search-pages 2 --max-results 30
```

- `--dork` без значения — список категорий.
- `--dork=<category>` — показать дорки категории.
- `--dork='<query>'` или `--dork "<query>"` — выполнить поиск.
- `--engine major|all|duckduckgo,google,bing,...` — выбрать движки.
- `--searx <url>` — добавить SearXNG.
- `--dork-limit <n>` — ограничить число дорков в категории (0 = все).
- `--search-delay <ms>` — пауза между поисками (по умолчанию 2500).
- `--max-consecutive-errors <n>` — остановиться после N ошибок подряд (0 = без остановки).
- `--include-domain` / `--exclude-domain` — фильтры по домену (можно повторять).
- `--no-canonicalize`, `--no-sort-query` — управление нормализацией URL.

Доступные движки: `duckduckgo`, `google`, `bing`, `yandex`, `brave`, `startpage`, `mojeek`, `yahoo`, `ecosia`, `qwant`, `searx`, `marginalia`, `baidu`.

### Поиск бекап-файлов: `--backup`

```powershell
# Все дорки категории backup_dorks
sdork --backup

# С ограничением и конкретными движками
sdork --backup --dork-limit 5 --engine google,bing

# Свой запрос
sdork --backup='intitle:"index of" "database.sql" OR "db.sql" OR "users.sql"'

# Машиночитаемый вывод
sdork --backup --json --dork-limit 3
```

Формат текстового вывода:

```text
--- Backup Files: backup_dorks ---

https://example.com/backup/
├– database.sql, 12,5 КБ
├– users.sql, 1536 КБ
└– dump.zip, 0,3 КБ
```

Размер берётся из `Index of`-листинга, а для прямых ссылок — из `Content-Length` через `HEAD`. По умолчанию детально разбираются первые 20 объединённых результатов; `--max-results N` (N > 0) задаёт лимит и для поиска, и для разбора. В интерактивном терминале нажмите Enter во время поиска, чтобы остановить его и вывести уже найденные результаты. `--backup` не является проверкой уязвимости: это разведка. Скачивайте и используйте найденные данные только в рамках разрешённого теста.

### Типы проверок

| Флаг | Что проверяет |
| --- | --- |
| `--sqli` | SQL-инъекции: error-based, time-based, boolean |
| `--nosqli` | NoSQL-инъекции (MongoDB) |
| `--xss` | Reflected/DOM XSS |
| `--ssti` | Server-Side Template Injection |
| `--ssrf` | Server-Side Request Forgery |
| `--lfi` | Local File Inclusion |
| `--rfi` | Remote File Inclusion |
| `--xxe` | XML External Entity |
| `--cmdi` | Command Injection |
| `--idor` | Insecure Direct Object Reference |
| `--openredir` | Open Redirect (`--open_redirect` — алиас) |
| `--crlf` | CRLF/header injection |
| `--ldap` | LDAP Injection |
| `--xpath` | XPath Injection |
| `--code_injection` | Инъекции в eval/system-подобные sink-и |
| `--deserialization` | Небезопасная десериализация |
| `--file_upload` | Обход загрузки файлов |
| `--format_string` | Format String |
| `--header_injection` | Header/email header injection |
| `--host_header_injection` | Host Header Injection |
| `--info_disclosure` | Утечки, debug-вывод, каталоги, бекапы |
| `--jsonp_xss` | JSONP callback XSS |
| `--jwt` | Слабые JWT (kid injection, alg confusion) |
| `--logic_bypass` | Бизнес-логика и обход ограничений |
| `--session_fixation` | Session Fixation |
| `--all` | Все типы проверок и все связанные дорки |

Примеры:

```powershell
sdork --sqli -u "https://target.example/?id=1"
sdork --xss --sqli -u "https://target.example/search?q=FUZZ"
sdork --ssrf -u "https://target.example/fetch?url=FUZZ" --oob
sdork --lfi --dork-limit 5 --max-targets 10
sdork --info_disclosure --dork-limit 10 --crawl
sdork --all -u "https://target.example/?q=FUZZ" --min-confidence high
```

`FUZZ` можно использовать в URL/параметрах; без `-u` цели берутся из дорков.

### HTTP, авторизация и сессия

```powershell
sdork --sqli -u "https://target.example/api?id=1" `
  -X POST -d '{"id":1}' -H 'Content-Type: application/json'

sdork --idor -u "https://target.example/user/1" `
  --cookie "session=USER1" --cookie2 "session=USER2"

sdork --sqli -u "https://target.example/account" `
  --login-url "https://target.example/login" `
  --login-data "user=alice&pass=secret" `
  --mfa-secret "BASE32SECRET"
```

Основные флаги:

- `-u, --url` — цель; если не указана, цели берутся из дорков.
- `-X, --method`, `-d, --data`, `-H, --header` — метод, тело и заголовки.
- `--cookie`, `--cookie2` — cookies для сравнения идентичностей (IDOR).
- `--csrf` — получить и подставить `CSRF_TOKEN`.
- `--bearer`, `--basic-auth user:password` — авторизация.
- `--login-url`, `--login-data`, `--login-method` — форма логина.
- `--mfa-secret`, `--mfa-code`, `--mfa-url`, `--mfa-data`, `--mfa-field` — TOTP/второй шаг.
- `--param` — ограничить инъекцию конкретным параметром/cookie.
- `--delay <ms>`, `--timeout <seconds>` — пауза и таймаут запросов.
- `--proxy [socks5://][user:pass@]host:port` — upstream-прокси.
- `--insecure` — отключить проверку TLS (только в разрешённой лаборатории).
- `--http2` — использовать HTTP/2 для HTTPS, включая прокси с ALPN.

### Discovery, crawl и checkpoint

```powershell
sdork --xss --crawl --crawl-depth 2 --crawl-max-pages 50 --max-links 100
sdork --sqli --checkpoint discovery.json
sdork --sqli --resume discovery.json
```

- `--crawl` — обходить найденные страницы и собирать ссылки/формы.
- `--crawl-depth`, `--crawl-max-pages`, `--max-links` — ограничители обхода.
- `--checkpoint <file>` — сохранить результаты discovery.
- `--resume <file>` — продолжить с сохранённого checkpoint.
- `--max-targets`, `--dork-limit` — ограничить объём разведки.
- `--concurrency`, `--max-requests`, `--scan-timeout` — нагрузка и общий таймаут сканирования.

### Отчёты и вывод

```powershell
sdork --xss -u "https://target.example/?q=FUZZ" --summary --findings-table
sdork --xss -u "https://target.example/?q=FUZZ" --json
sdork --xss -u "https://target.example/?q=FUZZ" --out report.json
sdork --xss -u "https://target.example/?q=FUZZ" `
  --report-format html --report-file report.html
sdork --xss -u "https://target.example/?q=FUZZ" `
  --report-format sarif --report-file report.sarif
```

- `--json` — JSON в stdout.
- `--out <file>` — записать отчёт в файл.
- `--report-format text|json|html|csv|sarif` — формат отчёта.
- `--report-file <file>` — файл отчёта (если формат не задан, используется JSON).
- `--summary` — итоговая сводка.
- `--findings-table` — таблица findings.
- `--min-confidence low|medium|high` — порог уверенности.

### OpenAPI, GraphQL, WebSocket, extraction

```powershell
# OpenAPI/Swagger
sdork --openapi api.json --max-endpoints 20 -u https://target.example

# GraphQL introspection и проверка строковых аргументов
sdork --graphql -u https://target.example/graphql --max-fields 5

# WebSocket
sdork --ws -u wss://target.example/socket `
  --ws-send '{"ping":1}' --ws-wait 150 --ws-timeout 10000 `
  -H 'Origin: https://target.example'

# Blind extraction
sdork --extract -u "https://target.example/?id=FUZZ" `
  --extract-param id --extract-dbms mysql `
  --extract-query "SELECT password FROM users LIMIT 1"
```

Для `--extract` доступны шаблоны `mysql`, `postgres`, `mssql`, `sqlite`, `oracle`; можно задать свои `--extract-template`/`--extract-length-template` с `{{QUERY}}`, `{{POS}}`, `{{MID}}`.

### OOB, CAPTCHA, рендеринг, VPN

```powershell
# OOB-листенер
sdork --ssrf -u "https://target.example/fetch?url=FUZZ" --oob --oob-host 127.0.0.1

# CAPTCHA через сервис
sdork --xss -u "https://target.example/form" `
  --captcha-provider 2captcha --captcha-type recaptcha --captcha-sitekey SITEKEY

# JS-рендеринг
sdork --xss -u "https://target.example/app" --render-js --browser "C:\path\to\chrome.exe"

# VPN-профиль xray
sdork --vpn-list
sdork --backup --vpn=<profile> --dork-limit 3
```

- `--oob`, `--oob=<domain>`, `--oob-host`, `--oob-port`, `--smtp-port` — колбэки.
- `--captcha-token`, `--captcha-command`, `--captcha-provider`, `--captcha-api-key`, `--captcha-type`, `--captcha-sitekey`, `--captcha-poll`, `--captcha-timeout`.
- `--render-js` — рендеринг через Chrome/Edge или jsdom.
- `--render-unsafe` — разрешает `--no-sandbox` и выполнение скриптов в jsdom; используйте только в изолированной среде.
- `--random-agents` — ротация User-Agent/Accept-Language.
- `--tamper=space2comment/randomcase/...` — обфускация payload-ов.

`--captcha-command` получает URL страницы первым аргументом и HTML на stdin, а токен должен вывести в stdout.

## Переменные окружения

Официальные поисковые API (адаптеры включаются автоматически при наличии ключей):

- Google: `GOOGLE_API_KEY` или `GOOGLE_CSE_KEY`, плюс `GOOGLE_CSE_ID`.
- Bing: `BING_SEARCH_KEY` или `BING_API_KEY`.
- Brave: `BRAVE_SEARCH_KEY` или `BRAVE_API_KEY`.
- Yandex XML: `YANDEX_XML_USER` и `YANDEX_XML_KEY`.
- SerpAPI: `SERPAPI_KEY`.

CAPTCHA:

- `TWOCAPTCHA_API_KEY`
- `ANTICAPTCHA_API_KEY`
- `CAPMONSTER_API_KEY`
- `CAPTCHA_API_KEY` — общий fallback.

Прочее:

- `SDORK_XRAY` — путь к бинарнику xray.
- `SDORK_BROWSER` — путь к Chrome/Edge.
- `NO_COLOR` — отключить ANSI-цвета.

Ключи и токены не храните в репозитории и не передавайте в чужие отчёты.

## Формат вывода и коды завершения

- Обычный режим — человекочитаемый текст в stdout.
- `--json` — JSON в stdout.
- `--out`/`--report-file` — файл отчёта; формат задаётся `--report-format`.
- `--backup` — дерево вида `ссылка` → файлы с размерами в КБ.
- Код `0` — команда выполнена; код `1` — ошибка аргументов, нет целей или команда не распознана.

Логи/предупреждения могут идти в stderr, чтобы не ломать JSON в stdout.

## Структура проекта

```text
sdork/
├─ bin/
│  └─ sdork.js                 # entrypoint для команды sdork
├─ src/
│  ├─ cli.js                   # парсинг аргументов, команды, orchestration
│  ├─ banner.js                # ASCII-баннер и версия
│  └─ colors.js                # ANSI-цвета и TTY-детект
├─ tools/
│  ├─ dork.js                  # дорки, поисковые движки, парсинг выдачи
│  ├─ backup.js                # парсинг Index of и размеров бекап-файлов
│  ├─ discovery.js             # типы -> категории дорков, targets/forms, checkpoint
│  ├─ crawl.js                 # обход страниц, ссылки и формы
│  ├─ scanner.js               # построение точек, запуск payload-ов, findings
│  ├─ signatures.js            # загрузка/проверка сигнатур, сравнение ответов
│  ├─ dynamic.js               # динамические проверки/тайминг
│  ├─ rawhttp.js               # HTTP/1.1, HTTP/2, прокси, cookies, редиректы
│  ├─ auth.js                  # логин, cookies, TOTP/HOTP
│  ├─ extract.js               # boolean blind extraction
│  ├─ openapi.js               # OpenAPI/Swagger -> scan jobs
│  ├─ graphql.js               # introspection -> scan jobs
│  ├─ websocket.js             # raw WebSocket-клиент
│  ├─ oob.js                   # HTTP/SMTP OOB-листенер и токены
│  ├─ captcha.js               # 2captcha/anticaptcha/capmonster
│  ├─ proxy.js                 # xray-профили и прокси
│  ├─ socks5.js                # SOCKS5-клиент
│  ├─ render.js                # Chrome/Edge/jsdom-рендеринг
│  ├─ report.js                # text/JSON/HTML/CSV/SARIF и таблицы
│  ├─ progress.js              # прогресс discovery
│  ├─ loader.js                # загрузка JSON из проекта
│  ├─ encode.js                # кодирование payload-ов
│  ├─ tamper.js                # tamper-скрипты
│  └─ ua.js                    # пул User-Agent
├─ dorks/                      # 28 JSON-категорий поисковых дорков
├─ payloads/                   # payload-группы по типам проверок
├─ signatures/                 # сигнатуры, injection-точки, false-positive hints
├─ user-agents/
│  └─ ua.json                  # User-Agent pool
├─ test/
│  ├─ check.js                 # unit-проверки
│  └─ verify.js                # интеграционные проверки на локальном сервере
├─ .github/workflows/test.yml  # CI: Node 20/22, npm test
├─ VPN/                        # локальные xray-профили (секреты; .gitignore)
├─ tools/bin/                  # локальный xray и geo-данные (не в npm; .gitignore)
├─ package.json                # bin, scripts, files whitelist, engines >=20
├─ LICENSE                     # MIT
└─ README.md
```

`VPN/*.json` и `tools/bin/*` не должны попадать в git и npm-пакет. В `package.json` используется whitelist `files`, поэтому профили, бинарники и тесты не публикуются.

## Структура данных и расширение

### Дорки

Файл `dorks/<category>.json`:

```json
{
  "my_dorks": [
    "intitle:\"index of\" \"backup\"",
    "inurl:backup ext:sql"
  ]
}
```

`sdork --dork` покажет категорию и количество дорков. Чтобы привязать новую категорию к типу проверки, добавьте её в `TYPE_CATEGORIES` в `tools/discovery.js`.

### Сигнатуры

Файл `signatures/<type>.json` содержит `payload_ref`, точки инъекции, `match_policy`, сигналы и подсказки:

```json
{
  "my_type": {
    "payload_ref": "payloads/my_type.json",
    "injection": ["query", "body"],
    "match_policy": "any",
    "signals": [
      {
        "id": "my_signal",
        "source": "body",
        "match": "regex",
        "pattern": "(?i)error",
        "confidence": "high",
        "technique": "error_based",
        "note": "Error text disclosed"
      }
    ],
    "preconditions": [],
    "false_positive_hints": []
  }
}
```

Допустимые `source`: `body`, `headers`, `raw_response`, `cookie`, `status`, `time`, `length`, `oob`. Допустимые `match`: `regex`, `contains`, `equals`, `diff`, `in`, `delta`, `unchanged`, `hit`.

### Payload-ы

Файл `payloads/<type>.json` содержит группы payload-ов:

```json
{
  "my_type": [
    "PAYLOAD1",
    "PAYLOAD2"
  ]
}
```

Для сложных случаев используются именованные группы (`groups`), как в `payloads/jwt.json`.

### User-Agent

`user-agents/ua.json`:

```json
{
  "user_agents": [
    "Mozilla/5.0 ..."
  ]
}
```

После изменений в dorks/payloads/signatures запускайте `npm test`: проверяются JSON, ссылки `payload_ref`, regex-и и структура сигнатур.

## Тесты и CI

```powershell
npm test       # unit + integration
npm run check  # только unit
npm run verify # только интеграционные
```

- `test/check.js` проверяет парсинг, сигнатуры, discovery, отчёты, HTTP-клиент, auth, backup-парсер и другие модули.
- `test/verify.js` поднимает локальный HTTP-сервер и прогоняет сценарии сканирования, discovery, OOB и т.п.
- Живые поисковые системы, VPN и платные API в тестах не используются.
- CI: GitHub Actions, Node.js 20 и 22.

## Troubleshooting

**`sdork` не найден.** Выполните `npm link` в папке проекта или запускайте `node bin/sdork.js ...`.

**Поисковики отдают 202/429 или CAPTCHA.** Увеличьте `--search-delay`, уменьшите `--dork-limit`, смените `--engine`, используйте `--proxy`/`--searx` или официальный API-ключ. `--max-consecutive-errors` помогает остановить серию ошибок.

**Нет целей.** Проверьте `--dork-limit`, `--max-targets`, фильтры `--include-domain`/`--exclude-domain`, доступность движков и синтаксис запроса. Для Windows заключайте дорк с двойными кавычками в одинарные кавычки.

**Не работает VPN.** Проверьте `sdork --vpn-list`, наличие xray в `tools/bin`, `PATH` или `SDORK_XRAY`, а также имя профиля.

**Не работает JS-рендеринг.** Укажите `--browser` или установите `jsdom`; для выполнения скриптов нужен `--render-unsafe`, для Chrome без sandbox — только в изолированной среде.

**TLS-ошибка.** Только в разрешённой лаборатории используйте `--insecure`; в продакшене лучше настроить корректные сертификаты/прокси.

**OOB не получает колбэки.** Проверьте `--oob-host`, `--oob-port`, firewall/NAT и доступность слушателя с целевой стороны.

**Отчёт содержит чувствительные данные.** Храните отчёты и checkpoint-файлы безопасно; не публикуйте токены, cookies, дампы и персональные данные.

## Ограничения и безопасность

- Результаты дорков зависят от HTML поисковиков и могут требовать `--proxy`, `--searx` или `--insecure` в ограниченных сетях.
- JS-рендеринг требует Chrome/Edge или `jsdom`; они не входят в пакет. Chrome по умолчанию работает с sandbox, jsdom — без выполнения скриптов, если не указан `--render-unsafe`.
- Официальные поисковые API требуют ключей и подчиняются квотам провайдеров; в offline-тестах не используются.
- CAPTCHA-решение требует ключа, готового токена или внешнего `--captcha-command`; учитывайте ToS цели и сервиса.
- WebSocket-клиент сырой: поддержка кастомных заголовков, cookies, TLS и прокси есть, permessage-deflate — нет.
- Blind extraction — boolean-based и зависит от шаблона/контекста; встроенные шаблоны не перечисляют схемы и таблицы автоматически.
- MFA покрывает form login + TOTP (HOTP доступен как helper); OAuth, SAML и WebAuthn не автоматизированы.
- OOB-листенер по умолчанию слушает `0.0.0.0`; для локальных проверок ограничьте его `--oob-host 127.0.0.1`.
- `--render-unsafe`, `--insecure` и CAPTCHA-обход повышают риск; применяйте только в контролируемой среде и в рамках scope.
- Соблюдайте rate limits и не создавайте нагрузку, которая может нарушить работу цели.

## Лицензия

MIT. См. `LICENSE`.
