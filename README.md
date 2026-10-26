# conol-autoreg

Авторегистрация аккаунтов [conol.ai](https://conol.ai) и локальная панель управления
пулом. Рабочая часть — регистратор и панель. OpenAI-шлюз (2api) экспериментальный
и в текущем виде не работает; MCP не проверен.

## Статус

| Часть | Статус |
|---|---|
| Авторег | работает: 3 регистрации подряд без прокси, по `600` кредитов на аккаунт |
| Панель `127.0.0.1:9903` | работает: аккаунты, ключи, прокси, модели, логи |
| Шлюз `/v1` (2api) | не работает — не рассчитывай на него |
| MCP | не проверен, считать сомнительным |

## Что внутри

| Компонент | Что делает |
|---|---|
| `conol_register.py` / `main.py` | регистрация аккаунтов: форма, капча, подтверждение почты, API-ключ |
| `conol_captcha.py` | reCAPTCHA v3: бесплатно через headful Chrome (CDP) или платный AntiCaptcha как фолбэк |
| `conol_emails.py` | почта: плюс-алиасы Gmail (IMAP), catch-all через admin API, t-online |
| `conol_proxy.py` / `conol_brd_relay.py` | прокси: разбор, проверка exit-IP, ротация, релей авторизации для Chrome |
| `panel/server.py` | локальная панель на `127.0.0.1:9903`: аккаунты, ключи, прокси, модели, капча, логи |
| `upstream/conol_gateway.py` | экспериментальный шлюз на `127.0.0.1:9999`; в текущем виде не работает |
| `reverse_bridge/` | мост к удалённому агенту (CF-tunnel), опционально |
| `tests/` | офлайн-проверки: пул, прокси, pid-слот |

## Требования

- Python 3.10+
- `pip install -r requirements.txt`
- Chromium для Playwright: `python3 -m playwright install chromium`
- Linux: `gamescope` и `xdpyinfo` для невидимого headful-дисплея (бесплатная капча
  не работает в headless — conol отдаёт 403)
- Один Gmail-ящик с app-password **или** свой catch-all домен с admin API

## Быстрый старт

```bash
cp config.example.json config.json
# заполни config.json:
#   conol.password        — пароль для аккаунтов conol
#   gmail.*               — ящик и app-password для приёма писем
#   captcha.*             — ключи AntiCaptcha, если не используешь бесплатный chrome_cdp

python3 main.py --count 1 --provider gmail --free-captcha
python3 main.py check          # перепроверить пул: сессия + баланс
bash start.sh --no-browser     # панель на 127.0.0.1:9903
```

Регистрация пишет аккаунты в `data/conol_accounts_pool.jsonl`. Запускать лучше на
своей виртуальной машине: панель и Chrome работают локально.

## Почта

Провайдер выбирается в `config.json → emails`. Включён может быть один или несколько:

- **gmail** — плюс-алиасы одного ящика (`you+conol<tag>@gmail.com`), чтение по IMAP.
  Нужен app-password: Google Account → Security → 2-Step Verification → App passwords.
- **catchall** — свой домен с admin API формата `GET /admin/mails?address=...`,
  заголовок `x-admin-auth`. Ящики создавать не нужно.
- **tonline** — список готовых ящиков в файле (`creds_file`).

По умолчанию адрес собирается как `<email_prefix><suffix>@<email_domain>`.
Для Gmail удобно `"email_prefix": "yourname+conol"`, `"email_domain": "gmail.com"`.

## Ограничения

- **Бесплатная капча — только headful Chrome.** В `--headless` conol отвечает 403.
  `start.sh` поднимает невидимый `gamescope`-дисплей; на Windows/macOS проще
  использовать AntiCaptcha (`captcha.providers: ["anticaptcha"]`).
- **Прокси не обязательны.** Регистрация идёт напрямую; три подряд прошли без
  прокси. На большую серию conol может ответить `429` — тогда нужны прокси
  (`data/proxies.txt`).
- **Шлюз не работает.** Код лежит в `upstream/`, но использовать его как
  OpenAI-совместимый API нельзя. MCP не проверен.

## Безопасность

`config.json`, `data/`, cookies, пул аккаунтов и `proxies.txt` — в `.gitignore`.
В репозитории только `config.example.json` с плейсхолдерами. Не коммить реальные
пароли, app-password, ключи AntiCaptcha и сессии.
