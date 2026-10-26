# conol-autoreg-2api

Авторегистрация аккаунтов [conol.ai](https://conol.ai) и OpenAI-совместимый шлюз
к пулу аккаунтов. Один репозиторий: реггер + панель + шлюз.

## Что внутри

| Компонент | Что делает |
|---|---|
| `conol_register.py` / `main.py` | регистрация аккаунтов: форма, капча, подтверждение почты, API-ключ |
| `conol_captcha.py` | reCAPTCHA v3: бесплатно через headful Chrome (CDP) или платный AntiCaptcha как фолбэк |
| `conol_emails.py` | почта: плюс-алиасы Gmail (IMAP), catch-all через admin API, t-online |
| `conol_proxy.py` / `conol_brd_relay.py` | прокси: разбор, проверка exit-IP, ротация, релей авторизации для Chrome |
| `panel/server.py` | локальная панель на `127.0.0.1:9903`: аккаунты, ключи, прокси, модели, капча, логи |
| `upstream/conol_gateway.py` | шлюз на `127.0.0.1:9999`: OpenAI-совместимые `/v1/models` и `/v1/chat/completions` |
| `reverse_bridge/` | мост к удалённому агенту (CF-tunnel), опционально |
| `tests/` | офлайн-проверки: пул, прокси, pid-слот, tool-use шлюза |

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

Регистрация пишет аккаунты в `data/conol_accounts_pool.jsonl`. Шлюз читает тот же файл:

```bash
cd upstream
ENI_POOL_KEY=change-me python3 conol_gateway.py
# 127.0.0.1:9999, Authorization: Bearer change-me
curl -s http://127.0.0.1:9999/v1/models -H "Authorization: Bearer change-me"
```

Шлюз отдаёт 18 моделей (`gpt-5.6-luna`, `claude-haiku-4-5`, `deepseek-v4-pro`,
`glm-5.3`, `kimi-k2.7-code`, `grok-4.3`, `qwen3.7-*` и другие) и сам переключается
на следующий аккаунт при 401/403.

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
- **Лимит на регистрации с одного IP.** Примерно 2 аккаунта за окно, дальше
  `429 RATE_LIMITED`. Для серии нужны прокси (`data/proxies.txt`).
- **Ответы шлюза медленные** — 40–150 секунд на запрос, это особенность conol.
- Шлюз слушает только `127.0.0.1` и требует `ENI_POOL_KEY`: без него не стартует.

## Безопасность

`config.json`, `data/`, cookies, пул аккаунтов и `proxies.txt` — в `.gitignore`.
В репозитории только `config.example.json` с плейсхолдерами. Не коммить реальные
пароли, app-password, ключи AntiCaptcha и сессии.
