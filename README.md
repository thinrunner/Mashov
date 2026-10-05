# Mashov Hub

Семейная надстройка над משו"ב: двое детей в двух школах, одна быстрая сводка, уведомления в Telegram и простой веб-интерфейс со своей структурой. Только для семьи, запускается локально на Mac.

- Полная спецификация: [docs/SPEC.md](docs/SPEC.md). Строим её урезанную версию (MVP): Python-сервис + SQLite + Telegram-бот + простой веб-интерфейс. Без Docker, Tailscale и passkey на старте.
- Что известно про API: [docs/api-findings.md](docs/api-findings.md).

**Сейчас: Phase 0.** Проверяем на реальных аккаунтах, можно ли работать в SMS-режиме без постоянного участия человека.

## Phase 0 на Mac

Скрипт работает только локально: пароли и данные детей никуда, кроме web.mashov.info, не уходят. Сессии хранятся в Keychain, сырые ответы — в `~/MashovHub/spike` (вне репозитория).

```bash
brew install uv                      # один раз
git clone https://github.com/thinrunner/Mashov.git && cd Mashov

# 0. Узнать semel школы
uv run spike/phase0.py schools --search "название или город"

# Повторить шаги 1–4 для каждой школы (--account school-a / school-b)

# 1a. Вход по SMS, код вводится в скрипт. Это проверка, сможет ли бот принимать /code
uv run spike/phase0.py login --account school-a --method sms --semel 123456 --username <ת"ז>
# 1b. Если 1a не сработал: вход в окне браузера; скрипт перехватит сессию.
#     Отметьте «מכשיר פרטי»!
uv run --with playwright spike/phase0.py login --account school-a --method browser

# 2. Выгрузить все разделы и собрать отчёт
uv run spike/phase0.py dump --account school-a

# 3. Главный тест: вход без SMS по devicePass
uv run spike/phase0.py relogin-device --account school-a

# 4. Время жизни сессии: оставить на ночь, Mac не должен спать
caffeinate -i uv run spike/phase0.py probe --account school-a --hours 24 --relogin
```

Результат: `~/MashovHub/spike/findings-<account>.md` (только структура, статусы и замаскированные примеры) и `probe-<account>.log`. Просмотрите отчёт глазами и пришлите оба файла, чтобы заполнить [docs/api-findings.md](docs/api-findings.md) и решить go/no-go.

Важно: SMS приходит на номер, привязанный к аккаунту в Машове. Если в одной из школ это телефон жены, при SMS-входе код нужен с её телефона.
