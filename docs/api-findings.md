# API Машов: что известно до Phase 0

Источники (05.10.2026): JS-бандл `web.mashov.info/students` (Angular; конфиг `MashovApiVersion: 3.20210425`), интеграция [NirBY/ha-mashov](https://github.com/NirBY/ha-mashov), npm `mashov-api`. Реальные ответы для наших аккаунтов появятся после запуска `spike/phase0.py`: их дописываем в раздел «Результаты Phase 0».

## Аутентификация

**Вход:** `POST /api/login`

```json
{"semel": 123456, "year": 2027, "username": "...", "password": "...",
 "isPrivateDevice": true, "IsBiometric": false,
 "appName": "info.mashov.students", "apiVersion": "3.20210425", "appVersion": "...", "appBuild": "...",
 "deviceUuid": "chrome", "devicePlatform": "chrome", "deviceManufacturer": "...", "deviceModel": "desktop", "deviceVersion": "..."}
```

- Ответ: тело `{credential, accessToken}`, где `accessToken.children[]` — дети аккаунта, а `childGuid` — ID во всех URL вида `students/{guid}/…`.
- Заголовки ответа: `X-Csrf-Token` (дальше отправляется в каждом запросе), cookies сессии и **`devicePass`**, если отмечено «מכשיר פרטי».
- Ошибки: `401` — неверные данные; `403` с заголовком `Reason`, где `UserSuspended` означает, что дальше нужна капча, а `changepass` — что нужно сменить пароль; `400` — неверные поля.
- `year` — год окончания учебного года: 2026/27 = `2027`, переход 1 сентября.

**SMS (OTP):**
1. `POST /api/user/otp/request` `{cellphone, email, semel, username, captcha}`. Поле `captcha` — токен **Cloudflare Turnstile** (sitekey `0x4AAAAAACI5UnCCPR536XNv`). Получить его без человека и браузера нельзя, и обходить капчу мы не будем.
2. Код из SMS отправляется как `password` в обычный `POST /api/login`.

**Вход по devicePass (без пароля и SMS):**
- Веб-клиент сохраняет заголовок `devicePass` из ответа на вход и прикладывает его к каждому следующему вызову входа.
- Есть `POST /api/loginDevice` с пустым телом (только поля приложения) и заголовком `devicePass`. В веб-интерфейсе эта кнопка показывается только в нативном приложении. Работает ли эндпоинт для веб-клиента — **главная гипотеза Phase 0**.

**Прочее:**
- `POST /api/user/password` — смена пароля из залогиненной сессии. Это возможный путь «SMS один раз → дальше пароль», если школа разрешает.
- `changeSchool/{semel}/{year}` и `GET /api/user/bindings` — возможно, обе школы доступны из одного логина. Проверить.

## Эндпоинты для чтения

После входа нужны cookies и заголовок `X-Csrf-Token`. Датированные запросы принимают `?start=YYYY-MM-DD&end=YYYY-MM-DD`.

| Данные | Путь | Примечание |
|---|---|---|
| Оценки | `students/{guid}/grades` | |
| Поведение / посещаемость | `students/{guid}/behave` | датированный; поля `achvaCode`, `achvaName`, `justified`, `lessonDate`, `subject` |
| Домашка | `students/{guid}/homework` | |
| Расписание | `students/{guid}/timetable` | `[{timeTable, groupDetails}]` |
| Недельный план | `students/{guid}/lessons/plans` | ключи в нижнем регистре: `groupid`, `lessondate` |
| История уроков | `students/{guid}/lessons/history` | датированный; `lessonLog.tookPlace`, `homeWork`, `remark` |
| Доска объявлений | `students/{guid}/messageBoard` | |
| Ежедневное / внеурочное поведение | `students/{guid}/dailyBehave`, `outBehave` | датированные |
| Наблюдения (מעקב) | `students/{guid}/maakav` | датированный |
| Табели | `students/{guid}/reportCards`, `gradingPeriods` | |
| Почта | `mail/inbox/conversations?skip&take`, `mail/conversations/{id}`, `mail/counts` | |
| Уведомления Машов | `user/notifications?skip&take` | |
| Праздники, звонки | `holidays`, `bells` | на уровне школы |

Отдельного эндпоинта «изменения расписания» не нашли. Возможно, они видны через `lessons/history` (`tookPlace`) или `lessons/plans`. Проверить на реальных данных.

## Чем это грозит продукту

1. **Telegram-команда `/code` из спецификации не может сама запросить SMS**, потому что запрос защищён капчей. Схема может быть только такой: человек запрашивает код на сайте Машов, затем отправляет его боту. Сработает это, только если пройдёт тест `login --method sms`.
2. **Если `devicePass` работает**, SMS нужна один раз на устройство, дальше всё автоматически. Это лучший сценарий.
3. **Если не работают ни `devicePass`, ни смена на пароль**, человек нужен при каждом истечении сессии. Тогда решающим становится время жизни сессии (`probe`), и режим работы надо согласовать заново.

## Результаты Phase 0

Заполнить по `findings-<account>.md` для каждой школы.

| Вопрос | Школа A | Школа B |
|---|---|---|
| Вход `--method sms` (код введён в скрипт, не в браузер) | | |
| Вход `--method browser` | | |
| `devicePass` выдан | | |
| `relogin-device` работает | | |
| Время жизни сессии при опросе раз в 15 мин | | |
| Обе школы под одним логином (`user/bindings`) | | |
| Модули, недоступные родителю (403/404) | | |
| Где видны изменения расписания | | |
