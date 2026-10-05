# /// script
# requires-python = ">=3.11"
# dependencies = ["httpx>=0.27", "keyring>=25"]
# ///
"""Mashov Hub — Phase 0 spike.

Checks on real accounts what the product depends on: how login works (SMS / password /
"private device" re-login), which endpoints answer for a parent account, response shapes,
and how long a session lives. Runs locally only; nothing leaves the machine except
requests to web.mashov.info.

Secrets (cookies, CSRF token, devicePass) go to the OS keychain. Raw responses contain
children's personal data and stay in --data-dir (default ~/MashovHub/spike), outside the repo.
Only findings-<account>.md (keys, types, statuses, masked examples) is meant to be shared.
"""

from __future__ import annotations

import argparse
import datetime as dt
import getpass
import json
import os
import random
import re
import sys
import time
from pathlib import Path
from typing import Any

import httpx

API = "https://web.mashov.info/api/"
LOGIN_PAGE = "https://web.mashov.info/students/login"
KEYRING_SERVICE = "mashov-hub-spike"
DEFAULT_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
)
# Values the web client sends in every login call (see docs/api-findings.md).
APP_INFO = {
    "appName": "info.mashov.students",
    "apiVersion": "3.20210425",
    "appVersion": "3.20210425",
    "appBuild": "3.20210425",
    "deviceUuid": "chrome",
    "devicePlatform": "chrome",
    "deviceManufacturer": "mac",
    "deviceModel": "desktop",
    "deviceVersion": "130.0.0.0",
}
PAUSE = (1.5, 3.0)  # seconds between requests: sequential and polite


# ---------------------------------------------------------------- utils

def die(msg: str) -> None:
    print(f"\n✖ {msg}", file=sys.stderr)
    sys.exit(1)


def now() -> dt.datetime:
    return dt.datetime.now().astimezone()


def school_year(today: dt.date | None = None) -> int:
    """Mashov names the school year after the calendar year it ends in (rolls over Sep 1)."""
    d = today or dt.date.today()
    return d.year + 1 if d.month >= 9 else d.year


def data_dir(args) -> Path:
    p = Path(args.data_dir).expanduser()
    p.mkdir(parents=True, exist_ok=True)
    os.chmod(p, 0o700)
    return p


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2))
    os.chmod(path, 0o600)


def polite_pause() -> None:
    time.sleep(random.uniform(*PAUSE))


# ---------------------------------------------------------------- session storage

def _keyring():
    try:
        import keyring
        from keyring.errors import NoKeyringError

        keyring.get_password(KEYRING_SERVICE, "__probe__")
        return keyring
    except (ImportError, NoKeyringError, RuntimeError):
        return None


def save_session(args, sess: dict) -> None:
    kr = _keyring()
    blob = json.dumps(sess, ensure_ascii=False)
    if kr:
        kr.set_password(KEYRING_SERVICE, args.account, blob)
        print(f"  сессия сохранена в Keychain (service={KEYRING_SERVICE}, account={args.account})")
    else:
        path = data_dir(args) / "sessions" / f"{args.account}.json"
        write_json(path, sess)
        print(f"  ⚠ Keychain недоступен — сессия сохранена в файл {path} (chmod 600)")


def load_session(args) -> dict:
    kr = _keyring()
    blob = kr.get_password(KEYRING_SERVICE, args.account) if kr else None
    if not blob:
        path = data_dir(args) / "sessions" / f"{args.account}.json"
        blob = path.read_text() if path.exists() else None
    if not blob:
        die(f"Нет сохранённой сессии для '{args.account}'. Сначала: login --account {args.account}")
    return json.loads(blob)


# ---------------------------------------------------------------- http

def make_client(sess: dict | None = None) -> httpx.Client:
    c = httpx.Client(
        base_url=API,
        timeout=30,
        headers={
            "User-Agent": (sess or {}).get("user_agent") or DEFAULT_UA,
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "he-IL,he;q=0.9,en;q=0.8",
            "Origin": "https://web.mashov.info",
            "Referer": LOGIN_PAGE,
        },
    )
    if sess:
        for ck in sess.get("cookies", []):
            c.cookies.set(ck["name"], ck["value"], domain=ck.get("domain") or "web.mashov.info",
                          path=ck.get("path") or "/")
        if sess.get("csrf"):
            c.headers["X-Csrf-Token"] = sess["csrf"]
    return c


def describe_error(r: httpx.Response) -> str:
    reason = r.headers.get("reason") or ""
    body = r.text[:300].replace("\n", " ")
    return f"HTTP {r.status_code}" + (f", reason={reason}" if reason else "") + (f", body={body!r}" if body else "")


def session_from_login(r: httpx.Response, client: httpx.Client, method: str, prev: dict | None = None) -> dict:
    body = r.json()
    cred = body.get("credential") or {}
    token = body.get("accessToken") or {}
    children = token.get("children") or []
    prev = prev or {}
    return {
        "method": method,
        "login_time": now().isoformat(),
        "semel": cred.get("semel") or prev.get("semel"),
        "year": cred.get("year") or prev.get("year"),
        "username": prev.get("username") or token.get("username") or cred.get("username"),
        "csrf": r.headers.get("x-csrf-token"),
        # The web client stores this header and sends it back on every login call.
        "device_pass": r.headers.get("devicepass") or prev.get("device_pass"),
        "device_pass_rotated": bool(r.headers.get("devicepass")),
        "cookies": [{"name": c.name, "value": c.value, "domain": c.domain, "path": c.path}
                    for c in client.cookies.jar],
        "user_agent": client.headers.get("User-Agent"),
        "children": [{"guid": ch.get("childGuid"), "label": f"c{i + 1}"} for i, ch in enumerate(children)],
        "_login_body": body,  # stripped before saving to keychain, kept in raw dir
    }


def finish_login(args, sess: dict) -> None:
    body = sess.pop("_login_body", None)
    ts = now().strftime("%Y%m%d-%H%M%S")
    if body is not None:
        write_json(data_dir(args) / "raw" / args.account / f"login-{ts}.json", body)
    save_session(args, sess)
    print(f"\n✔ Вход выполнен ({sess['method']}). Детей в аккаунте: {len(sess['children'])}")
    print(f"  CSRF-токен: {'есть' if sess.get('csrf') else 'НЕТ'};  cookies: {len(sess['cookies'])}")
    if sess.get("device_pass"):
        print("  devicePass: ПОЛУЧЕН — можно проверять вход без SMS (команда relogin-device)")
    else:
        print("  devicePass: не получен (галочка «מכשיר פרטי» не стояла или сервер его не выдаёт)")


# ---------------------------------------------------------------- commands: schools / login

def cmd_schools(args) -> None:
    with make_client() as c:
        r = c.get("schools")
        r.raise_for_status()
        schools = r.json()
    q = args.search.strip()
    hits = [s for s in schools if q in str(s.get("semel")) or q.lower() in (s.get("name") or "").lower()]
    for s in hits[:30]:
        print(f"{s.get('semel'):>8}  {s.get('name')}  (годы: {', '.join(map(str, (s.get('years') or [])[-3:]))})")
    print(f"\nНайдено: {len(hits)}" + (" (показаны первые 30)" if len(hits) > 30 else ""))


def login_payload(semel: int, year: int, username: str, secret: str) -> dict:
    return {**APP_INFO, "semel": semel, "year": year, "username": username, "password": secret,
            "IsBiometric": False, "isPrivateDevice": True}


def cmd_login(args) -> None:
    if args.method == "browser":
        return login_browser(args)
    semel = args.semel or int(input("semel школы (найти: команда schools): ").strip())
    username = args.username or input("Имя пользователя Машов (обычно ת\"ז родителя): ").strip()
    year = args.year or school_year()
    if args.method == "sms":
        print(f"""
SMS-код запрашивается только через сайт: Машов защищает запрос капчей Cloudflare.
  1. Откройте {LOGIN_PAGE} в обычном браузере.
  2. Школа {semel}, пользователь {username}, способ входа — SMS (טלפון נייד), номер телефона.
  3. Пройдите капчу и нажмите «отправить код».
  4. НЕ вводите код на сайте. Введите его здесь.
""")
        secret = getpass.getpass("Код из SMS: ").strip()
    else:
        secret = getpass.getpass("Пароль Машов: ")
    with make_client() as c:
        r = c.post("login", json=login_payload(semel, year, username, secret),
                   headers={"Content-Type": "application/json;charset=UTF-8"})
        if r.status_code != 200:
            hint = ""
            if args.method == "sms":
                hint = ("\nВозможно, код привязан к сессии браузера. Тогда используйте --method browser "
                        "(это тоже результат Phase 0 — запишите его).")
            die(f"Вход не удался: {describe_error(r)}{hint}")
        sess = session_from_login(r, c, args.method, {"semel": semel, "year": year, "username": username})
    finish_login(args, sess)


def login_browser(args) -> None:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        die("Нужен Playwright: uv run --with playwright spike/phase0.py login --method browser ...")
    profile = data_dir(args) / "browser-profile"
    print(f"""
Откроется окно браузера со страницей входа Машов. Войдите как обычно (SMS или пароль)
и ОБЯЗАТЕЛЬНО отметьте «מכשיר פרטי» (личное устройство). Скрипт перехватит ответ на вход
и закроет окно. Ожидание до 10 минут.
""")

    def is_login(resp) -> bool:
        path = httpx.URL(resp.url).path.rstrip("/")
        return resp.request.method == "POST" and path in ("/api/login", "/api/loginDevice") and resp.status == 200

    with sync_playwright() as p:
        kwargs = dict(user_data_dir=str(profile), headless=False,
                      args=["--disable-blink-features=AutomationControlled"],
                      ignore_default_args=["--enable-automation"])
        try:
            ctx = p.chromium.launch_persistent_context(channel="chrome", **kwargs)  # installed Google Chrome
        except Exception:
            try:
                ctx = p.chromium.launch_persistent_context(**kwargs)
            except Exception:
                die("Не найден ни Google Chrome, ни Chromium Playwright. "
                    "Установите: uv run --with playwright playwright install chromium")
        page = ctx.pages[0] if ctx.pages else ctx.new_page()
        with page.expect_response(is_login, timeout=600_000) as info:
            page.goto(LOGIN_PAGE)
        resp = info.value
        body = resp.json()
        headers = resp.all_headers()
        ua = page.evaluate("navigator.userAgent")
        cookies = ctx.cookies("https://web.mashov.info")
        ctx.close()

    cred = body.get("credential") or {}
    children = (body.get("accessToken") or {}).get("children") or []
    sess = {
        "method": "browser",
        "login_time": now().isoformat(),
        "semel": cred.get("semel"),
        "year": cred.get("year"),
        "username": (body.get("accessToken") or {}).get("username") or cred.get("username"),
        "csrf": headers.get("x-csrf-token"),
        "device_pass": headers.get("devicepass"),
        "device_pass_rotated": bool(headers.get("devicepass")),
        "cookies": [{"name": c["name"], "value": c["value"], "domain": c["domain"], "path": c["path"]}
                    for c in cookies],
        "user_agent": ua,
        "children": [{"guid": ch.get("childGuid"), "label": f"c{i + 1}"} for i, ch in enumerate(children)],
        "_login_body": body,
    }
    finish_login(args, sess)


def cmd_relogin_device(args) -> None:
    """Key automation test: can we get a fresh session with only the stored devicePass?"""
    old = load_session(args)
    if not old.get("device_pass"):
        die("В сессии нет devicePass. Войдите заново с галочкой «מכשיר פרטי».")
    ok = relogin_with_device_pass(args, old, verbose=True)
    if not ok:
        die("Вход по devicePass не сработал → без SMS/пароля автоматический перелогин невозможен.")


def relogin_with_device_pass(args, old: dict, verbose: bool = False) -> bool:
    # Only loginDevice: a password-less POST /login would count as a failed attempt, and
    # repeated failures make Mashov demand a captcha (UserSuspended).
    with make_client() as c:  # fresh client: no old cookies, only devicePass
        c.headers["User-Agent"] = old.get("user_agent") or DEFAULT_UA
        r = c.post("loginDevice", json=dict(APP_INFO),
                   headers={"Content-Type": "application/json;charset=UTF-8", "devicePass": old["device_pass"]})
        if verbose:
            print(f"  POST loginDevice с devicePass → {describe_error(r) if r.status_code != 200 else 'HTTP 200'}")
        if r.status_code != 200:
            return False
        finish_login(args, session_from_login(r, c, "devicePass", old))
        return True


# ---------------------------------------------------------------- dump

def date_range(year: int) -> dict:
    start = dt.date(year - 1, 9, 1)
    end = dt.date.today() + dt.timedelta(days=30)
    return {"start": start.isoformat(), "end": end.isoformat()}


ACCOUNT_ENDPOINTS = [
    ("user_bindings", "user/bindings", None),
    ("user_notifications", "user/notifications", {"skip": 0, "take": 50}),
    ("mail_inbox", "mail/inbox/conversations", {"skip": 0, "take": 30}),
    ("mail_counts", "mail/counts", None),
    ("holidays", "holidays", None),
    ("bells", "bells", None),
]
# (name, path under students/{guid}/, dated)
STUDENT_ENDPOINTS = [
    ("grades", "grades", False),
    ("behave", "behave", True),
    ("homework", "homework", False),
    ("timetable", "timetable", False),
    ("lessons_plans", "lessons/plans", False),
    ("lessons_history", "lessons/history", True),
    ("message_board", "messageBoard", False),
    ("daily_behave", "dailyBehave", True),
    ("out_behave", "outBehave", True),
    ("maakav", "maakav", True),
    ("count_behave", "countBehave", False),
    ("lessons_count", "lessonsCount", False),
    ("grading_periods", "gradingPeriods", False),
    ("report_cards", "reportCards", False),
    ("justification_requests", "justificationrequests", True),
    ("study_files", "studyFiles", False),
    ("files", "files", False),
    ("details", "details", False),
]


class SessionExpired(Exception):
    pass


def fetch(c: httpx.Client, path: str, params: dict | None) -> tuple[httpx.Response, float]:
    t0 = time.monotonic()
    r = c.get(path, params=params)
    ms = (time.monotonic() - t0) * 1000
    if r.status_code == 401:
        raise SessionExpired(path)
    return r, ms


def cmd_dump(args) -> None:
    sess = load_session(args)
    if not sess.get("children"):
        die("В сессии нет детей — проверьте raw/<account>/login-*.json")
    ts = now().strftime("%Y%m%d-%H%M%S")
    base = data_dir(args)
    raw_dir = base / "raw" / args.account / ts
    masked_dir = base / "masked" / args.account / ts
    rng = date_range(int(sess.get("year") or school_year()))
    masker = Masker()
    results: list[dict] = []

    jobs = [(name, path, params, None) for name, path, params in ACCOUNT_ENDPOINTS]
    for ch in sess["children"]:
        for name, sub, dated in STUDENT_ENDPOINTS:
            jobs.append((name, f"students/{ch['guid']}/{sub}", rng if dated else None, ch["label"]))

    print(f"Выгрузка {len(jobs)} запросов, последовательно, с паузами…")
    with make_client(sess) as c:
        try:
            for i, (name, path, params, child) in enumerate(jobs):
                if i:
                    polite_pause()
                r, ms = fetch(c, path, params)
                key = f"{child}/{name}" if child else name
                row = {"key": key, "path": re.sub(r"students/[^/]+", "students/{guid}", path),
                       "params": ",".join(params) if params else "", "status": r.status_code,
                       "reason": r.headers.get("reason") or "", "ms": round(ms), "bytes": len(r.content)}
                data = None
                if r.status_code == 200 and r.content:
                    try:
                        data = r.json()
                    except ValueError:
                        row["status"] = "200 (не JSON)"
                if data is not None:
                    write_json(raw_dir / f"{key.replace('/', '__')}.json", data)
                    masked = masker.mask(data)
                    write_json(masked_dir / f"{key.replace('/', '__')}.json", masked)
                    row["shape"] = shape_summary(data)
                    row["schema"] = schema(data)
                    row["example"] = first_item(masked)
                results.append(row)
                print(f"  {key:<32} {row['status']!s:<14} {row['ms']:>5} ms  {row.get('shape', '')}")
        except SessionExpired as e:
            print(f"\n⚠ Сессия истекла (401) на {e}. Сохраняю то, что успели получить.")
            if sess.get("device_pass"):
                print("  Попробуйте: relogin-device --account", args.account)

    login_files = sorted((base / "raw" / args.account).glob("login-*.json"))
    login_body = json.loads(login_files[-1].read_text()) if login_files else {}
    out = base / f"findings-{args.account}.md"
    out.write_text(render_findings(args.account, sess, login_body, results, rng, masker))
    os.chmod(out, 0o600)
    print(f"\n✔ Сырые ответы: {raw_dir}\n✔ Замаскированные: {masked_dir}\n✔ Отчёт: {out}")
    print("  Перед отправкой отчёта просмотрите его глазами — маскирование автоматическое.")


# ---------------------------------------------------------------- probe

def cmd_probe(args) -> None:
    sess = load_session(args)
    if not sess.get("children"):
        die("В сессии нет детей.")
    log_path = data_dir(args) / f"probe-{args.account}.log"
    interval = args.interval * 60
    deadline = time.time() + args.hours * 3600
    login_time = dt.datetime.fromisoformat(sess["login_time"])
    last_tick = time.time()

    def log(line: str) -> None:
        stamped = f"{now().isoformat(timespec='seconds')}  {line}"
        print(stamped)
        with log_path.open("a") as f:
            f.write(stamped + "\n")

    log(f"probe start: account={args.account} method={sess['method']} login_time={sess['login_time']} "
        f"interval={args.interval}m relogin={args.relogin}")
    while time.time() < deadline:
        gap = time.time() - last_tick
        if gap > interval * 2 + 60:
            log(f"GAP {gap / 60:.0f} min — Mac спал или процесс был остановлен")
        last_tick = time.time()
        age = now() - login_time
        with make_client(sess) as c:
            try:
                r, ms = fetch(c, f"students/{sess['children'][0]['guid']}/timetable", None)
                log(f"ok   HTTP {r.status_code} {ms:.0f}ms  session_age={age}")
            except SessionExpired:
                log(f"EXPIRED (401)  session_age={age}  ← время жизни сессии при опросе раз в {args.interval} мин")
                if args.relogin and sess.get("device_pass"):
                    if relogin_with_device_pass(args, sess):
                        sess = load_session(args)
                        login_time = dt.datetime.fromisoformat(sess["login_time"])
                        log(f"RELOGIN ok via {sess['method']}  devicePass rotated={sess.get('device_pass_rotated')}")
                        continue
                    log("RELOGIN FAILED — devicePass не принят")
                break
            except httpx.HTTPError as e:
                log(f"net  {type(e).__name__} (нет сети?)")
        time.sleep(interval + random.uniform(-60, 60))
    log("probe end")


# ---------------------------------------------------------------- masking & schema

GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}([T ][\d:.]+)?(Z|[+-]\d{2}:?\d{2})?$")
TIME_RE = re.compile(r"^\d{1,2}:\d{2}(:\d{2})?$")
EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[a-z]{2,}", re.I)
LONG_DIGITS_RE = re.compile(r"\d{7,}")
# String values under these keys are school vocabulary, not personal data — kept for analysis.
KEEP_KEYS = {
    "subjectname", "groupname", "achvaname", "achvaaval", "eventcode", "lessontype", "gradetype",
    "typename", "type", "hollydayname", "holidayname", "justification", "gradingperiod", "periodname",
    "classcode", "status", "kind", "category", "folder", "dayname",
}
SECRET_KEYS = ("idnumber", "phone", "cellphone", "email", "password", "tz", "address")


class Masker:
    def __init__(self) -> None:
        self.guids: dict[str, str] = {}

    def _guid(self, v: str) -> str:
        return self.guids.setdefault(v.lower(), f"guid-{len(self.guids) + 1}")

    def mask(self, obj: Any, key: str = "") -> Any:
        k = key.lower()
        if isinstance(obj, dict):
            return {kk: self.mask(vv, kk) for kk, vv in obj.items()}
        if isinstance(obj, list):
            return [self.mask(x, key) for x in obj]
        if isinstance(obj, bool) or obj is None:
            return obj
        if isinstance(obj, (int, float)):
            return "‹num›" if any(s in k for s in SECRET_KEYS) or obj >= 10_000_000 else obj
        s = str(obj)
        if GUID_RE.match(s):
            return self._guid(s)
        if DATE_RE.match(s) or TIME_RE.match(s) or s == "":
            return s
        if any(sk in k for sk in SECRET_KEYS) or EMAIL_RE.search(s) or LONG_DIGITS_RE.search(s):
            return "‹secret›"
        if k in KEEP_KEYS and len(s) <= 60:
            return s
        return f"‹{len(s)}ch›"


def _type(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, int):
        return "int"
    if isinstance(v, float):
        return "float"
    if isinstance(v, str):
        return "date" if DATE_RE.match(v) else ("guid" if GUID_RE.match(v) else "str")
    if isinstance(v, list):
        return "list"
    return "object"


def schema(data: Any, prefix: str = "", depth: int = 0) -> dict[str, set]:
    """Flattened key → set of observed types, across all list items (two levels deep)."""
    out: dict[str, set] = {}
    items = data if isinstance(data, list) else [data]
    for it in items[:500]:
        if not isinstance(it, dict):
            out.setdefault(prefix or "<item>", set()).add(_type(it))
            continue
        for k, v in it.items():
            path = f"{prefix}{k}"
            out.setdefault(path, set()).add(_type(v))
            if depth < 2 and isinstance(v, dict):
                for sk, st in schema(v, path + ".", depth + 1).items():
                    out.setdefault(sk, set()).update(st)
            elif depth < 2 and isinstance(v, list) and v and isinstance(v[0], dict):
                for sk, st in schema(v, path + "[].", depth + 1).items():
                    out.setdefault(sk, set()).update(st)
    return out


def shape_summary(data: Any) -> str:
    if isinstance(data, list):
        return f"list[{len(data)}]"
    if isinstance(data, dict):
        return f"object{{{len(data)} keys}}"
    return type(data).__name__


def first_item(masked: Any) -> Any:
    if isinstance(masked, list):
        return masked[0] if masked else None
    return masked


def render_findings(account: str, sess: dict, login_body: dict, results: list[dict], rng: dict,
                    masker: Masker) -> str:
    token = login_body.get("accessToken") or {}
    cred = login_body.get("credential") or {}
    lines = [
        f"# Phase 0 findings — account `{account}`",
        "",
        f"Сгенерировано: {now().isoformat(timespec='seconds')}. Персональные данные замаскированы автоматически — "
        "проверьте глазами перед отправкой.",
        "",
        "## Вход",
        "",
        f"- метод: `{sess.get('method')}`; год: `{sess.get('year')}`; детей в аккаунте: **{len(sess.get('children', []))}**",
        f"- CSRF-токен: {'есть' if sess.get('csrf') else 'нет'}; devicePass: "
        f"{'**получен**' if sess.get('device_pass') else 'не получен'}",
        f"- cookies: {', '.join(sorted({c['name'] for c in sess.get('cookies', [])})) or '—'}",
        f"- ключи ответа login: {', '.join(sorted(login_body))}",
        f"- credential: {', '.join(sorted(cred))}",
        f"- accessToken: {', '.join(sorted(token))}",
        f"- accessToken.children[]: {', '.join(sorted(schema(token.get('children') or [])))}",
        "",
        "## Эндпоинты",
        "",
        f"Диапазон дат для датированных запросов: {rng['start']} … {rng['end']}",
        "",
        "| ключ | путь | params | статус | ms | размер | форма |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in results:
        status = f"{r['status']}" + (f" ({r['reason']})" if r["reason"] else "")
        lines.append(f"| {r['key']} | `{r['path']}` | {r['params']} | {status} | {r['ms']} | {r['bytes']} | "
                     f"{r.get('shape', '')} |")
    lines += ["", "## Схемы ответов", ""]
    seen: set[str] = set()
    for r in results:
        if "schema" not in r:
            continue
        name = r["key"].split("/")[-1]
        if name in seen:  # same endpoint for the second child — schema already shown
            continue
        seen.add(name)
        lines += [f"### {name}  `{r['path']}`  — {r.get('shape')}", "", "```"]
        for k, types in sorted(r["schema"].items()):
            lines.append(f"{k}: {' | '.join(sorted(types))}")
        lines += ["```", "", "<details><summary>пример (замаскирован)</summary>", "", "```json",
                  json.dumps(r["example"], ensure_ascii=False, indent=2)[:2500], "```", "</details>", ""]
    return "\n".join(lines)


# ---------------------------------------------------------------- cli

def main() -> None:
    ap = argparse.ArgumentParser(description="Mashov Hub — Phase 0 spike")
    ap.add_argument("--data-dir", default="~/MashovHub/spike", help="куда писать данные (вне репозитория)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("schools", help="найти semel школы по названию или номеру")
    s.add_argument("--search", required=True)
    s.set_defaults(func=cmd_schools)

    s = sub.add_parser("login", help="войти и сохранить сессию")
    s.add_argument("--account", required=True, help="метка аккаунта, напр. school-a")
    s.add_argument("--method", choices=["browser", "sms", "password"], default="browser")
    s.add_argument("--semel", type=int)
    s.add_argument("--username")
    s.add_argument("--year", type=int, help=f"учебный год Машов (по умолчанию {school_year()})")
    s.set_defaults(func=cmd_login)

    s = sub.add_parser("relogin-device", help="проверить вход только по devicePass (без SMS)")
    s.add_argument("--account", required=True)
    s.set_defaults(func=cmd_relogin_device)

    s = sub.add_parser("dump", help="выгрузить все эндпоинты и собрать findings-<account>.md")
    s.add_argument("--account", required=True)
    s.set_defaults(func=cmd_dump)

    s = sub.add_parser("probe", help="измерить время жизни сессии")
    s.add_argument("--account", required=True)
    s.add_argument("--interval", type=int, default=15, help="минут между проверками")
    s.add_argument("--hours", type=float, default=24)
    s.add_argument("--relogin", action="store_true", help="при истечении попробовать devicePass и продолжить")
    s.set_defaults(func=cmd_probe)

    args = ap.parse_args()
    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\nпрервано")
    except httpx.HTTPError as e:
        die(f"Сетевая ошибка: {type(e).__name__}: {e}")


if __name__ == "__main__":
    main()
