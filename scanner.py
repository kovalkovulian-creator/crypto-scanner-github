#!/usr/bin/env python3
"""
scanner.py — сканер новых монет Solana с уведомлениями в Telegram.

Что делает (по кругу, раз в CHECK_EVERY_SEC секунд):
  1. Берёт свежие монеты из DexScreener (новые профили токенов и бусты).
  2. Каждую новую прогоняет через проверку на скам (scam_check.analyze).
  3. Если монета прошла фильтр — присылает сигнал в Telegram-бота.
  4. Каждый сигнал пишет в journal.csv (бумажный журнал: цена в момент сигнала).

Запуск:
    python3 scanner.py --test     # проверить бота: найдёт ваш чат и пришлёт тестовое сообщение
    python3 scanner.py            # запустить сканер (остановить: Ctrl + C)
    python3 scanner.py --once     # один проход и выход (для проверки)
    python3 scanner.py --followup # только отчёты по прошлым сигналам

В постоянном режиме сканер ещё и отслеживает свои сигналы: через 1 ч, 24 ч и 7 дней
отвечает на исходное сообщение в боте (цена, ликвидность, скам или нет),
а в 21:00 присылает дневную сводку.

Настройки — в config.json (токен бота) и в блоке НАСТРОЙКИ ниже.
Сканер ничего не покупает и не продаёт. Это сигналы, решение принимаете вы.
"""

import csv
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

from scam_check import analyze, fetch_json, log, RUGCHECK_URL, DEXSCREENER_URL
from review import evaluate, to_float

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(HERE, "config.json")
SEEN_PATH = os.path.join(HERE, "seen.json")
JOURNAL_PATH = os.path.join(HERE, "journal.csv")
SIGNALS_PATH = os.path.join(HERE, "signals.json")

# ================= НАСТРОЙКИ =================
CHECK_EVERY_SEC = 120          # как часто проверять новые монеты
ALLOWED_VERDICTS = {"ЗЕЛЁНЫЙ", "ЖЁЛТЫЙ"}   # какие вердикты присылать (КРАСНЫЙ не присылаем никогда)
MAX_WARNINGS = 2               # жёлтые с большим числом предупреждений не присылаем
MIN_LIQUIDITY_USD = 30_000     # минимальная ликвидность для сигнала
MAX_TOP10_PCT = 40             # максимальная доля топ-10 кошельков
PAUSE_BETWEEN_TOKENS = 2       # пауза между проверками монет (чтобы не упереться в лимиты API)
FOLLOWUP_HOURS = [1, 24, 168]  # через сколько часов после сигнала присылать отчёт (1 ч, сутки, неделя)
DAILY_SUMMARY_HOUR = 21        # во сколько присылать дневную сводку (по времени Mac)
# =============================================

SOURCES = [
    "https://api.dexscreener.com/token-profiles/latest/v1",
    "https://api.dexscreener.com/token-boosts/latest/v1",
]


# ---------- файлы ----------
def load_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def save_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def journal_write(res):
    i = res["info"]
    new = not os.path.exists(JOURNAL_PATH)
    with open(JOURNAL_PATH, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if new:
            w.writerow(["время", "адрес", "символ", "вердикт", "цена_$", "капитализация_$",
                        "ликвидность_$", "топ10_%", "предупреждения", "график"])
        w.writerow([datetime.now().strftime("%Y-%m-%d %H:%M"), res["mint"], i.get("symbol"),
                    res["verdict"], i.get("price_usd"), i.get("market_cap"), i.get("liquidity_usd"),
                    i.get("top10_pct"), " | ".join(res["warnings"]), i.get("url")])


# ---------- Telegram ----------
def tg(token, method, params=None):
    url = f"https://api.telegram.org/bot{token}/{method}"
    data = urllib.parse.urlencode(params or {}).encode() if params else None
    req = urllib.request.Request(url, data=data)
    with urllib.request.urlopen(req, timeout=15) as r:
        resp = json.loads(r.read().decode())
    if not resp.get("ok"):
        raise RuntimeError(f"Telegram: {resp}")
    return resp["result"]


def get_config():
    cfg = load_json(CONFIG_PATH, {})
    # На GitHub токен и chat_id берутся из секретов (переменных окружения), а не из файла
    if os.environ.get("TELEGRAM_BOT_TOKEN"):
        cfg["telegram_bot_token"] = os.environ["TELEGRAM_BOT_TOKEN"].strip()
    if os.environ.get("TELEGRAM_CHAT_ID"):
        cfg["telegram_chat_id"] = int(os.environ["TELEGRAM_CHAT_ID"].strip())
    if not cfg.get("telegram_bot_token"):
        sys.exit("Нет токена бота: заполните config.json или секрет TELEGRAM_BOT_TOKEN")
    return cfg


def ensure_chat_id(cfg):
    """Находит ваш чат с ботом (по сообщению /start) и сохраняет chat_id в config.json."""
    if cfg.get("telegram_chat_id"):
        return cfg["telegram_chat_id"]
    token = cfg["telegram_bot_token"]
    try:
        me = tg(token, "getMe")
    except urllib.error.HTTPError as e:
        if e.code in (401, 404):
            sys.exit("Telegram отверг токен. Скопируйте токен из чата с @BotFather и вставьте в config.json.")
        raise
    log(f"✓ Бот найден: @{me.get('username')}")
    try:
        tg(token, "deleteWebhook")  # на случай, если у бота включён webhook — он «съедает» сообщения
    except Exception:
        pass
    updates = tg(token, "getUpdates", {"timeout": 0, "allowed_updates": "[]"})
    log(f"   получено событий от Telegram: {len(updates)}")
    chats = []
    for u in updates:
        for key in ("message", "edited_message", "my_chat_member"):
            chat = (u.get(key) or {}).get("chat")
            if chat and chat.get("type") == "private":
                chats.append(chat["id"])
    if not chats:
        sys.exit(f"Не нашёл вашего сообщения боту. Откройте @{me.get('username')} в Telegram, "
                 f"отправьте /start и запустите ещё раз.")
    cfg["telegram_chat_id"] = chats[-1]
    save_json(CONFIG_PATH, cfg)
    log(f"✓ Чат найден и сохранён в config.json (chat_id={chats[-1]})")
    return chats[-1]


def send(cfg, text, reply_to=None):
    params = {
        "chat_id": cfg["telegram_chat_id"],
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": "true",
    }
    if reply_to:
        params["reply_to_message_id"] = reply_to
        params["allow_sending_without_reply"] = "true"
    return tg(cfg["telegram_bot_token"], "sendMessage", params)


def format_signal(res):
    i = res["info"]
    icon = {"ЗЕЛЁНЫЙ": "🟢", "ЖЁЛТЫЙ": "🟡"}.get(res["verdict"], "⚪")
    def money(v):
        return f"${v:,.0f}" if isinstance(v, (int, float)) else "?"
    lines = [
        f"{icon} <b>{i.get('name') or '?'} ({i.get('symbol') or '?'})</b> — {res['verdict']}",
        f"Капитализация: {money(i.get('market_cap'))}",
        f"Ликвидность: {money(i.get('liquidity_usd'))}",
        f"Объём 24ч: {money(i.get('volume_24h'))}",
        f"Изменение 24ч: {i.get('price_change_24h')}%",
        f"Топ-10 кошельков: {i.get('top10_pct')}%",
        f"Возраст пары: {i.get('pair_age_hours')} ч",
    ]
    if res["warnings"]:
        lines.append("\n⚠️ " + "\n⚠️ ".join(res["warnings"]))
    lines.append(f"\n<code>{res['mint']}</code>")
    if i.get("url"):
        lines.append(f'<a href="{i["url"]}">График</a> · <a href="https://rugcheck.xyz/tokens/{res["mint"]}">RugCheck</a>')
    lines.append("\n<i>Это не прогноз цены. Решение за вами.</i>")
    return "\n".join(lines)


# ---------- сканирование ----------
def fresh_solana_tokens():
    found = []
    for url in SOURCES:
        try:
            for item in fetch_json(url) or []:
                if item.get("chainId") == "solana" and item.get("tokenAddress"):
                    found.append(item["tokenAddress"])
        except RuntimeError as e:
            log(f"   источник недоступен: {e}")
    return list(dict.fromkeys(found))  # без дублей, порядок сохранён


def passes_filter(res):
    i = res["info"]
    if res["verdict"] not in ALLOWED_VERDICTS or res["danger"]:
        return False
    if len(res["warnings"]) > MAX_WARNINGS:
        return False
    if (i.get("liquidity_usd") or 0) < MIN_LIQUIDITY_USD:
        return False
    if (i.get("top10_pct") or 0) > MAX_TOP10_PCT:
        return False
    return True


def check_token(mint):
    rug = dex = None
    try:
        rug = fetch_json(RUGCHECK_URL.format(mint=mint))
    except RuntimeError:
        pass
    try:
        dex = fetch_json(DEXSCREENER_URL.format(mint=mint))
    except RuntimeError:
        pass
    if rug is None and dex is None:
        return None
    return analyze(mint, rug, dex)


def scan_once(cfg, seen):
    tokens = [t for t in fresh_solana_tokens() if t not in seen]
    log(f"[{datetime.now():%H:%M:%S}] новых монет: {len(tokens)}")
    sent = 0
    for mint in tokens:
        res = check_token(mint)
        seen[mint] = int(time.time())
        if res is None:
            continue
        ok = passes_filter(res)
        sym = res["info"].get("symbol") or mint[:6]
        log(f"   {res['verdict']:<8} {sym:<12} {'→ СИГНАЛ' if ok else ''}")
        if ok:
            try:
                msg = send(cfg, format_signal(res))
                journal_write(res)
                track_signal(res, (msg or {}).get("message_id"))
                sent += 1
            except Exception as e:
                log(f"   не удалось отправить в Telegram: {e}")
        time.sleep(PAUSE_BETWEEN_TOKENS)
    # храним «виденные» монеты неделю
    cutoff = time.time() - 7 * 86400
    for k in [k for k, v in seen.items() if v < cutoff]:
        del seen[k]
    save_json(SEEN_PATH, seen)
    return sent


# ---------- отслеживание сигналов ----------
def load_signals():
    """signals.json + сигналы из journal.csv, которых там ещё нет (старые, до отслеживания)."""
    sig = load_json(SIGNALS_PATH, {"signals": {}, "last_summary": ""})
    if os.path.exists(JOURNAL_PATH):
        with open(JOURNAL_PATH, encoding="utf-8") as f:
            for r in csv.DictReader(f):
                if r["адрес"] not in sig["signals"]:
                    try:
                        ts = datetime.strptime(r["время"], "%Y-%m-%d %H:%M").timestamp()
                    except ValueError:
                        continue
                    sig["signals"][r["адрес"]] = {"symbol": r["символ"], "price": to_float(r["цена_$"]),
                                                  "ts": ts, "msg_id": None, "done": [], "last": None}
    return sig


def track_signal(res, msg_id):
    sig = load_signals()
    sig["signals"][res["mint"]] = {"symbol": res["info"].get("symbol"),
                                   "price": to_float(res["info"].get("price_usd")),
                                   "ts": time.time(), "msg_id": msg_id, "done": [], "last": None}
    save_json(SIGNALS_PATH, sig)


def fmt_h(h):
    return f"{h} ч" if h < 24 else (f"{h // 24} дн" if h % 24 == 0 else f"{h} ч")


def check_followups(cfg):
    sig = load_signals()
    now = time.time()
    for mint, s in sig["signals"].items():
        age_h = (now - s["ts"]) / 3600
        due = [h for h in FOLLOWUP_HOURS if age_h >= h and h not in s["done"]]
        if not due or not s.get("price"):
            continue
        h = max(due)  # если сканер был выключен — шлём только самый свежий пропущенный отчёт
        p1, liq, change, outcome = evaluate(mint, s["price"])
        if outcome == "нет данных":
            continue
        icon = {"плюс ✓": "📈", "минус": "📉", "без изменений": "➖", "СКАМ ✖": "💀"}.get(outcome, "•")
        text = (f"{icon} <b>{s.get('symbol') or mint[:6]}</b> через {fmt_h(h)}: "
                f"<b>{change:+.0f}%</b>\n"
                f"Цена: {s['price']} → {p1}\n"
                f"Ликвидность сейчас: ${liq:,.0f}\n"
                f"Итог: {outcome}")
        if outcome.startswith("СКАМ"):
            text += "\n\nФильтр пропустил скам — стоит разобрать, почему."
        try:
            send(cfg, text, reply_to=s.get("msg_id"))
        except Exception as e:
            log(f"   отчёт по {s.get('symbol')} не отправлен: {e}")
            continue
        s["done"] = sorted(set(s["done"]) | {x for x in FOLLOWUP_HOURS if x <= h})
        s["last"] = {"change": round(change, 1) if change is not None else None, "outcome": outcome, "ts": now}
        log(f"   отчёт: {s.get('symbol')} через {fmt_h(h)} → {outcome} ({change:+.0f}%)")
        time.sleep(1)
    save_json(SIGNALS_PATH, sig)


def maybe_daily_summary(cfg):
    sig = load_signals()
    today = datetime.now().strftime("%Y-%m-%d")
    if datetime.now().hour < DAILY_SUMMARY_HOUR or sig.get("last_summary") == today:
        return
    items = [s for s in sig["signals"].values() if s.get("last")]
    new_today = sum(1 for s in sig["signals"].values()
                    if datetime.fromtimestamp(s["ts"]).strftime("%Y-%m-%d") == today)
    lines = [f"📋 <b>Сводка за {datetime.now():%d.%m}</b>", f"Новых сигналов сегодня: {new_today}"]
    if items:
        cnt = lambda o: sum(1 for s in items if s["last"]["outcome"] == o)
        ch = [s["last"]["change"] for s in items if s["last"]["change"] is not None]
        lines += [f"Всего отслежено: {len(items)}",
                  f"📈 в плюсе: {cnt('плюс ✓')}   📉 в минусе: {cnt('минус')}   💀 скам: {cnt('СКАМ ✖')}"]
        if ch:
            lines.append(f"Среднее изменение: {sum(ch) / len(ch):+.1f}%")
        best = max(items, key=lambda s: s["last"]["change"] or -1e9)
        worst = min(items, key=lambda s: s["last"]["change"] or 1e9)
        lines.append(f"Лучший: {best.get('symbol')} {best['last']['change']:+.0f}%   "
                     f"Худший: {worst.get('symbol')} {worst['last']['change']:+.0f}%")
    lines.append("\n<i>Цифры по последнему отчёту каждого сигнала. Без комиссий.</i>")
    try:
        send(cfg, "\n".join(lines))
        sig["last_summary"] = today
        save_json(SIGNALS_PATH, sig)
    except Exception as e:
        log(f"   сводка не отправлена: {e}")


def main():
    cfg = get_config()
    ensure_chat_id(cfg)

    if "--test" in sys.argv:
        send(cfg, "✅ Крипто-сканер подключён. Сюда будут приходить сигналы.")
        log("✓ Тестовое сообщение отправлено — проверьте Telegram.")
        return

    seen = load_json(SEEN_PATH, {})
    if "--cycle" in sys.argv:      # один полный цикл: сканирование + отчёты + сводка (для GitHub Actions)
        for step in (lambda: scan_once(cfg, seen), lambda: check_followups(cfg),
                     lambda: maybe_daily_summary(cfg)):
            try:
                step()
            except Exception as e:
                log(f"   ошибка: {type(e).__name__}: {e}")
        return
    if "--followup" in sys.argv:   # только отчёты по прошлым сигналам
        check_followups(cfg)
        return
    if "--once" in sys.argv:
        n = scan_once(cfg, seen)
        log(f"Готово, сигналов: {n}")
        return

    send(cfg, f"▶️ Сканер запущен. Проверка каждые {CHECK_EVERY_SEC // 60} мин. "
              f"Отчёты по сигналам: через 1 ч, сутки и неделю. Сводка в {DAILY_SUMMARY_HOUR}:00.")
    log("Сканер запущен. Остановить: Ctrl + C")
    try:
        while True:
            for step in (lambda: scan_once(cfg, seen), lambda: check_followups(cfg),
                         lambda: maybe_daily_summary(cfg)):
                try:
                    step()
                except Exception as e:  # сканер не должен падать из-за одной ошибки
                    log(f"   ошибка: {type(e).__name__}: {e}")
            time.sleep(CHECK_EVERY_SEC)
    except KeyboardInterrupt:
        log("\nОстановлен.")
        try:
            send(cfg, "⏹ Сканер остановлен.")
        except Exception:
            pass


if __name__ == "__main__":
    main()
