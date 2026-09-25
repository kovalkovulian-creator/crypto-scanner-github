#!/usr/bin/env python3
"""
scam_check.py — проверка монеты на Solana на признаки скама.

Запуск:
    python scam_check.py <адрес_монеты>
    python scam_check.py <адрес_монеты> --json      # вывод в JSON (для будущего бота)

Источники (бесплатные, без ключей):
    - RugCheck   https://api.rugcheck.xyz  — права на выпуск/заморозку, холдеры, LP, риски
    - DexScreener https://api.dexscreener.com — ликвидность, объёмы, сделки, возраст пары

Важно: скрипт оценивает РИСК СКАМА по объективным признакам.
Он НЕ предсказывает цену и не гарантирует, что монета не упадёт.
"""

import json
import sys
import time
import urllib.request
import urllib.error

RUGCHECK_URL = "https://api.rugcheck.xyz/v1/tokens/{mint}/report"
DEXSCREENER_URL = "https://api.dexscreener.com/latest/dex/tokens/{mint}"

# ---- Пороги (можно подкручивать под свою стратегию) ----
MIN_LIQUIDITY_DANGER = 10_000      # $ — ниже почти наверняка ловушка
MIN_LIQUIDITY_WARN = 50_000        # $
TOP10_DANGER = 50                  # % предложения у топ-10 кошельков
TOP10_WARN = 30
CREATOR_DANGER = 10                # % предложения у создателя
CREATOR_WARN = 3
LP_LOCKED_WARN = 50                # % заблокированной ликвидности в главном пуле
YOUNG_PAIR_HOURS = 24              # пара моложе суток — повышенный риск
SELL_BUY_RATIO_WARN = 2.0          # продаж в 2+ раза больше покупок за 24ч


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def fetch_json(url, retries=1, timeout=10):
    last_err = None
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 scam-check/1.1"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode("utf-8"))
        except Exception as e:  # сеть, SSL, таймаут, битый JSON
            last_err = e
            log(f"   …попытка {attempt + 1} не удалась: {type(e).__name__}: {e}")
            if attempt < retries:
                time.sleep(1)
    raise RuntimeError(f"Не удалось получить {url}: {type(last_err).__name__}: {last_err}")


def pick_main_pair(dex):
    pairs = [p for p in (dex or {}).get("pairs") or [] if p.get("chainId") == "solana"]
    if not pairs:
        return None
    return max(pairs, key=lambda p: (p.get("liquidity") or {}).get("usd") or 0)


def pick_main_market(rug):
    markets = (rug or {}).get("markets") or []
    if not markets:
        return None
    def size(m):
        lp = m.get("lp") or {}
        return (lp.get("baseUSD") or 0) + (lp.get("quoteUSD") or 0)
    return max(markets, key=size)


def analyze(mint, rug, dex):
    """Чистая функция: на вход — ответы API, на выход — вердикт с причинами."""
    danger, warn, ok, info = [], [], [], {}

    # ---------- RugCheck ----------
    if rug:
        token = rug.get("token") or {}
        meta = rug.get("tokenMeta") or {}
        info["name"] = meta.get("name")
        info["symbol"] = meta.get("symbol")

        if rug.get("rugged"):
            danger.append("RugCheck пометил монету как уже «кинутую» (rugged)")

        mint_auth = rug.get("mintAuthority", token.get("mintAuthority"))
        freeze_auth = rug.get("freezeAuthority", token.get("freezeAuthority"))
        if mint_auth:
            danger.append("Право выпуска не отозвано — создатель может напечатать новые монеты")
        else:
            ok.append("Право выпуска отозвано")
        if freeze_auth:
            danger.append("Право заморозки не отозвано — ваши монеты могут заморозить (не дадут продать)")
        else:
            ok.append("Право заморозки отозвано")

        # Топ-10 холдеров (без пулов ликвидности, если их удаётся распознать)
        pool_owners = {m.get("pubkey") for m in rug.get("markets") or []}
        for m in rug.get("markets") or []:
            for key in ("liquidityAAccount", "liquidityBAccount"):
                acc = m.get(key) or {}
                if acc.get("owner"):
                    pool_owners.add(acc["owner"])
        holders = [h for h in rug.get("topHolders") or [] if h.get("owner") not in pool_owners]
        top10 = sum((h.get("pct") or 0) for h in holders[:10])
        info["top10_pct"] = round(top10, 1)
        if top10 >= TOP10_DANGER:
            danger.append(f"Топ-10 кошельков держат {top10:.1f}% — могут обвалить цену одной продажей")
        elif top10 >= TOP10_WARN:
            warn.append(f"Топ-10 кошельков держат {top10:.1f}% — высокая концентрация")
        else:
            ok.append(f"Топ-10 кошельков держат {top10:.1f}%")

        insiders = [h for h in rug.get("topHolders") or [] if h.get("insider")]
        if insiders:
            ins_pct = sum((h.get("pct") or 0) for h in insiders)
            warn.append(f"Инсайдеров среди топ-холдеров: {len(insiders)} ({ins_pct:.1f}%)")

        # Доля создателя
        supply = token.get("supply") or 0
        creator_bal = rug.get("creatorBalance") or 0
        if supply:
            creator_pct = creator_bal / supply * 100
            info["creator_pct"] = round(creator_pct, 2)
            if creator_pct >= CREATOR_DANGER:
                danger.append(f"У создателя {creator_pct:.1f}% монет")
            elif creator_pct >= CREATOR_WARN:
                warn.append(f"У создателя {creator_pct:.1f}% монет")

        # Блокировка ликвидности в главном пуле
        main_market = pick_main_market(rug)
        if main_market:
            lp = main_market.get("lp") or {}
            locked = lp.get("lpLockedPct") or 0
            info["main_market"] = main_market.get("marketType")
            info["lp_locked_pct"] = round(locked, 1)
            # У концентрированных пулов (CLMM/DLMM/whirlpool) LP-токенов нет — блокировка не применима
            clmm_like = main_market.get("marketType") in ("orca", "meteoraDlmm", "raydium_clmm")
            if not clmm_like:
                if locked < LP_LOCKED_WARN:
                    warn.append(f"В главном пуле заблокировано только {locked:.0f}% ликвидности — её могут вывести")
                else:
                    ok.append(f"В главном пуле заблокировано {locked:.0f}% ликвидности")

        # Риски, которые нашёл сам RugCheck
        for r in rug.get("risks") or []:
            text = f"RugCheck: {r.get('name')}"
            if r.get("description"):
                text += f" — {r['description']}"
            (danger if r.get("level") == "danger" else warn).append(text)

        info["rugcheck_score"] = rug.get("score_normalised")
    else:
        warn.append("Нет данных RugCheck — проверка неполная")

    # ---------- DexScreener ----------
    pair = pick_main_pair(dex)
    if pair:
        info.setdefault("name", (pair.get("baseToken") or {}).get("name"))
        info.setdefault("symbol", (pair.get("baseToken") or {}).get("symbol"))
        liq = (pair.get("liquidity") or {}).get("usd") or 0
        info["liquidity_usd"] = round(liq)
        info["price_usd"] = pair.get("priceUsd")
        info["market_cap"] = pair.get("marketCap") or pair.get("fdv")
        info["dex"] = pair.get("dexId")
        info["url"] = pair.get("url")

        if liq < MIN_LIQUIDITY_DANGER:
            danger.append(f"Ликвидность всего ${liq:,.0f} — выйти из позиции будет почти невозможно")
        elif liq < MIN_LIQUIDITY_WARN:
            warn.append(f"Ликвидность ${liq:,.0f} — низкая")
        else:
            ok.append(f"Ликвидность ${liq:,.0f}")

        created = pair.get("pairCreatedAt")
        if created:
            age_h = (time.time() * 1000 - created) / 3_600_000
            info["pair_age_hours"] = round(age_h, 1)
            if age_h < YOUNG_PAIR_HOURS:
                warn.append(f"Паре всего {age_h:.1f} ч — большинство рагов происходит в первые сутки")

        tx = (pair.get("txns") or {}).get("h24") or {}
        buys, sells = tx.get("buys") or 0, tx.get("sells") or 0
        info["buys_24h"], info["sells_24h"] = buys, sells
        if buys and sells / buys >= SELL_BUY_RATIO_WARN:
            warn.append(f"За 24ч продаж ({sells}) заметно больше покупок ({buys})")
        if buys + sells == 0:
            warn.append("За 24ч нет сделок — монета мёртвая")

        vol = (pair.get("volume") or {}).get("h24") or 0
        info["volume_24h"] = round(vol)
        info["price_change_24h"] = (pair.get("priceChange") or {}).get("h24")

        socials = ((pair.get("info") or {}).get("socials") or []) + ((pair.get("info") or {}).get("websites") or [])
        if not socials:
            warn.append("Нет сайта и соцсетей в DexScreener")
    else:
        danger.append("Монета не торгуется ни на одной DEX Solana (или адрес неверный)")

    # ---------- Вердикт ----------
    if danger:
        verdict = "КРАСНЫЙ"
        summary = "Высокий риск скама. Не входить."
    elif len(warn) >= 3:
        verdict = "ЖЁЛТЫЙ"
        summary = "Много тревожных признаков. Только если понимаете, что делаете, и на минимальную сумму."
    elif warn:
        verdict = "ЖЁЛТЫЙ"
        summary = "Явных признаков скама нет, но есть риски."
    else:
        verdict = "ЗЕЛЁНЫЙ"
        summary = "Явных признаков скама не найдено. Это не прогноз роста цены."

    return {
        "mint": mint,
        "verdict": verdict,
        "summary": summary,
        "danger": danger,
        "warnings": warn,
        "ok": ok,
        "info": info,
    }


def print_report(res):
    i = res["info"]
    icon = {"КРАСНЫЙ": "🔴", "ЖЁЛТЫЙ": "🟡", "ЗЕЛЁНЫЙ": "🟢"}[res["verdict"]]
    print()
    print(f"{icon}  {res['verdict']} — {i.get('name') or '?'} ({i.get('symbol') or '?'})")
    print(f"   {res['summary']}")
    print(f"   Адрес: {res['mint']}")
    print()
    rows = [
        ("Цена, $", i.get("price_usd")),
        ("Капитализация, $", f"{i['market_cap']:,.0f}" if i.get("market_cap") else None),
        ("Ликвидность, $", f"{i['liquidity_usd']:,}" if i.get("liquidity_usd") is not None else None),
        ("Объём 24ч, $", f"{i['volume_24h']:,}" if i.get("volume_24h") is not None else None),
        ("Изменение 24ч, %", i.get("price_change_24h")),
        ("Покупки / продажи 24ч", f"{i.get('buys_24h')} / {i.get('sells_24h')}" if "buys_24h" in i else None),
        ("Возраст пары, ч", i.get("pair_age_hours")),
        ("Топ-10 кошельков, %", i.get("top10_pct")),
        ("У создателя, %", i.get("creator_pct")),
        ("RugCheck score (меньше = лучше)", i.get("rugcheck_score")),
    ]
    for k, v in rows:
        if v is not None:
            print(f"   {k:<34} {v}")
    for title, items, mark in (("Критично", res["danger"], "✖"),
                               ("Настораживает", res["warnings"], "!"),
                               ("В порядке", res["ok"], "✓")):
        if items:
            print(f"\n   {title}:")
            for t in items:
                print(f"     {mark} {t}")
    if i.get("url"):
        print(f"\n   График: {i['url']}")
    print("\n   Это оценка риска скама, а не прогноз цены.\n")


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    as_json = "--json" in sys.argv
    if not args:
        print(__doc__)
        sys.exit(1)
    mint = args[0].strip()

    rug = dex = None
    errors = []
    log("→ Запрашиваю RugCheck…")
    try:
        rug = fetch_json(RUGCHECK_URL.format(mint=mint))
    except RuntimeError as e:
        errors.append(str(e))
    log("→ Запрашиваю DexScreener…")
    try:
        dex = fetch_json(DEXSCREENER_URL.format(mint=mint))
    except RuntimeError as e:
        errors.append(str(e))
    if rug is None and dex is None:
        print("Не удалось получить данные ни из одного источника:\n  " + "\n  ".join(errors))
        if any("CERTIFICATE" in e.upper() for e in errors):
            print("\nПохоже на проблему SSL-сертификатов Python на Mac. Выполните один раз:\n"
                  "  open '/Applications/Python 3*/Install Certificates.command'\n"
                  "или: pip3 install certifi")
        sys.exit(2)

    res = analyze(mint, rug, dex)
    if errors:
        res["errors"] = errors
    if as_json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    else:
        print_report(res)


if __name__ == "__main__":
    main()
