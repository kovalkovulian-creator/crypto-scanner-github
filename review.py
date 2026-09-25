#!/usr/bin/env python3
"""
review.py — проверка прошлых сигналов: что стало с монетами после сигнала.

Запуск:
    python3 review.py

Берёт все сигналы из journal.csv, запрашивает текущую цену и ликвидность
в DexScreener и показывает для каждого:
    - изменение цены с момента сигнала;
    - «СКАМ», если ликвидность исчезла или цена упала на 90%+ (фильтр ошибся);
    - итог: сколько сигналов в плюсе / в минусе / оказались скамом.

Результат также сохраняется в review.csv (можно открыть в Excel/Numbers).
Считает «если бы купил по сигналу и держал до сейчас», без комиссий и проскальзывания.
"""

import csv
import os
import sys
import time
from datetime import datetime

from scam_check import fetch_json, pick_main_pair, DEXSCREENER_URL

HERE = os.path.dirname(os.path.abspath(__file__))
JOURNAL_PATH = os.path.join(HERE, "journal.csv")
REVIEW_PATH = os.path.join(HERE, "review.csv")

RUG_DROP_PCT = -90        # падение цены на 90%+ считаем скамом/рагом
RUG_LIQUIDITY_USD = 1000  # ликвидность ниже $1k — пул выведен


def to_float(x):
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def evaluate(mint, p0):
    """Текущая цена/ликвидность монеты и итог относительно цены сигнала p0."""
    p1 = liq = None
    try:
        pair = pick_main_pair(fetch_json(DEXSCREENER_URL.format(mint=mint)))
        if pair:
            p1 = to_float(pair.get("priceUsd"))
            liq = (pair.get("liquidity") or {}).get("usd") or 0
    except RuntimeError:
        pass
    change = (p1 / p0 - 1) * 100 if p0 and p1 else None
    if p1 is None and liq is None:
        outcome = "нет данных"
    elif (liq is not None and liq < RUG_LIQUIDITY_USD) or (change is not None and change <= RUG_DROP_PCT):
        outcome = "СКАМ ✖"
    elif change is None:
        outcome = "нет данных"
    elif change >= 1:
        outcome = "плюс ✓"
    elif change <= -1:
        outcome = "минус"
    else:
        outcome = "без изменений"
    return p1, liq, change, outcome


def hours_since(ts):
    try:
        return (datetime.now() - datetime.strptime(ts, "%Y-%m-%d %H:%M")).total_seconds() / 3600
    except ValueError:
        return None


def fmt_age(h):
    if h is None:
        return "?"
    return f"{h:.0f} ч" if h < 48 else f"{h / 24:.1f} дн"


def main():
    if not os.path.exists(JOURNAL_PATH):
        sys.exit("journal.csv пока нет — сигналов ещё не было.")
    with open(JOURNAL_PATH, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        sys.exit("В journal.csv нет сигналов.")

    results = []
    print(f"\nПроверяю {len(rows)} сигнал(ов)…\n")
    print(f"   {'монета':<12} {'прошло':>8} {'цена тогда':>14} {'цена сейчас':>14} {'изменение':>10}  итог")
    print("   " + "-" * 76)

    for r in rows:
        mint, sym = r["адрес"], r["символ"] or r["адрес"][:6]
        p0 = to_float(r["цена_$"])
        age = hours_since(r["время"])
        p1, liq, change, outcome = evaluate(mint, p0)
        ch_txt = f"{change:+.0f}%" if change is not None else "?"
        print(f"   {sym:<12} {fmt_age(age):>8} {p0 or '?':>14} {p1 or '?':>14} {ch_txt:>10}  {outcome}")
        results.append({**r, "прошло_ч": round(age or 0, 1), "цена_сейчас_$": p1,
                        "ликвидность_сейчас_$": round(liq) if liq is not None else None,
                        "изменение_%": round(change, 1) if change is not None else None, "итог": outcome})
        time.sleep(0.5)

    with open(REVIEW_PATH, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        w.writeheader()
        w.writerows(results)

    plus = sum(1 for x in results if x["итог"].startswith("плюс"))
    minus = sum(1 for x in results if x["итог"] == "минус")
    flat = sum(1 for x in results if x["итог"] == "без изменений")
    scam = sum(1 for x in results if x["итог"].startswith("СКАМ"))
    changes = [x["изменение_%"] for x in results if x["изменение_%"] is not None]
    avg = sum(changes) / len(changes) if changes else None

    print("\n   Итог:")
    print(f"     в плюсе: {plus}   в минусе: {minus}   без изменений: {flat}   оказались скамом: {scam}")
    if avg is not None:
        print(f"     среднее изменение цены: {avg:+.1f}% (если бы вложил поровну в каждый сигнал)")
    young = sum(1 for x in results if (x["прошло_ч"] or 0) < 24)
    if young:
        print(f"     ⚠ {young} сигнал(ов) моложе суток — выводы по ним делать рано.")
    print(f"\n   Подробно сохранено в review.csv\n")


if __name__ == "__main__":
    main()
