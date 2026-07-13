#!/usr/bin/env python3

from __future__ import annotations

import csv
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGISTERS = ROOT / "registers"
ID_PATTERNS = {
    "asset": re.compile(r"^A-\d{2}$"),
    "threat": re.compile(r"^T-\d{2}$"),
    "control": re.compile(r"^M-\d{2}$"),
    "test": re.compile(r"^P-\d{2}$"),
}


def read_rows(filename: str) -> list[dict[str, str]]:
    path = REGISTERS / filename
    with path.open("r", encoding="utf-8-sig", newline="") as source:
        return list(csv.DictReader(source))


def values(rows: list[dict[str, str]], key: str) -> set[str]:
    return {row[key].strip() for row in rows if row.get(key, "").strip()}


def check_ids(ids: set[str], kind: str, errors: list[str]) -> None:
    pattern = ID_PATTERNS[kind]
    for item_id in sorted(ids):
        if not pattern.fullmatch(item_id):
            errors.append(f"некорректный идентификатор {kind}: {item_id!r}")


def main() -> int:
    assets = read_rows("assets.csv")
    threats = read_rows("threats.csv")
    controls = read_rows("controls.csv")
    links = read_rows("traceability.csv")

    asset_ids = values(assets, "asset_id")
    threat_ids = values(threats, "threat_id")
    control_ids = values(controls, "control_id")

    errors: list[str] = []
    threat_links: Counter[str] = Counter()
    control_links: Counter[str] = Counter()

    check_ids(asset_ids, "asset", errors)
    check_ids(threat_ids, "threat", errors)
    check_ids(control_ids, "control", errors)

    for row_number, row in enumerate(threats, start=2):
        threat_id = row.get("threat_id", "").strip()
        if not row.get("bdu_search_key", "").strip():
            errors.append(f"строка threats.csv:{row_number}: для {threat_id} отсутствует ключ поиска БДУ")
        if row.get("status", "").strip() not in {"Актуальна", "Неактуальна", "Требует уточнения"}:
            errors.append(f"строка threats.csv:{row_number}: некорректный статус угрозы {threat_id}")

    for line_number, row in enumerate(links, start=2):
        threat_id = row.get("threat_id", "").strip()
        asset_id = row.get("asset_id", "").strip()
        control_id = row.get("control_id", "").strip()
        test_id = row.get("test_id", "").strip()

        if threat_id not in threat_ids:
            errors.append(f"строка traceability.csv:{line_number}: неизвестная угроза {threat_id!r}")
        if asset_id not in asset_ids:
            errors.append(f"строка traceability.csv:{line_number}: неизвестный актив {asset_id!r}")
        if control_id not in control_ids:
            errors.append(f"строка traceability.csv:{line_number}: неизвестная мера {control_id!r}")
        if not ID_PATTERNS["test"].fullmatch(test_id):
            errors.append(f"строка traceability.csv:{line_number}: некорректный метод проверки {test_id!r}")

        if threat_id:
            threat_links[threat_id] += 1
        if control_id:
            control_links[control_id] += 1

    for threat_id in sorted(threat_ids):
        if threat_links[threat_id] == 0:
            errors.append(f"для угрозы {threat_id} отсутствуют связи")

    for control_id in sorted(control_ids):
        if control_links[control_id] == 0:
            errors.append(f"мера {control_id} не используется в матрице трассируемости")

    print(f"Активов: {len(asset_ids)}")
    print(f"Угроз: {len(threat_ids)}")
    print(f"Мер защиты: {len(control_ids)}")
    print(f"Связей: {len(links)}")

    if errors:
        print("\nОбнаружены ошибки:")
        for error in errors:
            print(f"- {error}")
        return 1

    print("\nПроверка пройдена: реестры согласованы, все угрозы и меры имеют связи.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())