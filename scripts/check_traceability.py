#!/usr/bin/env python3

from __future__ import annotations

import csv
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGISTERS = ROOT / "registers"


def read_rows(filename: str) -> list[dict[str, str]]:
    path = REGISTERS / filename
    with path.open("r", encoding="utf-8-sig", newline="") as source:
        return list(csv.DictReader(source))


def values(rows: list[dict[str, str]], key: str) -> set[str]:
    return {row[key].strip() for row in rows if row.get(key, "").strip()}


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

    for line_number, row in enumerate(links, start=2):
        threat_id = row.get("threat_id", "").strip()
        asset_id = row.get("asset_id", "").strip()
        control_id = row.get("control_id", "").strip()
        test_id = row.get("test_id", "").strip()

        if threat_id not in threat_ids:
            errors.append(f"строка {line_number}: неизвестная угроза {threat_id!r}")
        if asset_id not in asset_ids:
            errors.append(f"строка {line_number}: неизвестный актив {asset_id!r}")
        if control_id not in control_ids:
            errors.append(f"строка {line_number}: неизвестная мера {control_id!r}")
        if not test_id:
            errors.append(f"строка {line_number}: не указан метод проверки")

        if threat_id:
            threat_links[threat_id] += 1

    for threat_id in sorted(threat_ids):
        if threat_links[threat_id] == 0:
            errors.append(f"для угрозы {threat_id} отсутствуют связи")

    print(f"Активов: {len(asset_ids)}")
    print(f"Угроз: {len(threat_ids)}")
    print(f"Мер защиты: {len(control_ids)}")
    print(f"Связей: {len(links)}")

    if errors:
        print("\nОбнаружены ошибки:")
        for error in errors:
            print(f"- {error}")
        return 1

    print("\nПроверка пройдена: все угрозы связаны с активами, мерами и испытаниями.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
