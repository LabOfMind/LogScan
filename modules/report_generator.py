"""Сохранение отчётов LogScan в JSON и CSV."""

import csv
import json
from pathlib import Path


CSV_FIELDS = (
    "value",
    "type",
    "result",
    "date",
    "status",
    "malicious",
    "suspicious",
    "harmless",
    "undetected",
    "message",
)


def prepare_output_path(file_path: str | Path) -> Path:
    """Создать родительскую директорию отчёта при необходимости."""
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def save_json(items: list[dict], file_path: str | Path) -> None:
    """Сохранить читаемый JSON-отчёт в UTF-8."""
    path = prepare_output_path(file_path)
    with path.open("w", encoding="utf-8") as output_file:
        json.dump(items, output_file, ensure_ascii=False, indent=4)


def save_csv(items: list[dict], file_path: str | Path) -> None:
    """Сохранить CSV-отчёт со строкой заголовков."""
    path = prepare_output_path(file_path)
    with path.open("w", encoding="utf-8", newline="") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(items)
