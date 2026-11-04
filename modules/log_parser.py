"""Извлечение IP-адресов и SHA256-хэшей из текста."""

import re
from pathlib import Path


IP_PATTERN = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
SHA256_PATTERN = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")


def is_valid_ipv4(value: str) -> bool:
    """Проверить, что IPv4 содержит четыре октета от 0 до 255."""
    parts = value.split(".")
    return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)


def unique_in_order(values: list[str]) -> list[str]:
    """Убрать повторы, сохранив порядок первого появления."""
    return list(dict.fromkeys(values))


def parse_log(file_path: str | Path) -> tuple[list[str], list[str]]:
    """Прочитать лог и вернуть уникальные валидные IPv4 и SHA256."""
    text = Path(file_path).read_text(encoding="utf-8")
    ip_addresses = [value for value in IP_PATTERN.findall(text) if is_valid_ipv4(value)]
    hashes = [value.lower() for value in SHA256_PATTERN.findall(text)]
    return unique_in_order(ip_addresses), unique_in_order(hashes)
