"""Проверка IP-адресов и SHA256 через VirusTotal API v3."""

import logging

import requests


API_URL = "https://www.virustotal.com/api/v3"
REQUEST_TIMEOUT = 10
STAT_NAMES = ("malicious", "suspicious", "harmless", "undetected")


def mock_result() -> dict:
    """Вернуть явный результат без обращения к VirusTotal."""
    return {
        "status": "mock",
        "result": "NOT_CHECKED",
        "message": "VirusTotal check skipped: API key was not provided",
    }


def error_result(message: str) -> dict:
    """Сформировать единообразное описание ошибки проверки."""
    logging.error("VirusTotal error: %s", message)
    return {"status": "error", "result": "ERROR", "message": message}


def check_value(endpoint: str, api_key: str | None) -> dict:
    """Выполнить запрос к VirusTotal и получить статистику анализа."""
    if not api_key:
        return mock_result()

    try:
        response = requests.get(
            f"{API_URL}/{endpoint}",
            headers={"x-apikey": api_key},
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
    except requests.Timeout:
        return error_result("VirusTotal request timed out")
    except requests.ConnectionError:
        return error_result("Could not connect to VirusTotal")
    except requests.HTTPError:
        return error_result(f"VirusTotal returned HTTP {response.status_code}")
    except requests.RequestException as error:
        return error_result(f"VirusTotal request failed: {error}")

    try:
        payload = response.json()
    except requests.exceptions.JSONDecodeError:
        return error_result("VirusTotal returned invalid JSON")

    try:
        stats = payload["data"]["attributes"]["last_analysis_stats"]
        values = {name: int(stats[name]) for name in STAT_NAMES}
    except (KeyError, TypeError, ValueError):
        return error_result("VirusTotal response is missing last_analysis_stats")

    return {"status": "checked", "result": "CHECKED", **values}


def check_ip(ip_address: str, api_key: str | None = None) -> dict:
    """Проверить IPv4-адрес."""
    return check_value(f"ip_addresses/{ip_address}", api_key)


def check_hash(file_hash: str, api_key: str | None = None) -> dict:
    """Проверить SHA256-хэш файла."""
    return check_value(f"files/{file_hash}", api_key)
