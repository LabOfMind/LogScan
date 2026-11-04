"""Точка входа CLI-утилиты LogScan."""

import argparse
import logging
from datetime import datetime
from pathlib import Path

from modules.log_parser import parse_log
from modules.report_generator import save_csv, save_json
from modules.virustotal import check_hash, check_ip


def configure_logging() -> None:
    """Настроить запись журнала работы в файл logscan.log."""
    logging.basicConfig(
        filename="logscan.log",
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        encoding="utf-8",
    )


def parse_arguments() -> argparse.Namespace:
    """Получить и проверить аргументы командной строки."""
    parser = argparse.ArgumentParser(description="Анализ IP и SHA256 в серверных логах")
    parser.add_argument(
        "-log-file", "--log-file", required=True, dest="log_file", help="Путь к лог-файлу"
    )
    parser.add_argument(
        "-api-key", "--api-key", dest="api_key", help="API-ключ VirusTotal"
    )
    parser.add_argument(
        "-output", "--output", required=True, help="Путь к файлу отчёта"
    )
    parser.add_argument(
        "-format", "--format", required=True, choices=("json", "csv"), dest="report_format"
    )
    return parser.parse_args()


def make_report_item(value: str, item_type: str, check_result: dict) -> dict:
    """Добавить к результату обязательные поля отчёта."""
    return {
        "value": value,
        "type": item_type,
        "result": check_result.get("result", "ERROR"),
        "date": datetime.now().astimezone().isoformat(timespec="seconds"),
        **{key: value for key, value in check_result.items() if key != "result"},
    }


def main() -> int:
    """Запустить анализ лога и сохранить отчёт."""
    configure_logging()
    logging.info("LogScan started")
    args = parse_arguments()
    log_path = Path(args.log_file)
    output_path = Path(args.output)
    logging.info("Log file: %s", log_path)

    if not log_path.is_file():
        message = f"Ошибка: лог-файл не найден: {log_path}"
        print(message)
        logging.error(message)
        return 1

    try:
        ip_addresses, hashes = parse_log(log_path)
        print(f"Найдено IP: {len(ip_addresses)}; SHA256: {len(hashes)}")
        logging.info("Found %d IP addresses and %d SHA256 hashes", len(ip_addresses), len(hashes))

        report_items = []
        for ip_address in ip_addresses:
            logging.info("Checking IP: %s", ip_address)
            report_items.append(make_report_item(ip_address, "IP", check_ip(ip_address, args.api_key)))

        for file_hash in hashes:
            logging.info("Checking HASH: %s", file_hash)
            report_items.append(make_report_item(file_hash, "HASH", check_hash(file_hash, args.api_key)))

        if args.report_format == "json":
            save_json(report_items, output_path)
        else:
            save_csv(report_items, output_path)

        logging.info("Report created: %s", output_path)
        logging.info("LogScan finished")
        print(f"Отчёт сохранён: {output_path}")
        return 0
    except (OSError, UnicodeError) as error:
        logging.exception("File processing error")
        print(f"Ошибка обработки файла: {error}")
        return 1
    except Exception as error:
        logging.exception("Unexpected error")
        print(f"Непредвиденная ошибка: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
