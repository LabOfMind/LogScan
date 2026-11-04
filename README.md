# LogScan

LogScan — учебная CLI-утилита на Python для поиска IPv4-адресов и SHA256-хэшей в серверном логе. Она удаляет дубликаты, проверяет артефакты через VirusTotal API v3 (или безопасно пропускает проверку без ключа) и сохраняет отчёт в JSON либо CSV.

## Структура проекта

```text
LogScan/
├── main.py
├── requirements.txt
├── README.md
├── .gitignore
├── logs/
│   └── sample.log
├── output/
│   ├── report.json
│   └── report.csv
└── modules/
    ├── __init__.py
    ├── log_parser.py
    ├── virustotal.py
    └── report_generator.py
```

После запуска в корне также создаётся `logscan.log` с журналом работы.

## Требования

- Python 3.10 или новее;
- доступ в интернет и API-ключ нужны только для настоящей проверки VirusTotal.

## Установка в Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Установка в Windows PowerShell

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## Запуск

Без API-ключа включается mock-режим. Запросы в VirusTotal не отправляются, а отчёт явно содержит результат `NOT_CHECKED`:

```bash
python main.py --log-file logs/sample.log --output output/report.json --format json
```

С VirusTotal API key:

```bash
python main.py --log-file logs/sample.log --api-key YOUR_API_KEY --output output/report.json --format json
```

Для CSV укажите другой выходной файл и формат:

```bash
python main.py -log-file logs/sample.log -output output/report.csv -format csv
```

Не записывайте настоящий API-ключ в исходный код или Git.

## Аргументы CLI

| Аргумент | Обязательный | Назначение |
|---|---:|---|
| `-log-file`, `--log-file` | да | путь к анализируемому лог-файлу |
| `-api-key`, `--api-key` | нет | ключ VirusTotal; без него работает mock-режим |
| `-output`, `--output` | да | путь для нового отчёта; папки создаются автоматически |
| `-format`, `--format` | да | формат отчёта: только `json` или `csv` |

## Пример JSON

```json
[
    {
        "value": "192.168.1.10",
        "type": "IP",
        "result": "NOT_CHECKED",
        "date": "2026-10-18T12:00:00+03:00",
        "status": "mock",
        "message": "VirusTotal check skipped: API key was not provided"
    }
]
```

## Пример CSV

```csv
value,type,result,date,status,malicious,suspicious,harmless,undetected,message
192.168.1.10,IP,NOT_CHECKED,2026-10-18T12:00:00+03:00,mock,,,,,VirusTotal check skipped: API key was not provided
```

При успешной настоящей проверке поля `malicious`, `suspicious`, `harmless` и `undetected` содержат статистику VirusTotal. Сетевые и HTTP-ошибки записываются в отчёт со статусом `error`, не прерывая проверку остальных объектов.
