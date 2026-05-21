# RKN Whitelist Probe — Plan

См. `spec.md` для полного описания задачи и архитектуры.

Размер: **Large** — кросс-cutting, 7 провайдеров, TUI, anti-ban логика.

### [x] Step: Спецификация и план
Зафиксировать требования в `spec.md`, описать многоступенчатую проверку и anti-ban стратегию.

### [x] Step: Скелет проекта и конфигурация
`requirements.txt`, `pyproject.toml`, `.gitignore`, `config.example.yaml`, `run.bat`, пакет `rkn_probe/`.
- модуль `config.py` (pydantic-модели для конфига)
- модуль `state.py` (журнал в JSON)
- модуль `rate_limiter.py` (троттлинг + jitter + killswitch)

### [x] Step: Многоступенчатая проверка IP
`checker.py` — стадии RangeCheck/ICMP/TCP/TLS-SNI/HTTP-Probe, агрегация результата.

### [x] Step: Адаптеры провайдеров
`providers/base.py` + 7 модулей. Каждый умеет: allocate_ip, associate(ip, vm), disassociate(ip), release(ip), list_ips. Полная реализация для Selectel и Yandex Cloud, скелеты с TODO для остальных 5 (с указанием endpoint'ов из их публичной документации).

### [x] Step: Оркестратор и TUI
`orchestrator.py` — координирует provider × checker с учётом rate-limit. `app.py` — Textual-приложение с панелями: провайдеры/прогресс/лог/найденный IP. Запуск через `python -m rkn_probe`.

### [x] Step: Smoke-test и проверка импорта
`python -m rkn_probe --check` (валидация конфига без сети) + dry-run в mock-режиме.
