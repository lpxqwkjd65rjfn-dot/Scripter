# RKN Whitelist Probe — Spec

## Контекст
В РФ при включении режима «белого списка Минцифры» оператор связи
пропускает трафик только на ограниченное множество публичных IP.
Цель скрипта — для пользователя, физически подключённого к такому
оператору, определить, какой публичный IP в одном из российских
облаков попадает в этот белый список (т.е. реально достижим из сети
оператора).

## Поддерживаемые провайдеры
1. VK Cloud (OpenStack-based)
2. Yandex Cloud
3. SberCloud (Advanced)
4. Selectel (My Selectel / OpenStack)
5. Timeweb Cloud
6. UFOhosting
7. CDNvideo

## Сценарий работы
1. Пользователь подключается к нужному оператору вручную (USB-модем / Wi-Fi / VPN-bypass и т.п.).
2. Запускает скрипт (`run.bat`) на Windows.
3. В TUI выбирает провайдеров и нажимает Start.
4. Скрипт аллоцирует Floating/Elastic IP через API провайдера, привязывает к заранее подготовленной "пробной" VM с открытым HTTP-сервисом (или использует существующий пул IP), затем тестирует достижимость С локальной машины.
5. При обнаружении «белого» IP — скрипт останавливает перебор, показывает IP и предлагает оставить его за пользователем.
6. «Чёрные» IP освобождаются обратно в пул с задержкой.

## Многоступенчатая проверка (anti-false-positive)
Для каждого IP последовательно:
1. **AllocCheck** — API подтверждает, что IP аллоцирован и принадлежит нашему аккаунту.
2. **RangeCheck** — IP попадает в опубликованный CIDR-диапазон провайдера (WHOIS / known ranges).
3. **ICMP** — `ping` с локальной машины (опционально, многие операторы режут ICMP).
4. **TCP** — connect на порты 443 и 80 с таймаутом.
5. **TLS-SNI** — TLS-handshake с заданным SNI (для отсечения DPI-блока по SNI).
6. **HTTP-Probe** — GET `/probe` к нашему health-сервису на этой VM; ожидается заголовок-маркер `X-Probe: ok`.
   Это финальное подтверждение: IP проходит через белый список и трафик доходит до приложения.

IP считается «whitelisted» только если пройдены **стадии 4–6**.

## Anti-ban
Главная цель — не получить блок аккаунта у провайдера.
- Per-provider rate-limit: `min_interval_seconds`, `max_ops_per_hour`.
- Exponential backoff на 4xx/5xx и rate-limit-ответы.
- Random jitter ±20% на все интервалы.
- Глобальный killswitch при N подряд ошибках 401/403.
- Все API-операции логируются в `state.json` (для аудита и восстановления).
- Graceful shutdown освобождает все аллоцированные IP.

## Стек
- Python 3.11+
- `textual` + `rich` — TUI
- `httpx` — async HTTP клиент для всех API
- `pydantic` v2 — конфиг и модели
- `pyyaml` — конфиг
- `tenacity` — ретраи с backoff

## Структура проекта
```
.
├── run.bat                    # Запуск на Windows
├── requirements.txt
├── pyproject.toml
├── config.example.yaml        # Шаблон конфига
├── .gitignore
└── rkn_probe/
    ├── __init__.py
    ├── __main__.py            # python -m rkn_probe
    ├── app.py                 # Textual UI
    ├── config.py              # Загрузка конфига
    ├── checker.py             # Многоступенчатая проверка IP
    ├── rate_limiter.py        # Анти-бан троттлинг
    ├── state.py               # Журнал и persistence
    ├── orchestrator.py        # Координатор: provider × checker
    └── providers/
        ├── base.py            # Абстрактный CloudProvider
        ├── vk.py
        ├── yandex.py
        ├── sber.py
        ├── selectel.py
        ├── timeweb.py
        ├── ufohosting.py
        └── cdnvideo.py
```

## Что НЕ делаем в MVP
- Автоматическое создание VM с cloud-init: пользователь должен заранее
  подготовить одну «probe-VM» в каждом облаке с публичным HTTP-сервисом,
  отдающим `X-Probe: ok` на `/probe`. Это безопаснее (минимум API-операций)
  и снимает риск бана за массовое создание ВМ.
- Скрипт оперирует только **Floating/Elastic IP** — связывает/отвязывает
  их от probe-VM.
