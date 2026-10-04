# SmallnGinxControl v1.0.1

Дата релиза: 2026-10-04

Git tag: `v1.0.1`

## Изменения

- Во всех стандартных enabled/disabled vhost включена запись access logs в `/var/log/nginx/<host>-data.log`; существующие destinations сохранены. Операция выполняется после dry-run, backup, `nginx -t` и rollback-capable reload.
- Production logs включены для 44 server-блоков в 40 конфигурациях; retention timer активен.
- В Settings добавлен срок хранения host logs от 1 до 3650 дней, начальное значение 30 дней.
- Добавлены `smallnginxcontrol-log-cleanup.service` и ежедневный timer. Активные `*-data.log` ротируются, nginx получает reopen, архивы старше retention удаляются. Остальные nginx logs не затрагиваются.
- TOP-5 активных vhost отображает sampled bytes-sent из access logs горизонтальными полосами, в порядке убывания.
- Clone installer включает cleanup timer; README, документация и screenshots обновлены.

## Ограничения метрики трафика

TOP-5 суммирует распознаваемое поле status/bytes из последних 128 KiB каждого отдельного access log. Это не точный RX/TX интерфейса и не гарантированная статистика за фиксированное время. Хосты без access log, с `access_log off` или несовместимым custom format в рейтинг не попадают.

## Проверки

- 55 backend-тестов и 7 Playwright E2E-сценариев.
- Migration consistency, `manage.py check`, Python/JS syntax и installer syntax.
- Production: 44 server blocks получили per-host log directives; timer включён; HTTPS login возвращает 200, API без сессии — 401, `nginx -t` успешен.

## Развёртывание

Новый хост: [git clone deployment guide](deployment.md). Для существующего production checkout сохраните БД и `SECRET_KEY`, затем выполните migration/collectstatic и перезапустите panel service. Для версии исходников checkout tag `v1.0.1`.