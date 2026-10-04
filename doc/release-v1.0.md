# SmallnGinxControl v1.0

Дата релиза: 2026-10-04

Git tag: `v1.0`

Репозиторий: https://github.com/DgekStr/SmallnGinxControl

## Что входит

- Единая русскоязычная панель управления nginx с обзором метрик, хостов, reverse proxy, конфигураций, журналов и аудита.
- Изолированные профили нескольких серверов; удалённые операции через SSH с закреплённым SHA256 host fingerprint.
- Локальная аутентификация Django, смена пароля, CSRF, ограничение попыток входа, зашифрованное хранение SSH-секретов.
- Проверка активной конфигурации реальным `nginx -t`, транзакционная запись, резервные копии и откат при ошибках проверки/reload.
- Обратимый maintenance-режим для стандартного reverse proxy: HTTP 503 и `/var/www/html/maitenance.html`; исходный конфиг восстанавливается байт-в-байт.
- Просмотр access/error logs из `SNC_LOG_ROOT` и дополнительных ограниченных roots, в том числе `/var/http/<host>`.
- Подтверждаемое удаление только отключённых стандартных vhost с резервной копией и rollback при ошибке `nginx -t`/reload.
- Production deployment через `systemd`; центральное состояние хранится вне Git checkout.
- Локальные статические ресурсы, две темы, адаптивная desktop/mobile навигация.

## Проверки

- Django backend tests и Playwright E2E на Chrome.
- `manage.py check` и `node --check static/app.js`.
- Production-приёмка на Ubuntu: systemd active, HTTPS endpoint отвечает, nginx config test успешен, API без сессии возвращает 401.
- Сгенерированный maintenance-вариант production virtual host прошёл изолированный `nginx -t`; действующий сайт не переключался во время release-проверки.

## Установка

Новый хост: [инструкция git clone](deployment.md). Тег `v1.0` разворачивается через `deploy/install.sh`.

## Известные ограничения

- Панель — root-equivalent admin tool; доступ только доверенным администраторам. MFA и отдельный привилегированный helper не входят в v1.0.
- Для HTTPS по частному IP используется self-signed или внутренняя PKI; браузер должен доверять сертификату. Публично доверенный TLS проще получить на DNS-имя.
- Автоматический toggle ограничен стандартными `conf.d` и `sites-available`; нестандартные include требуют ручной работы.
- Проверка реального переключения сайта в production требует отдельного согласования окна; release acceptance не менял действующие сайты.