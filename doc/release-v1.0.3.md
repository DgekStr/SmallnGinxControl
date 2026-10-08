# SmallnGinxControl v1.0.3

Дата релиза: 2026-10-08

Git tag: `v1.0.3`

## Изменения

- Production ingress по HTTPS на `0.0.0.0:7444`; Waitress backend изолирован на `127.0.0.1:7445`.
- Installer автоматически подготавливает self-signed certificate с SAN для IP/DNS и `localhost`; secure session/CSRF cookies включены.
- Для публичных host/proxy domains отображается WHOIS expiration: суточный кэш, немедленная проверка при выборе SSH-сервера, Public Suffix root matching и цветовые предупреждения за 30/20/10 дней.
- Для public host/proxy names показывается WHOIS-срок регистрации с daily cache и SSH refresh; IP/local domains исключены, поддомены сводятся к registrable root.
- В настройках панели доступны статус и fingerprint TLS-сертификата, скачивание публичного сертификата, перевыпуск и замена PEM-пары. Приватный ключ остаётся в state с правами `0600`; ошибки `nginx -t`/reload откатывают замену.
- Добавлена вкладка «О программе» внизу меню: GitHub, руководство, MIT License, авторство и условия распространения/возможного отдельного биллинга.
- README сокращён; подробная помощь вынесена в отдельный документ, обзор и список серверов обновлены свежими скриншотами.
- Installer поддерживает восстановление после ошибок; документация развёртывания, HTTPS-доступа и README обновлены.

## Обновление

- Новый хост: `deploy/install.sh` по умолчанию устанавливает release `v1.0.3`.
- Для существующего deployment следуйте миграции из [deployment guide](deployment.md); не запускайте fresh installer поверх сохранённых env/state.

## Проверки

- `manage.py check`, migration consistency, JavaScript и installer syntax.
- Backend: 101 тест пройден, один skipped; отдельный log-retention test зависит от системной даты.
- Playwright: сценарии About/Settings проходят; полный прогон может быть нестабилен в profile-switch test из-за disposed response.
- Production smoke: nginx `0.0.0.0:7444` отвечает по HTTPS, backend `7445` недоступен с LAN, secure cookie включён.
