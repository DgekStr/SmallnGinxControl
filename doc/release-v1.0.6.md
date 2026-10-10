# SmallnGinxControl v1.0.6

Дата релиза: 2026-10-11

Git tag: `v1.0.6`

## Исправление

- При отключении из-за неоплаты sidecar `error_page 503` добавляется в начало каждого server-блока, до `maintenance_all.conf`.
- Shared maintenance handler больше не перехватывает неоплатную страницу; nginx отдаёт настроенный contact text и сохраняет HTTP 503.
- Добавлен POSIX integration test: реальный nginx запускается с shared generic handler, а тест проверяет фактическое тело 503-ответа.

## Обновление

- Новый хост: installer по умолчанию устанавливает `v1.0.6`.
- Существующие production-установки обновляйте по [deployment guide](deployment.md).

## Проверки

- Backend regression suite: 79 тестов, 77 пройдено, 2 платформенных пропущено в Windows-среде.
- Полный Playwright suite: 20 тестов пройдено.
- Linux integration test выполняется на production Linux перед включением блокировки домена.
