# SmallnGinxControl v1.0.8

Дата релиза: 2026-10-11

Git tag: `v1.0.8`

## Исправление

- Login script больше не падает, если Lucide asset недоступен: вызов `createIcons` проверяется перед использованием.
- При ошибке загрузки иконок продолжают работать вход, overview и выбор серверов.
- Обновлены cache-bust параметры Lucide и app/login scripts.

## Обновление

- Новый хост: installer по умолчанию устанавливает `v1.0.8`.
- Существующие серверы обновляйте по [deployment guide](deployment.md).

## Проверки

- Playwright имитирует недоступность Lucide и проверяет работу reveal-password, overview и server picker без JS runtime errors.
