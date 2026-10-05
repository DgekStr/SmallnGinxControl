# Развёртывание из Git

Production-установка клонирует версионированный релиз в `/opt/smallnginxcontrol`. Код, системная конфигурация и изменяемое состояние разделены: база, `SECRET_KEY`, сессии и SSH-секреты находятся в `/var/lib/smallnginxcontrol`, env-файл — в `/etc/smallnginxcontrol.env`.

## Требования

- Ubuntu/Debian с systemd и Python 3.12+.
- Git, nginx и доступ root для управления конфигурациями nginx.
- Для выпуска Let's Encrypt сертификатов через UI: Certbot, webroot `/var/www/html`, публично разрешённый входящий TCP/80 и DNS-имя, направленное на этот сервер. Само приложение не устанавливает Certbot.
- Сеть до GitHub/PyPI на время установки.
- Для прямого управления локальным nginx: `/usr/sbin/nginx`, `/var/log/nginx` и работающий systemd unit `nginx`.

Если `python3 -m venv` сообщает, что отсутствует `ensurepip`, установите пакет venv для текущего Python (например, `python3.12-venv`), затем повторите установку.

## Установка релиза

Сначала убедитесь, что `/opt/smallnginxcontrol`, `/etc/smallnginxcontrol.env` и systemd unit ещё не существуют. Установщик отказывается перезаписывать найденную установку.

```sh
git clone --depth 1 --branch v1.0.2 https://github.com/DgekStr/SmallnGinxControl.git /opt/smallnginxcontrol
cd /opt/smallnginxcontrol
sudo ./deploy/install.sh
```

`install.sh` предназначен для нового пустого хоста и запускается от root; при ручном клонировании установщику нужно задать `SNC_INSTALL_DIR` или использовать другой пустой каталог. Скрипт спрашивает IP/DNS панели, устанавливает Python-зависимости, создаёт env-файл с правами `0600`, запрашивает пароль администратора скрытым вводом, запускает миграции/bootstrap и включает systemd-сервис. Пароль не передаётся в аргументах процесса и не печатается. Требования Django к паролю: минимум 10 символов, не распространённый, не только цифры.

По умолчанию установщик клонирует стабильный release tag `v1.0.2`. Чтобы на новом пустом хосте развернуть текущую ветку `main` через тот же installer, сначала получите его скрипт, затем явно задайте ref:

```sh
git clone --depth 1 --branch main https://github.com/DgekStr/SmallnGinxControl.git /tmp/smallnginxcontrol-installer
cd /tmp/smallnginxcontrol-installer
sudo env SNC_RELEASE_TAG=main ./deploy/install.sh
```

Установщик сам клонирует выбранную ветку в `/opt/smallnginxcontrol`; установка по-прежнему требует пустого install path и отсутствующих systemd/env files. Ветка `main` подвижна и не заменяет immutable release tag для воспроизводимых установок. `git clone` получает только committed/pushed файлы: незакоммиченные изменения в рабочей копии в remote clone не попадут.

Проверить статус:

```sh
systemctl status smallnginxcontrol --no-pager
journalctl -u smallnginxcontrol -n 100 --no-pager
```

Приложение по умолчанию слушает только `127.0.0.1:7444`. Для первичного доступа используйте SSH-туннель:

```sh
ssh -N -L 7444:127.0.0.1:7444 root@SERVER
```

Затем откройте `http://127.0.0.1:7444`. Не меняйте `SNC_BIND` на публичный интерфейс, чтобы «открыть порт».

В локальном demo `SNC_BIND=127.0.0.1` также является значением по умолчанию. `serve.py` завершит запуск с ошибкой, если demo привязать к адресу, отличному от loopback: демо-пароль `admin / 12345` не предназначен для сетевого доступа. Для просмотра demo с другого компьютера используйте SSH-туннель из README. Не обходите эту проверку сменой bind; для постоянного сетевого доступа используйте production mode с сильным паролем, HTTPS reverse-proxy и ограничением firewall.

## HTTPS-доступ

Для постоянного внешнего адреса оставьте Waitress на loopback и настройте TLS reverse-proxy. Например, HTTPS на `192.0.2.15:7445` (TEST-NET documentation address) — только пример для отдельной машины; перед применением проверьте, что порт свободен и текущая конфигурация nginx сохранена. TLS сертификат должен содержать IP SAN. Self-signed сертификат шифрует соединение, но браузеры будут показывать предупреждение до доверия сертификату. Для сертификата без предупреждений используйте DNS-имя и публично доверенный CA.

В env-файле установить:

```sh
SNC_LOG_EXTRA_ROOTS=/var/http
SNC_CSRF_ORIGINS=https://PANEL-HOST:7445
SNC_TRUST_PROXY=1
SNC_SECURE_COOKIES=1
```

Затем выполнить `systemctl restart smallnginxcontrol`. Proxy обязан перезаписывать `Host` и `X-Forwarded-Proto`, а upstream должен оставаться `127.0.0.1:7444`. Разрешайте входящий TLS-порт только нужным сетям; не публикуйте backend HTTP напрямую.

## Обновление существующей установки

Сохраните БД, `/etc/smallnginxcontrol.env`, каталог state и текущий Git ref. Не заменяйте state и SECRET_KEY: от них зависят учётные записи и расшифровка SSH-паролей.

```sh
cd /opt/smallnginxcontrol
git status --short
git fetch --depth=1 origin main
if git show-ref --verify --quiet refs/heads/main; then
    git switch main
else
    git switch -c main FETCH_HEAD
fi
git pull --ff-only origin main
.venv/bin/pip install -r requirements.txt
set -a
. /etc/smallnginxcontrol.env
set +a
.venv/bin/python manage.py migrate --noinput
.venv/bin/python manage.py collectstatic --noinput
.venv/bin/python manage.py check
systemctl restart smallnginxcontrol
systemctl is-active smallnginxcontrol
systemctl enable --now smallnginxcontrol-log-cleanup.timer
```

Тег `v1.0.1` сохраняет предыдущий versioned release; текущая версия приложения — `v1.0.2`. Для установки предыдущего состояния используйте `git checkout v1.0.1`.

Если в каталоге есть локальные изменения, сначала сохраните их отдельно и не выполняйте `git reset --hard`.

## Reverse-proxy maintenance

Generated local и SSH host configs подключают `snippets/maintenance_all.conf` во все созданные `server`-блоки. Общий handler показывает `/var/www/html/maitenance.html` при 403/404 и 500/502/503/504 (ответ клиенту — 503). Для статического host поддерживаются `index.html` и `index.htm`. Перед включением убедитесь, что файл заглушки существует и читается nginx.

Стандартный выключаемый reverse proxy не удаляется из графа nginx: панель сохраняет оригинал в `$SNC_STATE_DIR/maintenance/`, включает `503` и показывает `/var/www/html/maitenance.html`. При включении оригинальный конфиг восстанавливается. Убедитесь, что файл страницы существует и читается пользователем nginx. Для proxy, уже подключающего `maintenance_all.conf`, используется имеющийся handler. Нестандартные include не переключаются автоматически.

Журналы читаются по директивам `access_log`/`error_log` из `$SNC_LOG_ROOT` и дополнительных абсолютных корней из `SNC_LOG_EXTRA_ROOTS` (по умолчанию `/var/http`). Для SSH-серверов этот список передаётся remote worker; SSH-пользователь должен иметь право читать указанные файлы. Динамические пути и пути вне разрешённых roots остаются заблокированы.

Удаление стандартного управляемого vhost доступно из UI с явным подтверждением, в том числе для активного сайта: интерфейс предупреждает о прекращении обслуживания. Конфиг и относящиеся к нему `sites-enabled` links удаляются транзакционно; перед удалением создаётся резервная копия, затем выполняются `nginx -t` и reload с rollback при ошибке. Upstream текущей панели защищён от удаления. Backup сохраняется в `$SNC_STATE_DIR/backups`; автоматически не очищается. Stream-конфиги и нестандартные include удалить из UI нельзя.

## Логи и retention

В `Настройки → Хранение логов` задаётся срок 1–3650 дней (по умолчанию 30). `smallnginxcontrol-log-cleanup.timer` запускается ежедневно примерно в 03:17: активные `/var/log/nginx/*-data.log` ротируются, nginx получает reopen, а архивы старше срока хранения удаляются. Другие журналы nginx команда не трогает. Проверка расписания: `systemctl list-timers smallnginxcontrol-log-cleanup.timer`; журнал работы: `journalctl -u smallnginxcontrol-log-cleanup.service`.

В `Настройки → TOP-5 по трафику` задаётся размер хвоста каждого access log для sampled traffic: default 128 КиБ, диапазон 1 байт–100 МБ. Настройка сохраняется в БД панели и применяется к локальным и SSH-managed nginx; просмотр содержимого журнала остаётся ограничен последними 128 КиБ.

Не редактируйте один nginx-файл параллельно через панель, shell, Certbot и другие средства. Перед production-операциями изучите конфиг, его include и журналы; сначала используйте `nginx -t`.

## GitHub и секреты

В Git входят исходники, vendor assets, тесты, документы и скриншоты. Не добавляйте `.env`, `var/`, `staticfiles/`, `.venv/`, `node_modules/`, `test-results/`, SQLite-файлы, private keys, production backups и любые реальные SSH-секреты. Секреты production хранятся вне checkout.