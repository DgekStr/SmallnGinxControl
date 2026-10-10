# Развёртывание из Git

Production-установка клонирует версионированный релиз в `/opt/smallnginxcontrol`. Код, системная конфигурация и изменяемое состояние разделены: база, `SECRET_KEY`, сессии и SSH-секреты находятся в `/var/lib/smallnginxcontrol`, env-файл — в `/etc/smallnginxcontrol.env`.

## Требования

- Ubuntu/Debian с systemd и Python 3.12+.
- Git и доступ root для управления конфигурациями nginx. Если nginx отсутствует на Debian/Ubuntu, installer установит его через `apt-get`.
- Для выпуска Let's Encrypt сертификатов через UI: Certbot, webroot `/var/www/html`, публично разрешённый входящий TCP/80 и DNS-имя, направленное на этот сервер. Само приложение не устанавливает Certbot.
- Сеть до GitHub/PyPI на время установки.
- Для WHOIS-срока регистрации доменов: исходящий TCP/43 к WHOIS-серверам нужных доменных зон. Если доступ закрыт, панель продолжит работать, но срок покажет как неизвестный.
- Для прямого управления локальным nginx: `/usr/sbin/nginx`, `/var/log/nginx` и работающий systemd unit `nginx`.

Если `python3 -m venv` сообщает, что отсутствует `ensurepip`, установщик попробует поставить соответствующий текущему Python пакет `pythonX.Y-venv` через `apt-get` на Debian/Ubuntu и повторит создание окружения. На других системах установите venv-пакет для активной версии Python вручную и запустите установщик повторно.

## Установка релиза

Сначала убедитесь, что `/opt/smallnginxcontrol`, `/etc/smallnginxcontrol.env` и systemd unit ещё не существуют. Установщик отказывается перезаписывать найденную установку.

```sh
git clone --depth 1 --branch v1.0.4 https://github.com/DgekStr/SmallnGinxControl.git /opt/smallnginxcontrol
cd /opt/smallnginxcontrol
sudo ./deploy/install.sh
```

`install.sh` предназначен для нового пустого хоста и запускается от root; при ручном клонировании установщику нужно задать `SNC_INSTALL_DIR` или использовать другой пустой каталог. Скрипт спрашивает IP/DNS панели и пароль администратора (скрытый ввод), устанавливает зависимости, создаёт env-файл с правами `0600`, запускает миграции/bootstrap и включает systemd-сервис. Пароль не передаётся в аргументах процесса и не печатается. Требования Django к паролю: минимум 10 символов, не распространённый, не только цифры. Installer выпускает локальный self-signed сертификат с SAN для IP/DNS панели и `localhost`, настраивает nginx TLS frontend на `0.0.0.0:7444`, а Waitress оставляет на `127.0.0.1:7445`; HTTP upstream наружу не публикуется. При ошибке после начала настройки installer останавливает созданные службы и удаляет созданные TLS/env/unit-файлы, сохраняя каталог state для безопасного повторного запуска.

По умолчанию установщик клонирует стабильный release tag `v1.0.4`. Чтобы на новом пустом хосте развернуть текущую ветку `main` через тот же installer, сначала получите его скрипт, затем явно задайте ref:

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

В production nginx принимает HTTPS на `0.0.0.0:7444`, Waitress слушает только `127.0.0.1:7445`. Откройте `https://SERVER-IP:7444`. Self-signed сертификат шифрует соединение, но не доверен клиентскому браузеру автоматически. Войдите в панель, откройте `Настройки → HTTPS панели`, скачайте публичный сертификат и добавьте его в доверенные сертификаты ОС/браузера; либо подтвердите предупреждение браузера. Не передавайте и не скачивайте приватный ключ.

Для доступа через SSH-туннель используйте:

```sh
ssh -N -L 7444:127.0.0.1:7444 root@SERVER
```

Затем откройте `https://localhost:7444`. Браузер покажет предупреждение, пока сертификат не будет доверен. Backend остаётся на loopback `127.0.0.1:7445`; не меняйте `SNC_BIND` на публичный интерфейс.

В локальном demo `SNC_BIND=127.0.0.1` и `SNC_PORT=7444` остаются значениями по умолчанию; demo обслуживается по HTTP и не меняет системный nginx. `serve.py` блокирует bind demo на сетевой интерфейс: пароль `admin / 12345` предназначен только для локального просмотра. Для постоянного сетевого доступа используйте production installer с TLS frontend и сильным паролем.

## HTTPS-доступ

В `Настройки → HTTPS панели` можно перевыпустить self-signed сертификат либо заменить его парой PEM certificate/private key. Принимается только незашифрованный private key, совпадающий с сертификатом; SAN должен покрывать настроенный IP/DNS панели. Перед заменой панель проверяет пару, выполняет `nginx -t` и reload; при неудаче восстанавливает предыдущие файлы и конфигурацию. Private key хранится в каталоге state с правами `0600`, никогда не возвращается в API и недоступен для скачивания.

Для сертификата без предупреждений замените self-signed пару на сертификат доверенного CA, содержащий SAN для имени/IP панели. После перевыпуска self-signed сертификата клиентские устройства должны доверить новый публичный сертификат.

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
install -o root -g root -m 0644 deploy/smallnginxcontrol-domain-expiry.service /etc/systemd/system/smallnginxcontrol-domain-expiry.service
install -o root -g root -m 0644 deploy/smallnginxcontrol-domain-expiry.timer /etc/systemd/system/smallnginxcontrol-domain-expiry.timer
systemctl daemon-reload
systemctl enable --now smallnginxcontrol-domain-expiry.timer
```

Для существующей установки до TLS frontend не запускайте fresh `install.sh`: он откажется перезаписывать systemd/env. После fast-forward обновления кода и `pip install`, сделайте одноразовый переход, сохранив env вне репозитория:

```sh
sudo cp -a /etc/smallnginxcontrol.env /var/lib/smallnginxcontrol/env.pre-panel-tls
sudo systemctl stop smallnginxcontrol
sudo python3 - <<'PY'
from pathlib import Path

path = Path('/etc/smallnginxcontrol.env')
lines = path.read_text().splitlines()
values = dict(line.split('=', 1) for line in lines if '=' in line and not line.lstrip().startswith('#'))
updates = {
    'SNC_PORT': '7445',
    'SNC_CSRF_ORIGINS': f"https://{values['SNC_SERVER']}:7444,https://localhost:7444",
    'SNC_TRUST_PROXY': '1',
    'SNC_SECURE_COOKIES': '1',
}
for key, value in updates.items():
    prefix = key + '='
    for index, line in enumerate(lines):
        if line.startswith(prefix):
            lines[index] = prefix + value
            break
    else:
        lines.append(prefix + value)
path.write_text('\n'.join(lines) + '\n')
path.chmod(0o600)
PY
sudo systemctl start smallnginxcontrol
cd /opt/smallnginxcontrol
set -a
. /etc/smallnginxcontrol.env
set +a
sudo -E .venv/bin/python manage.py shell -c 'from panel.panel_tls import install_panel_tls; install_panel_tls()'
sudo systemctl is-active smallnginxcontrol nginx
```

Затем проверьте `https://SNC_SERVER:7444/login/` и импортируйте публичный сертификат через `Настройки → HTTPS панели`. Если переключение не удалось, восстановите сохранённый env-файл и запустите службу, затем проверьте `nginx -t` и журнал до повторной попытки.

Тег `v1.0.2` сохраняет предыдущий versioned release; текущая версия приложения — `v1.0.4`. Для установки предыдущего состояния используйте `git checkout v1.0.2`.

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