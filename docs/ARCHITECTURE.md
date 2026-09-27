# Monitoringbot v4 — техническое описание

## Назначение

Monitoringbot — защищённая консоль наблюдения и управляемых операций Debian-сервера. Она работает через Telegram-бота и HTTPS WebUI. Система рассчитана на одного или несколько явно разрешённых владельцев, а не на публичный мониторинг.

## Доступ и защита

WebUI принимает Telegram Mini App `initData` с серверной HMAC-проверкой, проверяет Telegram user ID, срок `auth_date`, затем требует TOTP. Обычный браузер допускается только с IP из `web_allowed_ips` и проходит тот же TOTP. Сессии серверные, живут один час, записаны в SQLite и помечаются HttpOnly, Secure, SameSite=Strict cookie. Nginx ограничивает WebUI тем же IP allow-list.

Все действия пишутся в `audit_log`; секреты, TOTP, токен Telegram и confirmation tokens туда не попадают.

## Данные и надёжность

SQLite находится в `/var/lib/monitoringbot/monitoring.db`, использует WAL. Таблицы: `incidents`, `incident_events`, `snapshots`, `audit_log`, `pending_actions`, `command_runs`. Incidents и snapshots переживают рестарт. Legacy JSON сохраняется только как миграционный источник и конфигурация.

## Мониторинг

- CPU, load average, memory, swap, disk, network, сервисы.
- Периодические snapshots каждую минуту: CPU, RAM/cache, I/O, RX/TX.
- Графики за час, день и неделю, фиксированная или адаптивная шкала.
- Incident Engine: active/recovered/closed, warning/high/critical, deduplication, hysteresis, cooldown, acknowledgement и close.
- CPU/load, OOM, высокий входящий трафик, SSH login alerts, ежедневный отчёт в 06:00 UTC.

## Telegram

Сохранены `/status`, `/daily`, `/ping`, `/cpu`, `/ram`, `/disk`, `/load`, `/uptime`, `/sessions`, `/sshlogins`, `/killssh`, `/reboot`, `/shutdown`, `/logout`. Опасные команды требуют отдельного подтверждения. SSH-сессии перечисляются и завершаются только через ограниченный helper.

## WebUI

Dashboard, Incidents, Activity, Statistics, Tools, Backups, Client scripts, Firewall, внешние проверки. Интерфейс mobile-first: safe areas, 16px inputs, touch-action, press feedback, reduced motion, семантические статусы и доступные цветовые контрасты.

## Инструменты

- Backup: rsync в датированную директорию, metadata.json и backup.log; локальное `/root/backups` или подключённый носитель.
- Client scripts: просмотр, копирование или одноразовая wget-ссылка на десять минут.
- Password generator: криптографически случайный `5-6-7` из букв, цифр и символов.
- SSL: TLS protocol, cipher, issuer, expiry и days left.
- Check-Host: HTTP/ping/TCP/DNS с несколькими внешними узлами.
- Cheburcheck: безопасная ссылка проверки домена/IP на блокировки.

## Firewall

WebUI никогда не запускает `sudo`/`nft`. Root bridge `monitorbot-infrad.service` принимает фиксированный протокол по Unix socket только от `monitorbot`. Он показывает текущий ruleset, создаёт snapshot, preview и применяет собственную таблицу `inet monitoringbot`, не перезаписывая Docker или другие nftables tables. Профили: none, standard, hard. Hard предлагает IP запроса и переключатель сохранения HTTPS; откатывается через 120 секунд, пока WebUI не подтвердит соединение.

## Привилегии

Сервисы имеют `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem`, `ProtectHome` и минимальные `ReadWritePaths`. Root доступен только узким helpers: backup bridge, firewall bridge, SSH terminate helper и заранее определённые power actions. Пользовательский ввод не передаётся в shell; subprocess использует argument arrays.

## Ограничение консоли

В проекте нет произвольного браузерного root shell. Для аварийного доступа используются SSH/консоль провайдера и подтверждённые allow-listed операции. Это исключает превращение WebUI в удалённый root endpoint.
