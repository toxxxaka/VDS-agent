# Диагностические команды

Короткие команды из заметок оформлены в скрипты. Все пути и цели задаются аргументами; где удобно, скрипт спрашивает путь при запуске в терминале.

| Задача | Команда |
| --- | --- |
| Интерфейс, шлюз, ping, HTTP и порты | `./network-trace.sh [--interface ens3] [--url https://example.com]` |
| Время DNS, TCP, TLS и ответа сайта | `./http-timing.sh https://example.com [--repeat 3]` |
| Процесс, исполняемый файл и соединения | `./process-inspect.sh 2147` |
| Коды, IP, пути и User-Agent в access log | `./web-log-report.sh /path/to/access.log [--exclude-ip 186.2.16,45.10.240]` |
| Крупные файлы в каталоге | `./large-files.sh /var/www [--top 50] [--min-mib 100]` |
| HTTP внутри контейнера | `./container-probe.sh CONTAINER [http://127.0.0.1:3000/]` |
| Нагрузка, OOM, SSH, Nginx и MySQL | `./system-triage.sh` |
| Ссылка входа ISPmanager | `sudo ./ispmanager-login-link.sh [--host IP]` |
| Скачать и просмотреть `check_tw` | `./fetch-check-tw.sh` |
| Запустить проверенный `check_tw` | `./fetch-check-tw.sh --sha256 HEX --run` |

`web-log-report.sh` рассчитан на обычный combined access log. Для нестандартного `log_format` поля могут отличаться. Ссылка ISPmanager содержит секрет; запускайте её генератор в личном терминале. Скачанный `check_tw` исполняется только после проверки заранее известного SHA-256.
