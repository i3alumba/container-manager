# Инструкции для агентов

## Область действия

Правила действуют для всего самостоятельного репозитория
`i3alumba/container-manager`. Перед изменениями прочитай `README.md`.

- `container_manager/` — FastAPI-контроллер, приватные gRPC/mTLS-агенты Incus и relay.
- `container_manager/proto/` — схема и сгенерированные RPC-модули; не правь
  сгенерированные файлы вручную.
- `tests/` — изолированные проверки без production, реального Incus и credentials.
- `examples/` — проверяемые оператором конфигурации, units, sudoers и INPUT guard;
  это не автоматический installer и не разрешение менять хосты.
- Dockerfile собирает только непривилегированный контроллер. UI остаётся в
  `i3alumba/dashboard`; CI, Kubernetes и закреплённый gitlink принадлежат
  `LumbaBalumba/public-page`.

## Ветки и публикация

Изменения проходят строго последовательно:

```text
dev → отдельная рабочая ветка → PR №1 в dev → проверенный dev → PR №2 в master
```

1. Проверь ветку, `git status`, локальные инструкции и удалённые refs. Не работай
   на detached HEAD, не переноси чужие изменения и не делай автоматический stash,
   reset или clean.
2. На чистом дереве: `git fetch origin`, `git switch dev`,
   `git pull --ff-only origin dev`, затем создай отдельную рабочую ветку. Если
   `dev` отсутствует или расходится с origin, остановись и согласуй действия.
3. Не коммить напрямую в `dev`/`master`, не обходи PR прямым push/cherry-pick/local
   merge в целевую ветку. PR №2 создаётся после слияния №1 и проверки `dev`.
4. Commit, push, создание/слияние PR и deployment требуют явного разрешения
   пользователя на соответствующие действия. Одно изменение кода не разрешает
   публикацию.
5. Родитель фиксирует доступный удалённо коммит отдельным gitlink-изменением после
   публикации подмодуля, по собственному порядку двух PR. Не используй
   `git submodule update --remote`. Само слияние этого репозитория не выпускает
   сервис; parent master может запустить production Jenkins.

## Разработка и проверки

Сохраняй архитектуру и делай минимальные целевые изменения. Используй Python/uv,
типизацию и простые зависимости; не обновляй версии без необходимости. Форматируй
только изменённые файлы: Python — Black, Markdown/JSON — Prettier. Из корня:

```sh
uv sync --locked
uv run pytest -q
uv run black --check container_manager tests examples/network-guard.py --exclude 'control_pb2'
uv run container-manager --help
```

Проверки с mocked host/API и localhost TLS не доказывают production-доступность,
изоляцию, restore или корректность полного внешнего TCP/UDP-пути. Реальные
приёмочные проверки описаны в README и требуют отдельного разрешения.

## Безопасность и данные

- Не сохраняй/не публикуй passwords, JWT, cookies, private keys, `.env`, kubeconfig,
  рабочие SQLite/backup/volume данные; не отражай их в ошибках, argv и логах.
- На каждом HTTP-запросе нужны live `is_active is True` + точный boolean
  `services.hosting is True` и явный bearer. Это согласованный per-service
  Hosting-admin contract; `is_staff`/`is_superuser` не обходят отсутствующий или
  отозванный grant. До readiness Auth сохраняет прежнее staff-derived право.
  Cookie-only и Auth outage закрываются отказом, без положительного grant cache.
- Incus socket и node agent — host-root trust boundary. Не выставляй Incus API
  публично и не монтируй socket в контроллер.
- Сохраняй unprivileged isolated UID/GID, отсутствие nesting/VM, managed-only
  devices и фиксированные project/pool/network. Никаких произвольных host paths,
  образов, upstream-адресов, shell/exec или удаления гостя через public API.
- Полный root и отдельный `/home` постоянны. Start/stop/password/port edits не
  пересоздают гостя и не удаляют данные. Нет дисковой квоты; SSD exhaustion — риск.
- Любой новый mapping проверяет реальные sockets/NAT/nft обоих узлов и registry,
  затем получает исключительное резервирование. Неизвестное — отказ, не «free».
  Не убивай чужие listeners и не обходи неизвестные firewall-правила.
- Не меняй production, версии ядра/k3s/Docker, старые сервисы, network/firewall,
  диски/PVC/БД и project restrictions без явного разрешения. Не flush/reset rules,
  не поднимай намеренно остановленные workloads ради проверки. UID/network
  isolation нельзя ослаблять ради зелёного теста.
- Существующие runtime-блокеры README остаются блокерами выпуска. Вынос в submodule
  не означает согласование нового TCP-target поведения или backup-policy.

## Отчёт

Укажи ветки/файлы, реально выполненные проверки, ограничения и незакрытые гейты.
Отдельно различай подготовленный код, commits/push, PR и фактический deployment.
