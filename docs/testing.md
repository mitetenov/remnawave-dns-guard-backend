# Проверки и диагностика

## Локальные команды

Нужен Go 1.27.3:

```sh
go mod tidy
go mod verify
test -z "$(gofmt -l $(git ls-files '*.go'))"
go vet ./...
golangci-lint run
go test -count=1 ./...
go test -race -vet=off -count=1 ./...
go build ./...
docker build --platform linux/amd64 -t remnawave-dns-guard-backend:local .
```

Оставлены изолированные unit-тесты: парсинг подписок, URL/IP и профилей, версии возможностей агента, Fernet/Unicode golden-векторы, а также provider API с подменённым HTTP transport. Проверки не открывают SQLite и не запускают другие сервисы, контейнеры или бинарные процессы. Python-интеграционные harness, Go-to-Go wire suite, image smoke и тесты реальной БД удалены по принятой политике тестирования.

CI использует Ubuntu 26.04, проверяет tidy/verify/gofmt/vet/golangci-lint v2.15.0, unit/race и production build. Compose проверяется с инертными CI-параметрами; Docker-образ только собирается и проверяется на AMD64. После этих проверок main сохраняет публикацию latest и sha-<полный commit SHA>; PR не публикует. Живые Cloudflare/Remnawave, базы, DNS и узлы в тестах не используются. Runtime SQLite, HTTP API, healthcheck и backup/restore остаются production-функциями.

## Частые причины отказа

| Симптом | Что проверить |
| --- | --- |
| Compose сообщает, что env file не найден | `.env` рядом с `docker-compose.yaml` |
| Backend не запускается | Секреты, `PUBLIC_ORIGIN`, права UID 10001 на `/data`, целостность SQLite и прежний `APP_SECRET` |
| Login/изменения дают 403 | Точный Origin, secure Cookie через HTTPS, сохранение заголовков proxy |
| Зоны Cloudflare не видны | `Zone Read` + `DNS Edit`, разрешённая зона |
| Remnawave 401/403 | HTTPS URL, API token и read scopes, сохранение Authorization |
| Агент не виден | Одинаковый токен, HTTPS URL, исходящий доступ, отсутствие браузерной авторизации на `/api/agent/` |
| Проверки не идут | Здоровая контрольная связь, включённые цели, профиль и время следующего задания |
| Все цели ошибочны, control здоров | Общий VLESS профиль и доступность `PROBE_URLS` |
| Адрес protected | Последний фактический A; сначала добавьте и проверьте другой IP |
| Исключённый IP не вернулся | Автоматика, ручное включение, серия успехов и доступность Cloudflare |
| Docker unhealthy не перезапускается | Docker restart реагирует на завершение процесса, а не только на healthcheck |

В runtime нет shell, curl, Python и sqlite CLI. Healthcheck выполняет `/dns-guard --healthcheck`; для резервного копирования используйте встроенные `--backup`/`--restore` по инструкции. Передавайте обезличенные статусы и версии, не `.env`, SQLite, URI или конфиги с секретами.
