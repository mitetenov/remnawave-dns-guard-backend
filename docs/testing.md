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
ANSIBLE_REPO_TOKEN="$(gh auth token)" docker buildx build --load --platform linux/amd64 \
  --secret id=ansible_repo_token,env=ANSIBLE_REPO_TOKEN -t remnawave-dns-guard-backend:local .
```

Оставлены изолированные unit-тесты: парсинг подписок, URL/IP и профилей, версии возможностей агента, Fernet/Unicode golden-векторы, политика активации узлов после успешных серий всех доступных чекеров и подтверждения DNS, а также provider API с подменённым HTTP transport. Проверки не открывают SQLite и не запускают другие сервисы, контейнеры или бинарные процессы. Python-интеграционные harness, Go-to-Go wire suite, image smoke и тесты реальной БД удалены по принятой политике тестирования.

CI использует Ubuntu 26.04, проверяет tidy/verify/gofmt/vet/golangci-lint v2.15.0, unit/race и production build. Compose проверяется с инертными CI-параметрами. При сборке образа AMD64 проверяется синтаксис двух встроенных плейбуков. Для сборки нужен доступ на чтение `mitetenov/ansible`. После этих проверок main публикует latest и sha-<полный commit SHA>. Тесты замены узла запускают имитацию Ansible и SSH. Тесты изолированы от UpCloud, Cloudflare, Remnawave, DNS и действующих узлов. [Сборка и CI](../README.md#сборка-и-ci)

## Замер DNS-сверки

Замер одного прохода с 50 активациями, ожидающими результатов, на 1000 узлах и трёх агентах. Тест использует SQLite в памяти и не обращается к Cloudflare.

```sh
go test -run '^$' -bench '^BenchmarkReconcilerPendingEnrollments$' -benchmem
```

## Частые причины отказа

| Симптом | Что проверить |
| --- | --- |
| Compose сообщает, что env file не найден | `.env` рядом с `docker-compose.yaml` |
| Backend не запускается | Секреты, `PUBLIC_ORIGIN`, права UID 10001 на `/data`, целостность SQLite и прежний `APP_SECRET` |
| Login/изменения дают 403 | Точный Origin, secure Cookie через HTTPS, сохранение заголовков proxy |
| Зоны Cloudflare не видны | `Zone Read` + `DNS Edit`, разрешённая зона |
| Remnawave 401/403 | HTTPS URL, API token и права чтения/изменения хостов, сохранение Authorization |
| Агент не виден | Одинаковый токен, HTTPS URL, исходящий доступ, отсутствие браузерной авторизации на `/api/agent/` |
| Проверки не идут | Здоровая контрольная связь, включённые цели, профиль и время следующего задания |
| Все цели ошибочны, control здоров | Общий VLESS профиль и доступность `PROBE_URLS` |
| Адрес protected | Последний фактический A; сначала добавьте и проверьте другой IP |
| Исключённый IP не вернулся | Автоматика, ручное включение, серия успехов и доступность Cloudflare |
| Docker unhealthy не перезапускается | Docker restart реагирует на завершение процесса, а не только на healthcheck |

Образ backend включает Ansible, плейбуки для заказов и OpenSSH. Healthcheck выполняет `/dns-guard --healthcheck`; для резервного копирования используйте встроенные `--backup`/`--restore` по инструкции. Передавайте обезличенные статусы и версии, не `.env`, SQLite, URI или конфиги с секретами.
