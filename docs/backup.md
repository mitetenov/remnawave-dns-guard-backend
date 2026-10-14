# Резервная копия SQLite

База содержит настройки, цели, состояние, журнал и зашифрованные секреты. Храните копии и соответствующий `APP_SECRET` отдельно от сервера, с ограниченным доступом. SQLite backup API ниже создаёт согласованный снимок, включая данные WAL; копировать один `guard.db` во время работы нельзя.

## Копирование работающего backend

Из корня проекта:

```sh
mkdir -p backups
chmod 700 backups
docker compose exec -T backend python - <<'PY'
import os, sqlite3
path = '/tmp/guard-backup.db'
if os.path.exists(path):
    os.unlink(path)
fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
os.close(fd)
source = sqlite3.connect('file:/data/guard.db?mode=ro', uri=True)
backup = sqlite3.connect(path)
source.backup(backup)
assert backup.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
backup.close()
source.close()
os.chmod(path, 0o600)
PY
docker compose cp backend:/tmp/guard-backup.db backups/guard-backup.db
chmod 600 backups/guard-backup.db
docker compose exec -T backend rm /tmp/guard-backup.db
```

Команда перезаписывает `backups/guard-backup.db`: перед повторным запуском переименуйте прошлую копию. Проверьте размер и храните версии с датой. Защищённую копию `.env` (или секреты в менеджере секретов) храните отдельно; она нужна для восстановления `APP_SECRET`, доступа администратора и токена агента. Резервная копия БД сама не откатывает уже выполненные изменения Cloudflare DNS.

## Восстановление

Сначала сделайте новую копию текущего состояния. Используйте доверенный проверенный файл `backups/guard-backup.db`, исходный `APP_SECRET` и совместимую версию исходников. Команды ниже **заменяют БД**; backend должен быть остановлен, другой экземпляр не должен писать в тот же том. **Перед восстановлением остановите RU-агент** на его хосте (`docker compose stop agent`), чтобы автоматические DNS-операции из старого снимка не начались до вашей проверки.

```sh
docker compose stop backend
docker compose run --rm --no-deps -T --user 0 --cap-add CHOWN --cap-add DAC_OVERRIDE \
  -v "$PWD/backups:/backup:ro" backend python - <<'PY'
import os, sqlite3
source = sqlite3.connect('file:/backup/guard-backup.db?mode=ro', uri=True)
if source.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
    raise SystemExit('Backup integrity check failed; current database was not touched')
staged = '/data/guard-restore.db'
if os.path.exists(staged):
    os.unlink(staged)
fd = os.open(staged, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
os.close(fd)
restored = sqlite3.connect(staged)
source.backup(restored)
if restored.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
    raise SystemExit('Restored database integrity check failed')
restored.close()
source.close()
os.chown(staged, 10001, 10001)
for path in ('/data/guard.db-wal', '/data/guard.db-shm'):
    if os.path.exists(path):
        os.unlink(path)
os.replace(staged, '/data/guard.db')
PY
docker compose start backend
curl --fail http://127.0.0.1:8080/api/health
```

Backend работает с UID/GID `10001`. Для bind mount вместо стандартного именованного тома обеспечьте права этого пользователя на `/data`. Одноразовый контейнер восстановления выше использует root с CHOWN/DAC_OVERRIDE для чтения защищённой копии и восстановления владельца БД; обычный backend продолжает работать непривилегированно. Для именованного тома права `/data` берутся из образа при первом создании. До замены база проверяется во временном файле; остановленный backend остаётся необходимым условием. При ошибке восстановления backend не запускайте до выяснения причины.

После запуска войдите в UI, поставьте автоматику пулов на паузу, проверьте интеграции и реальное DNS, затем включайте её осознанно. Старый снимок может не соответствовать текущему Cloudflare; восстановление конфигурации само по себе не восстанавливает DNS-зону. После проверки верните RU-агент командой `docker compose start agent` на его хосте.
