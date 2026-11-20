package guard

// Capture the committed order state, including transitions made by an operator
// while a worker is waiting for a provider.
func (s *Store) initializeOrderLogs() {
	s.transaction(func() {
		s.exec(`CREATE TABLE IF NOT EXISTS server_order_logs(
 id INTEGER PRIMARY KEY, order_id TEXT NOT NULL REFERENCES server_orders(id) ON DELETE CASCADE,
 recorded_at TEXT NOT NULL, stage TEXT NOT NULL, level TEXT NOT NULL, message TEXT NOT NULL,
 occurrences INTEGER NOT NULL DEFAULT 1);
 CREATE INDEX IF NOT EXISTS server_order_logs_order ON server_order_logs(order_id,id);

 INSERT INTO server_order_logs(order_id,recorded_at,stage,level,message)
 SELECT id,updated_at,stage,CASE WHEN error IS NULL THEN 'info' ELSE 'error' END,
 COALESCE(error,'Состояние заказа на момент включения журнала')
 FROM server_orders o WHERE NOT EXISTS (SELECT 1 FROM server_order_logs WHERE order_id=o.id);

 CREATE TRIGGER IF NOT EXISTS server_order_log_created AFTER INSERT ON server_orders BEGIN
   INSERT INTO server_order_logs(order_id,recorded_at,stage,level,message)
   VALUES(NEW.id,NEW.created_at,NEW.stage,'info','Заказ принят');
 END;
 CREATE TRIGGER IF NOT EXISTS server_order_log_state AFTER UPDATE OF stage,error ON server_orders
 WHEN NEW.stage != OLD.stage OR NEW.error IS NOT NULL BEGIN
   UPDATE server_order_logs SET recorded_at=NEW.updated_at, occurrences=occurrences+1
   WHERE id=(SELECT MAX(id) FROM server_order_logs WHERE order_id=NEW.id)
     AND NEW.stage=OLD.stage AND NEW.error=OLD.error AND message=NEW.error AND level='error';
   INSERT INTO server_order_logs(order_id,recorded_at,stage,level,message)
   SELECT NEW.id,NEW.updated_at,NEW.stage,CASE WHEN NEW.error IS NULL THEN 'info' ELSE 'error' END,
          COALESCE(NEW.error,'') WHERE changes()=0;
 END;
 CREATE TRIGGER IF NOT EXISTS server_order_log_create_attempt AFTER UPDATE OF create_attempted ON server_orders
 WHEN NEW.create_attempted != OLD.create_attempted BEGIN
   INSERT INTO server_order_logs(order_id,recorded_at,stage,level,message)
   VALUES(NEW.id,NEW.updated_at,NEW.stage,'info',CASE WHEN NEW.create_attempted=1
     THEN 'Начата попытка создания сервера' ELSE 'Оператор подтвердил повторное создание' END);
 END;
 CREATE TRIGGER IF NOT EXISTS server_order_log_limit AFTER INSERT ON server_order_logs BEGIN
   DELETE FROM server_order_logs WHERE order_id=NEW.order_id AND id <= (
     SELECT id FROM server_order_logs WHERE order_id=NEW.order_id ORDER BY id DESC LIMIT 1 OFFSET 200);
 END;`)
	})
}
