CREATE KEYSPACE IF NOT EXISTS notification_platform
WITH replication = {'class': 'SimpleStrategy', 'replication_factor': 1};

CREATE TABLE IF NOT EXISTS notification_platform.delivery_status (
  tenant_id text,
  notification_id text,
  status_ts timestamp,
  user_id text,
  channel text,
  content text,
  status text,
  attempt int,
  error text,
  PRIMARY KEY ((tenant_id, notification_id), status_ts)
) WITH CLUSTERING ORDER BY (status_ts DESC);
