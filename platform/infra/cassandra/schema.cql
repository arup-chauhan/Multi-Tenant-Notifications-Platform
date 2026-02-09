CREATE KEYSPACE IF NOT EXISTS notification_platform
WITH replication = {'class': 'SimpleStrategy', 'replication_factor': 1};

CREATE TABLE IF NOT EXISTS notification_platform.delivery_status (
  tenant_id text,
  notification_id text,
  status_ts timestamp,
  user_id text,
  channel text,
  content text,
  correlation_id text,
  trace_id text,
  status text,
  attempt int,
  error text,
  PRIMARY KEY ((tenant_id, notification_id), status_ts)
) WITH CLUSTERING ORDER BY (status_ts DESC);

CREATE TABLE IF NOT EXISTS notification_platform.notification_state (
  tenant_id text,
  notification_id text,
  updated_ts timestamp,
  user_id text,
  channel text,
  content text,
  correlation_id text,
  trace_id text,
  status text,
  attempt int,
  error text,
  PRIMARY KEY ((tenant_id), notification_id)
);

CREATE TABLE IF NOT EXISTS notification_platform.tenant_audit_log (
  tenant_id text,
  event_time timestamp,
  event_type text,
  notification_id text,
  details text,
  PRIMARY KEY ((tenant_id), event_time)
) WITH CLUSTERING ORDER BY (event_time DESC);
