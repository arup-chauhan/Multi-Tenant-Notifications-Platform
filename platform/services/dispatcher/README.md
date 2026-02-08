# Dispatcher Service

Responsibilities:

1. Consume Redis Streams via consumer groups
2. Retry failed delivery attempts
3. Route exhausted events to DLQ
4. Coordinate storage writes and delivery status updates
