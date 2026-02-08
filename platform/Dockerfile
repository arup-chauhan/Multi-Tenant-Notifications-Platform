FROM ubuntu:24.04 AS builder

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential cmake ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY platform ./platform

ARG SERVICE_TARGET=notification_gateway
RUN cmake -S platform -B platform/build && \
    cmake --build platform/build --target ${SERVICE_TARGET} --config Release

FROM ubuntu:24.04 AS runtime
ARG INSTALL_CASSANDRA_TOOLS=false
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates && \
    if [ "$INSTALL_CASSANDRA_TOOLS" = "true" ]; then \
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends cassandra-tools; \
    fi && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

ARG SERVICE_TARGET=notification_gateway
COPY --from=builder /src/platform/build/services/*/${SERVICE_TARGET} /app/service

ENTRYPOINT ["/app/service"]
